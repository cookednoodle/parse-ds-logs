"""Tie message IDs to the structs that decode them.

The mapping comes from a YAML or JSON file, because a message ID is a
preprocessor macro and macros leave no trace in debug info.  Two shapes are
read, told apart by their contents:

* the short one written by hand, where each entry names one message ID and the
  struct its packets carry, and a command may choose a struct by function code;
* the output of a scanner over the flight software, keyed by message ID value,
  carrying the struct under ``fcodes`` for commands and recording which apps
  send and receive each message.  Entries it could not resolve are skipped and
  reported rather than failing the run, since a scan of a whole code base is
  expected to come back with loose ends.
"""

from __future__ import annotations

import io
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .decode import Decoder, DecodeError, Options, compile_struct
from .dsfile import Geometry
from .typemodel import KIND_STRUCT, KIND_UNION, TypeRegistry, close_names

_SAFE_CHARS = "-_."

# What a generated map writes where it could not work out a struct.
UNRESOLVED_STRUCT = "UNKNOWN"


class DictionaryError(Exception):
    """Raised when the mapping file cannot be used."""


class UnknownStructError(DictionaryError):
    """Raised when a struct the mapping names is not in the type file."""


def safe_name(name: str) -> str:
    """A file name that keeps the message ID readable."""
    out = []  # type: List[str]
    for char in name:
        out.append(char if char.isalnum() or char in _SAFE_CHARS else "_")
    return "".join(out).strip("_") or "unnamed"


def parse_int(value: Any, what: str) -> int:
    """Accept 2192, 0x890 or '0x890' for a message ID or function code."""
    if isinstance(value, bool):
        raise DictionaryError("%s must be a number, not a boolean" % what)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0)
        except ValueError:
            pass
    raise DictionaryError("%s must be a number, got %r" % (what, value))


class MidEntry(object):
    """One message ID and how to decode its packets.

    ``read_mapping`` fills everything but ``decoders``, which needs a type
    registry and is attached by :meth:`Dictionary.load`.  That split is what
    lets ``dsdecode extract`` learn which structs a mapping wants before any
    types have been read.
    """

    __slots__ = (
        "name",
        "value",
        "default_struct",
        "by_fcn",
        "decoders",
        "file_name",
        "apps",
        "publishers",
    )

    def __init__(self, name: str, value: int) -> None:
        self.name = name
        self.value = value
        self.default_struct = None  # type: Optional[str]
        self.by_fcn = {}  # type: Dict[int, str]
        self.decoders = {}  # type: Dict[Optional[int], Decoder]
        self.file_name = safe_name(name)
        # Filled from a generated map, which knows where a message comes from.
        self.apps = []  # type: List[str]
        self.publishers = []  # type: List[str]

    def decoder_for(self, fcn_code: Optional[int]) -> Optional[Decoder]:
        if fcn_code is not None and fcn_code in self.decoders:
            return self.decoders[fcn_code]
        return self.decoders.get(None)

    def output_name(self, fcn_code: Optional[int]) -> str:
        """Commands that decode per function code get their own output file."""
        if fcn_code is not None and fcn_code in self.decoders:
            return "%s_fcn%d" % (self.file_name, fcn_code)
        return self.file_name


class Mapping(object):
    """A mapping file that has been read and checked, but not compiled."""

    __slots__ = ("path", "entries", "skipped", "skipped_apps", "generated")

    def __init__(
        self,
        path: str,
        entries: List[MidEntry],
        skipped: Optional[List[Tuple[str, str]]] = None,
        skipped_apps: Optional[List[str]] = None,
        generated: bool = False,
    ) -> None:
        self.path = path
        self.entries = entries
        # (name, why) for entries a generated map could not resolve.
        self.skipped = skipped or []
        # Directories the generating scanner did not look at.
        self.skipped_apps = skipped_apps or []
        self.generated = generated

    def struct_apps(self) -> Dict[str, List[str]]:
        """Which apps each struct belongs to, for the extract summary.

        Senders are preferred over receivers, because the app that publishes a
        message is the one whose view of the struct was recorded.
        """
        out = {}  # type: Dict[str, List[str]]
        for entry in self.entries:
            apps = entry.publishers or entry.apps
            if not apps:
                continue
            for struct in [entry.default_struct] + list(entry.by_fcn.values()):
                if not struct:
                    continue
                known = out.setdefault(struct, [])
                for app in apps:
                    if app not in known:
                        known.append(app)
        return out

    def struct_names(self) -> List[str]:
        """Every struct the mapping names, in file order, without repeats."""
        names = []  # type: List[str]
        seen = set()  # type: set
        for entry in self.entries:
            for name in [entry.default_struct] + list(entry.by_fcn.values()):
                if name and name not in seen:
                    seen.add(name)
                    names.append(name)
        return names

    def __len__(self) -> int:
        return len(self.entries)


def read_mapping(path: str) -> Mapping:
    """Read and check a mapping file without needing any types.

    Everything that can be judged from the file alone is judged here, so
    ``dsdecode extract --mids`` rejects a malformed mapping with the same
    message ``decode`` would give, just earlier.
    """
    if not os.path.exists(path):
        raise DictionaryError("mapping file %s does not exist" % path)
    with io.open(path, "r", encoding="utf-8") as handle:
        try:
            data = yaml.safe_load(handle)
        except yaml.YAMLError as exc:
            raise DictionaryError("cannot read %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise DictionaryError("%s must hold a mapping with a 'mids' key" % path)
    mids = data.get("mids", data)
    if not isinstance(mids, dict) or not mids:
        raise DictionaryError("%s has no message IDs under 'mids'" % path)
    if _looks_generated(data, mids):
        entries, skipped = _read_generated(mids)
        if not entries:
            raise DictionaryError(
                "%s has no message ID that could be used: %s"
                % (path, "; ".join("%s (%s)" % pair for pair in skipped[:5]))
            )
        return Mapping(
            path,
            entries,
            skipped=skipped,
            skipped_apps=[str(app) for app in (data.get("skipped_apps") or [])],
            generated=True,
        )
    return Mapping(path, [_read_entry(key, value) for key, value in mids.items()])


def _looks_generated(data: Dict[str, Any], mids: Dict[Any, Any]) -> bool:
    """Tell a generated map from one written by hand.

    Only a generated map records the apps a message is used by, the function
    codes under their own key, or the directories its scanner skipped.
    """
    if "skipped_apps" in data:
        return True
    for value in mids.values():
        if isinstance(value, dict) and ("fcodes" in value or "usages" in value):
            return True
    return False


def _usable_struct(struct: Any) -> bool:
    """False for a struct a scanner could not work out."""
    return (
        isinstance(struct, str)
        and bool(struct.strip())
        and struct.strip() != UNRESOLVED_STRUCT
    )


def _read_generated(mids: Dict[Any, Any]) -> Tuple[List[MidEntry], List[Tuple[str, str]]]:
    """Turn a generated map into entries, setting aside what cannot be used.

    A scan of a whole code base comes back with message IDs whose value or
    struct it could not resolve.  Those are no use for decoding, but they are
    not a reason to refuse the file, so they are collected and reported.
    """
    entries = []  # type: List[MidEntry]
    skipped = []  # type: List[Tuple[str, str]]
    for key, value in mids.items():
        if not isinstance(value, dict):
            skipped.append((str(key), "the entry is not an object"))
            continue
        name = str(value.get("name") or key)
        if value.get("value") is None:
            skipped.append((name, "its message ID was never resolved"))
            continue
        try:
            mid_value = parse_int(value.get("value"), "value of %s" % name)
        except DictionaryError as exc:
            skipped.append((name, str(exc)))
            continue
        entry = MidEntry(name=name, value=mid_value)
        if value.get("type") == "command":
            _read_generated_command(entry, value, skipped)
        else:
            struct = value.get("struct")
            if _usable_struct(struct):
                entry.default_struct = str(struct).strip()
            _record_usages(entry, value.get("usages"))
        if entry.default_struct is None and not entry.by_fcn:
            skipped.append((name, "no struct was resolved for it"))
            continue
        entries.append(entry)
    return entries, skipped


def _read_generated_command(
    entry: MidEntry, value: Dict[str, Any], skipped: List[Tuple[str, str]]
) -> None:
    """Read a command's structs, which sit under one key per function code."""
    fcodes = value.get("fcodes")
    if not isinstance(fcodes, dict):
        skipped.append((entry.name, "it is a command with no function codes"))
        return
    for key, fcode in fcodes.items():
        if not isinstance(fcode, dict):
            continue
        label = str(fcode.get("name") or key)
        where = "%s function code %s" % (entry.name, label)
        struct = fcode.get("struct")
        if not _usable_struct(struct):
            skipped.append((where, "no struct was resolved for it"))
            continue
        _record_usages(entry, fcode.get("usages"))
        # A usage that named no function code stands for every other one.
        if key is None or str(key).strip().lower() == "null":
            entry.default_struct = str(struct).strip()
            continue
        code = fcode.get("value")
        if code is None:
            code = key
        try:
            entry.by_fcn[parse_int(code, where)] = str(struct).strip()
        except DictionaryError:
            skipped.append((where, "its function code was never resolved"))


def _record_usages(entry: MidEntry, usages: Any) -> None:
    """Note which apps a message passes through, sender first."""
    if not isinstance(usages, list):
        return
    for usage in usages:
        if not isinstance(usage, dict):
            continue
        app = usage.get("app")
        if not app:
            continue
        app = str(app)
        if app not in entry.apps:
            entry.apps.append(app)
        if usage.get("direction") == "outgoing" and app not in entry.publishers:
            entry.publishers.append(app)


class Dictionary(object):
    """Every mapped message ID, with a compiled decoder for each."""

    def __init__(self, registry: TypeRegistry, geometry: Geometry) -> None:
        self.registry = registry
        self.geometry = geometry
        self.entries = {}  # type: Dict[int, MidEntry]

    def lookup(self, msgid: int) -> Optional[MidEntry]:
        return self.entries.get(msgid)

    def __len__(self) -> int:
        return len(self.entries)

    # -- loading ---------------------------------------------------------

    @classmethod
    def load(
        cls,
        path: str,
        registry: TypeRegistry,
        geometry: Geometry,
        options: Optional[Options] = None,
        warn: Optional[Any] = None,
    ) -> "Dictionary":
        warn = warn or (lambda msg: print("warning: %s" % msg, file=sys.stderr))
        mapping = read_mapping(path)
        if mapping.skipped:
            shown = ", ".join(name for name, _ in mapping.skipped[:3])
            if len(mapping.skipped) > 3:
                shown += ", and %d more" % (len(mapping.skipped) - 3)
            warn(
                "%d entr(y/ies) in %s have no message ID or no struct and were "
                "skipped: %s. Run 'dsdecode extract --mids %s' to see them all."
                % (len(mapping.skipped), path, shown, path)
            )

        dictionary = cls(registry, geometry)
        index = _NameIndex(registry)
        options = options or Options()
        for entry in mapping.entries:
            _compile_entry(entry, index, options, registry, warn)
            existing = dictionary.entries.get(entry.value)
            if existing is not None:
                warn(
                    "message ID 0x%04X is mapped twice, as %s and %s; keeping %s"
                    % (entry.value, existing.name, entry.name, existing.name)
                )
                continue
            dictionary.entries[entry.value] = entry
            for decoder in entry.decoders.values():
                if not decoder.has_header:
                    warn(
                        "%s has no cFS message header, so it is decoded as a bare "
                        "payload starting after the packet header" % decoder.type_name
                    )
        return dictionary


def _read_entry(key: Any, value: Any) -> MidEntry:
    """Turn one line of the mapping into an entry, with no decoders yet."""
    name = None  # type: Optional[str]
    mid_value = None  # type: Optional[int]
    if isinstance(key, int) or (isinstance(key, str) and _looks_numeric(key)):
        mid_value = parse_int(key, "message ID %r" % key)
    else:
        name = str(key)

    struct_spec = None  # type: Any
    if isinstance(value, str):
        struct_spec = value
    elif isinstance(value, dict):
        struct_spec = value.get("struct")
        if "value" in value:
            mid_value = parse_int(value["value"], "value of %s" % (name or key))
        if "name" in value and name is None:
            name = str(value["name"])
    else:
        raise DictionaryError(
            "entry %r must be a struct name or a mapping with 'struct', got %r" % (key, value)
        )

    if mid_value is None:
        raise DictionaryError(
            "entry %r has no message ID: give it a 'value', or use the message "
            "ID as the key" % key
        )
    if struct_spec is None:
        raise DictionaryError("entry %r has no 'struct'" % key)
    if name is None:
        name = "MID_0x%04X" % mid_value

    entry = MidEntry(name=name, value=mid_value)
    if isinstance(struct_spec, str):
        entry.default_struct = struct_spec
    elif isinstance(struct_spec, dict):
        default = struct_spec.get("default")
        if default is not None:
            entry.default_struct = str(default)
        for fcn, struct_name in (struct_spec.get("fcn") or {}).items():
            code = parse_int(fcn, "function code in %s" % name)
            entry.by_fcn[code] = str(struct_name)
        if entry.default_struct is None and not entry.by_fcn:
            raise DictionaryError(
                "entry %s needs a 'default' struct, one or more 'fcn' entries, or both" % name
            )
    else:
        raise DictionaryError("entry %s has an unreadable 'struct' value" % name)
    return entry


def _compile_entry(
    entry: MidEntry,
    index: "_NameIndex",
    options: Options,
    registry: TypeRegistry,
    warn: Optional[Any] = None,
) -> None:
    """Attach a decoder to an entry for each struct it names."""
    if entry.default_struct is not None:
        entry.decoders[None] = _compile(
            entry.default_struct, index, options, registry, entry.name, warn
        )
    for code, struct_name in entry.by_fcn.items():
        entry.decoders[code] = _compile(
            struct_name, index, options, registry, entry.name, warn
        )


def _compile(
    struct_name: str,
    index: "_NameIndex",
    options: Options,
    registry: TypeRegistry,
    mid_name: str,
    warn: Optional[Any] = None,
) -> Decoder:
    resolved = index.resolve(struct_name)
    try:
        return compile_struct(registry, resolved, options, warn=warn)
    except DecodeError as exc:
        raise DictionaryError("%s: %s" % (mid_name, exc))


def _looks_numeric(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    try:
        int(stripped, 0)
        return True
    except ValueError:
        return False


class _NameIndex(object):
    """Finds a struct in the registry, forgiving about namespaces and case."""

    def __init__(self, registry: TypeRegistry) -> None:
        self.registry = registry
        self._by_tail = {}  # type: Dict[str, List[str]]
        self._by_lower = {}  # type: Dict[str, List[str]]
        for name, node in registry.types.items():
            if node.kind not in (KIND_STRUCT, KIND_UNION) and node.kind != "typedef":
                continue
            tail = name.rsplit("::", 1)[-1]
            self._by_tail.setdefault(tail, []).append(name)
            self._by_lower.setdefault(name.lower(), []).append(name)
            self._by_lower.setdefault(tail.lower(), []).append(name)

    def resolve(self, wanted: str) -> str:
        wanted = wanted.strip()
        if wanted in self.registry.types:
            return wanted
        for table, key in ((self._by_tail, wanted), (self._by_lower, wanted.lower())):
            matches = sorted(set(table.get(key, [])))
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise DictionaryError(
                    "struct %r is ambiguous; write one of: %s" % (wanted, ", ".join(matches))
                )
        raise UnknownStructError(
            "struct %r is not in the type file%s" % (wanted, self._suggest(wanted))
        )

    def _suggest(self, wanted: str) -> str:
        tail = wanted.rsplit("::", 1)[-1]
        close = []  # type: List[str]
        for match in close_names(wanted, self._by_tail):
            close.extend(self._by_tail.get(match, []))
        if not close:
            lowered = tail.lower()
            close = sorted(
                set(
                    name
                    for key, names in self._by_lower.items()
                    if lowered in key or key in lowered
                    for name in names
                )
            )
        if not close:
            return ""
        return ". Close names: %s" % ", ".join(sorted(set(close))[:8])
