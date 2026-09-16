"""Tie message IDs to the structs that decode them.

The mapping comes from a small YAML or JSON file the user writes, because a
message ID is a preprocessor macro and macros leave no trace in debug info.
Each entry names one message ID and the struct its packets carry; commands may
choose a struct by function code.
"""

from __future__ import annotations

import difflib
import io
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .decode import Decoder, DecodeError, Options, compile_struct
from .dsfile import Geometry
from .typemodel import KIND_STRUCT, KIND_UNION, TypeRegistry

_SAFE_CHARS = "-_."


class DictionaryError(Exception):
    """Raised when the mapping file cannot be used."""


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
    """One message ID and how to decode its packets."""

    __slots__ = ("name", "value", "default_struct", "by_fcn", "decoders", "file_name")

    def __init__(self, name: str, value: int) -> None:
        self.name = name
        self.value = value
        self.default_struct = None  # type: Optional[str]
        self.by_fcn = {}  # type: Dict[int, str]
        self.decoders = {}  # type: Dict[Optional[int], Decoder]
        self.file_name = safe_name(name)

    def decoder_for(self, fcn_code: Optional[int]) -> Optional[Decoder]:
        if fcn_code is not None and fcn_code in self.decoders:
            return self.decoders[fcn_code]
        return self.decoders.get(None)

    def output_name(self, fcn_code: Optional[int]) -> str:
        """Commands that decode per function code get their own output file."""
        if fcn_code is not None and fcn_code in self.decoders:
            return "%s_fcn%d" % (self.file_name, fcn_code)
        return self.file_name


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

        dictionary = cls(registry, geometry)
        index = _NameIndex(registry)
        options = options or Options()
        for key, value in mids.items():
            entry = _read_entry(key, value, index, options, registry)
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


def _read_entry(
    key: Any, value: Any, index: "_NameIndex", options: Options, registry: TypeRegistry
) -> MidEntry:
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
        entry.decoders[None] = _compile(struct_spec, index, options, registry, name)
    elif isinstance(struct_spec, dict):
        default = struct_spec.get("default")
        if default is not None:
            entry.default_struct = str(default)
            entry.decoders[None] = _compile(str(default), index, options, registry, name)
        for fcn, struct_name in (struct_spec.get("fcn") or {}).items():
            code = parse_int(fcn, "function code in %s" % name)
            entry.by_fcn[code] = str(struct_name)
            entry.decoders[code] = _compile(str(struct_name), index, options, registry, name)
        if not entry.decoders:
            raise DictionaryError(
                "entry %s needs a 'default' struct, one or more 'fcn' entries, or both" % name
            )
    else:
        raise DictionaryError("entry %s has an unreadable 'struct' value" % name)
    return entry


def _compile(
    struct_name: str, index: "_NameIndex", options: Options, registry: TypeRegistry, mid_name: str
) -> Decoder:
    resolved = index.resolve(struct_name)
    try:
        return compile_struct(registry, resolved, options)
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
        raise DictionaryError(
            "struct %r is not in the type file%s" % (wanted, self._suggest(wanted))
        )

    def _suggest(self, wanted: str) -> str:
        tail = wanted.rsplit("::", 1)[-1]
        close = []  # type: List[str]
        for match in difflib.get_close_matches(tail, sorted(self._by_tail), n=5, cutoff=0.6):
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
