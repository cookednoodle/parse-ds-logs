"""Read struct layouts out of the DWARF debug info in a compiled build.

Everything here observes what the compiler actually did: offsets, padding,
array extents and bitfield placement come from the debug info rather than from
re-parsing headers, so C++ classes, inheritance and namespaces land in the type
registry with the same layout the flight software uses at run time.
"""

from __future__ import annotations

import hashlib
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from elftools.elf.elffile import ELFFile

from .typemodel import (
    ENC_BOOL,
    ENC_CHAR,
    ENC_FLOAT,
    ENC_INT,
    ENC_UINT,
    GEOMETRY_TYPES,
    KIND_STRUCT,
    KIND_UNION,
    VOID_KEY,
    ArrayType,
    BaseType,
    EnumType,
    Member,
    PointerType,
    StructType,
    TypeRegistry,
    TypedefType,
    array_key,
    close_names,
    pointer_key,
)

# DWARF base-type encodings we care about (DW_ATE_*).
DW_ATE_address = 0x01
DW_ATE_boolean = 0x02
DW_ATE_float = 0x04
DW_ATE_signed = 0x05
DW_ATE_signed_char = 0x06
DW_ATE_unsigned = 0x07
DW_ATE_unsigned_char = 0x08
DW_ATE_UTF = 0x10

DW_OP_plus_uconst = 0x23

_COMPOSITE_TAGS = ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type")
_QUALIFIER_TAGS = (
    "DW_TAG_const_type",
    "DW_TAG_volatile_type",
    "DW_TAG_restrict_type",
    "DW_TAG_atomic_type",
    "DW_TAG_immutable_type",
    "DW_TAG_packed_type",
    "DW_TAG_shared_type",
)
_POINTER_TAGS = (
    "DW_TAG_pointer_type",
    "DW_TAG_reference_type",
    "DW_TAG_rvalue_reference_type",
    "DW_TAG_ptr_to_member_type",
)
# Tags the top-level walk registers on sight.  Anonymous composites are left
# out: they are picked up through the typedef or member that refers to them,
# which gives them a better name.
_WALK_TAGS = _COMPOSITE_TAGS + ("DW_TAG_typedef", "DW_TAG_enumeration_type")

# A scope whose name qualifies the types declared inside it.
_SCOPE_TAGS = ("DW_TAG_namespace",) + _COMPOSITE_TAGS


class DwarfError(Exception):
    """Raised when a file cannot be read for type information."""


def _uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
    return result, pos


def _attr(die: Any, name: str) -> Any:
    attr = die.attributes.get(name)
    return None if attr is None else attr.value


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _die_name(die: Any) -> Optional[str]:
    """The DIE's own name, following specification/origin links if needed."""
    name = _text(_attr(die, "DW_AT_name"))
    if name is not None:
        return name
    for link in ("DW_AT_specification", "DW_AT_abstract_origin"):
        if link in die.attributes:
            try:
                target = _ref_die(die, link)
            except Exception:
                return None
            if target is not None:
                return _text(_attr(target, "DW_AT_name"))
    return None


def _ref_die(die: Any, attr_name: str = "DW_AT_type") -> Optional[Any]:
    """Resolve a DIE reference attribute to the DIE it points at."""
    attr = die.attributes.get(attr_name)
    if attr is None:
        return None
    form = attr.form
    dwarf = die.dwarfinfo
    if form == "DW_FORM_ref_addr":
        return dwarf.get_DIE_from_refaddr(attr.value)
    if form == "DW_FORM_ref_sig8":
        try:
            return dwarf.get_DIE_by_sig8(attr.value)
        except Exception:
            return None
    if form in (
        "DW_FORM_ref1",
        "DW_FORM_ref2",
        "DW_FORM_ref4",
        "DW_FORM_ref8",
        "DW_FORM_ref",
        "DW_FORM_ref_udata",
    ):
        return dwarf.get_DIE_from_refaddr(die.cu.cu_offset + attr.value, die.cu)
    return None


def _member_offset(die: Any) -> Optional[int]:
    """Byte offset of a member, from a constant or a location expression."""
    attr = die.attributes.get("DW_AT_data_member_location")
    if attr is None:
        return None
    value = attr.value
    if isinstance(value, int):
        return value
    if isinstance(value, (list, bytes, bytearray)):
        raw = bytes(value)
        if not raw:
            return 0
        if raw[0] == DW_OP_plus_uconst:
            offset, _ = _uleb128(raw, 1)
            return offset
    return None


def _anon_key(prefix: str, signature: str) -> str:
    digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:12]
    return "%s:%s" % (prefix, digest)


# How a mapping name matched a type, best first.  These mirror the tiers in
# dictionary._NameIndex.resolve.
TIER_EXACT = 0
TIER_TAIL = 1
TIER_CASE = 2

_TIER_NAMES = {TIER_EXACT: "exactly", TIER_TAIL: "by name without its namespace", TIER_CASE: "ignoring case"}


class NameFilter(object):
    """Decides which types an extraction keeps, and records what matched.

    The rules mirror the struct lookup in ``dictionary._NameIndex``: a name
    matches a type exactly, or by the part after the last ``::``, or ignoring
    case.  Keeping the two in step is what stops a struct resolving here and
    then failing at decode time.
    """

    def __init__(self, names: Sequence[str], always: Sequence[str] = ()) -> None:
        self.wanted = []  # type: List[str]
        self.optional = set()  # type: Set[str]
        self.resolved = {}  # type: Dict[str, Dict[int, List[str]]]
        # Every named type seen anywhere in the build, for suggesting a
        # correction when a mapping name is not found.
        self.seen_names = set()  # type: Set[str]
        self._exact = {}  # type: Dict[str, List[str]]
        self._by_tail = {}  # type: Dict[str, List[str]]
        self._by_lower = {}  # type: Dict[str, List[str]]
        self._quick = set()  # type: Set[str]
        for name in names:
            self._add(name, False)
        for name in always:
            self._add(name, True)

    def _add(self, name: str, optional: bool) -> None:
        name = (name or "").strip()
        if not name or name in self.resolved:
            return
        self.wanted.append(name)
        self.resolved[name] = {}
        if optional:
            self.optional.add(name)
        tail = name.rsplit("::", 1)[-1]
        # Keyed by the mapping name, looked up with what a type offers.
        self._exact.setdefault(name, []).append(name)
        self._by_tail.setdefault(name, []).append(name)
        self._by_lower.setdefault(name.lower(), []).append(name)
        for text in (name, tail):
            self._quick.add(text)
            self._quick.add(text.lower())

    # -- matching --------------------------------------------------------

    def wants(self, name: str) -> bool:
        """Cheap test on a type's own name, before qualifying it costs anything.

        Never rejects a name that :meth:`match` would accept: every rule there
        needs the type's own name to equal a mapping name, or the tail of one,
        give or take case.
        """
        return name in self._quick or name.lower() in self._quick

    def match(self, qualified: str) -> List[Tuple[str, int]]:
        """Every mapping name this type satisfies, with how it matched."""
        tail = qualified.rsplit("::", 1)[-1]
        out = []  # type: List[Tuple[str, int]]
        for wanted in self._exact.get(qualified, ()):
            out.append((wanted, TIER_EXACT))
        for wanted in self._by_tail.get(tail, ()):
            out.append((wanted, TIER_TAIL))
        for key in (qualified.lower(), tail.lower()):
            for wanted in self._by_lower.get(key, ()):
                out.append((wanted, TIER_CASE))
        return out

    # -- results ---------------------------------------------------------

    def record(self, wanted: str, tier: int, key: str) -> None:
        tiers = self.resolved.setdefault(wanted, {})
        keys = tiers.setdefault(tier, [])
        if key not in keys:
            keys.append(key)

    def resolution(self, wanted: str) -> List[str]:
        """The types a mapping name resolves to, from its best matching rule."""
        tiers = self.resolved.get(wanted) or {}
        for tier in sorted(tiers):
            if tiers[tier]:
                return sorted(tiers[tier])
        return []

    def tier_of(self, wanted: str) -> Optional[int]:
        tiers = self.resolved.get(wanted) or {}
        for tier in sorted(tiers):
            if tiers[tier]:
                return tier
        return None

    def describe(self, wanted: str) -> str:
        """How a mapping name resolved, for the extract summary."""
        keys = self.resolution(wanted)
        if not keys:
            return "not found"
        tier = self.tier_of(wanted)
        how = "" if tier == TIER_EXACT else " (matched %s)" % _TIER_NAMES.get(tier, "")
        return "%s%s" % (", ".join(keys), how)

    def missing(self) -> List[str]:
        return [w for w in self.wanted if w not in self.optional and not self.resolution(w)]

    def ambiguous(self) -> List[Tuple[str, List[str]]]:
        found = []  # type: List[Tuple[str, List[str]]]
        for wanted in self.wanted:
            keys = self.resolution(wanted)
            if len(keys) > 1:
                found.append((wanted, keys))
        return found


class Extractor:
    """Builds a :class:`TypeRegistry` from one or more ELF files."""

    def __init__(
        self,
        verbose: bool = False,
        warn: Optional[Any] = None,
        names: Optional[NameFilter] = None,
    ) -> None:
        self.registry = TypeRegistry()
        # When set, only the types this filter matches are registered; their
        # dependencies still follow, because _key_for_die recurses.
        self._names = names
        self.verbose = verbose
        self._warn_fn = warn or (lambda msg: print("warning: %s" % msg, file=sys.stderr))
        self._warned = set()  # type: Set[str]
        # DIE offset -> registry key, valid for the file being read.
        self._keys = {}  # type: Dict[int, str]
        # DIE offset of an anonymous composite -> name of the typedef for it.
        self._anon_names = {}  # type: Dict[int, str]
        self._in_progress = set()  # type: Set[int]
        self._pointer_size = 8

    # -- public API ------------------------------------------------------

    def add_file(self, path: str) -> None:
        """Read every type in one ELF file into the registry."""
        try:
            handle = open(path, "rb")
        except OSError as exc:
            raise DwarfError("cannot open %s: %s" % (path, exc))
        with handle:
            try:
                elf = ELFFile(handle)
            except Exception as exc:
                raise DwarfError("%s is not an ELF file (%s)" % (path, exc))
            if not elf.has_dwarf_info():
                raise DwarfError(
                    "%s has no DWARF debug info: rebuild with -g "
                    "(for example -DCMAKE_BUILD_TYPE=Debug)" % path
                )
            self.registry.endian = "little" if elf.little_endian else "big"
            self._pointer_size = elf.elfclass // 8
            self.registry.pointer_size = self._pointer_size
            dwarf = elf.get_dwarf_info()
            # Offsets are only unique within one file.
            self._keys = {}
            count = 0
            for cu in dwarf.iter_CUs():
                count += self._read_cu(cu)
                # Drop the CU's parsed DIEs; a whole cFS build does not fit in
                # memory otherwise.  Anything referenced later is re-parsed.
                cu._dielist = []
                cu._diemap = []
            if path not in self.registry.sources:
                self.registry.sources.append(path)
            if self.verbose:
                print(
                    "%s: %d types (%d total)" % (path, count, len(self.registry.types)),
                    file=sys.stderr,
                )
        self._update_geometry()

    def warn(self, message: str) -> None:
        if message not in self._warned:
            self._warned.add(message)
            self._warn_fn(message)

    # -- compile unit walk -----------------------------------------------

    def _read_cu(self, cu: Any) -> int:
        self._pointer_size = cu["address_size"] or self._pointer_size
        interesting = []  # type: List[Tuple[Any, Any]]
        self._anon_names = {}
        try:
            dies = list(cu.iter_DIEs())
        except Exception as exc:
            self.warn("skipping a compile unit that failed to parse: %s" % exc)
            return 0
        for die in dies:
            if die.is_null():
                continue
            tag = die.tag
            is_typedef = tag == "DW_TAG_typedef"
            if is_typedef:
                # Runs whether or not the typedef is wanted: it is what gives
                # "typedef struct {...} Foo_t" its name.
                self._note_anon_typedef(die)
            elif tag not in _WALK_TAGS:
                continue
            name = _die_name(die)
            if self._names is None:
                if is_typedef or name is not None:
                    interesting.append((die, ()))
                continue
            if name is None:
                continue
            self._names.seen_names.add(name)
            if not self._names.wants(name):
                continue
            matches = self._names.match(self._qualify(die, name))
            if matches:
                interesting.append((die, matches))
        before = len(self.registry.types)
        for die, matches in interesting:
            try:
                key = self._key_for_die(die)
            except Exception as exc:  # keep going; one bad type is not fatal
                self.warn("could not read type at DIE offset 0x%x: %s" % (die.offset, exc))
                continue
            if matches and key and key != VOID_KEY and self._names is not None:
                for wanted, tier in matches:
                    self._names.record(wanted, tier, key)
        return len(self.registry.types) - before

    def _note_anon_typedef(self, die: Any) -> None:
        """Record ``typedef struct {...} Foo_t`` so the struct is named Foo_t."""
        name = _die_name(die)
        if not name:
            return
        target = _ref_die(die)
        if target is None:
            return
        if target.tag in _COMPOSITE_TAGS or target.tag == "DW_TAG_enumeration_type":
            if _die_name(target) is None:
                self._anon_names.setdefault(target.offset, self._qualify(die, name))

    # -- naming ----------------------------------------------------------

    def _qualify(self, die: Any, name: str) -> str:
        """Prefix a name with its enclosing namespaces and classes."""
        parts = []  # type: List[str]
        try:
            parent = die.get_parent()
        except Exception:
            parent = None
        while parent is not None and parent.tag in _SCOPE_TAGS:
            parent_name = _die_name(parent)
            if parent_name:
                parts.append(parent_name)
            try:
                parent = parent.get_parent()
            except Exception:
                break
        if not parts:
            return name
        parts.reverse()
        return "::".join(parts + [name])

    # -- type registration -----------------------------------------------

    def _key_for_die(self, die: Optional[Any]) -> str:
        """Registry key for the type a DIE describes, registering it if new."""
        if die is None:
            return VOID_KEY
        cached = self._keys.get(die.offset)
        if cached is not None:
            return cached
        if die.offset in self._in_progress:
            # Only reachable through a malformed cycle; pointers stop recursion.
            return VOID_KEY
        self._in_progress.add(die.offset)
        try:
            key = self._build(die)
        finally:
            self._in_progress.discard(die.offset)
        self._keys[die.offset] = key
        return key

    def _build(self, die: Any) -> str:
        tag = die.tag
        if tag in _QUALIFIER_TAGS:
            return self._key_for_die(_ref_die(die))
        if tag == "DW_TAG_base_type":
            return self._build_base(die)
        if tag == "DW_TAG_typedef":
            return self._build_typedef(die)
        if tag in _COMPOSITE_TAGS:
            return self._build_composite(die)
        if tag == "DW_TAG_array_type":
            return self._build_array(die)
        if tag == "DW_TAG_enumeration_type":
            return self._build_enum(die)
        if tag in _POINTER_TAGS:
            return self._build_pointer(die)
        if tag == "DW_TAG_subroutine_type":
            # Only ever reachable behind a pointer, which records its own size.
            return VOID_KEY
        return VOID_KEY

    def _build_base(self, die: Any) -> str:
        name = _die_name(die) or "unnamed_base"
        size = _attr(die, "DW_AT_byte_size") or 0
        encoding = _attr(die, "DW_AT_encoding")
        enc = ENC_UINT
        if name == "char" or encoding == DW_ATE_UTF:
            # Only plain char holds text.  signed char and unsigned char are
            # how cFS spells int8 and uint8, which are numbers.
            enc = ENC_CHAR
        elif encoding == DW_ATE_float:
            enc = ENC_FLOAT
        elif encoding == DW_ATE_boolean:
            enc = ENC_BOOL
        elif encoding in (DW_ATE_signed, DW_ATE_signed_char):
            enc = ENC_INT
        elif encoding in (DW_ATE_unsigned, DW_ATE_unsigned_char, DW_ATE_address):
            enc = ENC_UINT
        key = name
        existing = self.registry.types.get(key)
        if existing is None:
            self.registry.types[key] = BaseType(name=key, size=size, encoding=enc)
        elif getattr(existing, "size", size) != size:
            self._note_conflict(key, getattr(existing, "size", 0), size)
        return key

    def _build_typedef(self, die: Any) -> str:
        name = _die_name(die)
        if not name:
            return self._key_for_die(_ref_die(die))
        key = self._qualify(die, name)
        target_die = _ref_die(die)
        existing = self.registry.types.get(key)
        if existing is not None:
            return key
        if target_die is None:
            self.registry.types[key] = TypedefType(name=key, target=VOID_KEY)
            return key
        # typedef struct {...} Foo_t: name the struct Foo_t rather than
        # inserting a typedef to an anonymous type.
        anon_composite = (
            target_die.tag in _COMPOSITE_TAGS or target_die.tag == "DW_TAG_enumeration_type"
        ) and _die_name(target_die) is None
        if anon_composite and target_die.offset not in self._keys:
            target_key = self._key_for_die(target_die)
            if target_key == key:
                return key
        else:
            target_key = self._key_for_die(target_die)
        if target_key == key:
            return key
        self.registry.types[key] = TypedefType(name=key, target=target_key)
        return key

    def _build_composite(self, die: Any) -> str:
        if "DW_AT_declaration" in die.attributes or "DW_AT_byte_size" not in die.attributes:
            # An incomplete type; the definition lives in another compile unit.
            return VOID_KEY
        size = _attr(die, "DW_AT_byte_size") or 0
        kind = KIND_UNION if die.tag == "DW_TAG_union_type" else KIND_STRUCT
        name = _die_name(die)
        key = None  # type: Optional[str]
        if name:
            key = self._qualify(die, name)
        else:
            key = self._anon_names.get(die.offset)
        if key is not None:
            existing = self.registry.types.get(key)
            if existing is not None:
                # Already known from another compile unit or another file.
                if getattr(existing, "size", size) != size:
                    self._note_conflict(key, getattr(existing, "size", 0), size)
                return key
            # Reserve the name before reading members so a member that refers
            # back to this type through a pointer does not recurse.
            self.registry.types[key] = StructType(name=key, size=size, kind=kind)
        members, is_cpp = self._read_members(die, key)
        if key is None:
            signature = "%s|%d|%s" % (
                kind,
                size,
                ",".join(
                    "%s@%s:%s:%s" % (m.name, m.offset, m.type, m.bit_offset) for m in members
                ),
            )
            key = _anon_key("@anon", signature)
            if key in self.registry.types:
                return key
        node = StructType(name=key, size=size, members=members, kind=kind, cpp=is_cpp)
        self.registry.types[key] = node
        return key

    def _read_members(self, die: Any, own_key: Optional[str]) -> Tuple[List[Member], bool]:
        members = []  # type: List[Member]
        is_cpp = False
        for child in die.iter_children():
            if child.is_null():
                continue
            tag = child.tag
            if tag == "DW_TAG_inheritance":
                is_cpp = True
                members.extend(self._read_inherited(child, own_key))
                continue
            if tag in ("DW_TAG_subprogram", "DW_TAG_variable", "DW_TAG_template_type_param"):
                # Member functions and static data members occupy no storage.
                is_cpp = is_cpp or tag == "DW_TAG_subprogram"
                continue
            if tag != "DW_TAG_member":
                continue
            if "DW_AT_declaration" in child.attributes or "DW_AT_external" in child.attributes:
                continue  # static data member
            member = self._read_member(child, die)
            if member is not None:
                members.append(member)
        members.sort(key=lambda m: (m.offset if m.bit_offset is None else m.bit_offset // 8))
        return members, is_cpp

    def _read_member(self, child: Any, parent: Any) -> Optional[Member]:
        name = _die_name(child) or ""
        offset = _member_offset(child)
        if offset is None:
            if parent.tag == "DW_TAG_union_type" or "DW_AT_data_bit_offset" in child.attributes:
                offset = 0
            else:
                return None
        type_key = self._key_for_die(_ref_die(child))
        bit_size = _attr(child, "DW_AT_bit_size")
        if bit_size is None:
            return Member(name=name, offset=offset, type=type_key)
        data_bit_offset = _attr(child, "DW_AT_data_bit_offset")
        if data_bit_offset is not None:
            # DWARF 4 and later: absolute bit offset from the start of the type.
            bit_offset = data_bit_offset
        else:
            # DWARF 3 and earlier count from the most significant bit of the
            # storage unit, so the meaning depends on target byte order.
            storage = _attr(child, "DW_AT_byte_size")
            if storage is None:
                storage = self.registry.sizeof(type_key) or 0
            legacy = _attr(child, "DW_AT_bit_offset")
            if legacy is None:
                return Member(name=name, offset=offset, type=type_key)
            if self.registry.endian == "little":
                bit_offset = offset * 8 + (storage * 8 - legacy - bit_size)
            else:
                bit_offset = offset * 8 + legacy
        return Member(
            name=name,
            offset=bit_offset // 8,
            type=type_key,
            bit_size=bit_size,
            bit_offset=bit_offset,
        )

    def _read_inherited(self, child: Any, own_key: Optional[str]) -> List[Member]:
        """Flatten a base class into the deriving type at its real offset."""
        base_offset = _member_offset(child)
        if base_offset is None:
            self.warn(
                "skipping a virtually inherited base of %s: its offset is only "
                "known at run time" % (own_key or "an anonymous type")
            )
            return []
        base_key = self._key_for_die(_ref_die(child))
        base = self.registry.resolve(base_key)
        if base is None or base.kind not in (KIND_STRUCT, KIND_UNION):
            return []
        out = []  # type: List[Member]
        for member in base.members:  # type: ignore[union-attr]
            out.append(
                Member(
                    name=member.name,
                    offset=member.offset + base_offset,
                    type=member.type,
                    bit_size=member.bit_size,
                    bit_offset=(
                        None if member.bit_offset is None else member.bit_offset + base_offset * 8
                    ),
                )
            )
        return out

    def _build_array(self, die: Any) -> str:
        elem_key = self._key_for_die(_ref_die(die))
        dims = []  # type: List[int]
        for child in die.iter_children():
            if child.is_null() or child.tag != "DW_TAG_subrange_type":
                continue
            count = _attr(child, "DW_AT_count")
            if count is None:
                upper = _attr(child, "DW_AT_upper_bound")
                if isinstance(upper, int):
                    lower = _attr(child, "DW_AT_lower_bound")
                    lower = lower if isinstance(lower, int) else 0
                    count = upper - lower + 1
                else:
                    count = 0  # flexible or variable-length array member
            if not isinstance(count, int) or count < 0:
                count = 0
            dims.append(count)
        if not dims:
            dims = [0]
        elem_size = self.registry.sizeof(elem_key) or 0
        size = _attr(die, "DW_AT_byte_size")
        if not isinstance(size, int):
            total = elem_size
            for dim in dims:
                total *= dim
            size = total
        key = array_key(elem_key, dims)
        if key not in self.registry.types:
            self.registry.types[key] = ArrayType(name=key, elem=elem_key, dims=dims, size=size)
        return key

    def _build_enum(self, die: Any) -> str:
        values = {}  # type: Dict[int, str]
        for child in die.iter_children():
            if child.is_null() or child.tag != "DW_TAG_enumerator":
                continue
            const = _attr(child, "DW_AT_const_value")
            label = _die_name(child)
            if isinstance(const, int) and label:
                values[const] = label
        size = _attr(die, "DW_AT_byte_size")
        underlying = _ref_die(die)
        if not isinstance(size, int):
            size = self.registry.sizeof(self._key_for_die(underlying)) if underlying else None
            size = size or 4
        encoding = ENC_INT if any(v < 0 for v in values) else ENC_UINT
        if underlying is not None:
            base = self.registry.resolve(self._key_for_die(underlying))
            if base is not None and getattr(base, "encoding", None) in (ENC_INT, ENC_UINT):
                encoding = base.encoding  # type: ignore[union-attr]
        name = _die_name(die)
        if name:
            key = self._qualify(die, name)
        else:
            key = self._anon_names.get(die.offset)
        if key is None:
            signature = "%d|%s" % (size, ",".join("%d=%s" % kv for kv in sorted(values.items())))
            key = _anon_key("@enum", signature)
        existing = self.registry.types.get(key)
        if existing is None:
            self.registry.types[key] = EnumType(
                name=key, size=size, values=values, encoding=encoding
            )
        elif getattr(existing, "size", size) != size:
            self._note_conflict(key, getattr(existing, "size", 0), size)
        return key

    def _build_pointer(self, die: Any) -> str:
        size = _attr(die, "DW_AT_byte_size")
        if not isinstance(size, int):
            size = self._pointer_size
        # The pointee is named but never followed: that would recurse through
        # self-referential structs, and a recorded pointer value is not useful
        # beyond its raw bits anyway.
        target = None  # type: Optional[str]
        target_die = _ref_die(die)
        if target_die is not None:
            name = _die_name(target_die)
            if name:
                target = self._qualify(target_die, name)
        key = pointer_key(size, target)
        if key not in self.registry.types:
            self.registry.types[key] = PointerType(name=key, size=size, target=target)
        return key

    # -- bookkeeping -----------------------------------------------------

    def _note_conflict(self, key: str, old: int, new: int) -> None:
        message = "%s has two different sizes in this build (%d and %d bytes); keeping %d" % (
            key,
            old,
            new,
            old,
        )
        if message not in self.registry.conflicts:
            self.registry.conflicts.append(message)
            self.warn(message)

    def _update_geometry(self) -> None:
        for name in GEOMETRY_TYPES:
            size = self.registry.sizeof(name)
            if size:
                self.registry.geometry[name] = size


def extract(
    paths: Sequence[str],
    verbose: bool = False,
    warn: Optional[Any] = None,
    names: Optional[NameFilter] = None,
    allow_missing: bool = False,
) -> TypeRegistry:
    """Read types from ``paths`` into one registry.

    With no ``names`` filter this reads every type in the given files.  With
    one, it keeps the types that filter matches and, through the recursion in
    ``_key_for_die``, everything those types are built from.
    """
    extractor = Extractor(verbose=verbose, warn=warn, names=names)
    errors = []  # type: List[str]
    for path in paths:
        if not os.path.exists(path):
            errors.append("%s does not exist" % path)
            continue
        try:
            extractor.add_file(path)
        except DwarfError as exc:
            errors.append(str(exc))
    registry = extractor.registry
    if not registry.sources:
        raise DwarfError("; ".join(errors) or "no input files")
    for message in errors:
        extractor.warn(message)
    if names is not None:
        _finish_filtered(registry, names, extractor, allow_missing)
    return registry


def _finish_filtered(
    registry: TypeRegistry, names: NameFilter, extractor: Extractor, allow_missing: bool
) -> None:
    """Record what each mapping name resolved to, and report what did not."""
    registry.filtered = True
    registry.roots = dict(
        (wanted, names.resolution(wanted))
        for wanted in names.wanted
        if wanted not in names.optional and names.resolution(wanted)
    )
    for wanted, keys in names.ambiguous():
        extractor.warn(
            "%r matches more than one type in this build (%s); all of them are kept, "
            "so write the one you mean in the mapping" % (wanted, ", ".join(keys))
        )
    missing = names.missing()
    if not missing:
        return
    details = []  # type: List[str]
    for wanted in missing:
        hint = close_names(wanted, names.seen_names)
        details.append("%s%s" % (wanted, (" (did you mean %s?)" % ", ".join(hint)) if hint else ""))
    message = "%d struct(s) named in the mapping are not in %s: %s" % (
        len(missing),
        ", ".join(registry.sources),
        "; ".join(details),
    )
    if allow_missing:
        extractor.warn(message)
    else:
        raise DwarfError(message)
