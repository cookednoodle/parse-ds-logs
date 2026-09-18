"""In-memory type model plus its JSON representation.

The model is a flat registry of named type nodes.  Every reference from one
node to another is a string key into that registry, which keeps the JSON
representation simple and lets the whole thing round-trip without a graph
walk.  Composite types that have no name of their own (arrays, pointers) get a
deterministic synthetic key so that identical types share one node.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, IO, List, Optional, Union

# Node kinds.
KIND_BASE = "base"
KIND_STRUCT = "struct"
KIND_UNION = "union"
KIND_ARRAY = "array"
KIND_ENUM = "enum"
KIND_POINTER = "pointer"
KIND_TYPEDEF = "typedef"

# Scalar encodings.
ENC_INT = "int"
ENC_UINT = "uint"
ENC_FLOAT = "float"
ENC_BOOL = "bool"
ENC_CHAR = "char"
ENC_VOID = "void"

VOID_KEY = "void"

SCHEMA_VERSION = 1


@dataclass
class BaseType:
    """A primitive type: an integer, a float, a bool, a character, or void."""

    name: str
    size: int
    encoding: str
    kind: str = KIND_BASE

    def to_json(self) -> Dict[str, Any]:
        return {"kind": KIND_BASE, "size": self.size, "encoding": self.encoding}


@dataclass
class Member:
    """One field of a struct or union.

    ``offset`` is in bytes from the start of the containing type.  For a
    bitfield, ``bit_offset`` is the absolute offset in bits from that same
    start and ``bit_size`` its width; ``offset`` is then only advisory.
    An empty ``name`` marks an anonymous struct or union member, whose own
    fields are flattened into the parent without a prefix.
    """

    name: str
    offset: int
    type: str
    bit_size: Optional[int] = None
    bit_offset: Optional[int] = None

    def to_json(self) -> Dict[str, Any]:
        out = {"name": self.name, "offset": self.offset, "type": self.type}  # type: Dict[str, Any]
        if self.bit_size is not None:
            out["bit_size"] = self.bit_size
            out["bit_offset"] = self.bit_offset
        return out

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Member":
        return cls(
            name=data["name"],
            offset=data["offset"],
            type=data["type"],
            bit_size=data.get("bit_size"),
            bit_offset=data.get("bit_offset"),
        )


@dataclass
class StructType:
    """A struct, a C++ class, or a union.

    Base-class fields are flattened into ``members`` at their real offsets, so
    a decoder never has to know about inheritance.
    """

    name: str
    size: int
    members: List[Member] = field(default_factory=list)
    kind: str = KIND_STRUCT
    cpp: bool = False

    def to_json(self) -> Dict[str, Any]:
        out = {
            "kind": self.kind,
            "size": self.size,
            "members": [m.to_json() for m in self.members],
        }  # type: Dict[str, Any]
        if self.cpp:
            out["cpp"] = True
        return out


@dataclass
class ArrayType:
    """A one- or multi-dimensional array.  A dimension of 0 is a flexible array."""

    name: str
    elem: str
    dims: List[int]
    size: int
    kind: str = KIND_ARRAY

    def to_json(self) -> Dict[str, Any]:
        return {"kind": KIND_ARRAY, "size": self.size, "elem": self.elem, "dims": list(self.dims)}


@dataclass
class EnumType:
    name: str
    size: int
    values: Dict[int, str] = field(default_factory=dict)
    encoding: str = ENC_INT
    kind: str = KIND_ENUM

    def to_json(self) -> Dict[str, Any]:
        return {
            "kind": KIND_ENUM,
            "size": self.size,
            "encoding": self.encoding,
            # JSON object keys must be strings.
            "values": dict((str(k), v) for k, v in sorted(self.values.items())),
        }


@dataclass
class PointerType:
    name: str
    size: int
    target: Optional[str] = None
    kind: str = KIND_POINTER

    def to_json(self) -> Dict[str, Any]:
        out = {"kind": KIND_POINTER, "size": self.size}  # type: Dict[str, Any]
        if self.target:
            out["target"] = self.target
        return out


@dataclass
class TypedefType:
    name: str
    target: str
    kind: str = KIND_TYPEDEF

    def to_json(self) -> Dict[str, Any]:
        return {"kind": KIND_TYPEDEF, "target": self.target}


TypeNode = Union[BaseType, StructType, ArrayType, EnumType, PointerType, TypedefType]


# Sizes of the cFS header types, harvested from debug info when present.  The
# decoder reads the layout of a recorded packet from these, so they are kept
# apart from the type registry itself.  Defaults match cFE 7.x (Caelum) built
# for CCSDS version 1 with a 6-byte telemetry time field.
GEOMETRY_TYPES = (
    "CFE_MSG_Message_t",
    "CFE_MSG_TelemetryHeader_t",
    "CFE_MSG_CommandHeader_t",
    "CFE_MSG_TelemetrySecondaryHeader_t",
    "CFE_MSG_CommandSecondaryHeader_t",
    "DS_FileHeader_t",
    "CFE_FS_Header_t",
)

GEOMETRY_DEFAULTS = {
    "CFE_MSG_Message_t": 6,
    "CFE_MSG_TelemetryHeader_t": 16,
    "CFE_MSG_CommandHeader_t": 8,
    "CFE_MSG_TelemetrySecondaryHeader_t": 6,
    "CFE_MSG_CommandSecondaryHeader_t": 2,
    "DS_FileHeader_t": 76,
    "CFE_FS_Header_t": 64,
}


# Measured against this project's own names: a genuine typo scores 0.86 and
# up against what it should have been, while a name that simply is not in the
# build tops out around 0.63.  Guessing across that gap misleads more than it
# helps, so the threshold sits inside it.
_LOOKS_LIKE_A_TYPO = 0.75


def close_names(wanted: str, pool: Any, limit: int = 5) -> List[str]:
    """Names from ``pool`` that look like ``wanted``, for an error message.

    Shared by the extractor and the mapping loader so a misspelled struct gets
    the same kind of hint wherever it is caught.
    """
    tail = wanted.rsplit("::", 1)[-1]
    return difflib.get_close_matches(tail, sorted(pool), n=limit, cutoff=_LOOKS_LIKE_A_TYPO)


def array_key(elem: str, dims: List[int]) -> str:
    """Synthetic registry key for an array type."""
    return "%s[%s]" % (elem, "][".join(str(d) for d in dims))


def pointer_key(size: int, target: Optional[str]) -> str:
    """Synthetic registry key for a pointer type."""
    if target:
        return "%s*" % target
    return "void*%d" % size


@dataclass
class TypeRegistry:
    """Every type extracted from a build, keyed by name."""

    types: Dict[str, TypeNode] = field(default_factory=dict)
    endian: str = "little"
    pointer_size: int = 8
    geometry: Dict[str, int] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    # Set when extraction was filtered to a mapping: which registry type each
    # name in that mapping matched, so a filtered file can be audited.
    roots: Dict[str, List[str]] = field(default_factory=dict)
    # Names the mapping asked for that this build does not have.  Kept so a
    # later decode can tell a struct that was never here from one added to the
    # mapping after this file was written.
    unresolved: List[str] = field(default_factory=list)
    # Packet header types this project declared beyond the cFE ones, carried
    # here so a declaration made once at extract time reaches every decode.
    header_types: List[str] = field(default_factory=list)
    filtered: bool = False

    def __post_init__(self) -> None:
        if VOID_KEY not in self.types:
            self.types[VOID_KEY] = BaseType(name=VOID_KEY, size=0, encoding=ENC_VOID)

    # -- lookup ----------------------------------------------------------

    def get(self, key: str) -> Optional[TypeNode]:
        return self.types.get(key)

    def resolve(self, key: str) -> Optional[TypeNode]:
        """Follow typedefs to the first node that is not a typedef."""
        seen = set()  # type: set
        while key and key not in seen:
            seen.add(key)
            node = self.types.get(key)
            if node is None:
                return None
            if node.kind != KIND_TYPEDEF:
                return node
            key = node.target  # type: ignore[union-attr]
        return None

    def resolve_name(self, key: str) -> Optional[str]:
        """The name of the node ``key`` resolves to, typedefs followed."""
        node = self.resolve(key)
        return node.name if node is not None else None

    def typedef_chain(self, key: str) -> List[str]:
        """Every name along the typedef chain starting at ``key``, inclusive."""
        chain = []  # type: List[str]
        seen = set()  # type: set
        while key and key not in seen:
            seen.add(key)
            chain.append(key)
            node = self.types.get(key)
            if node is None or node.kind != KIND_TYPEDEF:
                break
            key = node.target  # type: ignore[union-attr]
        return chain

    def sizeof(self, key: str) -> Optional[int]:
        node = self.resolve(key)
        if node is None or node.kind == KIND_TYPEDEF:
            return None
        return getattr(node, "size", None)

    # -- serialization ---------------------------------------------------

    def to_json(self) -> Dict[str, Any]:
        return {
            "version": SCHEMA_VERSION,
            "endian": self.endian,
            "pointer_size": self.pointer_size,
            "geometry": dict(sorted(self.geometry.items())),
            "sources": list(self.sources),
            "conflicts": list(self.conflicts),
            "filtered": self.filtered,
            "roots": dict((k, list(v)) for k, v in sorted(self.roots.items())),
            "unresolved": sorted(self.unresolved),
            "header_types": sorted(self.header_types),
            "types": dict((k, v.to_json()) for k, v in sorted(self.types.items())),
        }

    def dump(self, stream: IO[str], indent: Optional[int] = 1) -> None:
        json.dump(self.to_json(), stream, indent=indent, sort_keys=False)
        stream.write("\n")

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "TypeRegistry":
        version = data.get("version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                "unsupported type file version %r (this build reads version %d)"
                % (version, SCHEMA_VERSION)
            )
        reg = cls(
            endian=data.get("endian", "little"),
            pointer_size=data.get("pointer_size", 8),
            geometry=dict((k, int(v)) for k, v in (data.get("geometry") or {}).items()),
            sources=list(data.get("sources") or []),
            conflicts=list(data.get("conflicts") or []),
            roots=dict((k, list(v)) for k, v in (data.get("roots") or {}).items()),
            unresolved=[str(name) for name in (data.get("unresolved") or [])],
            header_types=[str(name) for name in (data.get("header_types") or [])],
            filtered=bool(data.get("filtered")),
        )
        for name, node in (data.get("types") or {}).items():
            reg.types[name] = _node_from_json(name, node)
        return reg

    @classmethod
    def load(cls, stream: IO[str]) -> "TypeRegistry":
        return cls.from_json(json.load(stream))


def _node_from_json(name: str, data: Dict[str, Any]) -> TypeNode:
    kind = data.get("kind")
    if kind == KIND_BASE:
        return BaseType(name=name, size=data["size"], encoding=data["encoding"])
    if kind in (KIND_STRUCT, KIND_UNION):
        return StructType(
            name=name,
            size=data["size"],
            members=[Member.from_json(m) for m in data.get("members", [])],
            kind=kind,
            cpp=bool(data.get("cpp")),
        )
    if kind == KIND_ARRAY:
        return ArrayType(name=name, elem=data["elem"], dims=list(data["dims"]), size=data["size"])
    if kind == KIND_ENUM:
        return EnumType(
            name=name,
            size=data["size"],
            values=dict((int(k), v) for k, v in (data.get("values") or {}).items()),
            encoding=data.get("encoding", ENC_INT),
        )
    if kind == KIND_POINTER:
        return PointerType(name=name, size=data["size"], target=data.get("target"))
    if kind == KIND_TYPEDEF:
        return TypedefType(name=name, target=data["target"])
    raise ValueError("unknown type kind %r for %r" % (kind, name))
