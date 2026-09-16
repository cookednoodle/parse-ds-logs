"""Compile a struct from the type registry into a flat list of CSV columns.

A message type is walked once, up front, into a list of fields that each know
their byte offset and how to unpack themselves.  Decoding a packet is then a
handful of ``unpack_from`` calls, which matters when a log holds millions of
them.  Nested structs, arrays, bitfields and unions all flatten into columns
named after the path taken to reach them, so every row of a CSV has the same
shape.
"""

from __future__ import annotations

import itertools
import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .typemodel import (
    ENC_BOOL,
    ENC_CHAR,
    ENC_FLOAT,
    ENC_INT,
    ENC_UINT,
    KIND_ARRAY,
    KIND_ENUM,
    KIND_POINTER,
    KIND_STRUCT,
    KIND_UNION,
    TypeRegistry,
)

# Members of these types carry the packet header, which is reported in the
# fixed leading columns instead of being repeated per message type.
#
# Only a header at the top level of a mapped struct is matched, by walk_top
# below.  A header a C++ class inherits from, or one nested inside another
# member, is not recognized yet; see Limitations in the README for what each
# does today and for the header-region fix that covers both.
HEADER_TYPES = frozenset(
    [
        "CFE_MSG_Message_t",
        "CFE_MSG_TelemetryHeader_t",
        "CFE_MSG_CommandHeader_t",
        "CFE_SB_TlmHdr_t",
        "CFE_SB_CmdHdr_t",
        "CFE_SB_Msg_t",
        "CCSDS_SpacePacket_t",
        "CCSDS_PrimaryHeader_t",
        "CCSDS_TelemetryPacket_t",
        "CCSDS_CommandPacket_t",
    ]
)

_INT_FORMATS = {1: "b", 2: "h", 4: "i", 8: "q"}
_UINT_FORMATS = {1: "B", 2: "H", 4: "I", 8: "Q"}
_FLOAT_FORMATS = {4: "f", 8: "d"}

MAX_DEPTH = 32


class DecodeError(Exception):
    """Raised when a type cannot be turned into a set of columns."""


class Options:
    """Knobs that change how values are rendered."""

    __slots__ = ("char_arrays", "enum_values", "max_depth")

    def __init__(
        self, char_arrays: str = "text", enum_values: bool = False, max_depth: int = MAX_DEPTH
    ) -> None:
        self.char_arrays = char_arrays
        self.enum_values = enum_values
        self.max_depth = max_depth


class _Field(object):
    """One or more columns read from a fixed offset."""

    __slots__ = ("names", "offset", "width")

    def __init__(self, names: List[str], offset: int, width: int) -> None:
        self.names = names
        self.offset = offset
        self.width = width

    def read(self, data: bytes, base: int) -> Sequence[Any]:
        raise NotImplementedError


class _Scalar(_Field):
    __slots__ = ("codec", "kind", "enum_map")

    def __init__(
        self,
        name: str,
        offset: int,
        codec: struct.Struct,
        kind: str,
        enum_map: Optional[Dict[int, str]] = None,
    ) -> None:
        _Field.__init__(self, [name], offset, codec.size)
        self.codec = codec
        self.kind = kind
        self.enum_map = enum_map

    def read(self, data: bytes, base: int) -> Sequence[Any]:
        value = self.codec.unpack_from(data, base + self.offset)[0]
        if self.kind == ENC_BOOL:
            return (1 if value else 0,)
        if self.kind == KIND_ENUM and self.enum_map is not None:
            return (self.enum_map.get(value, value),)
        if self.kind == KIND_POINTER:
            return ("0x%x" % value,)
        return (value,)


class _Vector(_Field):
    """A whole array of one scalar type, unpacked in a single call."""

    __slots__ = ("codec", "kind", "enum_map")

    def __init__(
        self,
        names: List[str],
        offset: int,
        codec: struct.Struct,
        kind: str,
        enum_map: Optional[Dict[int, str]] = None,
    ) -> None:
        _Field.__init__(self, names, offset, codec.size)
        self.codec = codec
        self.kind = kind
        self.enum_map = enum_map

    def read(self, data: bytes, base: int) -> Sequence[Any]:
        values = self.codec.unpack_from(data, base + self.offset)
        if self.kind == ENC_BOOL:
            return [1 if v else 0 for v in values]
        if self.kind == KIND_ENUM and self.enum_map is not None:
            return [self.enum_map.get(v, v) for v in values]
        if self.kind == KIND_POINTER:
            return ["0x%x" % v for v in values]
        return values


class _Chars(_Field):
    """A char array, reported as one string cut at the first NUL."""

    __slots__ = ()

    def read(self, data: bytes, base: int) -> Sequence[Any]:
        start = base + self.offset
        raw = data[start : start + self.width]
        end = raw.find(b"\x00")
        if end >= 0:
            raw = raw[:end]
        text = raw.decode("utf-8", "replace")
        if not text.isprintable():
            text = "".join(c if c.isprintable() else "\\x%02x" % ord(c) for c in text)
        return (text,)


class _Bits(_Field):
    """A bitfield, masked out of the bytes that hold it."""

    __slots__ = ("bit_shift", "bit_size", "signed")

    def __init__(self, name: str, bit_offset: int, bit_size: int, signed: bool) -> None:
        byte_offset = bit_offset // 8
        bit_shift = bit_offset - byte_offset * 8
        width = (bit_shift + bit_size + 7) // 8
        _Field.__init__(self, [name], byte_offset, width)
        self.bit_shift = bit_shift
        self.bit_size = bit_size
        self.signed = signed

    def read(self, data: bytes, base: int) -> Sequence[Any]:
        start = base + self.offset
        raw = data[start : start + self.width]
        whole = int.from_bytes(raw, "little")
        value = (whole >> self.bit_shift) & ((1 << self.bit_size) - 1)
        if self.signed and value & (1 << (self.bit_size - 1)):
            value -= 1 << self.bit_size
        return (value,)


class _Raw(_Field):
    """Anything with no natural scalar form, reported as hex."""

    __slots__ = ()

    def read(self, data: bytes, base: int) -> Sequence[Any]:
        start = base + self.offset
        return (data[start : start + self.width].hex(),)


class Decoder(object):
    """Turns the bytes of one message into a row of values."""

    __slots__ = ("type_name", "columns", "fields", "size", "header_size", "has_header")

    def __init__(
        self,
        type_name: str,
        fields: List[_Field],
        size: int,
        header_size: int,
        has_header: bool,
    ) -> None:
        self.type_name = type_name
        self.fields = fields
        self.size = size
        self.header_size = header_size
        self.has_header = has_header
        self.columns = []  # type: List[str]
        for field in fields:
            self.columns.extend(field.names)

    def decode(self, data: bytes, base: int = 0, limit: Optional[int] = None) -> List[Any]:
        """Decode one message.

        ``base`` is where this struct starts inside ``data``.  Fields that run
        past ``limit`` come back as None so a short packet still produces a row.
        """
        if limit is None:
            limit = len(data)
        row = []  # type: List[Any]
        for field in self.fields:
            start = base + field.offset
            if start + field.width > limit:
                row.extend([None] * len(field.names))
            else:
                row.extend(field.read(data, base))
        return row


def compile_struct(
    registry: TypeRegistry, type_key: str, options: Optional[Options] = None
) -> Decoder:
    """Flatten ``type_key`` into the columns and fields of a decoder."""
    options = options or Options()
    node = registry.resolve(type_key)
    if node is None:
        raise DecodeError("type %r is not in the type file" % type_key)
    if node.kind not in (KIND_STRUCT, KIND_UNION):
        raise DecodeError("type %r is a %s, not a struct" % (type_key, node.kind))
    builder = _Builder(registry, options)
    header_size = builder.walk_top(node)
    fields = builder.fields
    return Decoder(
        type_name=type_key,
        fields=fields,
        size=node.size,
        header_size=header_size,
        has_header=header_size > 0,
    )


class _Builder(object):
    def __init__(self, registry: TypeRegistry, options: Options) -> None:
        self.registry = registry
        self.options = options
        self.fields = []  # type: List[_Field]
        self.prefix_char = ">" if registry.endian == "big" else "<"
        self._used = {}  # type: Dict[str, int]

    # -- helpers ---------------------------------------------------------

    def _unique(self, name: str) -> str:
        count = self._used.get(name, 0)
        self._used[name] = count + 1
        if count == 0:
            return name
        return "%s#%d" % (name, count + 1)

    def _format(self, encoding: str, size: int) -> Optional[str]:
        if encoding == ENC_FLOAT:
            return _FLOAT_FORMATS.get(size)
        if encoding == ENC_BOOL:
            return _UINT_FORMATS.get(size)
        if encoding in (ENC_INT, ENC_CHAR):
            return _INT_FORMATS.get(size)
        return _UINT_FORMATS.get(size)

    def _is_header(self, type_key: str) -> bool:
        for name in self.registry.typedef_chain(type_key):
            if name in HEADER_TYPES:
                return True
        resolved = self.registry.resolve_name(type_key)
        return resolved in HEADER_TYPES

    # -- walk ------------------------------------------------------------

    def walk_top(self, node: Any) -> int:
        """Walk a message type, skipping its header member.

        Returns the size of the header found at the start of the struct, or 0
        when the type is a bare payload with no header of its own.
        """
        header_size = 0
        for member in node.members:
            if self._is_header(member.type) and member.offset == 0:
                header_size = self.registry.sizeof(member.type) or 0
                continue
            self._walk_member(member, "", 0, 1)
        return header_size

    def _walk_member(self, member: Any, prefix: str, base: int, depth: int) -> None:
        name = member.name or ""
        if name:
            column = "%s.%s" % (prefix, name) if prefix else name
        else:
            column = prefix  # anonymous struct or union member
        offset = base + member.offset
        if member.bit_size is not None:
            node = self.registry.resolve(member.type)
            signed = getattr(node, "encoding", ENC_UINT) == ENC_INT
            bit_offset = member.bit_offset
            if bit_offset is None:
                bit_offset = offset * 8
            else:
                bit_offset = bit_offset + base * 8
            self.fields.append(_Bits(self._unique(column), bit_offset, member.bit_size, signed))
            return
        self._walk_type(member.type, column, offset, depth)

    def _walk_type(self, type_key: str, column: str, offset: int, depth: int) -> None:
        if depth > self.options.max_depth:
            return
        node = self.registry.resolve(type_key)
        if node is None:
            return
        kind = node.kind
        if kind in (KIND_STRUCT, KIND_UNION):
            for member in node.members:
                self._walk_member(member, column, offset, depth + 1)
            return
        if kind == KIND_ARRAY:
            self._walk_array(node, column, offset, depth)
            return
        if kind == KIND_ENUM:
            fmt = self._format(node.encoding, node.size)
            if fmt is None:
                self.fields.append(_Raw([self._unique(column)], offset, node.size))
                return
            enum_map = None if self.options.enum_values else node.values
            codec = struct.Struct(self.prefix_char + fmt)
            self.fields.append(_Scalar(self._unique(column), offset, codec, KIND_ENUM, enum_map))
            return
        if kind == KIND_POINTER:
            fmt = _UINT_FORMATS.get(node.size)
            if fmt is None:
                self.fields.append(_Raw([self._unique(column)], offset, node.size))
                return
            codec = struct.Struct(self.prefix_char + fmt)
            self.fields.append(_Scalar(self._unique(column), offset, codec, KIND_POINTER))
            return
        # A base type.
        size = getattr(node, "size", 0)
        if not size:
            return
        encoding = getattr(node, "encoding", ENC_UINT)
        if encoding == ENC_CHAR and size == 1:
            self.fields.append(_Chars([self._unique(column)], offset, 1))
            return
        fmt = self._format(encoding, size)
        if fmt is None:
            self.fields.append(_Raw([self._unique(column)], offset, size))
            return
        codec = struct.Struct(self.prefix_char + fmt)
        self.fields.append(_Scalar(self._unique(column), offset, codec, encoding))

    def _walk_array(self, node: Any, column: str, offset: int, depth: int) -> None:
        dims = [d for d in node.dims]
        total = 1
        for dim in dims:
            total *= dim
        if total <= 0:
            return  # flexible array member: no storage of its own
        elem = self.registry.resolve(node.elem)
        if elem is None:
            return
        elem_size = getattr(elem, "size", 0) or 0
        if elem_size <= 0:
            return
        encoding = getattr(elem, "encoding", None)

        # A char array is one string, not one column per character.
        if (
            elem.kind not in (KIND_STRUCT, KIND_UNION, KIND_ARRAY)
            and encoding == ENC_CHAR
            and elem_size == 1
            and self.options.char_arrays == "text"
        ):
            if len(dims) == 1:
                self.fields.append(_Chars([self._unique(column)], offset, dims[0]))
            else:
                row_len = dims[-1]
                for index in itertools.product(*[range(d) for d in dims[:-1]]):
                    suffix = "".join("[%d]" % i for i in index)
                    step = 0
                    for axis, value in enumerate(index):
                        stride = 1
                        for later in dims[axis + 1 :]:
                            stride *= later
                        step += value * stride
                    self.fields.append(
                        _Chars([self._unique(column + suffix)], offset + step, row_len)
                    )
            return

        names = [column + "".join("[%d]" % i for i in index) for index in _indices(dims)]

        # An array of scalars unpacks in one call.
        if elem.kind == KIND_ENUM:
            fmt = self._format(elem.encoding, elem_size)
            enum_map = None if self.options.enum_values else elem.values
            if fmt is not None:
                codec = struct.Struct(self.prefix_char + str(total) + fmt)
                self.fields.append(
                    _Vector(
                        [self._unique(n) for n in names], offset, codec, KIND_ENUM, enum_map
                    )
                )
                return
        elif elem.kind == KIND_POINTER:
            fmt = _UINT_FORMATS.get(elem_size)
            if fmt is not None:
                codec = struct.Struct(self.prefix_char + str(total) + fmt)
                self.fields.append(
                    _Vector([self._unique(n) for n in names], offset, codec, KIND_POINTER)
                )
                return
        elif elem.kind not in (KIND_STRUCT, KIND_UNION, KIND_ARRAY):
            fmt = self._format(encoding, elem_size)
            if fmt is not None:
                codec = struct.Struct(self.prefix_char + str(total) + fmt)
                self.fields.append(
                    _Vector([self._unique(n) for n in names], offset, codec, encoding)
                )
                return

        # An array of composites: walk each element in turn.
        for position, index in enumerate(_indices(dims)):
            suffix = "".join("[%d]" % i for i in index)
            self._walk_type(node.elem, column + suffix, offset + position * elem_size, depth + 1)


def _indices(dims: Sequence[int]) -> Iterable[Tuple[int, ...]]:
    return itertools.product(*[range(d) for d in dims])
