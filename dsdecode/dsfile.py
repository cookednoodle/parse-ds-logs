"""Read the files the DS app writes.

A DS file is a 64-byte cFE file header in big-endian byte order, then a DS
header written in the target's own byte order, then every recorded Software Bus
message laid end to end with no framing of its own.  A message's length comes
from its own CCSDS primary header, so the reader walks the file one packet at a
time and never has to hold the whole thing in memory.
"""

from __future__ import annotations

import struct
import sys
from typing import Any, BinaryIO, Dict, Iterator, List, Optional

from .typemodel import GEOMETRY_DEFAULTS, TypeRegistry

# 'cFE1' at the start of a cFE file header.
CFE_FS_CONTENT_TYPE = 0x63464531
CFE_FS_HEADER_SIZE = 64

CCSDS_PRIMARY_SIZE = 6
CCSDS_EXTENDED_SIZE = 4

HEADER_AUTO = "auto"
HEADER_CFE = "cfe"
HEADER_NONE = "none"

_FS_HEADER = struct.Struct(">8I32s")


class DsFileError(Exception):
    """Raised when a file cannot be read as a DS log."""


class Geometry(object):
    """Sizes of the header types this build uses, read from the debug info."""

    __slots__ = (
        "msg_hdr_size",
        "tlm_hdr_size",
        "cmd_hdr_size",
        "tlm_sec_size",
        "ds_hdr_size",
        "fs_hdr_size",
        "ccsds_v2",
    )

    def __init__(self, sizes: Optional[Dict[str, int]] = None, ccsds_v2: Optional[bool] = None):
        merged = dict(GEOMETRY_DEFAULTS)
        merged.update(sizes or {})
        self.msg_hdr_size = merged["CFE_MSG_Message_t"]
        self.tlm_hdr_size = merged["CFE_MSG_TelemetryHeader_t"]
        self.cmd_hdr_size = merged["CFE_MSG_CommandHeader_t"]
        self.tlm_sec_size = merged["CFE_MSG_TelemetrySecondaryHeader_t"]
        self.ds_hdr_size = merged["DS_FileHeader_t"]
        self.fs_hdr_size = merged["CFE_FS_Header_t"]
        # A 10-byte base message means the build uses the CCSDS version 2
        # extended header, which changes how a message ID is put together.
        if ccsds_v2 is None:
            ccsds_v2 = self.msg_hdr_size >= CCSDS_PRIMARY_SIZE + CCSDS_EXTENDED_SIZE
        self.ccsds_v2 = bool(ccsds_v2)

    @classmethod
    def from_registry(
        cls, registry: Optional[TypeRegistry], ccsds_v2: Optional[bool] = None
    ) -> "Geometry":
        return cls(registry.geometry if registry is not None else None, ccsds_v2)

    def payload_offset(self, is_cmd: bool, has_sec_hdr: bool) -> int:
        """Where a message's payload starts, after whatever header it carries."""
        if not has_sec_hdr:
            return self.msg_hdr_size
        return self.cmd_hdr_size if is_cmd else self.tlm_hdr_size

    def describe(self) -> str:
        return (
            "message header %d, telemetry header %d, command header %d, "
            "telemetry time %d, DS header %d, CCSDS version %d"
            % (
                self.msg_hdr_size,
                self.tlm_hdr_size,
                self.cmd_hdr_size,
                self.tlm_sec_size,
                self.ds_hdr_size,
                2 if self.ccsds_v2 else 1,
            )
        )


class FsHeader(object):
    """The cFE file header at the start of a DS file."""

    __slots__ = (
        "content_type",
        "sub_type",
        "length",
        "spacecraft_id",
        "processor_id",
        "application_id",
        "time_seconds",
        "time_subseconds",
        "description",
    )

    def __init__(self, values: Any, description: bytes) -> None:
        (
            self.content_type,
            self.sub_type,
            self.length,
            self.spacecraft_id,
            self.processor_id,
            self.application_id,
            self.time_seconds,
            self.time_subseconds,
        ) = values
        self.description = _text(description)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "content_type": "0x%08X" % self.content_type,
            "sub_type": self.sub_type,
            "length": self.length,
            "spacecraft_id": self.spacecraft_id,
            "processor_id": self.processor_id,
            "application_id": self.application_id,
            "create_time_seconds": self.time_seconds,
            "create_time_subseconds": self.time_subseconds,
            "description": self.description,
        }


class DsHeader(object):
    """The DS header that follows the cFE header."""

    __slots__ = ("close_seconds", "close_subsecs", "file_table_index", "file_name_type", "file_name")

    def __init__(
        self,
        close_seconds: int,
        close_subsecs: int,
        file_table_index: int,
        file_name_type: int,
        file_name: bytes,
    ) -> None:
        self.close_seconds = close_seconds
        self.close_subsecs = close_subsecs
        self.file_table_index = file_table_index
        self.file_name_type = file_name_type
        self.file_name = _text(file_name)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "close_time_seconds": self.close_seconds,
            "close_time_subseconds": self.close_subsecs,
            "file_table_index": self.file_table_index,
            "file_name_type": self.file_name_type,
            "file_name": self.file_name,
        }


class Packet(object):
    """One recorded Software Bus message."""

    __slots__ = (
        "index",
        "offset",
        "msgid",
        "apid",
        "version",
        "is_cmd",
        "has_sec_hdr",
        "seq_flags",
        "seq_count",
        "length",
        "fcn_code",
        "time_sec",
        "time_subsec",
        "payload_offset",
        "data",
    )

    def __init__(self, **kwargs: Any) -> None:
        for name in self.__slots__:
            setattr(self, name, kwargs.get(name))

    @property
    def time(self) -> Optional[float]:
        """Packet time in seconds, or None when the message carries none."""
        if self.time_sec is None:
            return None
        return self.time_sec + self.time_subsec


def _text(raw: bytes) -> str:
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    text = raw.decode("utf-8", "replace")
    if not text.isprintable():
        text = "".join(c if c.isprintable() else "\\x%02x" % ord(c) for c in text)
    return text


def _default_warn(message: str) -> None:
    print("warning: %s" % message, file=sys.stderr)


class DsFile(object):
    """Reads one DS log file."""

    def __init__(
        self,
        path: str,
        geometry: Optional[Geometry] = None,
        header_mode: str = HEADER_AUTO,
        warn: Optional[Any] = None,
    ) -> None:
        self.path = path
        self.geometry = geometry or Geometry()
        self.header_mode = header_mode
        self.warn = warn or _default_warn
        self.fs_header = None  # type: Optional[FsHeader]
        self.ds_header = None  # type: Optional[DsHeader]
        self.data_offset = 0
        self.truncated = False
        self._handle = None  # type: Optional[BinaryIO]

    # -- lifecycle -------------------------------------------------------

    def open(self) -> "DsFile":
        try:
            self._handle = open(self.path, "rb")
        except OSError as exc:
            raise DsFileError("cannot open %s: %s" % (self.path, exc))
        try:
            self._read_headers()
        except Exception:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> "DsFile":
        return self.open()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- headers ---------------------------------------------------------

    def _read_headers(self) -> None:
        handle = self._handle
        assert handle is not None
        if self.header_mode == HEADER_NONE:
            self.data_offset = 0
            return
        raw = handle.read(self.geometry.fs_hdr_size)
        short = len(raw) < self.geometry.fs_hdr_size
        content_type = None if len(raw) < 4 else struct.unpack_from(">I", raw, 0)[0]
        if short or content_type != CFE_FS_CONTENT_TYPE:
            if self.header_mode == HEADER_CFE:
                if short:
                    raise DsFileError(
                        "%s is %d bytes, too short to hold a cFE file header"
                        % (self.path, len(raw))
                    )
                raise DsFileError(
                    "%s does not start with a cFE file header (found 0x%08X, expected 0x%08X)"
                    % (self.path, content_type, CFE_FS_CONTENT_TYPE)
                )
            self.warn(
                "%s has no cFE file header; reading it as packets from byte 0 "
                "(a build with DS_FILE_HEADER_TYPE set to DS_FILE_HEADER_NONE)" % self.path
            )
            handle.seek(0)
            self.header_mode = HEADER_NONE
            self.data_offset = 0
            return
        self.header_mode = HEADER_CFE
        values = _FS_HEADER.unpack_from(raw, 0)
        self.fs_header = FsHeader(values[:8], values[8])
        ds_raw = handle.read(self.geometry.ds_hdr_size)
        if len(ds_raw) < self.geometry.ds_hdr_size:
            raise DsFileError(
                "%s ends inside its DS header: %d of %d bytes"
                % (self.path, len(ds_raw), self.geometry.ds_hdr_size)
            )
        name_len = self.geometry.ds_hdr_size - 12
        close_seconds, close_subsecs, table_index, name_type = struct.unpack_from("<IIHH", ds_raw, 0)
        self.ds_header = DsHeader(
            close_seconds, close_subsecs, table_index, name_type, ds_raw[12 : 12 + name_len]
        )
        self.data_offset = self.geometry.fs_hdr_size + self.geometry.ds_hdr_size

    # -- packets ---------------------------------------------------------

    def packets(self) -> Iterator[Packet]:
        """Walk the recorded messages from the current position to the end."""
        if self._handle is None:
            raise DsFileError("read from %s before it was opened" % self.path)
        handle = self._handle
        handle.seek(self.data_offset)
        geometry = self.geometry
        index = 0
        offset = self.data_offset
        while True:
            primary = handle.read(CCSDS_PRIMARY_SIZE)
            if not primary:
                return
            if len(primary) < CCSDS_PRIMARY_SIZE:
                self.truncated = True
                self.warn(
                    "%s ends with %d bytes that are too few for a packet header, at byte %d"
                    % (self.path, len(primary), offset)
                )
                return
            total = ((primary[4] << 8) | primary[5]) + 7
            rest = handle.read(total - CCSDS_PRIMARY_SIZE)
            if len(rest) < total - CCSDS_PRIMARY_SIZE:
                self.truncated = True
                self.warn(
                    "%s ends inside packet %d at byte %d: %d of %d bytes"
                    % (
                        self.path,
                        index,
                        offset,
                        len(rest) + CCSDS_PRIMARY_SIZE,
                        total,
                    )
                )
                return
            data = primary + rest
            yield self._make_packet(index, offset, data, geometry)
            index += 1
            offset += total

    def _make_packet(self, index: int, offset: int, data: bytes, geometry: Geometry) -> Packet:
        stream_id = (data[0] << 8) | data[1]
        version = (stream_id >> 13) & 0x07
        is_cmd = bool((stream_id >> 12) & 0x01)
        has_sec_hdr = bool((stream_id >> 11) & 0x01)
        apid = stream_id & 0x07FF
        sequence = (data[2] << 8) | data[3]
        seq_flags = (sequence >> 14) & 0x03
        seq_count = sequence & 0x3FFF

        if geometry.ccsds_v2:
            # Per cFE's version 2 message ID: seven bits of APID, the command
            # bit, and the subsystem from the extended header.
            msgid = data[1] & 0x7F
            if is_cmd:
                msgid |= 0x80
            if len(data) > 7:
                msgid |= (data[7] << 8) & 0xFF00
        else:
            msgid = stream_id

        fcn_code = None
        time_sec = None
        time_subsec = None
        if has_sec_hdr:
            if is_cmd:
                if len(data) > geometry.msg_hdr_size:
                    fcn_code = data[geometry.msg_hdr_size] & 0x7F
            else:
                start = geometry.msg_hdr_size
                end = start + geometry.tlm_sec_size
                if len(data) >= end:
                    time = data[start:end]
                    time_sec = int.from_bytes(time[0:4], "big")
                    sub_raw = time[4 : geometry.tlm_sec_size]
                    if sub_raw:
                        subsecs = int.from_bytes(sub_raw, "big")
                        time_subsec = subsecs / float(1 << (8 * len(sub_raw)))
                    else:
                        time_subsec = 0.0
        return Packet(
            index=index,
            offset=offset,
            msgid=msgid,
            apid=apid,
            version=version,
            is_cmd=is_cmd,
            has_sec_hdr=has_sec_hdr,
            seq_flags=seq_flags,
            seq_count=seq_count,
            length=len(data),
            fcn_code=fcn_code,
            time_sec=time_sec,
            time_subsec=time_subsec,
            payload_offset=geometry.payload_offset(is_cmd, has_sec_hdr),
            data=data,
        )


def summarize(path: str, geometry: Geometry, header_mode: str = HEADER_AUTO) -> Dict[str, Any]:
    """Header fields and a per-message-ID packet count for one file."""
    counts = {}  # type: Dict[int, List[Any]]
    with DsFile(path, geometry, header_mode) as ds:
        total = 0
        for packet in ds.packets():
            total += 1
            entry = counts.get(packet.msgid)
            if entry is None:
                counts[packet.msgid] = [1, packet.length, packet.length]
            else:
                entry[0] += 1
                entry[1] = min(entry[1], packet.length)
                entry[2] = max(entry[2], packet.length)
        return {
            "path": path,
            "header_mode": ds.header_mode,
            "fs_header": ds.fs_header.as_dict() if ds.fs_header else None,
            "ds_header": ds.ds_header.as_dict() if ds.ds_header else None,
            "data_offset": ds.data_offset,
            "packets": total,
            "truncated": ds.truncated,
            "by_msgid": counts,
        }
