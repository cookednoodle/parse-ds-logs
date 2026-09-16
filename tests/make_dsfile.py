"""Build DS files byte for byte, the way the DS app writes them.

Used by the tests, and handy on its own for producing a file to try the tool
against without flying anything.
"""

from __future__ import annotations

import struct
from typing import List, Optional, Sequence

CFE_FS_CONTENT_TYPE = 0x63464531
FS_HEADER_SIZE = 64
DS_HEADER_SIZE = 76
TLM_HEADER_SIZE = 16
CMD_HEADER_SIZE = 8


def fs_header(
    sub_type: int = 12,
    spacecraft_id: int = 0x42,
    processor_id: int = 1,
    application_id: int = 7,
    time_seconds: int = 1000,
    time_subseconds: int = 0,
    description: str = "DS data file",
) -> bytes:
    """The 64-byte cFE file header, in the big-endian order cFE writes."""
    return struct.pack(
        ">8I32s",
        CFE_FS_CONTENT_TYPE,
        sub_type,
        FS_HEADER_SIZE,
        spacecraft_id,
        processor_id,
        application_id,
        time_seconds,
        time_subseconds,
        description.encode("utf-8")[:31],
    )


def ds_header(
    close_seconds: int = 2000,
    close_subsecs: int = 0,
    file_table_index: int = 3,
    file_name_type: int = 1,
    file_name: str = "/ram/ds/seq001.ds",
    size: int = DS_HEADER_SIZE,
) -> bytes:
    """The DS header, written in the target's own byte order."""
    name_len = size - 12
    return struct.pack("<IIHH", close_seconds, close_subsecs, file_table_index, file_name_type) + (
        file_name.encode("utf-8")[: name_len - 1].ljust(name_len, b"\x00")
    )


def _primary(stream_id: int, seq_count: int, total: int, seq_flags: int = 3) -> bytes:
    return struct.pack(">HHH", stream_id, (seq_flags << 14) | (seq_count & 0x3FFF), total - 7)


def tlm_packet(
    msgid: int,
    payload: bytes = b"",
    seq_count: int = 0,
    time_sec: int = 0,
    time_subsec: int = 0,
    spare: bytes = b"\x00\x00\x00\x00",
    sec_size: int = 6,
) -> bytes:
    """One telemetry message: primary header, time, spare, then payload."""
    time = struct.pack(">I", time_sec) + (
        struct.pack(">H", time_subsec) if sec_size == 6 else struct.pack(">I", time_subsec)
    )
    body = time + spare + payload
    total = 6 + len(body)
    return _primary(msgid, seq_count, total) + body


def cmd_packet(msgid: int, payload: bytes = b"", seq_count: int = 0, fcn_code: int = 0) -> bytes:
    """One command message: primary header, function code and checksum, payload."""
    body = struct.pack("<BB", fcn_code & 0x7F, 0) + payload
    total = 6 + len(body)
    return _primary(msgid, seq_count, total) + body


def ds_file_bytes(
    packets: Sequence[bytes],
    with_headers: bool = True,
    ds_header_size: int = DS_HEADER_SIZE,
    close_seconds: int = 2000,
    truncate: int = 0,
    **header_kwargs: object
) -> bytes:
    """Assemble a whole DS file; ``truncate`` cuts bytes off the end."""
    parts = []  # type: List[bytes]
    if with_headers:
        parts.append(fs_header(**header_kwargs))  # type: ignore[arg-type]
        parts.append(ds_header(close_seconds=close_seconds, size=ds_header_size))
    parts.extend(packets)
    data = b"".join(parts)
    if truncate:
        data = data[:-truncate]
    return data


def write_ds_file(path: str, packets: Sequence[bytes], **kwargs: object) -> str:
    with open(path, "wb") as handle:
        handle.write(ds_file_bytes(packets, **kwargs))  # type: ignore[arg-type]
    return path
