"""Read back DS files built byte for byte."""

from __future__ import annotations

import pytest

import make_dsfile as mk
from dsdecode.dsfile import DsFile, DsFileError, Geometry, summarize


def write(tmp_path, name, packets, **kwargs):
    path = str(tmp_path / name)
    return mk.write_ds_file(path, packets, **kwargs)


def test_headers_and_packets_read_back(tmp_path):
    packets = [
        mk.tlm_packet(0x0890, payload=b"\x01\x02\x03\x04", seq_count=1, time_sec=100, time_subsec=0x8000),
        mk.tlm_packet(0x0891, payload=b"\xAA" * 8, seq_count=2, time_sec=101),
    ]
    path = write(tmp_path, "a.ds", packets, description="DS data file", close_seconds=2000)
    with DsFile(path, Geometry()) as ds:
        assert ds.fs_header.content_type == mk.CFE_FS_CONTENT_TYPE
        assert ds.fs_header.description == "DS data file"
        assert ds.ds_header.close_seconds == 2000
        assert ds.ds_header.file_name == "/ram/ds/seq001.ds"
        assert ds.data_offset == 140
        found = list(ds.packets())
    assert [p.msgid for p in found] == [0x0890, 0x0891]
    assert [p.apid for p in found] == [0x090, 0x091]
    assert [p.seq_count for p in found] == [1, 2]
    assert found[0].length == len(packets[0])
    assert found[0].time_sec == 100
    assert found[0].time_subsec == 0.5
    assert found[0].time == 100.5
    assert found[0].payload_offset == 16
    assert not found[0].is_cmd
    assert found[0].has_sec_hdr


def test_commands_carry_a_function_code(tmp_path):
    path = write(tmp_path, "cmd.ds", [mk.cmd_packet(0x1882, payload=b"\x07\x00\x00\x00", fcn_code=3)])
    with DsFile(path, Geometry()) as ds:
        packet = list(ds.packets())[0]
    assert packet.is_cmd
    assert packet.fcn_code == 3
    assert packet.payload_offset == 8
    assert packet.time_sec is None


def test_a_file_with_no_headers_is_detected(tmp_path):
    packets = [mk.tlm_packet(0x0890, payload=b"\x01\x02\x03\x04")]
    path = write(tmp_path, "raw.ds", packets, with_headers=False)
    warnings = []
    with DsFile(path, Geometry(), warn=warnings.append) as ds:
        found = list(ds.packets())
    assert ds.data_offset == 0
    assert [p.msgid for p in found] == [0x0890]
    assert any("no cFE file header" in w for w in warnings)


def test_forcing_a_cfe_header_on_a_headerless_file_fails(tmp_path):
    path = write(tmp_path, "raw2.ds", [mk.tlm_packet(0x0890)], with_headers=False)
    with pytest.raises(DsFileError):
        DsFile(path, Geometry(), header_mode="cfe").open()


def test_a_truncated_tail_is_reported_and_earlier_packets_survive(tmp_path):
    packets = [mk.tlm_packet(0x0890, payload=b"\x01" * 8), mk.tlm_packet(0x0890, payload=b"\x02" * 8)]
    path = write(tmp_path, "cut.ds", packets, truncate=9)
    warnings = []
    with DsFile(path, Geometry(), warn=warnings.append) as ds:
        found = list(ds.packets())
        assert ds.truncated
    assert len(found) == 1
    assert any("ends inside packet" in w for w in warnings)


def test_a_file_cut_inside_its_header_is_an_error(tmp_path):
    path = str(tmp_path / "stub.ds")
    with open(path, "wb") as handle:
        handle.write(mk.fs_header())
    with pytest.raises(DsFileError):
        DsFile(path, Geometry()).open()


def test_a_non_default_ds_header_size_is_honoured(tmp_path):
    geometry = Geometry({"DS_FileHeader_t": 76 + 64})
    packets = [mk.tlm_packet(0x0890, payload=b"\x01\x02\x03\x04")]
    path = write(tmp_path, "big.ds", packets, ds_header_size=76 + 64)
    with DsFile(path, geometry) as ds:
        assert ds.data_offset == 64 + 140
        assert [p.msgid for p in list(ds.packets())] == [0x0890]


def test_a_four_byte_subsecond_time_is_read(tmp_path):
    geometry = Geometry({"CFE_MSG_TelemetrySecondaryHeader_t": 8, "CFE_MSG_TelemetryHeader_t": 16})
    packet = mk.tlm_packet(
        0x0890, payload=b"", time_sec=7, time_subsec=0x40000000, spare=b"\x00\x00", sec_size=8
    )
    path = write(tmp_path, "t8.ds", [packet])
    with DsFile(path, geometry) as ds:
        found = list(ds.packets())[0]
    assert found.time_sec == 7
    assert found.time_subsec == 0.25


def test_ccsds_version_2_message_ids(tmp_path):
    # Version 2 adds a 4-byte extended header and builds the ID from the low
    # APID bits, the command bit and the subsystem.
    geometry = Geometry({"CFE_MSG_Message_t": 10}, ccsds_v2=True)
    body = b"\x00\x03\x00\x00" + b"\x00" * 6 + b"\x11\x22\x33\x44"
    packet = mk.tlm_packet(0x0890, payload=b"")
    packet = packet[:6] + body
    packet = packet[:4] + (len(packet) - 7).to_bytes(2, "big") + packet[6:]
    path = write(tmp_path, "v2.ds", [packet])
    with DsFile(path, geometry) as ds:
        found = list(ds.packets())[0]
    # Low seven bits of the APID byte, no command bit, subsystem 3 in the
    # extended header: 0x0310, not the version 1 stream ID.
    assert found.msgid == 0x0310


def test_summarize_counts_by_message_id(tmp_path):
    packets = [
        mk.tlm_packet(0x0890, payload=b"\x00" * 4),
        mk.tlm_packet(0x0890, payload=b"\x00" * 8),
        mk.tlm_packet(0x0891, payload=b"\x00" * 4),
    ]
    path = write(tmp_path, "counts.ds", packets)
    report = summarize(path, Geometry())
    assert report["packets"] == 3
    assert report["by_msgid"][0x0890][0] == 2
    assert report["by_msgid"][0x0891][0] == 1
    assert report["by_msgid"][0x0890][1] != report["by_msgid"][0x0890][2]


def test_an_empty_file_body_yields_no_packets(tmp_path):
    path = write(tmp_path, "empty.ds", [])
    with DsFile(path, Geometry()) as ds:
        assert list(ds.packets()) == []
        assert not ds.truncated
