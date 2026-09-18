"""End to end: read a build, decode a DS file, check the CSV."""

from __future__ import annotations

import csv
import io
import json
import os
import struct

import pytest

import make_dsfile as mk
from dsdecode.cli import main

HK_MID = 0x0890
GLOBAL_MID = 0x0891
CMD_MID = 0x1882

MIDS = """
mids:
  SAMPLE_HK_TLM_MID: {value: 0x0890, struct: sample::HkTlm_t}
  GLOBAL_TLM_MID:    {value: 0x0891, struct: GLOBAL_Tlm_t}
  SAMPLE_CMD_MID:
    value: 0x1882
    struct:
      default: sample::NoopCmd_t
      fcn: {1: sample::SetModeCmd_t}
"""


def global_packet(counter, words, seq_count=0, time_sec=50):
    # GLOBAL_Tlm_t is 28 bytes: a 16 byte header, a counter, three words and
    # two bytes of tail padding the compiler adds.
    payload = struct.pack("<I3H", counter, *words) + b"\x00\x00"
    return mk.tlm_packet(GLOBAL_MID, payload=payload, seq_count=seq_count, time_sec=time_sec)


@pytest.fixture
def workspace(tmp_path, fixture_so, sample_hk):
    """A types file, a mapping file and a DS file holding known packets."""
    raw, expected = sample_hk
    types_path = str(tmp_path / "types.json")
    assert main(["extract", "-o", types_path, fixture_so]) == 0
    mids_path = str(tmp_path / "mids.yaml")
    with io.open(mids_path, "w", encoding="utf-8") as handle:
        handle.write(MIDS)
    packets = [
        raw,
        global_packet(7, (1, 2, 3), seq_count=1),
        mk.cmd_packet(CMD_MID, payload=struct.pack("<I", 4), fcn_code=1),
        mk.cmd_packet(CMD_MID, payload=b"", fcn_code=0),
        mk.tlm_packet(0x0999, payload=b"\xDE\xAD\xBE\xEF"),
        raw,
    ]
    ds_path = str(tmp_path / "seq001.ds")
    mk.write_ds_file(ds_path, packets)
    return {
        "dir": str(tmp_path),
        "so": fixture_so,
        "types": types_path,
        "mids": mids_path,
        "ds": ds_path,
        "out": str(tmp_path / "out"),
        "expected": expected,
    }


def read_csv(path):
    with io.open(path, "r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_extract_writes_a_usable_type_file(workspace):
    with io.open(workspace["types"], "r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert data["version"] == 1
    assert data["endian"] == "little"
    assert data["geometry"]["CFE_MSG_TelemetryHeader_t"] == 16
    assert "sample::HkTlm_t" in data["types"]


def test_decode_writes_one_csv_per_message_id(workspace):
    code = main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            workspace["ds"],
        ]
    )
    assert code == 0
    written = sorted(os.listdir(workspace["out"]))
    assert written == [
        "GLOBAL_TLM_MID.csv",
        "SAMPLE_CMD_MID.csv",
        "SAMPLE_CMD_MID_fcn1.csv",
        "SAMPLE_HK_TLM_MID.csv",
    ]


def test_decoded_values_match_the_build(workspace):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            workspace["ds"],
        ]
    )
    rows = read_csv(os.path.join(workspace["out"], "SAMPLE_HK_TLM_MID.csv"))
    assert len(rows) == 2
    row = rows[0]
    assert row["file"] == "seq001.ds"
    assert row["msgid"] == "0x0890"
    assert row["apid"] == "0x090"
    assert row["seq"] == "42"
    assert row["time_sec"] == str(0x12345678)
    assert row["time_subsec"] == "0.5"
    assert row["time"] == "305419896.500000"
    assert row["Payload.Name"] == "hello"
    assert row["Payload.Mode"] == "MODE_SAFE"
    assert row["Payload.Bits.c"] == "300"
    assert row["Payload.Matrix[1][2]"] == "2"
    for column, value in workspace["expected"].items():
        got = row[column]
        try:
            assert abs(float(got) - float(value)) < 1e-9, column
        except ValueError:
            assert got == value, column


def test_a_plain_c_message_decodes(workspace):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            workspace["ds"],
        ]
    )
    rows = read_csv(os.path.join(workspace["out"], "GLOBAL_TLM_MID.csv"))
    assert len(rows) == 1
    assert rows[0]["Counter"] == "7"
    assert [rows[0]["Words[%d]" % i] for i in range(3)] == ["1", "2", "3"]


def test_commands_split_by_function_code(workspace):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            workspace["ds"],
        ]
    )
    set_mode = read_csv(os.path.join(workspace["out"], "SAMPLE_CMD_MID_fcn1.csv"))
    assert len(set_mode) == 1
    assert set_mode[0]["fcn_code"] == "1"
    assert set_mode[0]["Mode"] == "4"
    noop = read_csv(os.path.join(workspace["out"], "SAMPLE_CMD_MID.csv"))
    assert len(noop) == 1
    assert noop[0]["fcn_code"] == "0"


def test_unmapped_ids_are_skipped_but_counted(workspace, capsys):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            workspace["ds"],
        ]
    )
    err = capsys.readouterr().err
    assert "0x0999 (1)" in err
    assert not os.path.exists(os.path.join(workspace["out"], "MID_0x0999.csv"))


def test_unmapped_ids_can_be_written_as_hex(workspace):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            "--unknown",
            "raw",
            workspace["ds"],
        ]
    )
    rows = read_csv(os.path.join(workspace["out"], "MID_0x0999.csv"))
    assert len(rows) == 1
    assert rows[0]["raw"].endswith("deadbeef")


def test_the_summary_lists_the_files_written(workspace, capsys):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            workspace["ds"],
        ]
    )
    err = capsys.readouterr().err
    assert "decoded 5 packet(s) into 4 file(s)" in err


def test_only_selects_message_ids(workspace):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            "--only",
            "GLOBAL_TLM_MID",
            workspace["ds"],
        ]
    )
    assert os.listdir(workspace["out"]) == ["GLOBAL_TLM_MID.csv"]


def test_an_epoch_adds_a_utc_column(workspace):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            "--epoch",
            "1980-01-01",
            workspace["ds"],
        ]
    )
    rows = read_csv(os.path.join(workspace["out"], "SAMPLE_HK_TLM_MID.csv"))
    # 305419896.5 seconds after the 1980 epoch.
    assert rows[0]["time_utc"] == "1989-09-04T22:51:36.500000+00:00"


def test_jsonl_output(workspace):
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            "--format",
            "jsonl",
            workspace["ds"],
        ]
    )
    path = os.path.join(workspace["out"], "SAMPLE_HK_TLM_MID.jsonl")
    with io.open(path, "r", encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    assert len(records) == 2
    assert records[0]["Payload.Name"] == "hello"


def test_decoding_two_files_appends_to_one_csv(workspace, tmp_path):
    second = str(tmp_path / "seq002.ds")
    mk.write_ds_file(second, [global_packet(9, (4, 5, 6), time_sec=60)])
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            workspace["ds"],
            second,
        ]
    )
    rows = read_csv(os.path.join(workspace["out"], "GLOBAL_TLM_MID.csv"))
    assert [r["file"] for r in rows] == ["seq001.ds", "seq002.ds"]
    assert [r["Counter"] for r in rows] == ["7", "9"]


def test_info_reports_headers_and_counts(workspace, capsys):
    assert main(["info", "--types", workspace["types"], workspace["ds"]]) == 0
    out = capsys.readouterr().out
    assert "DS data file" in out
    assert "/ram/ds/seq001.ds" in out
    assert "0x0890" in out
    assert "packets: 6" in out


def test_info_works_without_a_type_file(workspace, capsys):
    assert main(["info", workspace["ds"]]) == 0
    assert "0x0999" in capsys.readouterr().out


def test_info_as_json(workspace, capsys):
    assert main(["info", "--json", workspace["ds"]]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report[0]["packets"] == 6
    assert report[0]["fs_header"]["description"] == "DS data file"


def test_no_matching_packets_is_an_error(workspace, tmp_path, capsys):
    empty = str(tmp_path / "empty.ds")
    mk.write_ds_file(empty, [])
    code = main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            workspace["out"],
            empty,
        ]
    )
    assert code == 1
    assert "no packets decoded" in capsys.readouterr().err


def test_a_bad_mapping_file_is_reported(workspace, tmp_path, capsys):
    bad = str(tmp_path / "bad.yaml")
    with io.open(bad, "w", encoding="utf-8") as handle:
        handle.write("mids:\n  HK: {value: 0x0890, struct: NotAType_t}\n")
    code = main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            bad,
            "--out",
            workspace["out"],
            workspace["ds"],
        ]
    )
    assert code == 1
    assert "not in the type file" in capsys.readouterr().err


def test_no_subcommand_prints_help(capsys):
    assert main([]) == 2
    assert "extract" in capsys.readouterr().out


# -- extracting only what the mapping needs --------------------------------


def read_types(path):
    with io.open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def test_a_filtered_extract_is_far_smaller(workspace, tmp_path, capsys):
    small = str(tmp_path / "types-small.json")
    assert main(["extract", "--mids", workspace["mids"], "-o", small, workspace["so"]]) == 0
    full_types = read_types(workspace["types"])
    small_types = read_types(small)
    assert not full_types["filtered"]
    assert small_types["filtered"]
    assert len(small_types["types"]) * 3 < len(full_types["types"])
    # The structs the mapping names, and the ones they are built from.
    assert "sample::HkTlm_t" in small_types["types"]
    assert "sample::HkPayload" in small_types["types"]
    assert "sample::UnionTlm_t" not in small_types["types"]
    out = capsys.readouterr().out
    assert "structs from the mapping" in out
    assert "sample::HkTlm_t" in out


def test_filtered_and_unfiltered_type_files_decode_identically(workspace, tmp_path):
    small = str(tmp_path / "types-small.json")
    main(["extract", "--mids", workspace["mids"], "-o", small, workspace["so"]])
    outputs = []
    for index, types in enumerate((workspace["types"], small)):
        out_dir = str(tmp_path / ("decode%d" % index))
        assert (
            main(
                [
                    "decode",
                    "--types",
                    types,
                    "--mids",
                    workspace["mids"],
                    "--out",
                    out_dir,
                    "--epoch",
                    "1980-01-01",
                    workspace["ds"],
                ]
            )
            == 0
        )
        outputs.append(out_dir)
    first, second = outputs
    assert sorted(os.listdir(first)) == sorted(os.listdir(second))
    assert os.listdir(first)
    for name in sorted(os.listdir(first)):
        with io.open(os.path.join(first, name), "r", encoding="utf-8") as handle:
            left = handle.read()
        with io.open(os.path.join(second, name), "r", encoding="utf-8") as handle:
            right = handle.read()
        assert left == right, "%s differs between the two type files" % name


def test_verbose_lists_the_types_kept_for_auditing(workspace, tmp_path, capsys):
    small = str(tmp_path / "types-small.json")
    main(["extract", "--mids", workspace["mids"], "-o", small, "-v", workspace["so"]])
    out = capsys.readouterr().out
    assert "types kept:" in out
    assert "sample::HkPayload" in out


def test_an_unqualified_name_is_reported_with_what_it_matched(workspace, tmp_path, capsys):
    mids = str(tmp_path / "short-names.yaml")
    with io.open(mids, "w", encoding="utf-8") as handle:
        handle.write("mids:\n  HK: {value: 0x0890, struct: HkTlm_t}\n")
    small = str(tmp_path / "types-short.json")
    assert main(["extract", "--mids", mids, "-o", small, workspace["so"]]) == 0
    assert read_types(small)["roots"] == {"HkTlm_t": ["sample::HkTlm_t"]}
    assert "sample::HkTlm_t" in capsys.readouterr().out


def test_a_struct_missing_from_the_build_fails_the_extract(workspace, tmp_path, capsys):
    mids = str(tmp_path / "typo.yaml")
    with io.open(mids, "w", encoding="utf-8") as handle:
        handle.write("mids:\n  HK: {value: 0x0890, struct: sample::HkTlmX_t}\n")
    out = str(tmp_path / "types-typo.json")
    assert main(["extract", "--mids", mids, "-o", out, workspace["so"]]) == 1
    assert "sample::HkTlmX_t" in capsys.readouterr().err
    assert not os.path.exists(out)


def test_allow_missing_writes_the_file_anyway(workspace, tmp_path, capsys):
    mids = str(tmp_path / "partial.yaml")
    with io.open(mids, "w", encoding="utf-8") as handle:
        handle.write(
            "mids:\n"
            "  HK: {value: 0x0890, struct: sample::HkTlm_t}\n"
            "  GONE: {value: 0x0899, struct: NotBuiltYet_t}\n"
        )
    out = str(tmp_path / "types-partial.json")
    assert (
        main(["extract", "--mids", mids, "--allow-missing", "-o", out, workspace["so"]]) == 0
    )
    assert read_types(out)["roots"] == {"sample::HkTlm_t": ["sample::HkTlm_t"]}
    assert "NotBuiltYet_t" in capsys.readouterr().err


def test_a_mapping_that_grew_says_to_extract_again(workspace, tmp_path, capsys):
    small = str(tmp_path / "types-small.json")
    main(["extract", "--mids", workspace["mids"], "-o", small, workspace["so"]])
    grown = str(tmp_path / "grown.yaml")
    with io.open(grown, "w", encoding="utf-8") as handle:
        handle.write(MIDS + "  EXTRA_TLM_MID: {value: 0x0899, struct: sample::UnionTlm_t}\n")
    code = main(
        [
            "decode",
            "--types",
            small,
            "--mids",
            grown,
            "--out",
            str(tmp_path / "out-grown"),
            workspace["ds"],
        ]
    )
    assert code == 1
    err = capsys.readouterr().err
    assert "sample::UnionTlm_t" in err
    assert "re-run" in err and "extract --mids" in err


def test_a_malformed_mapping_is_caught_at_extract_time(workspace, tmp_path, capsys):
    mids = str(tmp_path / "broken.yaml")
    with io.open(mids, "w", encoding="utf-8") as handle:
        handle.write("mids:\n  NO_VALUE_MID: {struct: sample::HkTlm_t}\n")
    assert main(["extract", "--mids", mids, "-o", str(tmp_path / "x.json"), workspace["so"]]) == 1
    assert "no message ID" in capsys.readouterr().err
