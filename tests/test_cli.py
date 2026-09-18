"""End to end: read a build, decode a DS file, check the CSV."""

from __future__ import annotations

import csv
import io
import json
import os
import struct
import subprocess
import sys

import pytest

import make_dsfile as mk
from dsdecode.cli import EXIT_BROKEN_PIPE, main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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


def partial_mapping(tmp_path, name="partial.yaml"):
    """A mapping naming one struct this build has and one it does not."""
    path = str(tmp_path / name)
    with io.open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "mids:\n"
            "  HK: {value: 0x0890, struct: sample::HkTlm_t}\n"
            "  GONE: {value: 0x0899, struct: NotBuiltYet_t}\n"
        )
    return path


def test_a_struct_missing_from_the_build_is_left_out_not_fatal(workspace, tmp_path, capsys):
    mids = partial_mapping(tmp_path)
    out = str(tmp_path / "types-partial.json")
    assert main(["extract", "--mids", mids, "-o", out, workspace["so"]]) == 0
    written = read_types(out)
    assert written["roots"] == {"sample::HkTlm_t": ["sample::HkTlm_t"]}
    assert written["unresolved"] == ["NotBuiltYet_t"]
    assert "NotBuiltYet_t" in capsys.readouterr().err


def test_the_summary_counts_absent_structs_without_listing_them(workspace, tmp_path, capsys):
    mids = partial_mapping(tmp_path)
    main(["extract", "--mids", mids, "-o", str(tmp_path / "t.json"), workspace["so"]])
    printed = capsys.readouterr().out
    assert "1 struct(s) named in the mapping are not in this build" in printed
    assert "run with -v to list them" in printed
    assert "NotBuiltYet_t" not in printed, "the audit list should not be buried"


def test_verbose_lists_the_absent_structs(workspace, tmp_path, capsys):
    mids = partial_mapping(tmp_path)
    main(["extract", "--mids", mids, "-v", "-o", str(tmp_path / "t.json"), workspace["so"]])
    assert "NotBuiltYet_t" in capsys.readouterr().out


def test_strict_makes_a_missing_struct_fatal_again(workspace, tmp_path, capsys):
    mids = partial_mapping(tmp_path)
    out = str(tmp_path / "types-strict.json")
    assert main(["extract", "--mids", mids, "--strict", "-o", out, workspace["so"]]) == 1
    assert "NotBuiltYet_t" in capsys.readouterr().err
    assert not os.path.exists(out)


def test_a_mapping_matching_nothing_in_the_build_still_fails(workspace, tmp_path, capsys):
    mids = str(tmp_path / "all-absent.yaml")
    with io.open(mids, "w", encoding="utf-8") as handle:
        handle.write("mids:\n  A: {value: 0x0890, struct: NotHere_t}\n")
    out = str(tmp_path / "types-none.json")
    assert main(["extract", "--mids", mids, "-o", out, workspace["so"]]) == 1
    assert "none of the" in capsys.readouterr().err
    assert not os.path.exists(out)


def test_decode_skips_message_ids_whose_struct_is_absent(workspace, tmp_path, capsys):
    """The other half: a type file with holes still decodes what it can."""
    mids = partial_mapping(tmp_path)
    types = str(tmp_path / "types-partial.json")
    assert main(["extract", "--mids", mids, "-o", types, workspace["so"]]) == 0
    capsys.readouterr()
    out_dir = str(tmp_path / "out-partial")
    assert (
        main(["decode", "--types", types, "--mids", mids, "--out", out_dir, workspace["ds"]])
        == 0
    )
    assert os.listdir(out_dir) == ["HK.csv"]
    assert len(read_csv(os.path.join(out_dir, "HK.csv"))) == 2
    err = capsys.readouterr().err
    assert "1 message ID(s) name a struct this build does not have" in err
    assert "GONE" in err


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


# -- a reader that stops early ---------------------------------------------


def run_with_no_reader(argv):
    """Run the command with its stdout going to a pipe nobody reads.

    Closing the read end before the child starts makes its first write fail,
    which is what `dsdecode info file.ds | head` does once head has gone, minus
    the race that makes timing-based versions of this test flaky.
    """
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [REPO_ROOT] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "dsdecode.cli"] + list(argv),
            stdout=write_fd,
            stderr=subprocess.PIPE,
            env=env,
        )
    finally:
        os.close(write_fd)
    _, errors = process.communicate()
    return process.returncode, errors.decode("utf-8", "replace")


def test_info_survives_a_reader_that_stops_early(workspace):
    code, errors = run_with_no_reader(["info", workspace["ds"]])
    assert "Traceback" not in errors
    assert "BrokenPipeError" not in errors
    assert "Exception ignored" not in errors
    assert code == EXIT_BROKEN_PIPE


def test_extract_survives_a_reader_that_stops_early(workspace, tmp_path):
    code, errors = run_with_no_reader(
        ["extract", "-v", "-o", str(tmp_path / "types-pipe.json"), workspace["so"]]
    )
    assert "Traceback" not in errors
    assert "BrokenPipeError" not in errors
    assert code == EXIT_BROKEN_PIPE


# -- a map generated by scanning the flight software -----------------------


GENERATED_MAP = {
    "mids": {
        "2192": {
            "name": "CTRL_APP_HK_TLM_MID",
            "value": 2192,
            "type": "telem",
            "struct": "sample::HkTlm_t",
            "usages": [
                {"app": "ctrl_app", "direction": "outgoing", "pipe": None, "fcode": None}
            ],
        },
        "2193": {
            "name": "NAV_APP_DIAG_TLM_MID",
            "value": 2193,
            "type": "telem",
            "struct": "GLOBAL_Tlm_t",
            "usages": [
                {"app": "nav_app", "direction": "outgoing", "pipe": None, "fcode": None}
            ],
        },
        "6274": {
            "name": "CTRL_APP_CMD_MID",
            "value": 6274,
            "type": "command",
            "fcodes": {
                "null": {
                    "name": None,
                    "value": None,
                    "struct": "sample::NoopCmd_t",
                    "usages": [{"app": "ctrl_app", "direction": "incoming", "pipe": "CMD"}],
                },
                "1": {
                    "name": "CTRL_APP_SET_MODE_CC",
                    "value": 1,
                    "struct": "sample::SetModeCmd_t",
                    "usages": [{"app": "ctrl_app", "direction": "incoming", "pipe": "CMD"}],
                },
            },
        },
        "CTRL_APP_ODD_MID": {
            "name": "CTRL_APP_ODD_MID",
            "value": None,
            "type": None,
            "struct": "UNKNOWN",
            "usages": [],
        },
    },
    "skipped_apps": ["legacy_app"],
}


@pytest.fixture
def generated_map(tmp_path):
    path = str(tmp_path / "msgid_map.json")
    with io.open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(GENERATED_MAP))
    return path


def test_extract_reads_a_generated_map(workspace, generated_map, tmp_path, capsys):
    out = str(tmp_path / "types-gen.json")
    assert main(["extract", "--mids", generated_map, "-o", out, workspace["so"]]) == 0
    printed = capsys.readouterr().out
    # Which app a struct belongs to, which is what the hand-written file cannot say.
    assert "sample::HkTlm_t" in printed
    assert "[ctrl_app]" in printed
    assert "[nav_app]" in printed
    # What the scanner could not resolve, and where it did not look.
    assert "CTRL_APP_ODD_MID" in printed
    assert "its message ID was never resolved" in printed
    assert "legacy_app" in printed
    assert read_types(out)["roots"]["sample::HkTlm_t"] == ["sample::HkTlm_t"]


def test_decode_reads_a_generated_map(workspace, generated_map, tmp_path, capsys):
    out_dir = str(tmp_path / "out-gen")
    assert (
        main(
            [
                "decode",
                "--types",
                workspace["types"],
                "--mids",
                generated_map,
                "--out",
                out_dir,
                workspace["ds"],
            ]
        )
        == 0
    )
    # Output files are named from the symbolic message ID names in the map.
    assert sorted(os.listdir(out_dir)) == [
        # Function code 0 took the struct from the map's "null" function code.
        "CTRL_APP_CMD_MID.csv",
        "CTRL_APP_CMD_MID_fcn1.csv",
        "CTRL_APP_HK_TLM_MID.csv",
        "NAV_APP_DIAG_TLM_MID.csv",
    ]
    rows = read_csv(os.path.join(out_dir, "CTRL_APP_HK_TLM_MID.csv"))
    assert len(rows) == 2
    assert rows[0]["Payload.Name"] == "hello"
    assert rows[0]["Payload.Mode"] == "MODE_SAFE"
    set_mode = read_csv(os.path.join(out_dir, "CTRL_APP_CMD_MID_fcn1.csv"))
    assert set_mode[0]["Mode"] == "4"
    assert "CTRL_APP_ODD_MID" in capsys.readouterr().err


def test_a_generated_map_decodes_the_same_values_as_a_hand_written_one(
    workspace, generated_map, tmp_path
):
    by_hand = str(tmp_path / "out-hand")
    generated = str(tmp_path / "out-generated")
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            workspace["mids"],
            "--out",
            by_hand,
            workspace["ds"],
        ]
    )
    main(
        [
            "decode",
            "--types",
            workspace["types"],
            "--mids",
            generated_map,
            "--out",
            generated,
            workspace["ds"],
        ]
    )
    # Different file names, same decoded rows.
    left = read_csv(os.path.join(by_hand, "SAMPLE_HK_TLM_MID.csv"))
    right = read_csv(os.path.join(generated, "CTRL_APP_HK_TLM_MID.csv"))
    payload = lambda rows: [
        dict((k, v) for k, v in row.items() if k.startswith("Payload.")) for row in rows
    ]
    assert payload(left) == payload(right)


# -- a project that defines its own header types ---------------------------


PROJ_MIDS = "mids:\n  PROJ_TLM_MID: {value: 0x0890, struct: PROJ_Tlm_t}\n"


def proj_packet(counter, words):
    """A packet laid out by the project's 12 byte header, not the cFE one."""
    payload = struct.pack("<I3H", counter, *words) + b"\x00\x00"
    body = struct.pack(">I", 50) + struct.pack(">H", 0) + payload
    total = 6 + len(body)
    return struct.pack(">HHH", 0x0890, (3 << 14) | 1, total - 7) + body


@pytest.fixture
def proj_workspace(tmp_path, fixture_so):
    mids = str(tmp_path / "proj.yaml")
    with io.open(mids, "w", encoding="utf-8") as handle:
        handle.write(PROJ_MIDS)
    ds = str(tmp_path / "proj.ds")
    mk.write_ds_file(ds, [proj_packet(7, (1, 2, 3))])
    return {"so": fixture_so, "mids": mids, "ds": ds, "dir": str(tmp_path)}


def decode_proj(workspace, tmp_path, name, extra_extract=(), extra_decode=()):
    types = str(tmp_path / ("types-%s.json" % name))
    assert (
        main(
            ["extract", "--mids", workspace["mids"], "-o", types]
            + list(extra_extract)
            + [workspace["so"]]
        )
        == 0
    )
    out_dir = str(tmp_path / ("out-%s" % name))
    code = main(
        [
            "decode",
            "--types",
            types,
            "--mids",
            workspace["mids"],
            "--out",
            out_dir,
        ]
        + list(extra_decode)
        + [workspace["ds"]]
    )
    return code, types, out_dir


def test_an_undeclared_project_header_decodes_wrongly_and_says_so(
    proj_workspace, tmp_path, capsys
):
    code, _, out_dir = decode_proj(proj_workspace, tmp_path, "plain")
    assert code == 0
    rows = read_csv(os.path.join(out_dir, "PROJ_TLM_MID.csv"))
    # Read from the cFE payload offset of 16 rather than this header's 12, so
    # the header bytes appear as columns and Counter is not 7.
    assert "TlmHeader.tPriHdr.StreamId[0]" in rows[0]
    assert rows[0].get("Counter") != "7"
    assert "--header-type" in capsys.readouterr().err


def test_declaring_the_header_on_decode_fixes_it(proj_workspace, tmp_path):
    code, _, out_dir = decode_proj(
        proj_workspace,
        tmp_path,
        "declared",
        extra_decode=["--header-type", "PROJ_MSG_TLM_HDR_T"],
    )
    assert code == 0
    rows = read_csv(os.path.join(out_dir, "PROJ_TLM_MID.csv"))
    assert list(rows[0])[-4:] == ["Counter", "Words[0]", "Words[1]", "Words[2]"]
    assert rows[0]["Counter"] == "7"
    assert [rows[0]["Words[%d]" % i] for i in range(3)] == ["1", "2", "3"]


def test_declaring_it_at_extract_time_carries_into_decode(proj_workspace, tmp_path):
    code, types, out_dir = decode_proj(
        proj_workspace,
        tmp_path,
        "carried",
        extra_extract=["--header-type", "PROJ_MSG_TLM_HDR_T"],
    )
    assert code == 0
    assert read_types(types)["header_types"] == ["PROJ_MSG_TLM_HDR_T"]
    # No flag on the decode: the type file carried the declaration.
    rows = read_csv(os.path.join(out_dir, "PROJ_TLM_MID.csv"))
    assert rows[0]["Counter"] == "7"


def test_several_header_types_fit_in_one_argument(proj_workspace, tmp_path):
    code, types, out_dir = decode_proj(
        proj_workspace,
        tmp_path,
        "commas",
        extra_extract=["--header-type", "PROJ_MSG_TLM_HDR_T,OTHER_HDR_T"],
    )
    assert code == 0
    assert read_types(types)["header_types"] == ["OTHER_HDR_T", "PROJ_MSG_TLM_HDR_T"]
    assert read_csv(os.path.join(out_dir, "PROJ_TLM_MID.csv"))[0]["Counter"] == "7"


def test_the_cfe_path_is_unchanged_by_all_this(workspace, tmp_path):
    out_dir = str(tmp_path / "out-cfe")
    assert (
        main(
            [
                "decode",
                "--types",
                workspace["types"],
                "--mids",
                workspace["mids"],
                "--out",
                out_dir,
                workspace["ds"],
            ]
        )
        == 0
    )
    rows = read_csv(os.path.join(out_dir, "SAMPLE_HK_TLM_MID.csv"))
    assert rows[0]["Payload.Name"] == "hello"
    assert "TelemetryHeader.Msg.CCSDS.Pri.StreamId[0]" not in rows[0]


# -- saying how a union is used ---------------------------------------------

ITEM_MID = 0x0893
UNION_MID = 0x0894

UNION_MIDS = """
unions:
  sample::Item_t:
    tag: Hdr.Kind
    cases: {ITEM_TEMP: Temp, ITEM_COUNT: Count}
mids:
  ITEM_TLM_MID:  {value: 0x0893, struct: sample::ItemTlm_t}
  UNION_TLM_MID: {value: 0x0894, struct: sample::UnionTlm_t}
"""


def item_packet(first, second):
    payload = b""
    for kind, seq, body in (first, second):
        payload += struct.pack("<II", kind, seq) + body.ljust(8, b"\x00")
    return mk.tlm_packet(ITEM_MID, payload=payload)


@pytest.fixture
def union_workspace(tmp_path, fixture_so):
    mids = str(tmp_path / "unions.yaml")
    with io.open(mids, "w", encoding="utf-8") as handle:
        handle.write(UNION_MIDS)
    types = str(tmp_path / "types-unions.json")
    assert main(["extract", "--mids", mids, "-o", types, fixture_so]) == 0
    ds = str(tmp_path / "unions.ds")
    mk.write_ds_file(
        ds,
        [
            item_packet((1, 5, struct.pack("<f", 1.5)), (2, 6, struct.pack("<IB", 77, 3))),
            item_packet((2, 7, struct.pack("<IB", 8, 0)), (9, 8, b"")),
            mk.tlm_packet(UNION_MID, payload=struct.pack("<fI", 2.5, 1)),
        ],
    )
    return {"mids": mids, "types": types, "ds": ds, "dir": str(tmp_path)}


def decode_unions(workspace, tmp_path, name, extra=()):
    out_dir = str(tmp_path / ("out-%s" % name))
    code = main(
        ["decode", "--types", workspace["types"], "--mids", workspace["mids"], "--out", out_dir]
        + list(extra)
        + [workspace["ds"]]
    )
    return code, out_dir


def test_a_tagged_union_fills_only_the_alternative_the_identifier_names(
    union_workspace, tmp_path
):
    code, out_dir = decode_unions(union_workspace, tmp_path, "tagged")
    assert code == 0
    rows = read_csv(os.path.join(out_dir, "ITEM_TLM_MID.csv"))
    assert len(rows) == 2
    payload_columns = [c for c in rows[0] if c.startswith("Items")]
    assert payload_columns == [
        "Items[0].Hdr.Kind",
        "Items[0].Hdr.Seq",
        "Items[0].Temp.Celsius",
        "Items[0].Count.Count",
        "Items[0].Count.Flags",
        "Items[1].Hdr.Kind",
        "Items[1].Hdr.Seq",
        "Items[1].Temp.Celsius",
        "Items[1].Count.Count",
        "Items[1].Count.Flags",
    ]
    first, second = rows
    assert first["Items[0].Hdr.Kind"] == "ITEM_TEMP"
    assert first["Items[0].Temp.Celsius"] == "1.5"
    assert first["Items[0].Count.Count"] == ""
    assert first["Items[1].Hdr.Kind"] == "ITEM_COUNT"
    assert first["Items[1].Temp.Celsius"] == ""
    assert (first["Items[1].Count.Count"], first["Items[1].Count.Flags"]) == ("77", "3")
    # An identifier with no case: the row says which value it was, nothing else.
    assert second["Items[1].Hdr.Kind"] == "9"
    assert second["Items[1].Temp.Celsius"] == ""
    assert second["Items[1].Count.Count"] == ""


def test_byte_views_stay_unless_asked_to_go(union_workspace, tmp_path):
    code, out_dir = decode_unions(union_workspace, tmp_path, "keep")
    assert code == 0
    row = read_csv(os.path.join(out_dir, "UNION_TLM_MID.csv"))[0]
    assert row["Value.f"] == "2.5"
    assert "Value.b[0]" in row
    code, out_dir = decode_unions(union_workspace, tmp_path, "drop", ["--union-bytes", "drop"])
    assert code == 0
    row = read_csv(os.path.join(out_dir, "UNION_TLM_MID.csv"))[0]
    assert row["Value.f"] == "2.5"
    assert "Value.b[0]" not in row
    assert list(row)[-3:] == ["Value.i", "Value.f", "Tag"]


def test_a_wrong_union_entry_stops_the_decode_with_the_entry_named(
    union_workspace, tmp_path, capsys
):
    with io.open(union_workspace["mids"], "w", encoding="utf-8") as handle:
        handle.write(UNION_MIDS.replace("unions:\n", "unions:\n  sample::Value_t: {keep: [x]}\n"))
    code, _ = decode_unions(union_workspace, tmp_path, "bad")
    assert code == 1
    err = capsys.readouterr().err
    assert "unions.sample::Value_t" in err
    assert "no member 'x'" in err


def test_extract_reads_a_mapping_with_a_unions_section(union_workspace, capsys):
    """The section is judged for shape at extract time, like the rest of the file."""
    with io.open(union_workspace["mids"], "w", encoding="utf-8") as handle:
        handle.write(
            UNION_MIDS.replace("unions:\n", "unions:\n  sample::Value_t: {keep: i, drop: b}\n")
        )
    types = os.path.join(union_workspace["dir"], "unused.json")
    code = main(["extract", "--mids", union_workspace["mids"], "-o", types, union_workspace["dir"]])
    assert code == 1
    assert "not both" in capsys.readouterr().err
