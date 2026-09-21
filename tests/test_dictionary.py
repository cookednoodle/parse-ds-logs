"""Load message ID mappings and turn them into decoders."""

from __future__ import annotations

import io
import json

import pytest

from dsdecode.decode import Options
from dsdecode.dictionary import Dictionary, DictionaryError, safe_name
from dsdecode.dsfile import Geometry


def write_mids(tmp_path, text, name="mids.yaml"):
    path = tmp_path / name
    with io.open(str(path), "w", encoding="utf-8") as handle:
        handle.write(text)
    return str(path)


def load(tmp_path, text, registry, **kwargs):
    path = write_mids(tmp_path, text)
    return Dictionary.load(path, registry, Geometry.from_registry(registry), **kwargs)


def test_a_named_entry_with_a_value(tmp_path, registry):
    mids = load(
        tmp_path,
        "mids:\n  SAMPLE_HK_TLM_MID: {value: 0x0890, struct: sample::HkTlm_t}\n",
        registry,
    )
    entry = mids.lookup(0x0890)
    assert entry is not None
    assert entry.name == "SAMPLE_HK_TLM_MID"
    assert entry.decoder_for(None).type_name == "sample::HkTlm_t"
    assert entry.output_name(None) == "SAMPLE_HK_TLM_MID"


def test_the_message_id_may_be_the_key(tmp_path, registry):
    mids = load(tmp_path, "mids:\n  0x0891: GLOBAL_Tlm_t\n", registry)
    entry = mids.lookup(0x0891)
    assert entry.name == "MID_0x0891"
    assert entry.decoder_for(None).type_name == "GLOBAL_Tlm_t"


def test_a_decimal_message_id_works_too(tmp_path, registry):
    mids = load(tmp_path, "mids:\n  2192: GLOBAL_Tlm_t\n", registry)
    assert mids.lookup(0x0890) is not None


def test_commands_can_choose_a_struct_by_function_code(tmp_path, registry):
    mids = load(
        tmp_path,
        "mids:\n"
        "  SAMPLE_CMD_MID:\n"
        "    value: 0x1882\n"
        "    struct:\n"
        "      default: sample::NoopCmd_t\n"
        "      fcn: {1: sample::SetModeCmd_t}\n",
        registry,
    )
    entry = mids.lookup(0x1882)
    assert entry.decoder_for(None).type_name == "sample::NoopCmd_t"
    assert entry.decoder_for(0).type_name == "sample::NoopCmd_t"
    assert entry.decoder_for(1).type_name == "sample::SetModeCmd_t"
    assert entry.output_name(1) == "SAMPLE_CMD_MID_fcn1"
    assert entry.output_name(0) == "SAMPLE_CMD_MID"


def test_a_namespace_may_be_left_off(tmp_path, registry):
    mids = load(tmp_path, "mids:\n  HK: {value: 0x0890, struct: HkTlm_t}\n", registry)
    assert mids.lookup(0x0890).decoder_for(None).type_name == "sample::HkTlm_t"


def test_lookup_is_case_insensitive_as_a_last_resort(tmp_path, registry):
    mids = load(tmp_path, "mids:\n  HK: {value: 0x0890, struct: hktlm_t}\n", registry)
    assert mids.lookup(0x0890).decoder_for(None).type_name == "sample::HkTlm_t"


def test_an_unknown_struct_names_close_matches(tmp_path, registry):
    with pytest.raises(DictionaryError) as caught:
        load(tmp_path, "mids:\n  HK: {value: 0x0890, struct: sample::HkTlmX_t}\n", registry)
    assert "not in the type file" in str(caught.value)
    assert "sample::HkTlm_t" in str(caught.value)


def test_an_entry_without_a_message_id_is_rejected(tmp_path, registry):
    with pytest.raises(DictionaryError) as caught:
        load(tmp_path, "mids:\n  SOME_MID: {struct: sample::HkTlm_t}\n", registry)
    assert "no message ID" in str(caught.value)


def test_an_entry_without_a_struct_is_rejected(tmp_path, registry):
    with pytest.raises(DictionaryError):
        load(tmp_path, "mids:\n  SOME_MID: {value: 5}\n", registry)


def test_an_empty_mapping_is_rejected(tmp_path, registry):
    with pytest.raises(DictionaryError):
        load(tmp_path, "mids: {}\n", registry)


def test_a_missing_mapping_file_is_reported(tmp_path, registry):
    with pytest.raises(DictionaryError):
        Dictionary.load(
            str(tmp_path / "nope.yaml"), registry, Geometry.from_registry(registry)
        )


def test_a_repeated_message_id_keeps_the_first_and_warns(tmp_path, registry):
    warnings = []
    mids = load(
        tmp_path,
        "mids:\n"
        "  FIRST: {value: 0x0890, struct: sample::HkTlm_t}\n"
        "  SECOND: {value: 0x0890, struct: GLOBAL_Tlm_t}\n",
        registry,
        warn=warnings.append,
    )
    assert mids.lookup(0x0890).name == "FIRST"
    assert any("mapped twice" in w for w in warnings)


def test_a_payload_struct_warns_that_it_has_no_header(tmp_path, registry):
    warnings = []
    load(
        tmp_path,
        "mids:\n  HK: {value: 0x0890, struct: sample::HkPayload}\n",
        registry,
        warn=warnings.append,
    )
    assert any("does not start with a header this build knows" in w for w in warnings)
    # The warning says what to do about it, not only what happened.
    assert any("--header-type" in w for w in warnings)


def test_options_reach_the_compiled_decoder(tmp_path, registry):
    mids = load(
        tmp_path,
        "mids:\n  HK: {value: 0x0890, struct: sample::HkTlm_t}\n",
        registry,
        options=Options(enum_values=True),
    )
    assert "Payload.Mode" in mids.lookup(0x0890).decoder_for(None).columns


def test_json_is_accepted(tmp_path, registry):
    path = write_mids(
        tmp_path,
        '{"mids": {"HK": {"value": 2192, "struct": "sample::HkTlm_t"}}}',
        name="mids.json",
    )
    mids = Dictionary.load(path, registry, Geometry.from_registry(registry))
    assert mids.lookup(0x0890) is not None


def test_file_names_stay_safe():
    assert safe_name("SAMPLE/HK MID") == "SAMPLE_HK_MID"
    assert safe_name("../etc/passwd") == ".._etc_passwd"


# -- reading a mapping without any types -----------------------------------


def test_read_mapping_lists_every_struct_it_names(tmp_path):
    from dsdecode.dictionary import read_mapping

    path = write_mids(
        tmp_path,
        "mids:\n"
        "  A: {value: 0x0890, struct: sample::HkTlm_t}\n"
        "  0x0891: GLOBAL_Tlm_t\n"
        "  C:\n"
        "    value: 0x1882\n"
        "    struct:\n"
        "      default: sample::NoopCmd_t\n"
        "      fcn: {1: sample::SetModeCmd_t, 2: sample::NoopCmd_t}\n",
    )
    mapping = read_mapping(path)
    assert len(mapping) == 3
    # File order, and a struct named twice is listed once.
    assert mapping.struct_names() == [
        "sample::HkTlm_t",
        "GLOBAL_Tlm_t",
        "sample::NoopCmd_t",
        "sample::SetModeCmd_t",
    ]


def test_read_mapping_checks_the_file_with_no_types_to_hand(tmp_path):
    from dsdecode.dictionary import read_mapping

    with pytest.raises(DictionaryError) as caught:
        read_mapping(write_mids(tmp_path, "mids:\n  SOME_MID: {struct: Whatever_t}\n"))
    assert "no message ID" in str(caught.value)


def test_read_mapping_and_dictionary_load_agree_on_a_bad_file(tmp_path, registry):
    from dsdecode.dictionary import read_mapping

    path = write_mids(tmp_path, "mids: {}\n")
    with pytest.raises(DictionaryError) as from_read:
        read_mapping(path)
    with pytest.raises(DictionaryError) as from_load:
        Dictionary.load(path, registry, Geometry.from_registry(registry))
    assert str(from_read.value) == str(from_load.value)


# -- maps generated by scanning the flight software ------------------------


def generated_map(**mids):
    """A map shaped like the output of a code-base scanner."""
    return {"mids": mids, "skipped_apps": []}


def telem_entry(name, value, struct, app="ctrl_app"):
    return {
        "name": name,
        "value": value,
        "type": "telem",
        "struct": struct,
        "usages": [{"app": app, "direction": "outgoing", "pipe": None, "fcode": None}],
    }


def write_generated(tmp_path, data, name="msgid_map.json"):
    path = tmp_path / name
    with io.open(str(path), "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data))
    return str(path)


def test_a_generated_map_is_recognized_and_read(tmp_path):
    from dsdecode.dictionary import read_mapping

    path = write_generated(
        tmp_path, generated_map(**{"2192": telem_entry("CTRL_APP_HK_TLM_MID", 2192, "sample::HkTlm_t")})
    )
    mapping = read_mapping(path)
    assert mapping.generated
    assert mapping.struct_names() == ["sample::HkTlm_t"]
    entry = mapping.entries[0]
    assert entry.name == "CTRL_APP_HK_TLM_MID"
    assert entry.value == 0x0890
    assert entry.default_struct == "sample::HkTlm_t"
    assert entry.publishers == ["ctrl_app"]


def test_a_hand_written_mapping_is_not_taken_for_a_generated_one(tmp_path):
    from dsdecode.dictionary import read_mapping

    mapping = read_mapping(
        write_mids(tmp_path, "mids:\n  HK: {value: 0x0890, struct: sample::HkTlm_t}\n")
    )
    assert not mapping.generated
    assert mapping.skipped == []


def test_a_generated_command_takes_its_structs_from_the_function_codes(tmp_path):
    from dsdecode.dictionary import read_mapping

    path = write_generated(
        tmp_path,
        generated_map(
            **{
                "6274": {
                    "name": "CTRL_APP_CMD_MID",
                    "value": 6274,
                    "type": "command",
                    "fcodes": {
                        "null": {
                            "name": None,
                            "value": None,
                            "struct": "sample::NoopCmd_t",
                            "usages": [
                                {"app": "ctrl_app", "direction": "incoming", "pipe": "CMD"}
                            ],
                        },
                        "1": {
                            "name": "CTRL_APP_SET_MODE_CC",
                            "value": 1,
                            "struct": "sample::SetModeCmd_t",
                            "usages": [
                                {"app": "ctrl_app", "direction": "incoming", "pipe": "CMD"}
                            ],
                        },
                    },
                }
            }
        ),
    )
    entry = read_mapping(path).entries[0]
    # A usage that named no function code stands in for the rest.
    assert entry.default_struct == "sample::NoopCmd_t"
    assert entry.by_fcn == {1: "sample::SetModeCmd_t"}
    assert entry.apps == ["ctrl_app"]
    assert entry.publishers == []


def test_a_function_code_uses_its_resolved_value_over_its_key(tmp_path):
    from dsdecode.dictionary import read_mapping

    path = write_generated(
        tmp_path,
        generated_map(
            **{
                "6274": {
                    "name": "CMD_MID",
                    "value": 6274,
                    "type": "command",
                    "fcodes": {
                        "CTRL_APP_SET_MODE_CC": {
                            "name": "CTRL_APP_SET_MODE_CC",
                            "value": 4,
                            "struct": "sample::SetModeCmd_t",
                            "usages": [],
                        }
                    },
                }
            }
        ),
    )
    assert read_mapping(path).entries[0].by_fcn == {4: "sample::SetModeCmd_t"}


def test_a_message_id_the_scanner_could_not_resolve_is_set_aside(tmp_path):
    from dsdecode.dictionary import read_mapping

    path = write_generated(
        tmp_path,
        generated_map(
            **{
                "2192": telem_entry("CTRL_APP_HK_TLM_MID", 2192, "sample::HkTlm_t"),
                "CTRL_APP_ODD_MID": {
                    "name": "CTRL_APP_ODD_MID",
                    "value": None,
                    "type": None,
                    "struct": "UNKNOWN",
                    "usages": [],
                },
            }
        ),
    )
    mapping = read_mapping(path)
    assert [e.name for e in mapping.entries] == ["CTRL_APP_HK_TLM_MID"]
    assert mapping.skipped == [("CTRL_APP_ODD_MID", "its message ID was never resolved")]


def test_a_struct_the_scanner_could_not_resolve_is_set_aside(tmp_path):
    from dsdecode.dictionary import read_mapping

    path = write_generated(
        tmp_path,
        generated_map(
            **{
                "2192": telem_entry("CTRL_APP_HK_TLM_MID", 2192, "sample::HkTlm_t"),
                "2193": telem_entry("CTRL_APP_DIAG_TLM_MID", 2193, "UNKNOWN"),
            }
        ),
    )
    mapping = read_mapping(path)
    assert [e.name for e in mapping.entries] == ["CTRL_APP_HK_TLM_MID"]
    assert mapping.skipped == [("CTRL_APP_DIAG_TLM_MID", "no struct was resolved for it")]


def test_one_unresolved_function_code_does_not_lose_the_others(tmp_path):
    from dsdecode.dictionary import read_mapping

    path = write_generated(
        tmp_path,
        generated_map(
            **{
                "6274": {
                    "name": "CTRL_APP_CMD_MID",
                    "value": 6274,
                    "type": "command",
                    "fcodes": {
                        "1": {
                            "name": "SET_MODE_CC",
                            "value": 1,
                            "struct": "sample::SetModeCmd_t",
                            "usages": [],
                        },
                        "CTRL_APP_MYSTERY_CC": {
                            "name": "CTRL_APP_MYSTERY_CC",
                            "value": None,
                            "struct": "sample::NoopCmd_t",
                            "usages": [],
                        },
                    },
                }
            }
        ),
    )
    mapping = read_mapping(path)
    assert mapping.entries[0].by_fcn == {1: "sample::SetModeCmd_t"}
    assert mapping.skipped == [
        ("CTRL_APP_CMD_MID function code CTRL_APP_MYSTERY_CC", "its function code was never resolved")
    ]


def test_a_generated_map_with_nothing_usable_is_an_error(tmp_path):
    from dsdecode.dictionary import read_mapping

    path = write_generated(
        tmp_path, generated_map(**{"2192": telem_entry("ONLY_MID", 2192, "UNKNOWN")})
    )
    with pytest.raises(DictionaryError) as caught:
        read_mapping(path)
    assert "no message ID that could be used" in str(caught.value)
    assert "ONLY_MID" in str(caught.value)


def test_struct_apps_prefers_the_app_that_sends_a_message(tmp_path):
    from dsdecode.dictionary import read_mapping

    entry = telem_entry("HK_MID", 2192, "sample::HkTlm_t", app="ctrl_app")
    entry["usages"].append({"app": "gnc_app", "direction": "incoming", "pipe": "DATA", "fcode": None})
    mapping = read_mapping(write_generated(tmp_path, generated_map(**{"2192": entry})))
    assert mapping.struct_apps() == {"sample::HkTlm_t": ["ctrl_app"]}


def test_a_generated_map_compiles_into_decoders(tmp_path, registry):
    path = write_generated(
        tmp_path, generated_map(**{"2192": telem_entry("CTRL_APP_HK_TLM_MID", 2192, "sample::HkTlm_t")})
    )
    mids = Dictionary.load(path, registry, Geometry.from_registry(registry))
    entry = mids.lookup(0x0890)
    assert entry.name == "CTRL_APP_HK_TLM_MID"
    assert entry.decoder_for(None).type_name == "sample::HkTlm_t"


def test_loading_a_generated_map_warns_about_what_it_skipped(tmp_path, registry):
    warnings = []
    path = write_generated(
        tmp_path,
        generated_map(
            **{
                "2192": telem_entry("CTRL_APP_HK_TLM_MID", 2192, "sample::HkTlm_t"),
                "2193": telem_entry("CTRL_APP_DIAG_TLM_MID", 2193, "UNKNOWN"),
            }
        ),
    )
    Dictionary.load(
        path, registry, Geometry.from_registry(registry), warn=warnings.append
    )
    assert any("CTRL_APP_DIAG_TLM_MID" in w and "skipped" in w for w in warnings)


def test_a_dropped_column_is_warned_about_when_the_mapping_loads(tmp_path, registry):
    """A type file with a hole in it says so, rather than a short CSV."""
    from dsdecode.typemodel import Member, StructType, TypeRegistry

    types = dict(registry.types)
    types["Holey_t"] = StructType(
        "Holey_t",
        24,
        [
            Member("TelemetryHeader", 0, "CFE_MSG_TelemetryHeader_t"),
            Member("Good", 16, "uint32"),
            Member("Lost", 20, "NotInTheFile_t"),
        ],
    )
    broken = TypeRegistry(
        types=types,
        endian=registry.endian,
        pointer_size=registry.pointer_size,
        geometry=dict(registry.geometry),
    )
    warnings = []
    mids = Dictionary.load(
        write_mids(tmp_path, "mids:\n  HK: {value: 0x0890, struct: Holey_t}\n"),
        broken,
        Geometry.from_registry(broken),
        warn=warnings.append,
    )
    assert mids.lookup(0x0890).decoder_for(None).columns == ["Good"]
    assert any("Lost" in w and "NotInTheFile_t" in w for w in warnings)


# -- structs this build does not have --------------------------------------


def registry_missing(registry, absent):
    """A copy of the build that records some mapping names as not present."""
    from dsdecode.typemodel import TypeRegistry

    return TypeRegistry(
        types=dict(registry.types),
        endian=registry.endian,
        pointer_size=registry.pointer_size,
        geometry=dict(registry.geometry),
        filtered=True,
        unresolved=list(absent),
    )


def test_a_message_id_whose_struct_is_absent_is_skipped(tmp_path, registry):
    broken = registry_missing(registry, ["NotBuiltYet_t"])
    warnings = []
    mids = Dictionary.load(
        write_mids(
            tmp_path,
            "mids:\n"
            "  HK: {value: 0x0890, struct: sample::HkTlm_t}\n"
            "  GONE: {value: 0x0899, struct: NotBuiltYet_t}\n",
        ),
        broken,
        Geometry.from_registry(broken),
        warn=warnings.append,
    )
    assert mids.lookup(0x0890) is not None
    assert mids.lookup(0x0899) is None
    assert any("GONE" in w and "does not have" in w for w in warnings)


def test_a_command_keeps_the_function_codes_it_can_decode(tmp_path, registry):
    broken = registry_missing(registry, ["NotBuiltYet_t"])
    mids = Dictionary.load(
        write_mids(
            tmp_path,
            "mids:\n"
            "  CMD: \n"
            "    value: 0x1882\n"
            "    struct:\n"
            "      default: sample::NoopCmd_t\n"
            "      fcn: {1: NotBuiltYet_t, 2: sample::SetModeCmd_t}\n",
        ),
        broken,
        Geometry.from_registry(broken),
        warn=lambda message: None,
    )
    entry = mids.lookup(0x1882)
    assert entry is not None
    assert entry.decoder_for(None).type_name == "sample::NoopCmd_t"
    assert entry.decoder_for(2).type_name == "sample::SetModeCmd_t"
    # Function code 1 falls back to the default rather than vanishing.
    assert entry.decoder_for(1).type_name == "sample::NoopCmd_t"


def test_a_mapping_with_nothing_left_to_decode_is_an_error(tmp_path, registry):
    broken = registry_missing(registry, ["NotBuiltYet_t"])
    with pytest.raises(DictionaryError) as caught:
        Dictionary.load(
            write_mids(tmp_path, "mids:\n  GONE: {value: 0x0899, struct: NotBuiltYet_t}\n"),
            broken,
            Geometry.from_registry(broken),
            warn=lambda message: None,
        )
    assert "no message ID" in str(caught.value)


def test_a_struct_not_recorded_as_absent_still_says_to_re_extract(tmp_path, registry):
    """The stale type file case keeps its own, different, error."""
    from dsdecode.dictionary import UnknownStructError

    broken = registry_missing(registry, ["SomethingElse_t"])
    with pytest.raises(UnknownStructError):
        Dictionary.load(
            write_mids(tmp_path, "mids:\n  NEW: {value: 0x0899, struct: NeverMentioned_t}\n"),
            broken,
            Geometry.from_registry(broken),
            warn=lambda message: None,
        )


# -- declaring a project's own header types --------------------------------


def test_header_types_declared_in_the_mapping_reach_the_decoder(tmp_path, registry):
    mids = load(
        tmp_path,
        "header_types: [PROJ_MSG_TLM_HDR_T]\n"
        "mids:\n  PROJ: {value: 0x0890, struct: PROJ_Tlm_t}\n",
        registry,
    )
    decoder = mids.lookup(0x0890).decoder_for(None)
    assert decoder.has_header
    assert decoder.header_size == 12
    assert decoder.columns == ["Counter", "Words[0]", "Words[1]", "Words[2]"]


def test_header_types_work_in_a_file_with_no_mids_key(tmp_path, registry):
    # The short form, where the whole document is message IDs.
    mids = load(
        tmp_path,
        "header_types: [PROJ_MSG_TLM_HDR_T]\n" "0x0890: PROJ_Tlm_t\n",
        registry,
    )
    entry = mids.lookup(0x0890)
    assert entry is not None, "the declaration must not be read as a message ID"
    assert entry.decoder_for(None).has_header


def test_header_types_recorded_in_the_type_file_reach_the_decoder(tmp_path, registry):
    from dsdecode.typemodel import TypeRegistry

    carried = TypeRegistry(
        types=dict(registry.types),
        endian=registry.endian,
        pointer_size=registry.pointer_size,
        geometry=dict(registry.geometry),
        header_types=["PROJ_MSG_TLM_HDR_T"],
    )
    mids = Dictionary.load(
        write_mids(tmp_path, "mids:\n  PROJ: {value: 0x0890, struct: PROJ_Tlm_t}\n"),
        carried,
        Geometry.from_registry(carried),
    )
    assert mids.lookup(0x0890).decoder_for(None).has_header


def test_header_types_passed_by_the_caller_reach_the_decoder(tmp_path, registry):
    mids = load(
        tmp_path,
        "mids:\n  PROJ: {value: 0x0890, struct: PROJ_Tlm_t}\n",
        registry,
        options=Options(header_types=["PROJ_MSG_TLM_HDR_T"]),
    )
    assert mids.lookup(0x0890).decoder_for(None).has_header


def test_an_undeclared_project_header_warns_with_the_remedy(tmp_path, registry):
    warnings = []
    load(
        tmp_path,
        "mids:\n  PROJ: {value: 0x0890, struct: PROJ_Tlm_t}\n",
        registry,
        warn=warnings.append,
    )
    assert any("PROJ_Tlm_t" in w and "--header-type" in w for w in warnings)


# -- saying how a union is used ---------------------------------------------

ITEM_MIDS = (
    "mids:\n"
    "  ITEM_TLM_MID: {value: 0x0893, struct: sample::ItemTlm_t}\n"
    "  UNION_TLM_MID: {value: 0x0894, struct: sample::UnionTlm_t}\n"
)


def test_a_unions_section_reaches_the_decoder(tmp_path, registry):
    mids = load(
        tmp_path,
        "unions:\n"
        "  sample::Item_t:\n"
        "    tag: Hdr.Kind\n"
        "    cases: {ITEM_TEMP: Temp, ITEM_COUNT: Count}\n"
        "  sample::Value_t: {keep: [i, f]}\n" + ITEM_MIDS,
        registry,
    )
    items = mids.lookup(0x0893).decoder_for(None)
    assert items.columns[:5] == [
        "Items[0].Hdr.Kind",
        "Items[0].Hdr.Seq",
        "Items[0].Temp.Celsius",
        "Items[0].Count.Count",
        "Items[0].Count.Flags",
    ]
    assert mids.lookup(0x0894).decoder_for(None).columns == ["Value.i", "Value.f", "Tag"]


def test_a_union_may_be_named_without_its_namespace(tmp_path, registry):
    mids = load(tmp_path, "unions:\n  Value_t: {drop: b}\n" + ITEM_MIDS, registry)
    assert mids.lookup(0x0894).decoder_for(None).columns == ["Value.i", "Value.f", "Tag"]


def test_union_bytes_in_the_mapping_drops_byte_views_everywhere(tmp_path, registry):
    mids = load(tmp_path, "union_bytes: drop\n" + ITEM_MIDS, registry)
    assert mids.lookup(0x0894).decoder_for(None).columns == ["Value.i", "Value.f", "Tag"]
    assert "Items[0].Bytes[0]" not in mids.lookup(0x0893).decoder_for(None).columns


def test_union_bytes_passed_by_the_caller_works_the_same(tmp_path, registry):
    mids = load(tmp_path, ITEM_MIDS, registry, options=Options(union_bytes="drop"))
    assert mids.lookup(0x0894).decoder_for(None).columns == ["Value.i", "Value.f", "Tag"]


def test_the_settings_work_in_a_file_with_no_mids_key(tmp_path, registry):
    mids = load(
        tmp_path,
        "union_bytes: drop\n"
        "unions:\n  sample::Item_t: {tag: Hdr.Kind, cases: {1: Temp}}\n"
        "0x0893: sample::ItemTlm_t\n"
        "0x0894: sample::UnionTlm_t\n",
        registry,
    )
    assert mids.lookup(0x0893) is not None, "the settings must not be read as message IDs"
    assert "Items[0].Count.Count" not in mids.lookup(0x0893).decoder_for(None).columns
    assert mids.lookup(0x0894).decoder_for(None).columns == ["Value.i", "Value.f", "Tag"]


def test_a_union_not_in_the_type_file_is_passed_over_with_a_warning(tmp_path, registry):
    warnings = []
    mids = load(
        tmp_path,
        "unions:\n  OtherApp::Payload_t: {tag: Id, cases: {1: A}}\n" + ITEM_MIDS,
        registry,
        warn=warnings.append,
    )
    assert mids.lookup(0x0893) is not None
    assert any("OtherApp::Payload_t" in w and "ignored" in w for w in warnings)


def test_a_union_entry_naming_a_struct_is_an_error(tmp_path, registry):
    with pytest.raises(DictionaryError) as caught:
        load(tmp_path, "unions:\n  sample::Vec3: {keep: x}\n" + ITEM_MIDS, registry)
    assert "not a union" in str(caught.value)


def test_a_wrong_member_is_an_error_that_names_the_file_and_entry(tmp_path, registry):
    with pytest.raises(DictionaryError) as caught:
        load(
            tmp_path,
            "unions:\n  sample::Item_t: {tag: Hdr.Id, cases: {1: Temp}}\n" + ITEM_MIDS,
            registry,
        )
    message = str(caught.value)
    assert "mids.yaml" in message
    assert "unions.sample::Item_t" in message
    assert "no member 'Id'" in message


def test_a_wrong_keep_is_caught_when_the_mapping_is_loaded(tmp_path, registry):
    with pytest.raises(DictionaryError) as caught:
        load(tmp_path, "unions:\n  sample::Value_t: {keep: [x]}\n" + ITEM_MIDS, registry)
    assert "no member 'x'" in str(caught.value)


@pytest.mark.parametrize(
    "spec, complaint",
    [
        ("{}", "says nothing"),
        ("{keep: i, drop: b}", "not both"),
        ("{tag: Hdr.Kind}", "needs 'cases'"),
        ("{cases: {1: Temp}}", "needs 'tag'"),
        ("{tag: Hdr.Kind, cases: {1: Temp}, drop: Bytes}", "cannot go with 'tag'"),
        ("{tag: Hdr.Kind, cases: {1: 7}}", "must name a member"),
        ("{keep: []}", "names no member"),
        ("{keep: 5}", "member name or a list"),
        ("{tag: 5, cases: {1: Temp}}", "name the member"),
        ("{tags: Hdr.Kind}", "unknown key"),
        ("Temp", "must be a mapping"),
    ],
)
def test_a_malformed_union_entry_is_rejected_before_any_types_are_read(tmp_path, spec, complaint):
    from dsdecode.dictionary import read_mapping

    with pytest.raises(DictionaryError) as caught:
        read_mapping(write_mids(tmp_path, "unions:\n  sample::Item_t: %s\n" % spec + ITEM_MIDS))
    assert complaint in str(caught.value)
    assert "unions.sample::Item_t" in str(caught.value)


def test_a_bad_union_bytes_value_is_rejected(tmp_path):
    from dsdecode.dictionary import read_mapping

    with pytest.raises(DictionaryError) as caught:
        read_mapping(write_mids(tmp_path, "union_bytes: sometimes\n" + ITEM_MIDS))
    assert "keep or drop" in str(caught.value)


def test_unions_may_be_written_as_json(tmp_path, registry):
    path = write_mids(
        tmp_path,
        json.dumps(
            {
                "unions": {"sample::Item_t": {"tag": "Hdr.Kind", "cases": {"1": "Temp"}}},
                "mids": {"ITEM": {"value": 2195, "struct": "sample::ItemTlm_t"}},
            }
        ),
        name="mids.json",
    )
    mids = Dictionary.load(path, registry, Geometry.from_registry(registry))
    columns = mids.lookup(0x0893).decoder_for(None).columns
    assert "Items[0].Temp.Celsius" in columns
    assert "Items[0].Count.Count" not in columns
