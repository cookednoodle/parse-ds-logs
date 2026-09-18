"""Load message ID mappings and turn them into decoders."""

from __future__ import annotations

import io

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
    assert any("no cFS message header" in w for w in warnings)


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
