"""Decode packets whose contents the compiled fixture defines."""

from __future__ import annotations

import struct

import pytest

from dsdecode.decode import DecodeError, Options, compile_struct


def as_row(decoder, raw, base=0):
    return dict(zip(decoder.columns, decoder.decode(raw, base)))


def same(got, expected):
    try:
        return abs(float(got) - float(expected)) <= 1e-9 * max(1.0, abs(float(expected)))
    except (TypeError, ValueError):
        return str(got) == expected


def test_every_field_round_trips(registry, sample_hk):
    raw, expected = sample_hk
    decoder = compile_struct(registry, "sample::HkTlm_t")
    row = as_row(decoder, raw)
    missing = [name for name in expected if name not in row]
    assert not missing, "columns missing from the decoder: %s" % missing
    wrong = [
        (name, expected[name], row[name]) for name in expected if not same(row[name], expected[name])
    ]
    assert not wrong, "values did not round trip: %s" % wrong


def test_header_columns_are_left_out(registry):
    decoder = compile_struct(registry, "sample::HkTlm_t")
    assert decoder.has_header
    assert decoder.header_size == 16
    assert not [c for c in decoder.columns if "TelemetryHeader" in c]
    assert decoder.columns[0] == "Payload.CommandCounter"


def test_a_payload_without_a_header_is_marked(registry):
    decoder = compile_struct(registry, "sample::HkPayload")
    assert not decoder.has_header
    assert decoder.header_size == 0
    assert decoder.columns[0] == "CommandCounter"


def test_a_payload_struct_decodes_at_an_offset(registry, sample_hk):
    raw, expected = sample_hk
    decoder = compile_struct(registry, "sample::HkPayload")
    row = as_row(decoder, raw, base=16)
    assert row["CommandCounter"] == int(float(expected["Payload.CommandCounter"]))
    assert row["Name"] == "hello"


def test_arrays_flatten_in_row_major_order(registry):
    decoder = compile_struct(registry, "sample::HkTlm_t")
    index = decoder.columns.index("Payload.Matrix[0][0]")
    assert decoder.columns[index : index + 6] == [
        "Payload.Matrix[0][0]",
        "Payload.Matrix[0][1]",
        "Payload.Matrix[0][2]",
        "Payload.Matrix[1][0]",
        "Payload.Matrix[1][1]",
        "Payload.Matrix[1][2]",
    ]


def test_char_arrays_can_be_split_into_bytes(registry, sample_hk):
    raw, _ = sample_hk
    decoder = compile_struct(registry, "sample::HkTlm_t", Options(char_arrays="bytes"))
    row = as_row(decoder, raw)
    assert "Payload.Name" not in row
    assert row["Payload.Name[0]"] == ord("h")
    assert row["Payload.Name[4]"] == ord("o")
    assert row["Payload.Name[5]"] == 0


def test_enums_can_be_reported_as_numbers(registry, sample_hk):
    raw, _ = sample_hk
    named = as_row(compile_struct(registry, "sample::HkTlm_t"), raw)
    numeric = as_row(compile_struct(registry, "sample::HkTlm_t", Options(enum_values=True)), raw)
    assert named["Payload.Mode"] == "MODE_SAFE"
    assert numeric["Payload.Mode"] == 7


def test_unions_report_every_alternative(registry):
    decoder = compile_struct(registry, "sample::UnionTlm_t")
    assert "Value.i" in decoder.columns
    assert "Value.f" in decoder.columns
    assert "Value.b[0]" in decoder.columns
    raw = b"\x00" * 16 + struct.pack("<f", 1.5) + struct.pack("<I", 9)
    row = as_row(decoder, raw)
    assert row["Value.f"] == 1.5
    assert row["Value.i"] == struct.unpack("<i", struct.pack("<f", 1.5))[0]
    assert row["Tag"] == 9


def test_anonymous_members_flatten_without_a_prefix(registry):
    decoder = compile_struct(registry, "ANON_Tlm_t")
    assert "Parts.lo" in decoder.columns
    assert "Parts.hi" in decoder.columns
    assert "whole" in decoder.columns
    assert "bytes[3]" in decoder.columns
    raw = b"\x00" * 16 + struct.pack("<HH", 7, 9) + struct.pack("<I", 0x04030201)
    row = as_row(decoder, raw)
    assert (row["Parts.lo"], row["Parts.hi"]) == (7, 9)
    assert row["whole"] == 0x04030201
    assert row["bytes[0]"] == 1


def test_a_short_packet_gives_empty_cells_not_an_error(registry, sample_hk):
    raw, _ = sample_hk
    decoder = compile_struct(registry, "sample::HkTlm_t")
    cut = raw[:40]
    row = as_row_limited(decoder, cut)
    assert row["Payload.CommandCounter"] is not None
    assert row["Payload.Voltage"] is None
    assert row["Payload.Matrix[1][2]"] is None


def as_row_limited(decoder, raw):
    return dict(zip(decoder.columns, decoder.decode(raw, 0, len(raw))))


def test_unknown_type_is_reported(registry):
    with pytest.raises(DecodeError):
        compile_struct(registry, "NoSuchMessage_t")


def test_a_scalar_type_is_rejected(registry):
    with pytest.raises(DecodeError):
        compile_struct(registry, "uint32")


# -- fields that get no column ---------------------------------------------


def awkward(registry, members, extra=None, size=32, options=None):
    """Compile a message struct built to be awkward, and collect the warnings.

    Everything happens against a copy, because the registry fixture is shared
    by the whole session and a test that dirties it would break its neighbours.
    """
    from dsdecode.typemodel import Member, StructType, TypeRegistry

    types = dict(registry.types)
    types.update(extra or {})
    types["Awkward_t"] = StructType(
        "Awkward_t",
        size,
        [Member("TelemetryHeader", 0, "CFE_MSG_TelemetryHeader_t")] + list(members),
    )
    copy = TypeRegistry(
        types=types,
        endian=registry.endian,
        pointer_size=registry.pointer_size,
        geometry=dict(registry.geometry),
    )
    warnings = []
    decoder = compile_struct(copy, "Awkward_t", options, warn=warnings.append)
    return decoder, warnings


def test_a_member_whose_type_is_missing_says_so_and_keeps_the_rest(registry):
    from dsdecode.typemodel import Member

    decoder, warnings = awkward(
        registry,
        [
            Member("Before", 16, "uint32"),
            Member("Missing", 20, "NotInTheFile_t"),
            Member("After", 24, "uint32"),
        ],
    )
    # The fields around the hole still decode.
    assert decoder.columns == ["Before", "After"]
    assert len(warnings) == 1
    assert "Missing" in warnings[0]
    assert "NotInTheFile_t" in warnings[0]
    assert "not in the type file" in warnings[0]
    assert "Awkward_t" in warnings[0]


def test_fields_sharing_one_missing_type_are_reported_together(registry):
    from dsdecode.typemodel import Member

    decoder, warnings = awkward(
        registry,
        [
            Member("First", 16, "NotInTheFile_t"),
            Member("Second", 20, "NotInTheFile_t"),
            Member("Third", 24, "NotInTheFile_t"),
        ],
    )
    assert decoder.columns == []
    assert len(warnings) == 1, "one cause should be one line, not one per field"
    for name in ("First", "Second", "Third"):
        assert name in warnings[0]


def test_a_flexible_array_says_why_it_has_no_columns(registry):
    from dsdecode.typemodel import ArrayType, Member

    decoder, warnings = awkward(
        registry,
        [Member("Count", 16, "uint32"), Member("Data", 20, "uint8[0]")],
        extra={"uint8[0]": ArrayType("uint8[0]", "uint8", [0], 0)},
    )
    assert decoder.columns == ["Count"]
    assert len(warnings) == 1
    assert "Data" in warnings[0]
    assert "flexible array" in warnings[0]


def test_a_member_the_debug_info_could_not_type_is_reported(registry):
    from dsdecode.typemodel import Member

    decoder, warnings = awkward(registry, [Member("Callback", 16, "void")])
    assert decoder.columns == []
    assert len(warnings) == 1
    assert "Callback" in warnings[0]
    assert "debug info" in warnings[0]


def test_an_array_whose_element_type_is_missing_is_reported(registry):
    from dsdecode.typemodel import ArrayType, Member

    decoder, warnings = awkward(
        registry,
        [Member("Items", 16, "Gone_t[4]")],
        extra={"Gone_t[4]": ArrayType("Gone_t[4]", "Gone_t", [4], 16)},
    )
    assert decoder.columns == []
    assert len(warnings) == 1
    assert "Items" in warnings[0]
    assert "Gone_t" in warnings[0]


def test_nesting_past_the_depth_limit_is_reported(registry):
    warnings = []
    decoder = compile_struct(
        registry, "sample::HkTlm_t", Options(max_depth=1), warn=warnings.append
    )
    assert decoder.columns == []
    assert len(warnings) == 1
    assert "nested deeper than 1 levels" in warnings[0]
    # A long list is cut short rather than filling the terminal.
    assert "and" in warnings[0] and "more" in warnings[0]


def test_every_type_in_the_build_compiles_without_a_warning(registry):
    """The guard that keeps these warnings from becoming noise."""
    from dsdecode.typemodel import KIND_STRUCT, KIND_UNION

    warnings = []
    names = [
        name
        for name, node in registry.types.items()
        if node.kind in (KIND_STRUCT, KIND_UNION)
    ]
    assert len(names) > 30, "the fixture should offer plenty to compile"
    for name in names:
        compile_struct(registry, name, warn=warnings.append)
    assert warnings == []
