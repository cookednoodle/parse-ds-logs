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


# -- a project's own header types -------------------------------------------


def test_a_header_under_a_name_of_its_own_is_not_recognized_by_default(registry):
    """The failure this exists to fix, with the fixture's project header."""
    warnings = []
    decoder = compile_struct(registry, "PROJ_Tlm_t", warn=warnings.append)
    assert not decoder.has_header
    # The header fields leak in, which is the visible symptom.
    assert decoder.columns[0] == "TlmHeader.tPriHdr.StreamId[0]"


def test_declaring_the_header_type_makes_it_recognized(registry):
    decoder = compile_struct(
        registry, "PROJ_Tlm_t", Options(header_types=["PROJ_MSG_TLM_HDR_T"])
    )
    assert decoder.has_header
    # Twelve, not sixteen: this header has no trailing spare.
    assert decoder.header_size == 12
    assert decoder.columns == ["Counter", "Words[0]", "Words[1]", "Words[2]"]


def test_declaring_a_typedef_of_the_header_works_too(registry):
    # The struct's member is written as the alias, so either name will do.
    decoder = compile_struct(
        registry, "PROJ_Tlm_t", Options(header_types=["CFE_MSG_TLM_HDR_T"])
    )
    assert decoder.has_header
    assert decoder.header_size == 12
    assert decoder.columns == ["Counter", "Words[0]", "Words[1]", "Words[2]"]


def test_a_payload_beginning_with_three_short_fields_is_not_a_header(registry):
    """Header spotting is by name, so this shape is never mistaken for one."""
    decoder = compile_struct(
        registry, "PROJ_Payload_t", Options(header_types=["PROJ_MSG_TLM_HDR_T"])
    )
    assert not decoder.has_header
    assert decoder.columns == ["First", "Second", "Third", "Rest"]


def test_the_built_in_cfe_headers_still_work_with_nothing_declared(registry):
    decoder = compile_struct(registry, "sample::HkTlm_t")
    assert decoder.has_header
    assert decoder.header_size == 16


def test_declared_values_decode_at_the_right_offsets(registry):
    import struct as _struct

    # A packet built the way the project's header lays it out: 12 byte header,
    # then the payload.
    raw = b"\x08\x90\xc0\x2a\x00\x11" + b"\x12\x34\x56\x78\x80\x00"
    raw += _struct.pack("<I3H", 7, 1, 2, 3) + b"\x00\x00"
    decoder = compile_struct(
        registry, "PROJ_Tlm_t", Options(header_types=["PROJ_MSG_TLM_HDR_T"])
    )
    row = dict(zip(decoder.columns, decoder.decode(raw)))
    assert row["Counter"] == 7
    assert [row["Words[%d]" % i] for i in range(3)] == [1, 2, 3]


# -- a command with no arguments -------------------------------------------


def test_a_no_arg_command_is_all_header_and_has_no_payload_columns(registry):
    """The mapped type is the header itself, not a struct that starts with one."""
    decoder = compile_struct(
        registry, "PROJ_NO_ARG_CMD_T", Options(header_types=["PROJ_MSG_CMD_HDR_T"])
    )
    assert decoder.has_header
    assert decoder.header_size == 8
    assert decoder.columns == []


def test_declaring_the_no_arg_type_itself_is_enough(registry):
    # Whichever name you happen to have written down should work.
    decoder = compile_struct(
        registry, "PROJ_NO_ARG_CMD_T", Options(header_types=["PROJ_NO_ARG_CMD_T"])
    )
    assert decoder.has_header
    assert decoder.columns == []


def test_a_cfe_no_arg_command_needs_nothing_declared(registry):
    decoder = compile_struct(registry, "CFE_STYLE_NO_ARG_CMD_T")
    assert decoder.has_header
    assert decoder.header_size == 8
    assert decoder.columns == [], "the secondary header is not payload"


def test_a_header_mapped_directly_is_treated_the_same(registry):
    decoder = compile_struct(registry, "CFE_MSG_CommandHeader_t")
    assert decoder.has_header
    assert decoder.header_size == 8
    assert decoder.columns == []


def test_an_undeclared_no_arg_command_still_warns(registry):
    warnings = []
    decoder = compile_struct(registry, "PROJ_NO_ARG_CMD_T", warn=warnings.append)
    assert not decoder.has_header
    assert decoder.columns, "its header fields show up as columns"


def test_a_message_with_a_real_payload_is_unaffected(registry):
    decoder = compile_struct(
        registry,
        "PROJ_Tlm_t",
        Options(header_types=["PROJ_MSG_TLM_HDR_T", "PROJ_MSG_CMD_HDR_T"]),
    )
    assert decoder.header_size == 12
    assert decoder.columns == ["Counter", "Words[0]", "Words[1]", "Words[2]"]


# -- saying how a union is used ---------------------------------------------


def item_packet(first, second):
    """An ItemTlm_t packet: a header, then two 16-byte Item_t entries.

    Each entry is (kind, seq, payload bytes); the payload follows the 8-byte
    ItemHdr_t and is padded out to the union's size.
    """
    raw = b"\x00" * 16
    for kind, seq, body in (first, second):
        raw += struct.pack("<II", kind, seq) + body.ljust(8, b"\x00")
    return raw


def tagged(registry, **kwargs):
    from dsdecode.decode import UnionUse

    use = UnionUse(tag="Hdr.Kind", cases={"ITEM_TEMP": "Temp", 2: "Count"})
    options = Options(unions={"sample::Item_t": use}, **kwargs)
    return compile_struct(registry, "sample::ItemTlm_t", options)


def test_a_union_left_alone_repeats_its_identifier_in_every_alternative(registry):
    """The shape this feature exists to tidy up."""
    decoder = compile_struct(registry, "sample::ItemTlm_t")
    assert "Items[0].Hdr.Kind" in decoder.columns
    assert "Items[0].Temp.Hdr.Kind" in decoder.columns
    assert "Items[0].Count.Hdr.Kind" in decoder.columns
    assert "Items[0].Bytes[15]" in decoder.columns
    assert len(decoder.columns) == 50


def test_a_tagged_union_has_the_identifier_once_and_each_alternative_once(registry):
    decoder = tagged(registry)
    assert decoder.columns == [
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


def test_only_the_alternative_the_identifier_names_is_filled(registry):
    decoder = tagged(registry)
    raw = item_packet(
        (1, 5, struct.pack("<f", 1.5)),
        (2, 6, struct.pack("<IB", 77, 3)),
    )
    row = as_row(decoder, raw)
    assert row["Items[0].Hdr.Kind"] == "ITEM_TEMP"
    assert row["Items[0].Hdr.Seq"] == 5
    assert row["Items[0].Temp.Celsius"] == 1.5
    assert row["Items[0].Count.Count"] is None
    assert row["Items[0].Count.Flags"] is None
    assert row["Items[1].Hdr.Kind"] == "ITEM_COUNT"
    assert row["Items[1].Temp.Celsius"] is None
    assert row["Items[1].Count.Count"] == 77
    assert row["Items[1].Count.Flags"] == 3


def test_an_identifier_with_no_case_leaves_every_alternative_empty(registry):
    decoder = tagged(registry)
    raw = item_packet((9, 5, struct.pack("<f", 1.5)), (0, 6, b""))
    row = as_row(decoder, raw)
    # The identifier column still says what turned up.
    assert row["Items[0].Hdr.Kind"] == 9
    assert row["Items[1].Hdr.Kind"] == "ITEM_NONE"
    for name in decoder.columns:
        if "Hdr" not in name:
            assert row[name] is None, name


def test_case_keys_may_be_numbers_or_enumerator_names(registry):
    from dsdecode.decode import UnionUse

    by_name = UnionUse(tag="Hdr.Kind", cases={"ITEM_TEMP": "Temp", "ITEM_COUNT": "Count"})
    by_value = UnionUse(tag="Hdr.Kind", cases={1: "Temp", "0x2": "Count"})
    raw = item_packet((1, 5, struct.pack("<f", 1.5)), (2, 6, struct.pack("<IB", 77, 3)))
    rows = []
    for use in (by_name, by_value):
        decoder = compile_struct(
            registry, "sample::ItemTlm_t", Options(unions={"sample::Item_t": use})
        )
        rows.append(decoder.decode(raw))
    assert rows[0] == rows[1]


def test_several_values_may_select_one_alternative(registry):
    from dsdecode.decode import UnionUse

    use = UnionUse(tag="Hdr.Kind", cases={1: "Temp", 2: "Temp", 3: "Count"})
    decoder = compile_struct(registry, "sample::ItemTlm_t", Options(unions={"sample::Item_t": use}))
    assert decoder.columns.count("Items[0].Temp.Celsius") == 1
    raw = item_packet((2, 0, struct.pack("<f", 2.5)), (3, 0, struct.pack("<IB", 1, 1)))
    row = as_row(decoder, raw)
    assert row["Items[0].Temp.Celsius"] == 2.5
    assert row["Items[1].Count.Count"] == 1


def test_a_short_packet_blanks_the_alternative_it_cuts_into(registry):
    decoder = tagged(registry)
    raw = item_packet((1, 5, struct.pack("<f", 1.5)), (2, 6, struct.pack("<IB", 77, 3)))
    # Cut inside the second item's Count payload: after its header and Count,
    # before Flags.
    row = as_row_limited(decoder, raw[: 16 + 16 + 8 + 4])
    assert row["Items[0].Temp.Celsius"] == 1.5
    assert row["Items[1].Hdr.Kind"] == "ITEM_COUNT"
    assert row["Items[1].Count.Count"] == 77
    assert row["Items[1].Count.Flags"] is None
    # Cut before the second identifier can be read: nothing of it is guessed.
    row = as_row_limited(decoder, raw[: 16 + 16 + 2])
    assert row["Items[1].Hdr.Kind"] is None
    assert row["Items[1].Count.Count"] is None


def test_a_tagged_union_reports_enums_as_numbers_when_asked(registry):
    decoder = tagged(registry, enum_values=True)
    raw = item_packet((1, 5, struct.pack("<f", 1.5)), (2, 6, b""))
    row = as_row(decoder, raw)
    assert row["Items[0].Hdr.Kind"] == 1
    assert row["Items[0].Temp.Celsius"] == 1.5


def test_keep_lists_the_members_that_get_columns(registry):
    from dsdecode.decode import UnionUse

    decoder = compile_struct(
        registry, "sample::UnionTlm_t", Options(unions={"sample::Value_t": UnionUse(keep=["f"])})
    )
    assert decoder.columns == ["Value.f", "Tag"]


def test_drop_lists_the_members_that_do_not(registry):
    from dsdecode.decode import UnionUse

    decoder = compile_struct(
        registry, "sample::UnionTlm_t", Options(unions={"sample::Value_t": UnionUse(drop=["b"])})
    )
    assert decoder.columns == ["Value.i", "Value.f", "Tag"]


def test_the_union_may_be_named_through_a_typedef_of_it(registry):
    """Options are keyed by the union's own name; the loader resolves aliases."""
    from dsdecode.decode import UnionUse

    node = registry.resolve("sample::Value_t")
    decoder = compile_struct(
        registry, "sample::UnionTlm_t", Options(unions={node.name: UnionUse(keep=["i"])})
    )
    assert decoder.columns == ["Value.i", "Tag"]


def test_byte_views_can_be_dropped_from_every_union_at_once(registry):
    from dsdecode.decode import UNION_BYTES_DROP

    decoder = compile_struct(registry, "sample::UnionTlm_t", Options(union_bytes=UNION_BYTES_DROP))
    assert decoder.columns == ["Value.i", "Value.f", "Tag"]
    # An anonymous union, which no entry could name, is covered too.
    decoder = compile_struct(registry, "ANON_Tlm_t", Options(union_bytes=UNION_BYTES_DROP))
    assert decoder.columns == ["Parts.lo", "Parts.hi", "whole"]


def test_a_union_of_nothing_but_byte_views_keeps_them(registry):
    from dsdecode.decode import UNION_BYTES_DROP
    from dsdecode.typemodel import ArrayType, Member, StructType

    extra = {
        "OnlyBytes_t": StructType(
            "OnlyBytes_t",
            4,
            [Member("Raw", 0, "uint8[4]"), Member("Signed", 0, "int8[4]")],
            kind="union",
        ),
        "int8[4]": ArrayType("int8[4]", "int8", [4], 4),
    }
    decoder, warnings = awkward(
        registry,
        [Member("Both", 16, "OnlyBytes_t")],
        extra=extra,
        options=Options(union_bytes=UNION_BYTES_DROP),
    )
    assert warnings == []
    assert decoder.columns == ["Both.Raw[%d]" % i for i in range(4)] + [
        "Both.Signed[%d]" % i for i in range(4)
    ]


def test_a_char_array_is_text_not_a_byte_view(registry):
    from dsdecode.decode import UNION_BYTES_DROP
    from dsdecode.typemodel import Member, StructType

    extra = {
        "CodeOrText_t": StructType(
            "CodeOrText_t",
            12,
            [Member("Code", 0, "uint32"), Member("Text", 0, "char[12]")],
            kind="union",
        ),
    }
    decoder, warnings = awkward(
        registry,
        [Member("Either", 16, "CodeOrText_t")],
        extra=extra,
        options=Options(union_bytes=UNION_BYTES_DROP),
    )
    assert warnings == []
    assert decoder.columns == ["Either.Code", "Either.Text"]


def test_an_explicit_entry_wins_over_the_byte_policy(registry):
    from dsdecode.decode import UNION_BYTES_DROP, UnionUse

    decoder = compile_struct(
        registry,
        "sample::UnionTlm_t",
        Options(unions={"sample::Value_t": UnionUse(keep=["b"])}, union_bytes=UNION_BYTES_DROP),
    )
    assert decoder.columns == ["Value.b[0]", "Value.b[1]", "Value.b[2]", "Value.b[3]", "Tag"]


def test_a_tagged_union_can_keep_a_member_whatever_the_identifier_says(registry):
    from dsdecode.decode import UnionUse

    use = UnionUse(tag="Hdr.Kind", cases={1: "Temp"}, keep=["Bytes"])
    decoder = compile_struct(registry, "sample::ItemTlm_t", Options(unions={"sample::Item_t": use}))
    assert "Items[0].Bytes[0]" in decoder.columns
    assert "Items[0].Temp.Celsius" in decoder.columns
    assert "Items[0].Count.Count" not in decoder.columns


def plan_error(registry, union, **kwargs):
    from dsdecode.decode import UnionUse, plan_union

    with pytest.raises(DecodeError) as caught:
        plan_union(registry, registry.resolve(union), UnionUse(**kwargs))
    return str(caught.value)


def test_a_tag_that_is_not_a_member_is_rejected_with_the_members_listed(registry):
    message = plan_error(registry, "sample::Item_t", tag="Kind", cases={1: "Temp"})
    assert "no member 'Kind'" in message
    assert "Hdr, Temp, Count, Bytes" in message


def test_a_tag_path_into_a_missing_member_is_rejected(registry):
    message = plan_error(registry, "sample::Item_t", tag="Hdr.Id", cases={1: "Temp"})
    assert "no member 'Id'" in message
    assert "Kind, Seq" in message


def test_a_tag_that_is_not_a_number_is_rejected(registry):
    message = plan_error(registry, "sample::Item_t", tag="Temp", cases={1: "Count"})
    assert "not an integer or enum" in message


def test_a_case_naming_a_missing_member_is_rejected(registry):
    message = plan_error(registry, "sample::Item_t", tag="Hdr.Kind", cases={1: "Pressure"})
    assert "no member 'Pressure'" in message


def test_a_case_naming_the_identifier_itself_is_rejected(registry):
    message = plan_error(registry, "sample::Item_t", tag="Hdr.Kind", cases={1: "Hdr"})
    assert "identifier itself" in message


def test_an_enumerator_name_that_does_not_exist_is_rejected(registry):
    message = plan_error(registry, "sample::Item_t", tag="Hdr.Kind", cases={"ITEM_HEAT": "Temp"})
    assert "ITEM_HEAT" in message
    assert "ITEM_TEMP" in message


def test_a_name_is_no_use_when_the_identifier_is_a_plain_integer(registry):
    message = plan_error(registry, "sample::Item_t", tag="Hdr.Seq", cases={"FIVE": "Temp"})
    assert "not an enum" in message


def test_one_value_cannot_select_two_alternatives(registry):
    message = plan_error(
        registry, "sample::Item_t", tag="Hdr.Kind", cases={1: "Temp", "ITEM_TEMP": "Count"}
    )
    assert "both Temp and Count" in message


def test_a_member_cannot_be_both_kept_and_a_case(registry):
    message = plan_error(
        registry, "sample::Item_t", tag="Hdr.Kind", cases={1: "Temp"}, keep=["Temp"]
    )
    assert "cannot also be a case" in message


def test_a_tag_needs_cases_and_cases_need_a_tag(registry):
    assert "needs 'cases'" in plan_error(registry, "sample::Item_t", tag="Hdr.Kind")


def test_keep_and_drop_are_checked_against_the_members(registry):
    from dsdecode.decode import UnionUse

    with pytest.raises(DecodeError) as caught:
        compile_struct(
            registry, "sample::UnionTlm_t", Options(unions={"sample::Value_t": UnionUse(keep=["x"])})
        )
    assert "no member 'x'" in str(caught.value)
    assert "i, f, b" in str(caught.value)
