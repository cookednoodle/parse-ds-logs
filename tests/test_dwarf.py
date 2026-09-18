"""Check extracted layouts against the layout gcc itself reports."""

from __future__ import annotations

import pytest

from dsdecode.typemodel import KIND_ARRAY, KIND_STRUCT, KIND_UNION


def member_at(registry, type_name, path):
    """Find a member by dotted path, stepping into anonymous members."""
    node = registry.resolve(type_name)
    assert node is not None, "%s is missing from the registry" % type_name
    offset = 0
    for part in path.split("."):
        found = None
        for member in _members_including_anonymous(registry, node):
            if member[0].name == part:
                found = member
                break
        assert found is not None, "%s has no member %s" % (type_name, part)
        member, extra = found
        offset += member.offset + extra
        node = registry.resolve(member.type)
        assert node is not None
    return offset, getattr(node, "size", None)


def _members_including_anonymous(registry, node, base=0):
    for member in getattr(node, "members", []):
        if member.name:
            yield member, base
        else:
            inner = registry.resolve(member.type)
            if inner is not None:
                for pair in _members_including_anonymous(registry, inner, base + member.offset):
                    yield pair


def test_sizes_match_the_compiler(registry, compiler_layout):
    checked = 0
    for key, (_, size) in compiler_layout.items():
        what, name = key.split(" ", 1)
        if what != "sizeof":
            continue
        assert registry.sizeof(name) == size, "%s should be %d bytes" % (name, size)
        checked += 1
    assert checked >= 15


def test_member_offsets_match_the_compiler(registry, compiler_layout):
    checked = 0
    for key, (offset, size) in compiler_layout.items():
        what, name = key.split(" ", 1)
        if what != "offset":
            continue
        type_name, path = name.split(".", 1)
        got_offset, got_size = member_at(registry, type_name, path)
        assert got_offset == offset, "%s is at %d, not %d" % (name, got_offset, offset)
        assert got_size == size, "%s is %s bytes, not %d" % (name, got_size, size)
        checked += 1
    assert checked >= 20


def test_geometry_is_read_from_the_build(registry):
    assert registry.geometry["CFE_MSG_Message_t"] == 6
    assert registry.geometry["CFE_MSG_TelemetryHeader_t"] == 16
    assert registry.geometry["CFE_MSG_CommandHeader_t"] == 8
    assert registry.geometry["CFE_MSG_TelemetrySecondaryHeader_t"] == 6
    assert registry.geometry["DS_FileHeader_t"] == 76
    assert registry.geometry["CFE_FS_Header_t"] == 64


def test_no_conflicting_type_sizes(registry):
    assert registry.conflicts == []


def test_bitfields_carry_their_bit_positions(registry):
    flags = registry.resolve("sample::Flags")
    positions = dict((m.name, (m.bit_offset, m.bit_size)) for m in flags.members)
    assert positions == {"a": (0, 1), "b": (1, 3), "c": (4, 9)}


def test_base_class_members_are_flattened_in_place(registry):
    payload = registry.resolve("sample::HkPayload")
    names = [m.name for m in payload.members]
    assert names[:3] == ["CommandCounter", "CommandErrorCounter", "Status"]
    by_name = dict((m.name, m.offset) for m in payload.members)
    assert by_name["CommandCounter"] == 0
    assert by_name["CommandErrorCounter"] == 4


def test_namespaces_qualify_type_names(registry):
    assert registry.resolve("sample::HkTlm_t") is not None
    assert registry.get("HkTlm_t") is None


def test_arrays_keep_their_shape(registry):
    payload = registry.resolve("sample::HkPayload")
    by_name = dict((m.name, m.type) for m in payload.members)
    matrix = registry.resolve(by_name["Matrix"])
    assert matrix.kind == KIND_ARRAY
    assert matrix.dims == [2, 3]
    assert matrix.size == 24
    name = registry.resolve(by_name["Name"])
    assert name.dims == [12]
    assert registry.resolve(name.elem).encoding == "char"
    raw = registry.resolve(by_name["Raw"])
    assert registry.resolve(raw.elem).encoding == "uint", "uint8 is a number, not text"


def test_enumerators_are_captured(registry):
    mode = registry.resolve("sample::Mode_t")
    assert mode.values == {0: "MODE_IDLE", 1: "MODE_RUN", 7: "MODE_SAFE"}


def test_unions_are_marked_as_unions(registry):
    value = registry.resolve("sample::Value_t")
    assert value.kind == KIND_UNION
    assert sorted(m.offset for m in value.members) == [0, 0, 0]


def test_typedef_of_anonymous_struct_takes_the_typedef_name(registry):
    ds_header = registry.resolve("DS_FileHeader_t")
    assert ds_header.kind == KIND_STRUCT
    assert [m.name for m in ds_header.members] == [
        "CloseSeconds",
        "CloseSubsecs",
        "FileTableIndex",
        "FileNameType",
        "FileName",
    ]


def test_missing_file_is_reported(tmp_path):
    from dsdecode.dwarf import DwarfError, extract

    with pytest.raises(DwarfError):
        extract([str(tmp_path / "not-here.so")])


def test_file_without_debug_info_is_reported(tmp_path):
    from dsdecode.dwarf import DwarfError, extract

    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"not an elf file at all")
    with pytest.raises(DwarfError):
        extract([str(plain)])


# -- filtering to a mapping ------------------------------------------------


def filtered(so, names, **kwargs):
    """Extract only the named structs, as 'dsdecode extract --mids' does."""
    from dsdecode.dwarf import NameFilter, extract
    from dsdecode.typemodel import GEOMETRY_TYPES

    return extract([so], names=NameFilter(names, always=GEOMETRY_TYPES), **kwargs)


def test_filtering_keeps_the_named_struct_and_what_it_depends_on(fixture_so):
    reg = filtered(fixture_so, ["sample::HkTlm_t"])
    assert reg.filtered
    assert "sample::HkTlm_t" in reg.types
    for dependency in (
        "sample::HkPayload",
        "sample::Vec3",
        "sample::Flags",
        "sample::Mode_t",
        "CFE_MSG_TelemetryHeader_t",
        "char[12]",
        "int32[2][3]",
        "uint64",
    ):
        assert dependency in reg.types, "%s should have been pulled in" % dependency


def test_filtering_drops_types_nothing_mapped_needs(fixture_so):
    reg = filtered(fixture_so, ["sample::HkTlm_t"])
    for unrelated in ("sample::UnionTlm_t", "ANON_Tlm_t", "GLOBAL_Tlm_t", "sample::Value_t"):
        assert unrelated not in reg.types, "%s should have been left out" % unrelated


def test_filtering_leaves_far_less_to_read(fixture_so):
    from dsdecode.dwarf import extract

    full = extract([fixture_so])
    small = filtered(fixture_so, ["sample::HkTlm_t"])
    assert len(small.types) * 3 < len(full.types)


def test_geometry_types_survive_filtering(fixture_so):
    # Nothing a message struct contains refers to these two, but the decoder
    # needs their sizes to read a DS file at all.
    reg = filtered(fixture_so, ["sample::HkTlm_t"])
    assert reg.geometry["DS_FileHeader_t"] == 76
    assert reg.geometry["CFE_FS_Header_t"] == 64
    assert "DS_FileHeader_t" in reg.types


def test_filtering_records_what_each_mapping_name_resolved_to(fixture_so):
    reg = filtered(fixture_so, ["HkTlm_t"])
    assert reg.roots == {"HkTlm_t": ["sample::HkTlm_t"]}
    assert "DS_FileHeader_t" not in reg.roots, "geometry types are not mapping names"


def test_filtering_resolves_a_name_ignoring_case(fixture_so):
    reg = filtered(fixture_so, ["hktlm_t"])
    assert reg.roots == {"hktlm_t": ["sample::HkTlm_t"]}


def test_a_struct_that_is_not_in_the_build_stops_extraction(fixture_so):
    from dsdecode.dwarf import DwarfError

    with pytest.raises(DwarfError) as caught:
        filtered(fixture_so, ["sample::HkTlm_t", "sample::HkTlmX_t"])
    message = str(caught.value)
    assert "sample::HkTlmX_t" in message
    assert "HkTlm_t" in message, "the error should suggest a close name"


def test_allow_missing_warns_and_carries_on(fixture_so):
    warnings = []
    reg = filtered(
        fixture_so, ["sample::HkTlm_t", "Nope_t"], allow_missing=True, warn=warnings.append
    )
    assert any("Nope_t" in w for w in warnings)
    assert reg.roots == {"sample::HkTlm_t": ["sample::HkTlm_t"]}


def test_unfiltered_extraction_is_unchanged(registry):
    assert not registry.filtered
    assert registry.roots == {}
