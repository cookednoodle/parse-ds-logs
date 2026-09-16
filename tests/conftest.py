"""Compile the C++ fixture with debug info so tests can read real gcc output."""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, HERE)

from dsdecode.dwarf import extract  # noqa: E402


@pytest.fixture(scope="session", params=["-gdwarf-4", "-gdwarf-5"])
def fixture_so(request, tmp_path_factory):
    """Path to the compiled fixture, once per DWARF version."""
    compiler = os.environ.get("CXX") or shutil.which("g++") or shutil.which("clang++")
    if not compiler:
        pytest.skip("no C++ compiler available")
    out_dir = tmp_path_factory.mktemp("fixture")
    out = str(out_dir / ("fixture%s.so" % request.param[-1]))
    command = [
        compiler,
        "-g",
        request.param,
        "-O0",
        "-shared",
        "-fPIC",
        "-std=c++11",
        "-Wno-invalid-offsetof",
        "-I",
        FIXTURES,
        os.path.join(FIXTURES, "fixture.cpp"),
        "-o",
        out,
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        pytest.skip(
            "%s cannot build the fixture with %s: %s"
            % (compiler, request.param, result.stdout.decode("utf-8", "replace")[:400])
        )
    return out


@pytest.fixture(scope="session")
def registry(fixture_so):
    """Types read out of the compiled fixture."""
    return extract([fixture_so])


@pytest.fixture(scope="session")
def fixture_lib(fixture_so):
    """The fixture loaded through ctypes, for layout and sample data."""
    lib = ctypes.CDLL(fixture_so)
    lib.dsdecode_layout.restype = ctypes.c_char_p
    lib.dsdecode_sample_hk_expected.restype = ctypes.c_char_p
    lib.dsdecode_sample_hk.restype = ctypes.POINTER(ctypes.c_ubyte)
    lib.dsdecode_sample_hk.argtypes = [ctypes.POINTER(ctypes.c_ulong)]
    return lib


@pytest.fixture(scope="session")
def compiler_layout(fixture_lib):
    """{'sizeof T': (0, size), 'offset T.M': (offset, size)} as gcc reports it."""
    table = {}
    for line in fixture_lib.dsdecode_layout().decode().splitlines():
        if not line.strip():
            continue
        what, name, offset, size = line.split(" ")
        table["%s %s" % (what, name)] = (int(offset), int(size))
    return table


@pytest.fixture(scope="session")
def sample_hk(fixture_lib):
    """(bytes of a filled housekeeping packet, {column: expected text})."""
    length = ctypes.c_ulong()
    pointer = fixture_lib.dsdecode_sample_hk(ctypes.byref(length))
    raw = bytes(bytearray(pointer[i] for i in range(length.value)))
    expected = {}
    for line in fixture_lib.dsdecode_sample_hk_expected().decode().splitlines():
        if not line.strip():
            continue
        name, _, value = line.partition("=")
        expected[name] = value
    return raw, expected
