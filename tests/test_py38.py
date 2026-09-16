"""Guard the Python 3.8 floor.

Development happens on a newer interpreter, so nothing here would otherwise
notice a 3.9-only call until it reached a machine that has 3.8.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

import dsdecode

PACKAGE = os.path.dirname(os.path.abspath(dsdecode.__file__))


def test_the_package_runs_on_python_38():
    vermin = shutil.which("vermin")
    if not vermin:
        pytest.skip("vermin is not installed (pip install -e .[dev])")
    result = subprocess.run(
        [vermin, "-t=3.8-", "--no-tips", "--violations", PACKAGE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = result.stdout.decode("utf-8", "replace")
    assert result.returncode == 0, "code needs a newer Python than 3.8:\n%s" % output
