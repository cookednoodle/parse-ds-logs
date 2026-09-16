"""Write decoded packets out, one file per message ID."""

from __future__ import annotations

import csv
import io
import json
import os
from typing import Any, Dict, List, Optional, Sequence


class Sink(object):
    """Base for the output formats: one file per message ID, opened on demand."""

    extension = "out"

    def __init__(self, out_dir: str) -> None:
        self.out_dir = out_dir
        self._files = {}  # type: Dict[str, Any]
        self._columns = {}  # type: Dict[str, List[str]]
        self._names = []  # type: List[str]
        self.rows_written = 0

    def path_for(self, name: str) -> str:
        return os.path.join(self.out_dir, "%s.%s" % (name, self.extension))

    def _open(self, name: str, columns: Sequence[str]) -> Any:
        handle = self._files.get(name)
        if handle is None:
            if not os.path.isdir(self.out_dir):
                os.makedirs(self.out_dir)
            handle = self._create(name, columns)
            self._files[name] = handle
            self._columns[name] = list(columns)
            self._names.append(name)
        return handle

    def _create(self, name: str, columns: Sequence[str]) -> Any:
        raise NotImplementedError

    def write(self, name: str, columns: Sequence[str], row: Sequence[Any]) -> None:
        raise NotImplementedError

    def written(self) -> List[str]:
        """Paths written so far; still correct after the sink is closed."""
        return sorted(self.path_for(name) for name in self._names)

    def close(self) -> None:
        for handle in self._files.values():
            self._close_one(handle)
        self._files = {}

    def _close_one(self, handle: Any) -> None:
        handle.close()

    def __enter__(self) -> "Sink":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class CsvSink(Sink):
    """One CSV per message ID, with a header row written once."""

    extension = "csv"

    def __init__(self, out_dir: str) -> None:
        Sink.__init__(self, out_dir)
        self._writers = {}  # type: Dict[str, Any]

    def _create(self, name: str, columns: Sequence[str]) -> Any:
        handle = io.open(self.path_for(name), "w", encoding="utf-8", newline="")
        writer = csv.writer(handle)
        writer.writerow(columns)
        self._writers[name] = writer
        return handle

    def write(self, name: str, columns: Sequence[str], row: Sequence[Any]) -> None:
        self._open(name, columns)
        cells = ["" if value is None else value for value in row]
        self._writers[name].writerow(cells)
        self.rows_written += 1

    def close(self) -> None:
        Sink.close(self)
        self._writers = {}


class JsonlSink(Sink):
    """One JSON Lines file per message ID."""

    extension = "jsonl"

    def _create(self, name: str, columns: Sequence[str]) -> Any:
        return io.open(self.path_for(name), "w", encoding="utf-8")

    def write(self, name: str, columns: Sequence[str], row: Sequence[Any]) -> None:
        handle = self._open(name, columns)
        record = dict(zip(columns, row))
        handle.write(json.dumps(record, default=str, sort_keys=False))
        handle.write("\n")
        self.rows_written += 1


def make_sink(out_dir: str, fmt: str) -> Sink:
    if fmt == "csv":
        return CsvSink(out_dir)
    if fmt == "jsonl":
        return JsonlSink(out_dir)
    raise ValueError("unknown output format %r" % fmt)
