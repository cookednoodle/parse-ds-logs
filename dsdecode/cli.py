"""Command line entry point: extract types, inspect a file, decode to CSV."""

from __future__ import annotations

import argparse
import datetime
import io
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .decode import UNION_BYTES_DROP, UNION_BYTES_KEEP, Options
from .dictionary import (
    Dictionary,
    DictionaryError,
    UnknownStructError,
    read_mapping,
    safe_name,
)
from .dsfile import HEADER_AUTO, HEADER_CFE, HEADER_NONE, DsFile, DsFileError, Geometry, summarize
from .dwarf import DwarfError, NameFilter, describe_missing, extract
from .typemodel import GEOMETRY_TYPES, TypeRegistry
from .writers import make_sink

FIXED_COLUMNS = [
    "file",
    "pkt_index",
    "msgid",
    "apid",
    "seq",
    "length",
    "time_sec",
    "time_subsec",
    "time",
]


def _warn(message: str) -> None:
    print("warning: %s" % message, file=sys.stderr)


def _declared_headers(args: argparse.Namespace) -> List[str]:
    """Header type names from --header-type, repeated or comma separated."""
    names = []  # type: List[str]
    for argument in getattr(args, "header_type", None) or []:
        for name in argument.split(","):
            name = name.strip()
            if name and name not in names:
                names.append(name)
    return names


def _load_registry(path: str) -> TypeRegistry:
    with io.open(path, "r", encoding="utf-8") as handle:
        return TypeRegistry.load(handle)


def _parse_epoch(text: Optional[str]) -> Optional[datetime.datetime]:
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1]
    try:
        stamp = datetime.datetime.fromisoformat(cleaned)
    except ValueError:
        raise SystemExit(
            "could not read --epoch %r: write it as 1980-01-01 or 1980-01-01T00:00:00" % text
        )
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=datetime.timezone.utc)
    return stamp


# -- extract -------------------------------------------------------------


def cmd_extract(args: argparse.Namespace) -> int:
    names = None  # type: Optional[NameFilter]
    wanted = []  # type: List[str]
    if args.mids:
        try:
            mapping = read_mapping(args.mids)
        except DictionaryError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
        wanted = mapping.struct_names()
        # The header types are kept too: DS_FileHeader_t and CFE_FS_Header_t
        # describe the file itself, so no message struct depends on them.
        names = NameFilter(wanted, always=GEOMETRY_TYPES)
    try:
        registry = extract(
            args.elf,
            verbose=args.verbose,
            warn=_warn,
            names=names,
            strict=args.strict,
        )
    except DwarfError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    # Carried in the type file so a decode honours it without being told again.
    registry.header_types = _declared_headers(args)
    if args.mids and mapping.header_types:
        for name in mapping.header_types:
            if name not in registry.header_types:
                registry.header_types.append(name)
    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with io.open(args.output, "w", encoding="utf-8") as handle:
        registry.dump(handle)
    print(
        "wrote %s: %d types from %d file(s)"
        % (args.output, len(registry.types), len(registry.sources))
    )
    if names is not None:
        print(
            "  filtered to the %d struct(s) named in %s, and what they depend on"
            % (len(wanted), args.mids)
        )
        apps = mapping.struct_apps()
        found = [name for name in wanted if name not in registry.unresolved]
        print("  structs from the mapping:")
        for name in found:
            owners = apps.get(name)
            print(
                "    %-34s %s%s"
                % (name, names.describe(name), ("  [%s]" % ", ".join(owners)) if owners else "")
            )
        _report_absent_structs(registry, names, args.verbose)
        _report_mapping_gaps(mapping)
    if registry.geometry:
        print("  header sizes:")
        for name in sorted(registry.geometry):
            print("    %-34s %d bytes" % (name, registry.geometry[name]))
    absent = [name for name in GEOMETRY_TYPES if name not in registry.geometry]
    if absent:
        print(
            "  note: %s not found; defaults are used for those. Add core-cpu1 and "
            "the DS app to pick them up." % ", ".join(absent)
        )
    if registry.conflicts:
        print(
            "  %d type name(s) have more than one layout in this build; see "
            "'conflicts' in the file." % len(registry.conflicts)
        )
    if args.verbose:
        print("  types kept:")
        for name in sorted(registry.types):
            print("    %s" % name)
    return 0


def _report_absent_structs(registry: Any, names: Any, verbose: bool) -> None:
    """Account for structs the mapping named that this build does not have.

    A mapping normally covers a whole code base, so this list can be long.  It
    stays behind a count unless asked for, or the audit list above is buried.
    """
    absent = registry.unresolved
    if not absent:
        return
    print(
        "  %d struct(s) named in the mapping are not in this build%s"
        % (len(absent), ", left out:" if verbose else " (run with -v to list them)")
    )
    if verbose:
        for line in describe_missing(names, absent):
            print("    %s" % line)


def _report_mapping_gaps(mapping: Any) -> None:
    """Say what a generated map could not resolve, so it can be chased down."""
    if mapping.skipped:
        print(
            "  %d entr(y/ies) in %s could not be used:"
            % (len(mapping.skipped), mapping.path)
        )
        for name, reason in mapping.skipped:
            print("    %-34s %s" % (name, reason))
    if mapping.skipped_apps:
        print(
            "  the map records %d app(s) its scanner did not read: %s"
            % (len(mapping.skipped_apps), ", ".join(mapping.skipped_apps))
        )


# -- info ----------------------------------------------------------------


def cmd_info(args: argparse.Namespace) -> int:
    registry = _load_registry(args.types) if args.types else None
    geometry = Geometry.from_registry(registry, _ccsds_v2(args))
    reports = []  # type: List[Dict[str, Any]]
    failures = 0
    for path in args.files:
        try:
            reports.append(summarize(path, geometry, args.header))
        except DsFileError as exc:
            print("error: %s" % exc, file=sys.stderr)
            failures += 1
    if args.json:
        print(json.dumps(reports, indent=2, default=str))
        return 1 if failures and not reports else 0
    for report in reports:
        _print_info(report, geometry)
    return 1 if failures and not reports else 0


def _print_info(report: Dict[str, Any], geometry: Geometry) -> None:
    print("%s" % report["path"])
    print("  layout: %s" % geometry.describe())
    fs_header = report["fs_header"]
    if fs_header:
        print("  cFE file header:")
        for key, value in fs_header.items():
            print("    %-24s %s" % (key, value))
    else:
        print("  cFE file header: none (packets start at byte 0)")
    ds_header = report["ds_header"]
    if ds_header:
        print("  DS header:")
        for key, value in ds_header.items():
            print("    %-24s %s" % (key, value))
        if not ds_header["close_time_seconds"]:
            print("    note: close time is zero, so this file was never closed cleanly")
    print("  packets: %d%s" % (report["packets"], " (file ends truncated)" if report["truncated"] else ""))
    if report["by_msgid"]:
        print("    %-10s %8s  %s" % ("msgid", "packets", "length"))
        for msgid in sorted(report["by_msgid"]):
            count, low, high = report["by_msgid"][msgid]
            length = str(low) if low == high else "%d-%d" % (low, high)
            print("    0x%04X     %8d  %s" % (msgid, count, length))


# -- decode --------------------------------------------------------------


def cmd_decode(args: argparse.Namespace) -> int:
    try:
        registry = _load_registry(args.types)
    except (OSError, ValueError) as exc:
        print("error: cannot read %s: %s" % (args.types, exc), file=sys.stderr)
        return 1
    geometry = Geometry.from_registry(registry, _ccsds_v2(args))
    options = Options(
        char_arrays=args.char_arrays,
        enum_values=args.enum_values,
        header_types=_declared_headers(args),
        union_bytes=args.union_bytes,
    )
    try:
        dictionary = Dictionary.load(args.mids, registry, geometry, options, warn=_warn)
    except DictionaryError as exc:
        message = str(exc)
        if isinstance(exc, UnknownStructError) and registry.filtered:
            message += (
                ". %s was extracted for a mapping of %d struct(s), so a message ID "
                "added since then is not in it; re-run 'dsdecode extract --mids %s'"
                % (args.types, len(registry.roots), args.mids)
            )
        print("error: %s" % message, file=sys.stderr)
        return 1

    wanted = None  # type: Optional[set]
    if args.only:
        wanted = set(item.strip().lower() for item in args.only.split(",") if item.strip())
    epoch = _parse_epoch(args.epoch)

    decoded = 0
    unknown_counts = {}  # type: Dict[int, int]
    per_name = {}  # type: Dict[str, List[int]]
    truncated = 0
    failures = 0

    sink = make_sink(args.out, args.format)
    try:
        for path in args.files:
            try:
                handle = DsFile(path, geometry, args.header, warn=_warn).open()
            except DsFileError as exc:
                print("error: %s" % exc, file=sys.stderr)
                failures += 1
                continue
            label = os.path.basename(path)
            with handle as ds:
                for packet in ds.packets():
                    entry = dictionary.lookup(packet.msgid)
                    if entry is None:
                        unknown_counts[packet.msgid] = unknown_counts.get(packet.msgid, 0) + 1
                        if args.unknown == "raw" and _wanted(wanted, None, packet.msgid):
                            name = "MID_0x%04X" % packet.msgid
                            columns, values = _fixed(packet, label, epoch, None)
                            sink.write(
                                safe_name(name),
                                columns + ["raw"],
                                values + [packet.data.hex()],
                            )
                        continue
                    if not _wanted(wanted, entry.name, packet.msgid):
                        continue
                    decoder = entry.decoder_for(packet.fcn_code)
                    if decoder is None:
                        unknown_counts[packet.msgid] = unknown_counts.get(packet.msgid, 0) + 1
                        continue
                    base = 0 if decoder.has_header else packet.payload_offset
                    needed = base + decoder.size
                    if packet.length < needed:
                        truncated += 1
                        if args.verbose:
                            _warn(
                                "%s packet %d is %d bytes but %s needs %d"
                                % (label, packet.index, packet.length, decoder.type_name, needed)
                            )
                    row = decoder.decode(packet.data, base, packet.length)
                    columns, values = _fixed(
                        packet, label, epoch, packet.fcn_code if packet.is_cmd else None
                    )
                    name = entry.output_name(packet.fcn_code)
                    sink.write(name, columns + decoder.columns, values + row)
                    decoded += 1
                    counter = per_name.get(name)
                    if counter is None:
                        per_name[name] = [1]
                    else:
                        counter[0] += 1
    finally:
        sink.close()

    _report(sink.written(), per_name, unknown_counts, dictionary, decoded, truncated)
    if failures and not decoded:
        return 1
    if not decoded:
        print(
            "error: no packets decoded. Check that the message IDs in %s match the "
            "ones 'dsdecode info' reports for these files." % args.mids,
            file=sys.stderr,
        )
        return 1
    return 0


def _wanted(wanted: Optional[set], name: Optional[str], msgid: int) -> bool:
    if wanted is None:
        return True
    if name is not None and name.lower() in wanted:
        return True
    return ("0x%04x" % msgid) in wanted


def _fixed(
    packet: Any, label: str, epoch: Optional[datetime.datetime], fcn_code: Optional[int]
) -> Tuple[List[str], List[Any]]:
    columns = list(FIXED_COLUMNS)
    time_sec = packet.time_sec
    time_subsec = packet.time_subsec
    combined = packet.time
    values = [
        label,
        packet.index,
        "0x%04X" % packet.msgid,
        "0x%03X" % packet.apid,
        packet.seq_count,
        packet.length,
        time_sec,
        None if time_subsec is None else round(time_subsec, 9),
        None if combined is None else "%.6f" % combined,
    ]  # type: List[Any]
    if epoch is not None:
        columns.append("time_utc")
        if combined is None:
            values.append(None)
        else:
            stamp = epoch + datetime.timedelta(seconds=combined)
            values.append(stamp.isoformat())
    if fcn_code is not None:
        columns.append("fcn_code")
        values.append(fcn_code)
    return columns, values


def _report(
    written: Sequence[str],
    per_name: Dict[str, List[int]],
    unknown: Dict[int, int],
    dictionary: Dictionary,
    decoded: int,
    truncated: int,
) -> None:
    out = sys.stderr
    print("decoded %d packet(s) into %d file(s)" % (decoded, len(written)), file=out)
    for name in sorted(per_name):
        print("  %-36s %8d" % (name, per_name[name][0]), file=out)
    if truncated:
        print("  %d packet(s) were shorter than their struct" % truncated, file=out)
    if unknown:
        total = sum(unknown.values())
        print(
            "  %d packet(s) with %d unmapped message ID(s): %s"
            % (
                total,
                len(unknown),
                ", ".join("0x%04X (%d)" % (mid, count) for mid, count in sorted(unknown.items())),
            ),
            file=out,
        )


def _ccsds_v2(args: argparse.Namespace) -> Optional[bool]:
    if getattr(args, "ccsds_v2", False):
        return True
    if getattr(args, "ccsds_v1", False):
        return False
    return None


# -- argument parsing ----------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dsdecode",
        description=(
            "Decode cFS Data Storage (DS) log files using the message definitions "
            "in a compiled build's debug info."
        ),
    )
    parser.add_argument("--version", action="version", version="dsdecode %s" % __version__)
    subparsers = parser.add_subparsers(dest="command")

    extract_parser = subparsers.add_parser(
        "extract", help="read struct layouts from compiled binaries into a type file"
    )
    extract_parser.add_argument(
        "elf", nargs="+", help="core-cpu1 and the app .so files, built with -g"
    )
    extract_parser.add_argument(
        "-o", "--output", default="types.json", help="where to write the type file"
    )
    extract_parser.add_argument(
        "--mids",
        help=(
            "message ID mapping; keep only the structs it names and what they "
            "depend on, instead of every type in the build"
        ),
    )
    _add_header_type_arg(extract_parser)
    extract_parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "fail if any struct named in the mapping is not in these binaries, "
            "instead of leaving it out and carrying on"
        ),
    )
    extract_parser.add_argument(
        "-v", "--verbose", action="store_true", help="list every type kept"
    )
    extract_parser.set_defaults(func=cmd_extract)

    info_parser = subparsers.add_parser(
        "info", help="show a DS file's headers and the message IDs it holds"
    )
    info_parser.add_argument("files", nargs="+")
    info_parser.add_argument("--types", help="type file, for this build's header sizes")
    info_parser.add_argument("--json", action="store_true", help="report as JSON")
    _add_layout_args(info_parser)
    info_parser.set_defaults(func=cmd_info)

    decode_parser = subparsers.add_parser("decode", help="decode DS files to CSV")
    decode_parser.add_argument("files", nargs="+")
    decode_parser.add_argument("--types", required=True, help="type file from 'dsdecode extract'")
    decode_parser.add_argument("--mids", required=True, help="message ID mapping, YAML or JSON")
    decode_parser.add_argument("--out", default="out", help="directory for the output files")
    decode_parser.add_argument("--format", choices=("csv", "jsonl"), default="csv")
    decode_parser.add_argument(
        "--unknown",
        choices=("skip", "raw"),
        default="skip",
        help="what to do with unmapped message IDs (default: count and skip)",
    )
    decode_parser.add_argument("--only", help="comma separated names or message IDs to keep")
    decode_parser.add_argument(
        "--char-arrays",
        choices=("text", "bytes"),
        default="text",
        help="report a char array as one string (default) or one column per byte",
    )
    decode_parser.add_argument(
        "--enum-values", action="store_true", help="report enums as numbers, not names"
    )
    decode_parser.add_argument(
        "--union-bytes",
        choices=(UNION_BYTES_KEEP, UNION_BYTES_DROP),
        default=UNION_BYTES_KEEP,
        help=(
            "whether a union member that is only a byte array view of the same "
            "storage gets columns (default: keep); 'unions' in the mapping "
            "overrides this per type"
        ),
    )
    _add_header_type_arg(decode_parser)
    decode_parser.add_argument(
        "--epoch",
        help="mission epoch, such as 1980-01-01, to add a UTC timestamp column",
    )
    decode_parser.add_argument("-v", "--verbose", action="store_true")
    _add_layout_args(decode_parser)
    decode_parser.set_defaults(func=cmd_decode)
    return parser


def _add_header_type_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--header-type",
        action="append",
        metavar="NAME",
        help=(
            "a packet header type this project defines, beyond the cFE ones; "
            "repeat or separate with commas. A typedef of a declared type "
            "counts too, so name the underlying struct"
        ),
    )


def _add_layout_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--header",
        choices=(HEADER_AUTO, HEADER_CFE, HEADER_NONE),
        default=HEADER_AUTO,
        help="whether the files carry cFE and DS headers (default: detect)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--ccsds-v2", action="store_true", help="force CCSDS version 2 message IDs"
    )
    group.add_argument(
        "--ccsds-v1", action="store_true", help="force CCSDS version 1 message IDs"
    )


# What a process killed by SIGPIPE reports.  A reader closing the pipe early
# amounts to the same thing, so say so the same way.
EXIT_BROKEN_PIPE = 141


def _discard_remaining_output() -> None:
    """Send anything still to be written to os.devnull.

    Python flushes the standard streams on the way out.  With the pipe already
    closed that raises a second time, printing "Exception ignored" over
    whatever the reader did want, so point the stream somewhere harmless first.
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        if not getattr(args, "command", None):
            parser.print_help()
            return 2
        status = args.func(args)
        # Buffered output can fail here rather than at any one print.
        sys.stdout.flush()
        return status
    except BrokenPipeError:
        # A reader stopped early, as in 'dsdecode info file.ds | head'.  That
        # is the reader's business, not a failure worth a traceback.
        _discard_remaining_output()
        return EXIT_BROKEN_PIPE


if __name__ == "__main__":
    sys.exit(main())
