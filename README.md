# dsdecode

Decode the files the cFS [Data Storage (DS)](https://github.com/nasa/DS) app writes into CSV,
using the message definitions taken from your own compiled build.

Struct layouts come from the DWARF debug info in `core-cpu1` and your app `.so` files, so the
offsets, padding, array extents and bitfield positions are the ones gcc actually produced.
C++ apps are handled the same as C ones: namespaces, base classes, references to nested types
and anonymous members all resolve.

Built for cFE 7.x (Caelum, including the 6.7.99 development line) on little-endian x86.

## Install

```
pip install -e .
pip install -e .[dev]     # to run the tests
```

Python 3.8 or newer. Dependencies are pyelftools and PyYAML.

## 1. Build cFS with debug info

Debug info is the whole input, so the build has to carry it:

```
make prep BUILDTYPE=debug
make
```

or set `-DCMAKE_BUILD_TYPE=Debug`, or add `-g` to `CFE_C_FLAGS` in your
`*_build_custom.cmake`. Optimization level does not matter; `-g` does.

A compiler only emits debug info for types a translation unit actually uses. If a message
struct is declared in a header that no compiled code instantiates, add
`-fno-eliminate-unused-debug-types` so it is emitted anyway.

## 2. Look at a file first

```
dsdecode info /path/to/seq001.ds
```

This needs no type file, so it is the first thing to run. It prints the cFE file header, the
DS header, and a count of packets per message ID, which is the list you are about to write a
mapping for. A close time of zero means DS never closed the file cleanly, usually a reset
mid-recording.

## 3. Write the message ID mapping

Message IDs are preprocessor macros, and macros leave no trace in debug info, so this one
file is written by hand:

```yaml
mids:
  # name: used for the CSV file name
  MY_APP_HK_TLM_MID:  {value: 0x0890, struct: MyApp::HkTlm_t}
  MY_APP_DIAG_TLM_MID: {value: 0x0891, struct: MY_APP_DiagTlm_t}

  # a command message ID may pick its struct by function code
  MY_APP_CMD_MID:
    value: 0x1882
    struct:
      default: MyApp::NoopCmd_t
      fcn:
        1: MyApp::ResetCountersCmd_t
        2: MyApp::SetModeCmd_t

  # with no name of its own, the message ID can be the key
  0x0892: OTHER_APP_Tlm_t
```

Struct names are looked up as written, then with the C++ namespace left off, then
case-insensitively. An unknown name fails immediately and suggests close matches. JSON is
accepted in place of YAML.

Map the full message struct, the one that carries the CCSDS primary and secondary headers as
well as the payload. That is the normal case: the tool recognizes the header, leaves its fields
out of the payload columns because they are already in the fixed leading columns, and decodes
the struct from the first byte of the packet. The header is recognized whether it is written as
the header type directly or reached through an app typedef of it:

```c
typedef struct {
    CFE_MSG_TelemetryHeader_t TelemetryHeader;   /* recognized */
    MY_APP_HkTlm_Payload_t    Payload;
} MY_APP_HkTlm_t;
```

Mapping a struct that has no cFS message header of its own, a bare payload type, also works:
the tool notices and decodes it starting after the packet header. See **Limitations** for two
ways of embedding a header that are not recognized.

## 4. Extract the type definitions

```
dsdecode extract --mids mids.yaml -o types.json \
    build/exe/cpu1/core-cpu1 build/exe/cpu1/cf/*.so
```

Pass every binary whose messages you want to decode. Include the DS app itself, so the tool
picks up your `DS_TOTAL_FNAME_BUFSIZE`, and `core-cpu1` for the cFE header types.

With `--mids`, the type file holds only the structs your mapping names and the types those are
built from, which is usually a few dozen entries you can read through rather than the thousands
a cFS build defines. The command reports what each name in the mapping resolved to, which is
worth a look: struct lookup is deliberately forgiving about namespaces and case, so this is
where you confirm it found the type you meant.

```
wrote types.json: 61 types from 9 file(s)
  filtered to the 12 struct(s) named in mids.yaml, and what they depend on
  structs from the mapping:
    MY_APP_HkTlm_t                     MyApp::HkTlm_t (matched by name without its namespace)
    MY_APP_DiagTlm_t                   MY_APP_DiagTlm_t
  header sizes:
    CFE_FS_Header_t                    64 bytes
    CFE_MSG_CommandHeader_t            8 bytes
    CFE_MSG_Message_t                  6 bytes
    CFE_MSG_TelemetryHeader_t          16 bytes
    DS_FileHeader_t                    76 bytes
```

Those header sizes are how the decoder knows where each packet's payload begins, whether the
build uses CCSDS version 1 or 2 message IDs, and how long the DS header is. They are kept
whether or not a message struct refers to them. If one is missing, its default is used and the
command says so.

A struct the mapping names that is not in any of the binaries stops the run, with close names
suggested, so a typo surfaces here rather than at decode time. Use `--allow-missing` to carry on
without it, and `-v` to list every type kept.

**Re-run this after adding a message ID to the mapping.** The type file records that it was
filtered, so if you forget, decode says so and tells you to extract again.

Leaving `--mids` off extracts every type in the binaries. That is the way to go looking for a
type name when you are first writing a mapping, though `-v` on a filtered run and the suggestions
in the error message usually get you there.

## 5. Decode

```
dsdecode decode --types types.json --mids mids.yaml --out out/ /path/to/*.ds
```

You get `out/MY_APP_HK_TLM_MID.csv` and one more file per mapped message ID, appended across
every input file. Command IDs that decode per function code get one file each, named
`..._fcn1.csv`.

Every row starts with the same fixed columns:

| Column | Meaning |
| --- | --- |
| `file` | input file the packet came from |
| `pkt_index` | position of the packet within that file |
| `msgid` | message ID, as hex |
| `apid` | CCSDS application ID, as hex |
| `seq` | CCSDS sequence count |
| `length` | packet length in bytes |
| `time_sec` | seconds from the telemetry secondary header |
| `time_subsec` | subseconds as a fraction |
| `time` | the two added together |
| `time_utc` | only with `--epoch` |
| `fcn_code` | command packets only |

Then one column per field, named by the path taken to reach it: `Payload.Position.x`,
`Payload.Matrix[1][2]`, `Payload.Bits.c`. A `char` array is one string column cut at the first
NUL; a `uint8` array stays one numeric column per byte. Enums report the enumerator name.
Union members all appear, each decoded from the same bytes.

Useful flags:

- `--only NAME,0x0891` decode just these
- `--unknown raw` also write unmapped IDs as a hex `raw` column
- `--format jsonl` JSON Lines instead of CSV
- `--enum-values` numbers instead of enumerator names
- `--char-arrays bytes` one column per character
- `--epoch 1980-01-01` add a UTC timestamp column, using your mission epoch
- `--header none` files recorded with `DS_FILE_HEADER_TYPE` set to `DS_FILE_HEADER_NONE`
- `--ccsds-v2` force version 2 message IDs if the type file cannot tell

A packet shorter than its struct still produces a row, with the fields that ran off the end
left empty. Packet counts, unmapped IDs and short packets are all summarized on stderr when
the run finishes.

## What the file format is

With the default `DS_FILE_HEADER_TYPE` of `DS_FILE_HEADER_CFE`, a DS file is:

1. `CFE_FS_Header_t`, 64 bytes, big-endian, starting with `0x63464531` (`cFE1`).
2. `DS_FileHeader_t`, written raw in the target's own byte order, so little-endian on x86.
   Its close time is patched in when the file closes.
3. Every recorded Software Bus message, laid end to end with no framing. Each message's
   length comes from its own CCSDS primary header, which is how the reader walks the file.

Payload fields are in the target's byte order, because apps write their structs straight to
the bus. The CCSDS headers are big-endian.

## Limitations

- Message IDs generated through EDS or topic-ID macros are not scanned out of headers; write
  them into the mapping file. Scanning `*_mids.h`, including custom `MAKE_MID` style macros,
  is the obvious next step.
- Decoding a big-endian target's payloads is wired up but untested.
- Virtually inherited base classes are skipped, with a warning: their offset is only known at
  run time.
- Only a header at the top level of a mapped struct is recognized, so two ways of embedding one
  are not handled yet:
  - A C++ class that *inherits* from `CFE_MSG_TelemetryHeader_t` rather than holding it as a
    member. The base class is flattened during extraction, so only the innermost message member
    matches and the secondary header and spare bytes leak in as extra columns
    (`Sec.Time[0]` and so on). The payload values are still correct.
  - A header *nested inside another struct*, such as a member `Base` whose own first member is
    the header. Nothing at the top level matches, so the struct is treated as a bare payload and
    decoded from the packet's payload offset instead of from byte 0. Every field then reads
    16 bytes too far into the packet. The run warns that the struct has no message header, but
    the CSV it writes is wrong rather than empty, so check that warning if you see one.

  Both fall out of one fix: instead of skipping a single header member, work out the header
  *region* at the start of the struct (descend the members at offset 0 to find the first known
  header type, then widen the region to the full telemetry or command header size if a secondary
  header is present) and drop every field that falls inside it.

## Tests

```
python -m pytest
```

The suite compiles `tests/fixtures/fixture.cpp` with `-g` under both `-gdwarf-4` and
`-gdwarf-5` and checks the extracted layout against the `offsetof` and `sizeof` values the
compiler itself reports, then decodes a packet the fixture filled in and compares every field
to the values the C++ side says it wrote. `tests/make_dsfile.py` builds DS files byte for byte
and is usable on its own for producing test data. Tests skip cleanly where there is no C++
compiler.
