#!/usr/bin/env python3
"""
A lightweight Python 3 script that mirrors the core behavior of review_siftr2_log.c:
- Read the first line of a siftr2.5 format log file
- Iterate through the body records
- Read the last line

It also offers optional conveniences:
- Detects text vs binary body (very basic heuristic)
- Optional filtering by flowid (hex or decimal)
- Optional TSV output similar to the C writer thread

This script does not depend on project headers. It aims to be self-contained and
portable. Adjust parsing logic to match the exact siftr2.5 fields if needed.
"""

from __future__ import annotations
import argparse
import os
import sys
import struct
import time
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

# ---- Data structures to mirror the C code's record_t and pkt_node assumptions ----

@dataclass
class Record:
    direction: str  # 'i' or 'o'
    rel_time: int   # microseconds, relative to first flow start
    cwnd: int
    ssthresh: int
    srtt: int
    data_sz: int

# This struct definition is an assumption based on the C snippet's usage.
# Adjust the format string to match the real binary layout of your pkt_node.
# Example fields: flowid (u32), direction (u8), tval (u32), snd_cwnd (u32),
# snd_ssthresh (u32), srtt (u32), data_sz (u32). Padding/alignment may differ.
PKT_NODE_STRUCT = struct.Struct(
    '<'     # little endian
    'I'     # flowid
    'B'     # direction
    '3x'    # padding
    'I'     # tval
    'I'     # snd_cwnd
    'I'     # snd_ssthresh
    'I'     # srtt
    'I'     # data_sz
    'I'     # snd_wnd
    'I'     # rcv_wnd
    'I'     # t_flags
    'I'     # t_flags2
    'I'     # rto
    'I'     # snd_buf_hiwater
    'I'     # snd_buf_cc
    'I'     # rcv_buf_hiwater
    'I'     # rcv_buf_cc
    'I'     # pipe
    'i'     # t_segqlen (signed)
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Read siftr2.5 log: first line, body, last line.')
    p.add_argument('-f', '--file', required=True, help='Path to siftr2.5 log file')
    p.add_argument('-t', '--flow-start', type=int, default=0,
                   help='Unix timestamp of first flow start (for rel_time). Default 0')
    p.add_argument('-s', '--stats-flowid', help='Filter by flowid (hex like 0xc173985d; hex only)')
    p.add_argument('--verbose', action='store_true', help='Verbose output')
    return p.parse_args()


def to_flowid(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    s = s.strip().lower()
    # Allow optional 0x prefix; require pure hex otherwise
    if s.startswith('0x'):
        s = s[2:]
    # Validate hex characters only
    if not s or any(c not in '0123456789abcdef' for c in s):
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


def read_first_line(path: str) -> str:
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        first = f.readline()
    return first


def detect_rec_fmt(path: str) -> str:
    """Return 'binary' or 'txt' by inspecting the first line's rec_fmt=... field.
    Raises ValueError if the key is not present.
    """
    first = read_first_line(path)
    for field in first.strip().split('\t'):
        if field.startswith('rec_fmt='):
            return field.split('=', 1)[1].strip().lower()
    raise ValueError("rec_fmt key not found in the first line of the log")


def make_output_name(flowid: int, rec_fmt: str) -> str:
    """
    Generate output filename:
      plot_<flowid>.<bin|txt>.data
    """
    fmt = 'bin' if rec_fmt == 'binary' else 'txt'
    return f"plot_{flowid:08x}.{fmt}.data"


def read_last_line(path: str, chunk_size: int = 4096) -> str:
    # Efficiently read last line without loading entire file
    file_size = os.path.getsize(path)
    if file_size == 0:
        return ''
    with open(path, 'rb') as f:
        # Start from the end and search backwards for a newline
        offset = 0
        leftover = b''
        while True:
            read_size = min(chunk_size, file_size - offset)
            if read_size <= 0:
                # Reached beginning; return whatever we have
                data = f.read()
                if not data:
                    return leftover.decode('utf-8', errors='replace')
                lines = (data + leftover).splitlines()
                return lines[-1].decode('utf-8', errors='replace') if lines else ''
            offset += read_size
            f.seek(file_size - offset)
            block = f.read(read_size)
            if b'\n' in block:
                parts = (block + leftover).splitlines()
                return parts[-1].decode('utf-8', errors='replace') if parts else ''
            leftover = block + leftover


def get_footer_and_record_size(path: str) -> Tuple[int, int]:
    """
    Return a tuple (footer_offset, record_size_bytes). The footer_offset is the
    byte offset where the final ASCII line begins. The record_size_bytes is
    parsed from the footer's key `record_size=`; raises ValueError if missing.
    """
    with open(path, 'rb') as f:
        data = f.read()

    marker = b'disable_time_secs='
    idx = data.rfind(marker)
    if idx < 0:
        raise ValueError('Footer marker not found')

    footer = data[idx:].decode('utf-8', errors='replace').strip()

    record_size = None
    for field in footer.split('\t'):
        if field.startswith('record_size='):
            try:
                record_size = int(field.split('=', 1)[1])
            except ValueError:
                pass
            break

    if record_size is None:
        raise ValueError('record_size key not found or invalid in footer')

    return idx, record_size


def header_end_offset(path: str) -> int:
    """
    Return the byte offset immediately after the first line (header).
    """
    with open(path, 'rb') as f:
        first = f.readline()  # header line including newline
        return f.tell()


def iter_text_records(path: str, first_flow_start: int, flowid: Optional[int]) -> Iterator[Record]:
    """
    Parse siftr2.5 text format where each body line is a CSV with 18 fields
    corresponding to struct pkt_node in C:

    Index -> Field (hex unless noted):
      0: flowid (hex)
      1: direction ('i' or 'o')
      2: tval (relative time, hex)
      3: snd_cwnd (hex)
      4: snd_ssthresh (hex)
      5: srtt (hex)
      6: data_sz (hex)
      7: snd_wnd (hex)
      8: rcv_wnd (hex)
      9: t_flags (hex)
     10: t_flags2 (hex)
     11: rto (hex)
     12: snd_buf_hiwater (hex)
     13: snd_buf_cc (hex)
     14: rcv_buf_hiwater (hex)
     15: rcv_buf_cc (hex)
     16: pipe (hex)
     17: t_segqlen (hex)

    We yield a compact Record matching the C writer's needs, but we validate all fields.
    """
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        # Read and discard the header line (starts with enable_time_secs=)
        header = f.readline()
        # Iterate through body lines until footer (starts with disable_time_secs=)
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith('disable_time_secs='):
                break
            if line.startswith('enable_time_secs='):
                # In case there are multiple segments, skip headers
                continue
            parts = line.split(',')
            if len(parts) != 18:
                # Strict: require exactly 18 fields
                continue
            try:
                fid = int(parts[0], 16)
                if flowid is not None and fid != flowid:
                    continue
                direction = parts[1].strip().lower()[:1]
                # Parse all numeric fields as hex
                tval = int(parts[2], 16)
                snd_cwnd = int(parts[3], 16)
                snd_ssthresh = int(parts[4], 16)
                srtt = int(parts[5], 16)
                data_sz = int(parts[6], 16)
                # The rest are parsed to validate the line format (not used downstream yet)
                _snd_wnd = int(parts[7], 16)
                _rcv_wnd = int(parts[8], 16)
                _t_flags = int(parts[9], 16)
                _t_flags2 = int(parts[10], 16)
                _rto = int(parts[11], 16)
                _snd_buf_hiwater = int(parts[12], 16)
                _snd_buf_cc = int(parts[13], 16)
                _rcv_buf_hiwater = int(parts[14], 16)
                _rcv_buf_cc = int(parts[15], 16)
                _pipe = int(parts[16], 16)
                # t_segqlen may be signed in C, but source is hex text; parse as int
                _t_segqlen = int(parts[17], 16)
            except (ValueError, IndexError):
                continue

            yield Record(
                direction=direction,
                rel_time=tval - int(first_flow_start),
                cwnd=snd_cwnd,
                ssthresh=snd_ssthresh,
                srtt=srtt,
                data_sz=data_sz,
            )


def iter_binary_records(path: str, first_flow_start: int, flowid: Optional[int]) -> Iterator[Record]:
    # Determine boundaries and record size from header/footer
    hdr_end = header_end_offset(path)
    try:
        footer_off, rec_size = get_footer_and_record_size(path)
    except ValueError as e:
        raise
    # Sanity: ensure our assumed struct size matches rec_size if we use struct unpack
    if PKT_NODE_STRUCT.size != rec_size:
        # We can still read rec_size chunks, but unpacking may fail; warn via exception
        raise ValueError(f"Configured struct size ({PKT_NODE_STRUCT.size}) != record_size ({rec_size})")
    with open(path, 'rb') as f:
        # Seek to start of binary body (right after header line)
        f.seek(hdr_end)
        # Read fixed-size records up to (but not including) the footer
        while True:
            pos = f.tell()
            if pos + rec_size > footer_off:
                break
            chunk = f.read(rec_size)
            if len(chunk) < rec_size:
                break
            try:
                (fid, direction_u8, tval, snd_cwnd, snd_ssthresh, srtt, data_sz) = _unpack_pkt_node(chunk)
            except struct.error:
                break
            if flowid is not None and fid != flowid:
                continue
            direction = 'i' if direction_u8 == 0 else 'o'
            yield Record(
                direction=direction,
                rel_time=int(tval) - int(first_flow_start),
                cwnd=int(snd_cwnd),
                ssthresh=int(snd_ssthresh),
                srtt=int(srtt),
                data_sz=int(data_sz),
            )


def _unpack_pkt_node(chunk: bytes):
    fields = PKT_NODE_STRUCT.unpack(chunk)
    return (
        fields[0],  # flowid
        fields[1],  # direction
        fields[2],  # tval
        fields[3],  # snd_cwnd
        fields[4],  # snd_ssthresh
        fields[5],  # srtt
        fields[6],  # data_sz
    )


def write_tsv(out_path: str, recs: Iterator[Record]) -> None:
    if out_path == '-':
        w = sys.stdout
        close = False
    else:
        w = open(out_path, 'w', encoding='utf-8')
        close = True
    try:
        w.write('##direction\trelative_timestamp\tcwnd\tssthresh\tsrtt\tdata_size\n')
        for r in recs:
                # Formatting intentionally matches C fprintf():
                # "%c\t%.3f\t%8u\t%10u\t%6u\t%5u\n"
                w.write(
                    f"{r.direction}\t"
                    f"{r.rel_time/1000.0:.3f}\t"
                    f"{r.cwnd:8d}\t"
                    f"{r.ssthresh:10d}\t"
                    f"{r.srtt:6d}\t"
                    f"{r.data_sz:5d}\n")
    finally:
        if close:
            w.close()


def main() -> int:
    start_time = time.perf_counter()
    args = parse_args()
    flowid = to_flowid(args.stats_flowid)

    # First line (header)
    first_line = read_first_line(args.file)
    print('First line:')
    print(first_line.rstrip('\n'))

    # Last line
    last_line = read_last_line(args.file)
    print('Last line:')
    print(last_line)

    try:
        fmt = detect_rec_fmt(args.file)
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    if args.verbose:
        print(f'Detected body format: {fmt}')

    rec_iter = (
        iter_binary_records(args.file, args.flow_start, flowid)
        if fmt == 'binary'
        else iter_text_records(args.file, args.flow_start, flowid)
    )

    if flowid is not None:
        out_name = make_output_name(flowid, fmt)
        write_tsv(out_name, rec_iter)
        if args.verbose:
            print(f"Wrote TSV to: {out_name}")
    else:
        # No flowid → just sample output
        print('Sample records:')
        count = 0
        for r in rec_iter:
            print(r)
            count += 1
            if count >= 10:
                break

    # Print execution time
    elapsed = time.perf_counter() - start_time
    print(f"this program execution time: {elapsed:.3f} seconds")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

