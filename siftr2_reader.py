#!/usr/bin/env python3
"""
A lightweight Python 3 script that mirrors the core behavior of review_siftr2_log.c:
- Read the first line of a siftr2.5 format log file
- Iterate through the body records
- Read the last line

It also offers optional conveniences:
- Detects text vs binary body (very basic heuristic)
- Optional filtering by flowid (hex) and output its TSV data

This script does not depend on project headers. It aims to be self-contained and
portable. Adjust parsing logic to match the exact siftr2.5 fields if needed.
"""

from __future__ import annotations
import argparse
import os
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


# flow-level stats
@dataclass
class FlowStats:
    flowid: int
    data_pkt_cnt: int = 0
    fragment_cnt: int = 0

    payload_sum: int = 0
    payload_min: int = 65536
    payload_max: int = 0

    srtt_sum: int = 0
    srtt_min: int = 65536 ** 2  # power(2, 32)
    srtt_max: int = 0

    cwnd_sum: int = 0
    cwnd_min: int = 65536 ** 2  # power(2, 32)
    cwnd_max: int = 0

    rec_total: int = 0
    rec_in: int = 0
    rec_out: int = 0

    def update(self, r: Record, mss: int) -> None:
        self.rec_total += 1
        if r.direction == 'i':
            self.rec_in += 1
        else:
            self.rec_out += 1

        # SRTT
        self.srtt_sum += r.srtt
        self.srtt_min = min(self.srtt_min, r.srtt)
        self.srtt_max = max(self.srtt_max, r.srtt)

        # CWND
        self.cwnd_sum += r.cwnd
        self.cwnd_min = min(self.cwnd_min, r.cwnd)
        self.cwnd_max = max(self.cwnd_max, r.cwnd)

        # Packet / fragment heuristics (same assumption as C)
        if r.data_sz > 0:
            self.data_pkt_cnt += 1
            # Payload
            self.payload_sum += r.data_sz
            self.payload_min = min(self.payload_min, r.data_sz)
            self.payload_max = max(self.payload_max, r.data_sz)
            if (r.data_sz % mss) > 0:
                self.fragment_cnt += 1

    def dump(self) -> None:
        frag_ratio = (
            self.fragment_cnt / self.data_pkt_cnt if self.data_pkt_cnt else 0.0
        )

        print(f"input flow data_pkt_cnt: {self.data_pkt_cnt}, "
              f"fragment_cnt: {self.fragment_cnt}, "
              f"fragment_ratio: {frag_ratio:.3f}")

        print(f"           avg_payload: {self.payload_sum // self.data_pkt_cnt}, "
              f"min_payload: {self.payload_min}, "
              f"max_payload: {self.payload_max} bytes")

        print(f"           avg_srtt: {self.srtt_sum // self.rec_total}, "
              f"min_srtt: {self.srtt_min}, "
              f"max_srtt: {self.srtt_max} µs")

        print(f"           avg_cwnd: {self.cwnd_sum // self.rec_total}, "
              f"min_cwnd: {self.cwnd_min}, "
              f"max_cwnd: {self.cwnd_max} bytes")

        print(f"           has {self.rec_total} useful records "
              f"({self.rec_out} outputs, {self.rec_in} inputs)")


# This struct definition is an assumption based on the C snippet's usage.
# Adjust the format string to match the real binary layout of your pkt_node.
# Example fields: flowid (u32), direction (u8), tval (u32), snd_cwnd (u32),
# snd_ssthresh (u32), srtt (u32), data_sz (u32). Padding/alignment may differ.
PKT_NODE_STRUCT = struct.Struct(
    '<'     # little endian
    'I'     # flowid
    'I'     # direction
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


@dataclass
class FlowMeta:
    flowid: int
    ipver: int
    laddr: str
    lport: int
    faddr: str
    fport: int
    stack: str
    tcp_cc: str
    mss: int
    sack: int
    snd_scale: int
    rcv_scale: int
    nrecord: int
    ntrans: int


def parse_kv_fields(line: str) -> dict[str, str]:
    kv = {}
    for field in line.strip().split('\t'):
        if '=' in field:
            k, v = field.split('=', 1)
            kv[k] = v
    return kv


def format_time(secs: int, usecs: int) -> tuple[str, float]:
    epoch = secs + usecs / 1_000_000
    tm = time.localtime(secs)
    human = time.strftime('%Y-%m-%d %H:%M:%S', tm)
    return f"{human}.{usecs:06d}", epoch


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description='Read siftr2.5 log: first line, body, last line.')
    p.add_argument('-f', '--file', required=True, help='Path to siftr2.5 log file')
    p.add_argument('-s', '--stats-flowid', help='Filter by flowid (hex like c173985d or 0xc173985d; hex only)')
    p.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
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


def detect_rec_fmt(first_line: str) -> str:
    """Return 'binary' or 'txt' by inspecting the first line's rec_fmt=... field.
    Raises ValueError if the key is not present.
    """
    for field in first_line.strip().split('\t'):
        if field.startswith('rec_fmt='):
            return field.split('=', 1)[1].strip().lower()
    raise ValueError("rec_fmt key not found in the first line of the log")


def parse_flow_list(footer: str) -> list[FlowMeta]:
    flows: list[FlowMeta] = []

    for field in footer.split('\t'):
        if not field.startswith('flow_list='):
            continue

        payload = field.split('=', 1)[1]
        for entry in payload.split(';'):
            if not entry:
                continue

            parts = entry.split(',')
            if len(parts) != 14:
                continue

            flows.append(
                FlowMeta(
                    flowid=int(parts[0], 16),
                    ipver=int(parts[1]),
                    laddr=parts[2],
                    lport=int(parts[3]),
                    faddr=parts[4],
                    fport=int(parts[5]),
                    stack=parts[6],
                    tcp_cc=parts[7],
                    mss=int(parts[8]),
                    sack=int(parts[9]),
                    snd_scale=int(parts[10]),
                    rcv_scale=int(parts[11]),
                    nrecord=int(parts[12]),
                    ntrans=int(parts[13]),
                )
            )

    return flows


def dump_flow_list(flows: list[FlowMeta]) -> None:
    if not flows:
        return

    print("flow id list:")
    for f in flows:
        ipv = "IPv6" if f.ipver == 6 else "IPv4"

        print(
            f" id:{f.flowid:08x} {ipv} "
            f"({f.laddr}:{f.lport}<->{f.faddr}:{f.fport}) "
            f"stack:{f.stack} tcp_cc:{f.tcp_cc} "
            f"mss:{f.mss} SACK:{f.sack} "
            f"snd/rcv_scal:{f.snd_scale}/{f.rcv_scale} "
            f"cnt:{f.nrecord}/{f.ntrans}"
        )


def get_last_line_offset_and_record_size(path: str, fmt: str) -> Tuple[str, int, int]:
    """
    Return a tuple (last_line, footer_offset, record_size_bytes).
    The footer_offset is the byte offset where the final ASCII line begins.
    The record_size_bytes is parsed from the footer's key `record_size=`;
    raises ValueError if missing.

    This implementation scans from file end backward in chunks for efficiency.
    """
    marker = b'disable_time_secs='
    chunk_size = 4096
    file_size = os.path.getsize(path)
    with open(path, 'rb') as f:
        offset = 0
        buffer = b''
        while offset < file_size:
            read_size = min(chunk_size, file_size - offset)
            offset += read_size
            f.seek(file_size - offset)
            chunk = f.read(read_size)
            buffer = chunk + buffer
            idx = buffer.find(marker)
            if idx != -1:
                footer_offset = file_size - offset + idx
                footer = buffer[idx:].decode('utf-8', errors='replace').strip()
                record_size = None
                if fmt == 'binary':
                    for field in footer.split('\t'):
                        if field.startswith('record_size='):
                            try:
                                record_size = int(field.split('=', 1)[1])
                            except ValueError:
                                pass
                            break
                    if record_size is None:
                        raise ValueError('record_size key not found or invalid in footer')
                return footer, footer_offset, record_size
        raise ValueError('Footer marker not found')


def header_end_offset(path: str) -> int:
    """
    Return the byte offset immediately after the first line (header).
    """
    with open(path, 'rb') as f:
        _ = f.readline()  # header line including newline
        return f.tell()


def iter_text_records(path: str, first_tval: int, flowid: int) -> Iterator[Record]:
    """
    Parse siftr2.5 text format where each body line is a CSV with 18 fields
    corresponding to struct pkt_node in C.
    """
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        _ = f.readline()  # discard header line
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith('disable_time_secs='):
                break
            if line.startswith('enable_time_secs='):
                continue
            parts = line.split(',')
            if len(parts) != 18:
                continue
            try:
                fid = int(parts[0], 16)
                direction = parts[1].strip().lower()[:1]
                tval = int(parts[2], 16)
                snd_cwnd = int(parts[3], 16)
                snd_ssthresh = int(parts[4], 16)
                srtt = int(parts[5], 16)
                data_sz = int(parts[6], 16)
                # Validate rest of the fields (not used downstream)
                _ = [int(parts[i], 16) for i in range(7, 18)]
            except (ValueError, IndexError):
                continue

            if fid != flowid:
                continue
            yield Record(
                direction=direction,
                rel_time=tval - first_tval,
                cwnd=snd_cwnd,
                ssthresh=snd_ssthresh,
                srtt=srtt,
                data_sz=data_sz,
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


def iter_binary_records(path: str, first_tval: int, flowid: int, footer_offset: int, rec_size: int) -> Iterator[Record]:
    hdr_end = header_end_offset(path)

    if PKT_NODE_STRUCT.size != rec_size:
        raise ValueError(f"Configured struct size ({PKT_NODE_STRUCT.size}) != record_size ({rec_size})")

    with open(path, 'rb') as f:
        f.seek(hdr_end)
        while True:
            pos = f.tell()
            if pos + rec_size > footer_offset:
                break
            chunk = f.read(rec_size)
            if len(chunk) < rec_size:
                break
            try:
                fid, direction_int, tval, snd_cwnd, snd_ssthresh, srtt, data_sz = _unpack_pkt_node(chunk)
            except struct.error:
                break

            if fid != flowid:
                continue
            yield Record(
                direction= 'i' if direction_int == 0 else 'o',
                rel_time=tval - first_tval,
                cwnd=snd_cwnd,
                ssthresh=snd_ssthresh,
                srtt=srtt,
                data_sz=data_sz,
            )


def detect_first_tval(path: str, fmt: str, footer_offset: int, rec_size: int) -> Optional[int]:
    """Return the first record's tval (microseconds) or None if not found.

    For 'txt' format: the first record is the second line (after the header line),
    ignoring blank lines and any repeated header markers.

    For 'binary' format: the first record is the first fixed-size record immediately
    following the header line, provided it lies before the footer.
    """
    if fmt in ('txt', 'text', 'ascii'):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                _ = f.readline()  # skip header line
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    if line.startswith('disable_time_secs='):
                        return None
                    if line.startswith('enable_time_secs='):
                        continue
                    parts = line.split(',')
                    if len(parts) != 18:
                        continue
                    try:
                        return int(parts[2], 16)
                    except (ValueError, IndexError):
                        continue
        except OSError:
            return None
        return None
    elif fmt == 'binary':
        try:
            hdr_end = header_end_offset(path)
            if PKT_NODE_STRUCT.size != rec_size:
                return None
            with open(path, 'rb') as f:
                f.seek(hdr_end)
                if hdr_end + rec_size > footer_offset:
                    return None
                chunk = f.read(rec_size)
                if len(chunk) < rec_size:
                    return None
                try:
                    _, _, tval, _, _, _, _ = _unpack_pkt_node(chunk)
                except struct.error:
                    return None
                return int(tval)
        except (OSError, ValueError):
            return None
    else:
        return None


def main() -> int:
    start_time = time.perf_counter()
    args = parse_args()
    flowid = to_flowid(args.stats_flowid)

    if args.verbose:
        print(f"verbose mode enabled")
        print(f"input file name: {os.path.basename(args.file)}")

    first_line = read_first_line(args.file)
    if args.verbose:
        output_line = first_line.replace('\t', ', ')
        print(output_line.rstrip('\n'))

    try:
        fmt = detect_rec_fmt(first_line)
    except ValueError as e:
        print(f"Error: {e}")
        return 1

    last_line, footer_off, rec_size = get_last_line_offset_and_record_size(args.file, fmt)

    first_tval = detect_first_tval(args.file, fmt, footer_off, rec_size)
    if first_tval is None:
        print(f"Error: first_tval is None")
        return 1
    elif args.verbose:
        print(f"first flow start at: {first_tval/1_000.0:.3f}")

    if args.verbose:
        output_line = last_line.replace('\t', ', ')
        print()
        print(output_line)
        print()

    first_kv = parse_kv_fields(first_line)
    last_kv = parse_kv_fields(last_line)

    siftrver = first_kv.get('siftrver', 'unknown')
    print(f"siftr version: {siftrver}")

    if args.verbose:
        print(f'Detected record format: {fmt}')

    flows = parse_flow_list(last_line)
    dump_flow_list(flows)

    try:
        start_secs = int(first_kv['enable_time_secs'])
        start_usecs = int(first_kv['enable_time_usecs'])
        end_secs = int(last_kv['disable_time_secs'])
        end_usecs = int(last_kv['disable_time_usecs'])
    except KeyError as e:
        print(f"Error: missing timestamp field {e}")
        return 1

    start_str, start_epoch = format_time(start_secs, start_usecs)
    end_str, end_epoch = format_time(end_secs, end_usecs)
    duration = end_epoch - start_epoch

    print()
    print(f"starting_time: {start_str} ({start_epoch:.6f})")
    print(f"ending_time:   {end_str} ({end_epoch:.6f})")
    print(f"log duration: {duration:.2f} seconds")

    if flowid is not None:
        print(f"input flow id is: {flowid:08x}")
        flow_stats: Optional[FlowStats] = None
        this_flow_mss = 0
        this_flow_meta: Optional[FlowMeta] = None

        for f in flows:
            if f.flowid == flowid:
                this_flow_mss = f.mss
                this_flow_meta = f
                break

        rec_iter = (
            iter_binary_records(args.file, first_tval, flowid, footer_off, rec_size)
            if fmt == 'binary'
            else iter_text_records(args.file, first_tval, flowid)
        )

        out_name = f"plot_{flowid:08x}.data"
        with open(out_name, 'w', encoding='utf-8') as w:
            w.write('##direction\trelative_timestamp\tcwnd\tssthresh\tsrtt\tdata_size\n')
            for r in rec_iter:
                if flow_stats is None:
                    flow_stats = FlowStats(flowid=flowid)
                w.write(
                    f"{r.direction}\t"
                    f"{r.rel_time/1000.0:.3f}\t"
                    f"{r.cwnd:8d}\t"
                    f"{r.ssthresh:10d}\t"
                    f"{r.srtt:6d}\t"
                    f"{r.data_sz:5d}\n"
                )
                flow_stats.update(r, this_flow_mss)

        print(f"input file has total lines: {flow_stats.rec_total + 2}")
        print(f"plot_file_name: {out_name}")
        print("++++++++++++++++++++++++++++++ summary ++++++++++++++++++++++++++++")
        if flow_stats:
            flow_desc = None
            if this_flow_meta is not None:
                flow_desc = f"{this_flow_meta.laddr}:{this_flow_meta.lport}->{this_flow_meta.faddr}:{this_flow_meta.fport}"
            if flow_desc:
                print(f"  {flow_desc} flowid: {flow_stats.flowid:08x}")
            else:
                print(f"flowid: {flow_stats.flowid:08x}")
            flow_stats.dump()

    elapsed = time.perf_counter() - start_time
    print(f"\nthis program execution time: {elapsed:.3f} seconds")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

