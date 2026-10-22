#!/usr/bin/env python3
"""Convert a raw partition image to an Android sparse image (blocks of 4096 bytes).
Zero blocks become FILL chunks (still written as zeros); the space after the image up to
--partition-bytes becomes one DONT_CARE chunk. Usage: raw2sparse.py RAW OUT --partition-bytes N"""
import argparse, struct
p = argparse.ArgumentParser()
p.add_argument('raw'); p.add_argument('out'); p.add_argument('--partition-bytes', type=int, required=True)
a = p.parse_args()
BS = 4096
ZERO = bytes(BS)
chunks = []  # (type, blocks, payload-or-None)
RAW, FILL, DONT = 0xCAC1, 0xCAC2, 0xCAC3
with open(a.raw, 'rb') as src, open(a.out + '.body', 'wb') as body:
    run_type, run_blocks, run_data = None, 0, []
    def flush():
        global run_type, run_blocks, run_data
        if not run_blocks: return
        if run_type == RAW:
            data = b''.join(run_data)
            body.write(struct.pack('<HHII', RAW, 0, run_blocks, 12 + len(data))); body.write(data)
        else:
            body.write(struct.pack('<HHIII', FILL, 0, run_blocks, 16, 0))
        chunks.append(run_type)
        run_type, run_blocks, run_data = None, 0, []
    total = 0
    while True:
        blk = src.read(BS)
        if not blk: break
        if len(blk) < BS: blk += bytes(BS - len(blk))
        total += 1
        kind = FILL if blk == ZERO else RAW
        if kind != run_type or run_blocks >= 16384:
            flush(); run_type = kind
        run_blocks += 1
        if kind == RAW: run_data.append(blk)
    flush()
    part_blocks = a.partition_bytes // BS
    assert part_blocks >= total
    if part_blocks > total:
        body.write(struct.pack('<HHII', DONT, 0, part_blocks - total, 12)); chunks.append(DONT)
with open(a.out, 'wb') as out, open(a.out + '.body', 'rb') as body:
    out.write(struct.pack('<IHHHHIIII', 0xED26FF3A, 1, 0, 28, 12, BS, part_blocks, len(chunks), 0))
    while d := body.read(64 << 20): out.write(d)
import os; os.unlink(a.out + '.body')
print(f'{total} image blocks, {part_blocks} partition blocks, {len(chunks)} chunks')
