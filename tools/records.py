#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Makes tests/data/records.txt: TLS 1.3 records protected by an independent implementation (the
`cryptography` package), for the three suites. Each line is
`suite key iv seq content_type plaintext record` in hex (`-` for empty), with a fixed seed, so the
file is the same every time. Usage: records.py OUT_FILE
"""
import random
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

SUITES = {
    "aes128gcm": (16, AESGCM),
    "aes256gcm": (32, AESGCM),
    "chacha20poly1305": (32, ChaCha20Poly1305),
}


def main(out):
    rng = random.Random(0x8448)
    lines = []
    for suite, (key_len, cls) in SUITES.items():
        for length in (0, 1, 15, 16, 17, 100, 1024, 16384):
            for seq in (0, 1, 0xFFFFFFFF, 0x0102030405060708):
                if length == 16384 and seq != 0:
                    continue  # one full-size record is enough
                key = bytes(rng.randrange(256) for _ in range(key_len))
                iv = bytes(rng.randrange(256) for _ in range(12))
                plain = bytes(rng.randrange(256) for _ in range(length))
                typ = rng.choice([0x16, 0x17, 0x15])
                inner = plain + bytes([typ])
                header = bytes([0x17, 0x03, 0x03]) + (len(inner) + 16).to_bytes(2, "big")
                nonce = bytes(a ^ b for a, b in zip(iv, bytes(4) + seq.to_bytes(8, "big")))
                record = header + cls(key).encrypt(nonce, inner, header)
                lines.append(
                    f"{suite} {key.hex()} {iv.hex()} {seq} {typ:02x} {plain.hex() or '-'} {record.hex()}"
                )
    open(out, "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
