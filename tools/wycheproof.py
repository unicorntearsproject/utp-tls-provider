#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Turns Project Wycheproof's signature and X25519 test files into the compact lines the tests read.

Usage: wycheproof.py WYCHEPROOF_DIR OUT_DIR
(WYCHEPROOF_DIR holds the files of testvectors_v1 from https://github.com/C2SP/wycheproof, which are
Apache-2.0 licensed.) Each output line is `result tcId key msg sig`, in hex; the X25519 lines are
`result tcId public private shared`.
"""
import json
import os
import sys

SIGNATURES = {
    "ecdsa_p256_sha256": ("ecdsa_secp256r1_sha256_test", "uncompressed"),
    "ecdsa_p384_sha384": ("ecdsa_secp384r1_sha384_test", "uncompressed"),
    "ecdsa_p384_sha256": ("ecdsa_secp384r1_sha256_test", "uncompressed"),
    "ed25519": ("ed25519_test", "pk"),
    "rsa_pkcs1_2048_sha256": ("rsa_signature_2048_sha256_test", "publicKeyAsn"),
    "rsa_pkcs1_2048_sha384": ("rsa_signature_2048_sha384_test", "publicKeyAsn"),
    "rsa_pkcs1_2048_sha512": ("rsa_signature_2048_sha512_test", "publicKeyAsn"),
    "rsa_pkcs1_3072_sha256": ("rsa_signature_3072_sha256_test", "publicKeyAsn"),
    "rsa_pss_2048_sha256": ("rsa_pss_2048_sha256_mgf1_32_test", "publicKeyAsn"),
    "rsa_pss_2048_sha384": ("rsa_pss_2048_sha384_mgf1_48_test", "publicKeyAsn"),
    "rsa_pss_3072_sha256": ("rsa_pss_3072_sha256_mgf1_32_test", "publicKeyAsn"),
}


def key_of(group, field):
    if field == "publicKeyAsn":
        return group[field]
    return group["publicKey"][field]


def main(src, out):
    os.makedirs(out, exist_ok=True)
    for name, (file, field) in SIGNATURES.items():
        data = json.load(open(os.path.join(src, file + ".json")))
        lines = []
        for group in data["testGroups"]:
            key = key_of(group, field)
            for t in group["tests"]:
                lines.append(f"{t['result']} {t['tcId']} {key} {t['msg'] or '-'} {t['sig'] or '-'}")
        open(os.path.join(out, name + ".txt"), "w").write("\n".join(lines) + "\n")
    data = json.load(open(os.path.join(src, "x25519_test.json")))
    lines = []
    for group in data["testGroups"]:
        for t in group["tests"]:
            lines.append(f"{t['result']} {t['tcId']} {t['public']} {t['private']} {t['shared']}")
    open(os.path.join(out, "x25519.txt"), "w").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
