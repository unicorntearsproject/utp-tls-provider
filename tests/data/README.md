# Test data

These files are lines derived from [Project Wycheproof](https://github.com/C2SP/wycheproof)'s
`testvectors_v1` (Apache-2.0, Copyright Google LLC), made with `tools/wycheproof.py`. Each line of the
signature files is `result tcId key msg sig` in hex (`-` for empty); `x25519.txt` is
`result tcId public private shared`. `result` is Wycheproof's: `valid`, `invalid` or `acceptable`.
The RFC 8448 trace is from the TLS 1.3 example handshake in RFC 8448, section 3.
