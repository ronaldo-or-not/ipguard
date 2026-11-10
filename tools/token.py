#!/usr/bin/env python3
"""
Reference implementation of the identity-plumbing token wire format (v1, "t1").

This file is normative. docs/token-format.md describes the format in prose; where
the two disagree, this file wins. The WAS-side Java agent and the DB-side C
extension must both reproduce the vectors printed by `python3 token.py vectors`.

The point of having an executable spec is that two independent implementations
cannot silently diverge on whitespace, encoding, byte order, or padding -- a
divergence here is not a security event, it is a production outage (every
legitimate query gets denied).

Usage:
    python3 token.py vectors        # print canonical test vectors
    python3 token.py selftest       # verify this implementation against them
"""

import hashlib
import hmac
import struct
import sys

MAGIC = b"/*@t1:"
CLOSE = b"*/"
PAYLOAD_LEN = 112          # bytes, before base64url
B64_LEN = 150              # base64url(112 bytes), unpadded
PREFIX_LEN = len(MAGIC) + B64_LEN + len(CLOSE)   # 158

SIGNED_LEN = 80            # payload[0:80] is what the MAC covers
MAC_LEN = 32

FLAG_POSTURE_OK = 0x0001


def b64url_encode(raw: bytes) -> bytes:
    import base64
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def b64url_decode(txt: bytes) -> bytes:
    import base64
    pad = (-len(txt)) % 4
    return base64.urlsafe_b64decode(txt + b"=" * pad)


def ci_hash(ci: str) -> bytes:
    """CI (연계정보) is hashed, never carried in cleartext.

    Rationale: the token lives inside the SQL text, and SQL text lands in
    pg_stat_statements and in log_statement output. Carrying a raw CI there
    would create a new PII sink inside a system whose purpose is to prevent
    PII leakage. The DB side compares SHA-256(observed $1) against this field,
    which is sufficient for parameter-identity binding.
    """
    return hashlib.sha256(ci.encode("utf-8")).digest()


def sql_hash(sql_without_prefix: bytes) -> bytes:
    """Hash of the EXACT bytes of the query, with the 158-byte token prefix removed.

    NO normalization. No whitespace collapsing, no case folding, no
    literal->placeholder rewriting. Both sides hash the same octets or the
    scheme does not work. On the WAS side those octets must be taken from
    org.postgresql.core.v3.QueryExecutorImpl#sendParse's NativeQuery.nativeSql
    -- i.e. AFTER pgJDBC has rewritten ? -> $n and processed JDBC escapes --
    not from the application-level SQL string.
    """
    return hashlib.sha256(sql_without_prefix).digest()


def build_payload(ver, kid, flags, iat_ms, ttl_ms, ci_sha, sql_sha, key) -> bytes:
    assert len(ci_sha) == 32 and len(sql_sha) == 32
    body = (
        struct.pack("!BBH", ver, kid, flags)
        + struct.pack("!Q", iat_ms)
        + struct.pack("!I", ttl_ms)
        + ci_sha
        + sql_sha
    )
    assert len(body) == SIGNED_LEN, len(body)
    mac = hmac.new(key, body, hashlib.sha256).digest()
    payload = body + mac
    assert len(payload) == PAYLOAD_LEN
    return payload


def wrap(sql: bytes, payload: bytes) -> bytes:
    enc = b64url_encode(payload)
    assert len(enc) == B64_LEN, f"expected {B64_LEN} got {len(enc)}"
    return MAGIC + enc + CLOSE + sql


class Reject(Exception):
    pass


def parse(query: bytes, keys: dict, now_ms: int):
    """Fail-closed extraction + verification. Returns (fields, sql_without_prefix).

    Every failure path raises. There is no 'degraded' return value: a caller
    that cannot distinguish 'verified' from 'could not verify' will eventually
    fail open, which is the failure mode this whole design exists to prevent.
    """
    if len(query) < PREFIX_LEN:
        raise Reject("shorter than prefix")
    if query[: len(MAGIC)] != MAGIC:
        raise Reject("bad magic")
    if query[PREFIX_LEN - len(CLOSE): PREFIX_LEN] != CLOSE:
        raise Reject("bad close")

    enc = query[len(MAGIC): PREFIX_LEN - len(CLOSE)]
    if len(enc) != B64_LEN:
        raise Reject("bad b64 length")
    try:
        payload = b64url_decode(enc)
    except Exception:
        raise Reject("b64 decode failed")
    if len(payload) != PAYLOAD_LEN:
        raise Reject("bad payload length")

    body, mac = payload[:SIGNED_LEN], payload[SIGNED_LEN:]
    ver, kid, flags = struct.unpack("!BBH", body[0:4])
    if ver != 1:
        raise Reject(f"unsupported ver {ver}")
    key = keys.get(kid)
    if key is None:
        raise Reject(f"unknown kid {kid}")

    expect = hmac.new(key, body, hashlib.sha256).digest()
    # constant-time compare; a byte-wise early-exit compare is a timing oracle
    if not hmac.compare_digest(mac, expect):
        raise Reject("mac mismatch")

    iat_ms = struct.unpack("!Q", body[4:12])[0]
    ttl_ms = struct.unpack("!I", body[12:16])[0]
    if now_ms < iat_ms - 1000:          # 1s tolerance for clock skew
        raise Reject("token from the future")
    if now_ms > iat_ms + ttl_ms:
        raise Reject("expired")

    sql = query[PREFIX_LEN:]
    if not hmac.compare_digest(sql_hash(sql), body[48:80]):
        raise Reject("sql fingerprint mismatch")

    return {
        "ver": ver, "kid": kid, "flags": flags,
        "iat_ms": iat_ms, "ttl_ms": ttl_ms,
        "ci_sha256": body[16:48], "sql_sha256": body[48:80],
    }, sql


# --------------------------------------------------------------------------
# Canonical test vectors. Fixed inputs, no randomness, no clock.
# --------------------------------------------------------------------------
VEC_KEY = bytes(range(32))                     # 00 01 02 ... 1f
VEC_KID = 7
VEC_CI = "A" * 88                              # a Korean CI is 88 base64 chars
VEC_SQL = b"SELECT name, ssn FROM cust WHERE ci = $1"
VEC_IAT = 1_767_225_600_000                    # 2026-01-01T00:00:00Z
VEC_TTL = 5_000
VEC_FLAGS = FLAG_POSTURE_OK


def vectors():
    ci_sha = ci_hash(VEC_CI)
    sql_sha = sql_hash(VEC_SQL)
    payload = build_payload(1, VEC_KID, VEC_FLAGS, VEC_IAT, VEC_TTL,
                            ci_sha, sql_sha, VEC_KEY)
    wire = wrap(VEC_SQL, payload)
    return {
        "key_hex": VEC_KEY.hex(),
        "kid": VEC_KID,
        "ci": VEC_CI,
        "ci_sha256_hex": ci_sha.hex(),
        "sql": VEC_SQL.decode(),
        "sql_sha256_hex": sql_sha.hex(),
        "iat_ms": VEC_IAT,
        "ttl_ms": VEC_TTL,
        "flags": VEC_FLAGS,
        "payload_hex": payload.hex(),
        "mac_hex": payload[SIGNED_LEN:].hex(),
        "token_b64url": b64url_encode(payload).decode(),
        "prefix_len": PREFIX_LEN,
        "wire_len": len(wire),
        "wire": wire.decode(),
    }


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "vectors"
    v = vectors()
    if cmd == "vectors":
        for k in ("key_hex", "kid", "ci_sha256_hex", "sql", "sql_sha256_hex",
                  "iat_ms", "ttl_ms", "flags", "mac_hex", "token_b64url",
                  "prefix_len", "wire_len"):
            print(f"{k:16} {v[k]}")
        print(f"{'payload_hex':16} {v['payload_hex']}")
        print(f"{'wire':16} {v['wire']}")
        return 0

    if cmd == "selftest":
        wire = v["wire"].encode()
        assert len(wire) == PREFIX_LEN + len(VEC_SQL)
        fields, sql = parse(wire, {VEC_KID: VEC_KEY}, VEC_IAT + 1)
        assert sql == VEC_SQL, sql
        assert fields["ci_sha256"] == ci_hash(VEC_CI)
        assert fields["flags"] == VEC_FLAGS

        def must_reject(mutate, why):
            try:
                parse(mutate(bytearray(wire)), {VEC_KID: VEC_KEY}, VEC_IAT + 1)
            except Reject:
                return
            raise AssertionError(f"should have rejected: {why}")

        must_reject(lambda b: bytes(b[:5] + b"X" + b[6:]), "magic tampered")
        must_reject(lambda b: bytes(b[:20] + b"A" + b[21:]), "payload tampered")
        must_reject(lambda b: bytes(b) + b" ", "sql tampered (trailing space)")
        must_reject(lambda b: bytes(b[PREFIX_LEN:]), "no token at all")
        try:
            parse(wire, {VEC_KID: VEC_KEY}, VEC_IAT + VEC_TTL + 1)
            raise AssertionError("should have rejected: expired")
        except Reject:
            pass
        try:
            parse(wire, {99: VEC_KEY}, VEC_IAT + 1)
            raise AssertionError("should have rejected: unknown kid")
        except Reject:
            pass
        print("selftest OK")
        return 0

    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
