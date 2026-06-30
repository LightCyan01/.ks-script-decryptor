import sys, os, math, argparse, glob
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

PERIOD = 31

_W = [-6.0] * 256
for _b in range(0x20, 0x7f): _W[_b] = 1.0
_W[0x20] = 8; _W[0x09] = 6; _W[0x0a] = 7; _W[0x0d] = 7
for _b in range(ord('a'), ord('z') + 1): _W[_b] = 5
for _b in range(ord('A'), ord('Z') + 1): _W[_b] = 2
for _b in range(ord('0'), ord('9') + 1): _W[_b] = 2
for _c in '[]=,;:/*."\'@#$%&!?()+-_': _W[ord(_c)] = max(_W[ord(_c)], 3)
for _b in range(0x80, 0xc0): _W[_b] = 0.4
for _b in range(0xc0, 0xf5): _W[_b] = 0.4
_W[0x00] = -8


def xordec(data: bytes, key: bytes) -> bytes:
    P = len(key)
    return bytes(data[i] ^ key[i % P] for i in range(len(data)))


def detect_period(data: bytes, maxp: int = 48) -> int:
    best, bp = -1.0, PERIOD
    for s in range(1, maxp + 1):
        m = sum(1 for i in range(len(data) - s) if data[i] == data[i + s])
        r = m / max(1, len(data) - s)
        if r > best:
            best, bp = r, s
    return bp


def crack_freq(data: bytes, P: int) -> bytearray:
    key = bytearray(P)
    for c in range(P):
        col = data[c::P]
        key[c] = max(range(256), key=lambda k: sum(_W[b ^ k] for b in col))
    return key


def refine_bigram(data: bytes, key: bytearray, rounds: int = 10) -> bytearray:
    key = bytearray(key); P = len(key); n = len(data)
    for _ in range(rounds):
        dec = xordec(data, key)
        bg, ug = Counter(), Counter()
        for i in range(n - 1):
            bg[(dec[i], dec[i + 1])] += 1; ug[dec[i]] += 1
        ug[dec[-1]] += 1
        lp = lambda a, b: math.log((bg[(a, b)] + 0.1) / (ug[a] + 25.6))
        changed = False
        for c in range(P):
            def sc(k):
                s = 0.0
                for i in range(c, n, P):
                    if i > 0:        s += lp(data[i - 1] ^ key[(i - 1) % P], data[i] ^ k)
                    if i + 1 < n:    s += lp(data[i] ^ k, data[i + 1] ^ key[(i + 1) % P])
                return s
            ch = max(range(256), key=sc)
            if ch != key[c]:
                key[c] = ch; changed = True
        if not changed:
            break
    return key


def recover_key(data: bytes, P: int = None) -> bytes:
    if P is None:
        P = detect_period(data)
        if P not in (PERIOD, 2 * PERIOD):
            P = PERIOD
    return bytes(refine_bigram(data, crack_freq(data, P)))


def confidence(dec: bytes):
    try:
        t = dec.decode('utf-8'); utf8 = True
    except UnicodeDecodeError:
        t = dec.decode('utf-8', 'replace'); utf8 = False
    text = sum(1 for b in dec if b in (9, 10, 13) or 32 <= b < 127 or b >= 0x80) / max(1, len(dec))
    hits = sum(t.count(tok) for tok in ('[', ']', '@', 'text=', 'vo=', '[<<]', '[>>]', '*'))
    return utf8, round(text, 4), hits


def decrypt_bytes(data: bytes, key_hex: str = None):
    key = bytes.fromhex(key_hex) if key_hex else recover_key(data)
    return xordec(data, key), key


def _decrypt_one(job):
    src, dst, key_hex = job
    data = open(src, 'rb').read()
    dec, key = decrypt_bytes(data, key_hex)
    os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
    open(dst, 'wb').write(dec)
    utf8, tr, hits = confidence(dec)
    return dst, key.hex(), utf8, tr, hits


def main():
    ap = argparse.ArgumentParser(description="Decrypt Karigurashi Ren'ai Kirikiri .ks scripts.")
    ap.add_argument('path', nargs='?', help='a single .ks file (or use --dir)')
    ap.add_argument('out', nargs='?', help='output file for single-file mode (default: stdout)')
    ap.add_argument('--dir', help='decrypt every *.ks under this folder (recursive)')
    ap.add_argument('--out', dest='outdir', help='output folder for --dir (default: <dir>_dec)')
    ap.add_argument('--key', help='apply this known 31-byte key (hex) instead of cracking')
    ap.add_argument('-j', '--jobs', type=int, default=os.cpu_count() or 4,
                    help='parallel worker processes for --dir (default: all cores)')
    a = ap.parse_args()

    if a.dir:
        outdir = a.outdir or (a.dir.rstrip('/\\') + '_dec')
        files = sorted(glob.glob(os.path.join(a.dir, '**', '*.ks'), recursive=True))
        jobs = [(f, os.path.join(outdir, os.path.relpath(f, a.dir)), a.key) for f in files]
        bad = 0
        with ProcessPoolExecutor(max_workers=max(1, a.jobs)) as ex:
            for dst, kh, utf8, tr, hits in ex.map(_decrypt_one, jobs):
                flag = '' if (utf8 and tr > 0.97) else '  <-- LOW CONFIDENCE'
                if flag: bad += 1
                print(f"{os.path.relpath(dst, outdir):40s} utf8={utf8} text={tr} kag={hits}{flag}")
        print(f"\n{len(files)} files -> {outdir}   ({bad} low-confidence, {a.jobs} workers)")
        return

    if not a.path:
        ap.print_help(); return
    data = open(a.path, 'rb').read()
    dec, key = decrypt_bytes(data, a.key)
    utf8, tr, hits = confidence(dec)
    sys.stderr.write(f"key={key.hex()}  utf8={utf8} text={tr} kag={hits}\n")
    if a.out:
        open(a.out, 'wb').write(dec)
    else:
        sys.stdout.buffer.write(dec)

if __name__ == '__main__':
    main()
