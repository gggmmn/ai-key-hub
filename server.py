#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 密钥管理中心  —— 单文件零依赖
  · 口令门禁（PBKDF2 哈希 + 会话 Cookie + 失败限流）
  · API 密钥加密落盘（HMAC-SHA256 计数器流加密 + 完整性校验）
  · OpenAI 兼容统一网关（/v1/models, /v1/chat/completions 转发）
  · 纯标准库，无第三方依赖
"""
import argparse, base64, hashlib, hmac, json, os, re, secrets, ssl, sys, threading, time
import socket
import urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ══════════════════════════ 配置 ══════════════════════════
DATA_DIR    = "/data/ai-keys"
DATA_FILE   = os.path.join(DATA_DIR, "data.json")
MASTER_FILE = os.path.join(DATA_DIR, "master.key")
SESSION_FILE = os.path.join(DATA_DIR, "sessions.json")
STATIC_DIR  = "/opt/ai-keys/static"
CERT_DIR    = "/opt/ai-keys/certs"

DEFAULT_PORT     = 47586
SESSION_TTL      = 7 * 24 * 3600      # ★ 登录记住 7 天
SESSION_SHORT    = 12 * 3600          # 不勾「记住我」时：仅本次
LOGIN_WINDOW     = 300
LOGIN_MAX        = 8
MAX_BODY         = 2 * 1024 * 1024
PBKDF2_ITERS     = 260000

_lock = threading.RLock()
MASTER = b""            # 由 main() 载入
_sessions = {}          # token -> {"exp": ts}
_attempts = {}          # ip -> [ts, ...]

# ══════════════════════════ 加密 ══════════════════════════
def _hmac(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()

def keystream(key, nonce, n):
    """HMAC-SHA256 计数器模式伪随机流（无第三方库的对称加密）"""
    out, ctr = bytearray(), 0
    while len(out) < n:
        out += _hmac(key, nonce + ctr.to_bytes(8, "big"))
        ctr += 1
    return bytes(out[:n])

def encrypt(master, text):
    raw = text.encode("utf-8")
    nonce = secrets.token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(raw, keystream(master, nonce, len(raw))))
    tag = _hmac(master, nonce + ct)[:16]
    return base64.b64encode(nonce + tag + ct).decode()

def decrypt(master, blob):
    raw = base64.b64decode(blob)
    nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
    if not hmac.compare_digest(tag, _hmac(master, nonce + ct)[:16]):
        raise ValueError("密文完整性校验失败（数据被改动过）")
    return bytes(a ^ b for a, b in zip(ct, keystream(master, nonce, len(ct)))).decode("utf-8")

def pw_hash(password, salt=None, iters=PBKDF2_ITERS):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, 32)
    return salt.hex(), h.hex(), iters

def pw_verify(password, rec):
    salt = bytes.fromhex(rec["salt"])
    _, h, iters = pw_hash(password, salt, rec.get("iterations", PBKDF2_ITERS))
    return hmac.compare_digest(h, rec["hash"])

def gen_password(n=16):
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    s = "".join(secrets.choice(alpha) for _ in range(n))
    return "-".join(s[i:i+4] for i in range(0, n, 4))

# ══════════════════════════ 存储 ══════════════════════════
def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def load_master():
    if not os.path.exists(MASTER_FILE):
        os.makedirs(DATA_DIR, exist_ok=True)
        mk = secrets.token_bytes(32)
        with open(MASTER_FILE, "wb") as f:
            f.write(mk)
        os.chmod(MASTER_FILE, 0o600)
        return mk
    with open(MASTER_FILE, "rb") as f:
        return f.read()

def default_data():
    return {"auth": None, "settings": {}, "keys": [], "logs": []}

def load_data():
    if not os.path.exists(DATA_FILE):
        return default_data()
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        d = json.load(f)
    for k, v in default_data().items():
        d.setdefault(k, v)
    return d

def save_data(d):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, DATA_FILE)

def audit(d, action, detail="", ip=""):
    d["logs"].insert(0, {"at": now_str(), "action": action, "detail": detail, "ip": ip})
    del d["logs"][400:]

# ══════════════════════════ 会话持久化（让「记住 7 天」真的成立）══════════════════════════
def tok_hash(tok):
    """只存 token 的哈希 —— 就算 sessions.json 泄露也拿不到能用的登录凭证"""
    return hashlib.sha256(tok.encode()).hexdigest()

def save_sessions():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = SESSION_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_sessions, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, SESSION_FILE)
    except Exception:
        pass

def load_sessions():
    global _sessions
    try:
        with open(SESSION_FILE, encoding="utf-8") as f:
            raw = json.load(f)
        now = time.time()
        _sessions = {k: v for k, v in raw.items() if v.get("exp", 0) > now}
        if len(_sessions) != len(raw):
            save_sessions()          # ★ 顺手把已过期的条目从文件里清掉
    except Exception:
        _sessions = {}

def purge_sessions():
    """清掉已过期的会话"""
    now = time.time()
    dead = [k for k, v in _sessions.items() if v.get("exp", 0) <= now]
    for k in dead:
        _sessions.pop(k, None)
    if dead:
        save_sessions()

def key_hint(api_key):
    k = api_key or ""
    if len(k) <= 12:
        return k[:3] + "…" + k[-2:] if len(k) > 5 else "…"
    return k[:7] + "…" + k[-4:]

# ══════════════════════════ 密钥健康 / 自动冷却 ══════════════════════════
# 上游报错类型 → 冷却秒数（冷却期内该密钥被跳过，自动切下一个）
COOLDOWN = {"quota": 1800, "auth": 3600, "rate": 30, "server": 60, "net": 30, "other": 60}

PROBE_INTERVAL = 2        # ★ 后台检测线程的轮询间隔（秒）

QUOTA_HINTS = ("insufficient", "quota", "balance", "credit", "billing", "payment",
               "arrears", "no enough", "exceeded your current", "欠费", "余额不足",
               "额度", "已用完", "not enough")

def classify_error(status, text):
    """返回 (类型, 冷却秒, 人话原因)"""
    low = (text or "").lower()
    if status == 402 or any(h in low for h in QUOTA_HINTS):
        return "quota", COOLDOWN["quota"], "额度不足 / 无费用"
    if status in (401, 403):
        return "auth", COOLDOWN["auth"], "认证失败（密钥无效或过期）"
    if status == 429:
        return "rate", COOLDOWN["rate"], "触发限速（429）"
    if status >= 500:
        return "server", COOLDOWN["server"], "上游服务器错误 %d" % status
    if status == 0:
        return "net", COOLDOWN["net"], "网络/连接错误"
    return "other", COOLDOWN["other"], "HTTP %d" % status

def short_err(status, raw):
    """从上游错误体里抽出可读消息（不要把整坨 JSON 塞给用户）"""
    try:
        j = json.loads(raw)
        e = j.get("error")
        m = e.get("message") if isinstance(e, dict) else e
        m = m or j.get("message") or j.get("msg") or j.get("detail")
        if m:
            return "HTTP %d · %s" % (status, re.sub(r"\s+", " ", str(m))[:120])
    except Exception:
        pass
    txt = re.sub(r"\s+", " ", (raw or "")).strip()
    return ("HTTP %d · %s" % (status, txt[:110])) if txt else ("HTTP %d" % status)

def blank_health():
    return {"fails": 0, "oks": 0, "cooldown_until": 0, "reason": "",
            "last_error": "", "last_error_at": "", "probe_done_at": 0}

def cooldown_left(k):
    return max(0, int((k.get("health") or {}).get("cooldown_until", 0) - time.time()))

def cooling(k):
    return cooldown_left(k) > 0

def mark_fail(k, kind, secs, msg):
    h = k.setdefault("health", blank_health())
    h["fails"] = h.get("fails", 0) + 1
    h["cooldown_until"] = time.time() + secs
    h["reason"] = kind
    h["last_error"] = (msg or "")[:200]
    h["last_error_at"] = now_str()

def mark_ok(k):
    h = k.setdefault("health", blank_health())
    h["oks"] = h.get("oks", 0) + 1
    h["fails"] = 0
    h["cooldown_until"] = 0
    h["reason"] = ""
    h["last_error"] = ""

def heal(k):
    """手动重置健康状态"""
    k["health"] = blank_health()

# ══════════════════════════ 冷却到期主动检测 ══════════════════════════
_probing = set()          # 正在检测中的密钥 id（内存态，不落盘）

def pending_probe(k):
    """冷却已经到期、但还没做过「到期检测」"""
    h = k.get("health") or {}
    cu = h.get("cooldown_until", 0)
    return cu > 0 and cu <= time.time() and h.get("probe_done_at", 0) < cu

def key_state(k):
    """★ 不单独暴露「检测中」：冷却中 / 待检测 / 检测中 一律算 cooling。
       这样到期瞬间不会闪出假绿灯，也不用引入一个只存在 1~2 秒的状态。"""
    if not k.get("enabled"):
        return "off"
    if cooldown_left(k) > 0 or pending_probe(k) or k["id"] in _probing:
        return "cooling"
    return "ok"

def upstream_json(base_url, api_key, sub, timeout=20):
    url = base_url.rstrip("/") + sub
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "AIKeyHub/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

def probe_key(base_url, real):
    """真打一次上游，返回 (ok, kind, secs, msg)"""
    try:
        upstream_json(base_url, real, "/models", timeout=10)
        return True, "", 0, "连接正常"
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")[:400]
        kind, secs, _ = classify_error(e.code, raw)
        return False, kind, secs, short_err(e.code, raw)
    except Exception as e:
        kind, secs, _ = classify_error(0, str(e))
        return False, kind, secs, "%s: %s" % (type(e).__name__, str(e)[:110])

# ══════════ 真实对话探测（测试按钮用）══════════
TEST_MSG = "你好"           # 探测用的用户消息
TEST_MAXTOK = 1             # ★ 只要 1 个输出 token —— 费用几乎为 0
TEST_TIMEOUT = 30           # 慢的上游也够跑完，别误杀

def _pick_model(k):
    """挑一个用来测试的模型名：优先登记的模型，其次模型别名，最后 'auto'"""
    ms = [str(m).strip() for m in (k.get("models") or []) if str(m).strip()]
    if ms:
        return ms[0]
    return ""

def resolve_test_model(k, real):
    """★ 决定用哪个模型名测试：
       ① 密钥登记了模型 → 用第一个
       ② 没登记 → 现拉一次 /models 取第一个（很多服务商都能拉）
       ③ 都拿不到 → 返回空，调用方提示用户手填"""
    m = _pick_model(k)
    if m:
        return m
    try:
        j = upstream_json(k["base_url"], real, "/models", timeout=12)
        ids = sorted({str(x.get("id")) for x in (j.get("data") or []) if x.get("id")})
        return ids[0] if ids else ""
    except Exception:
        return ""

def test_chat(base_url, api_key, model, timeout=TEST_TIMEOUT, msg=TEST_MSG):
    """★ 真发一条对话请求：有回复=可用；报错/超时=不可用
       返回 (ok, kind, secs, msg, reply, ms)
       kind/secs 用于失败时的冷却分类，跟网关逻辑完全一致"""
    t0 = time.time()
    payload = {"model": model, "max_tokens": TEST_MAXTOK,
               "messages": [{"role": "user", "content": msg}]}
    try:
        req = urllib.request.Request(
            base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Authorization": "Bearer " + api_key,
                     "Content-Type": "application/json",
                     "Accept": "application/json",
                     "User-Agent": "AIKeyHub/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
        ms = int((time.time() - t0) * 1000)
        # 解析回复内容（能解析出内容最好，解析不了也算通——毕竟没报错）
        reply = ""
        try:
            j = json.loads(raw)
            ch = (j.get("choices") or [{}])[0]
            m = ch.get("message") or {}
            reply = (m.get("content") or ch.get("text") or "").strip()
            if not reply and m.get("reasoning_content"):
                reply = str(m["reasoning_content"]).strip()
        except Exception:
            reply = raw.strip()[:80]
        return True, "", 0, "对话正常", reply, ms
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")[:400]
        ms = int((time.time() - t0) * 1000)
        kind, secs, why = classify_error(e.code, raw)
        return False, kind, secs, short_err(e.code, raw), "", ms
    except urllib.error.URLError as e:
        ms = int((time.time() - t0) * 1000)
        kind, secs, _ = classify_error(0, str(e))
        rsn = str(getattr(e, "reason", e))[:110]
        return False, kind, secs, "连不上（%s）" % rsn, "", ms
    except socket.timeout:
        ms = int((time.time() - t0) * 1000)
        kind, secs, _ = classify_error(0, "timeout")
        return False, kind, secs, "上游 %d 秒无响应（超时）" % timeout, "", ms
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        kind, secs, _ = classify_error(0, str(e))
        return False, kind, secs, "%s: %s" % (type(e).__name__, str(e)[:110]), "", ms

def probe_new_key(base_url, api_key):
    """★ 新增密钥前的连通性检测
       返回 (level, 人话消息, kind, count, ms)
       level: ok=通 / warn=无法确认但放行 / fail=确认不可用（拒绝添加）"""
    t0 = time.time()
    try:
        j = upstream_json(base_url, api_key, "/models", timeout=15)
        ids = [m.get("id") for m in (j.get("data") or []) if m.get("id")]
        ms = int((time.time() - t0) * 1000)
        return "ok", "连接正常 · %d 个模型 · %dms" % (len(ids), ms), "", len(ids), ms
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")[:400]
        kind, secs, why = classify_error(e.code, raw)
        ms = int((time.time() - t0) * 1000)
        if e.code in (404, 405):
            return "warn", "该服务未提供 /models 接口，无法自动确认（已按可用添加，建议稍后手动「拉模型」）", kind, 0, ms
        if e.code == 429:
            return "warn", "该密钥被上游限速（429），密钥本身有效", kind, 0, ms
        if kind == "quota":
            return "fail", "密钥余额不足 / 已欠费 —— 请到该服务商充值后再添加", kind, 0, ms
        if kind == "auth":
            return "fail", "密钥无效或已被禁用（认证失败）—— 请检查 API Key 是否复制完整", kind, 0, ms
        if kind == "server":
            return "fail", "上游服务器故障（HTTP %d），稍后再试" % e.code, kind, 0, ms
        return "fail", "上游返回异常（%s）" % short_err(e.code, raw), kind, 0, ms
    except Exception as e:
        ms = int((time.time() - t0) * 1000)
        return "fail", "连不上这个地址（%s）—— 请检查 Base URL 是否填对、结尾是否多了斜杠" % str(e)[:110], "net", 0, ms

def probe_one(kid):
    """★ 检测单个密钥：通 → 恢复可用；不通 → 重新计时"""
    try:
        with _lock:
            d = load_data()
        k = next((x for x in d["keys"] if x["id"] == kid), None)
        if not k or not k.get("enabled"):
            return
        try:
            real = decrypt(MASTER, k["key_enc"])
        except Exception:
            return
        ok, kind, secs, msg = probe_key(k["base_url"], real)
        with _lock:
            fresh = load_data()                       # ★ 重新读，避免覆盖并发改动
            kk = next((x for x in fresh["keys"] if x["id"] == kid), None)
            if kk is None:
                return
            if ok:
                mark_ok(kk)
                audit(fresh, "到期检测 ✅", "%s 已恢复，重新参与调度" % kk["name"], "probe")
            else:
                mark_fail(kk, kind, secs, msg)
                audit(fresh, "到期检测 ❌", "%s 仍不可用（%s）→ 再冷却 %s"
                      % (kk["name"], msg[:60], _fmt_secs(secs)), "probe")
            kk.setdefault("health", blank_health())["probe_done_at"] = time.time()
            save_data(fresh)
    except Exception:
        pass
    finally:
        _probing.discard(kid)

def _fmt_secs(s):
    return ("%d 分钟" % (s // 60)) if s >= 60 else ("%d 秒" % s)

def probe_loop():
    """★ 后台线程：发现「冷却刚到期」的密钥 → 主动检测一次"""
    while True:
        try:
            time.sleep(PROBE_INTERVAL)
            with _lock:
                d = load_data()
            due = [k for k in d["keys"]
                   if k.get("enabled") and pending_probe(k) and k["id"] not in _probing]
            for k in due:
                _probing.add(k["id"])
                threading.Thread(target=probe_one, args=(k["id"],), daemon=True).start()
        except Exception:
            pass

# ══════════════════════════ HTTP ══════════════════════════
class Handler(BaseHTTPRequestHandler):
    server_version = "AIKeyHub/1.0"
    protocol_version = "HTTP/1.1"

    # ── 输出工具 ──
    def _sec_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        # ★ 提前返回错误（401/403/400）时请求体还躺在缓冲区里，
        #   不丢掉的话会被 HTTP/1.1 keep-alive 当成"下一个请求行"解析
        #   → 日志里出现 `400 Bad request syntax`，客户端表现为偶发连接错乱
        n = int(self.headers.get("Content-Length") or 0)
        if n > 0 and not getattr(self, "_body_read", False):
            if n <= MAX_BODY:
                try: self.rfile.read(n)
                except Exception: pass
            else:
                self.close_connection = True
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._sec_headers()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, obj, extra=extra)

    def _err(self, code, msg):
        self._json(code, {"error": msg})

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        self._body_read = True                  # ★ 标记已消费
        if n <= 0:
            return {}
        if n > MAX_BODY:
            raise ValueError("请求体过大")
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("JSON 格式错误")

    # ── 会话 ──
    def _cookie_token(self):
        c = self.headers.get("Cookie") or ""
        m = re.search(r"(?:^|;\s*)ai_keys_session=([A-Za-z0-9_\-]+)", c)
        return m.group(1) if m else None

    def _authed(self):
        tok = self._cookie_token()
        if not tok:
            return False
        h = tok_hash(tok)
        s = _sessions.get(h)
        if not s:
            return False
        if s["exp"] <= time.time():       # ★ 严格 7 天，不做滑动续期
            _sessions.pop(h, None)
            save_sessions()
            return False
        s["last"] = time.time()
        return True

    def _ip(self):
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def _is_secure(self):
        """★ 当前连接是不是走的 TLS —— 用类型判断最可靠
           （往 socket 上挂自定义属性在某些路径下会丢，导致 HTTP 连接也被当成 HTTPS，
             于是 Set-Cookie 带上 Secure，浏览器直接不保存 → 会话彻底失效）"""
        return isinstance(self.connection, ssl.SSLSocket)

    def _check_csrf(self):
        # 变更类请求必须带自定义头（配合 SameSite=Strict 双重防护）
        return self.headers.get("X-Requested-With") == "fetch"

    def log_message(self, fmt, *args):
        sys.stdout.write("[%s] %s %s\n" % (now_str(), self._ip(), fmt % args))
        sys.stdout.flush()

    # ══════════ 路由 ══════════
    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p in ("/", "/index.html"):
            return self._static("index.html")
        # ★ favicon 必须免登录：登录页自己也要显示图标
        if p in ("/favicon.ico", "/favicon-16.png", "/favicon-32.png",
                 "/favicon-180.png", "/apple-touch-icon.png"):
            return self._favicon(p)
        if p == "/health":
            return self._json(200, {"ok": True, "service": "ai-key-hub", "time": now_str()})
        if p == "/api/session":
            d = load_data()
            ok = self._authed()
            st = {"gateway_url": self._gateway_url()}
            exp = 0
            if ok:                      # ★ 未登录不返回网关令牌
                st["gateway_token"] = d["settings"].get("gateway_token", "")
                st["model_alias"] = d["settings"].get("model_alias", "auto")
                s = _sessions.get(tok_hash(self._cookie_token() or "")) or {}
                exp = int(s.get("exp", 0))
            return self._json(200, {"logged_in": ok, "settings": st,
                                    "session_exp": exp,
                                    "session_ttl": SESSION_TTL,
                                    "now": int(time.time())})
        if p.startswith("/v1/"):
            return self._gateway(p)
        if not self._authed():
            return self._err(401, "未登录")
        if p == "/api/keys":
            d = load_data()
            return self._json(200, {"keys": [self._public(k) for k in d["keys"]],
                                    "settings": {"gateway_url": self._gateway_url(),
                                                 "gateway_token": d["settings"].get("gateway_token", ""),
                                                 "model_alias": d["settings"].get("model_alias", "auto")}})
        m = re.fullmatch(r"/api/keys/([0-9a-f]+)/reveal", p)
        if m:
            d = load_data()
            k = next((x for x in d["keys"] if x["id"] == m.group(1)), None)
            if not k:
                return self._err(404, "密钥不存在")
            try:
                real = decrypt(MASTER, k["key_enc"])
            except Exception as e:
                return self._err(500, "解密失败: %s" % e)
            audit(d, "查看明文", k["name"], self._ip()); save_data(d)
            return self._json(200, {"key": real})
        if p == "/api/logs":
            return self._json(200, {"logs": load_data()["logs"][:100]})
        if p == "/api/export":
            d = load_data()
            out = {"version": 1, "exported": now_str(), "keys": []}
            for k in d["keys"]:
                try:
                    real = decrypt(MASTER, k["key_enc"])
                except Exception:
                    real = ""
                out["keys"].append({"name": k["name"], "provider": k["provider"],
                                    "base_url": k["base_url"], "api_key": real,
                                    "models": k["models"], "tags": k["tags"],
                                    "note": k["note"], "enabled": k["enabled"]})
            audit(d, "导出备份", "共 %d 条" % len(out["keys"]), self._ip()); save_data(d)
            return self._send(200, json.dumps(out, ensure_ascii=False, indent=2),
                              "application/json; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="ai-keys-export.json"'})
        return self._err(404, "接口不存在")

    def do_HEAD(self):
        return self.do_GET()

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        if p == "/api/login":
            return self._login()
        if p.startswith("/v1/"):
            return self._gateway(p)

        if not self._authed():
            return self._err(401, "未登录")
        if not self._check_csrf():
            return self._err(403, "缺少 CSRF 校验头")

        try:
            body = self._read_json()
        except ValueError as e:
            return self._err(400, str(e))

        if p == "/api/keys":
            return self._create(body)
        if p == "/api/logout":
            tok = self._cookie_token()
            if tok:
                _sessions.pop(tok_hash(tok), None)
                save_sessions()
            return self._json(200, {"ok": True}, {"Set-Cookie":
                "ai_keys_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if p == "/api/password":
            return self._change_pw(body)
        if p == "/api/gateway-token":
            d = load_data()
            d["settings"]["gateway_token"] = "gw-" + secrets.token_urlsafe(24)
            audit(d, "重置网关令牌", "", self._ip()); save_data(d)
            return self._json(200, {"token": d["settings"]["gateway_token"]})
        if p == "/api/import":
            return self._import(body)
        m = re.fullmatch(r"/api/keys/([0-9a-f]+)/test", p)
        if m:
            return self._test(m.group(1))
        m = re.fullmatch(r"/api/keys/([0-9a-f]+)/models", p)
        if m:
            return self._pull(m.group(1))
        m = re.fullmatch(r"/api/keys/([0-9a-f]+)/reset", p)
        if m:
            return self._reset_health(m.group(1))
        m = re.fullmatch(r"/api/keys/([0-9a-f]+)/move", p)
        if m:
            return self._move(m.group(1), body)
        if p == "/api/test-all":
            return self._test_all()
        if p == "/api/fetch-models":
            return self._fetch_models(body)
        if p == "/api/settings":
            return self._save_settings(body)
        return self._err(404, "接口不存在")

    def do_PUT(self):
        p = urllib.parse.urlparse(self.path).path
        if not self._authed():
            return self._err(401, "未登录")
        if not self._check_csrf():
            return self._err(403, "缺少 CSRF 校验头")
        m = re.fullmatch(r"/api/keys/([0-9a-f]+)", p)
        if not m:
            return self._err(404, "接口不存在")
        try:
            body = self._read_json()
        except ValueError as e:
            return self._err(400, str(e))
        return self._update(m.group(1), body)

    def do_DELETE(self):
        p = urllib.parse.urlparse(self.path).path
        if not self._authed():
            return self._err(401, "未登录")
        if not self._check_csrf():
            return self._err(403, "缺少 CSRF 校验头")
        m = re.fullmatch(r"/api/keys/([0-9a-f]+)", p)
        if not m:
            return self._err(404, "接口不存在")
        with _lock:
            d = load_data()
            k = next((x for x in d["keys"] if x["id"] == m.group(1)), None)
            if not k:
                return self._err(404, "密钥不存在")
            d["keys"] = [x for x in d["keys"] if x["id"] != m.group(1)]
            audit(d, "删除密钥", k["name"], self._ip()); save_data(d)
        return self._json(200, {"ok": True})

    # ══════════ 业务 ══════════
    def _gateway_url(self):
        host = self.headers.get("Host") or ("localhost:%d" % DEFAULT_PORT)
        scheme = "https" if self._is_secure() else "http"
        return "%s://%s/v1" % (scheme, host)

    def _public(self, k):
        cd = cooldown_left(k)
        h = k.get("health") or blank_health()
        return {"id": k["id"], "name": k["name"], "provider": k["provider"],
                "base_url": k["base_url"], "key_hint": k["key_hint"],
                "models": k["models"], "tags": k["tags"], "note": k["note"],
                "enabled": k["enabled"], "created": k["created"],
                "updated": k.get("updated", ""), "last_test": k.get("last_test"),
                "priority": k.get("priority", 999),
                "state": key_state(k), "probing": k["id"] in _probing,
                "probe_done_at": h.get("probe_done_at", 0),
                "available": bool(k["enabled"]) and cd == 0,
                "cooling": cd > 0, "cooldown_left": cd,
                "fails": h.get("fails", 0), "oks": h.get("oks", 0),
                "reason": h.get("reason", ""), "last_error": h.get("last_error", ""),
                "last_error_at": h.get("last_error_at", "")}

    def _login(self):
        ip = self._ip()
        now = time.time()
        hist = [t for t in _attempts.get(ip, []) if now - t < LOGIN_WINDOW]
        if len(hist) >= LOGIN_MAX:
            return self._err(429, "尝试次数过多，请 %d 分钟后再试" % (LOGIN_WINDOW // 60))
        try:
            body = self._read_json()
        except ValueError as e:
            return self._err(400, str(e))
        d = load_data()
        if not d["auth"]:
            return self._err(500, "系统未初始化口令，请重启服务")
        if not pw_verify(body.get("password", ""), d["auth"]):
            hist.append(now); _attempts[ip] = hist
            audit(d, "登录失败", "剩余尝试 %d" % (LOGIN_MAX - len(hist)), ip); save_data(d)
            return self._err(401, "口令错误（还可尝试 %d 次）" % (LOGIN_MAX - len(hist)))
        _attempts.pop(ip, None)
        remember = body.get("remember")
        remember = True if remember is None else bool(remember)
        ttl = SESSION_TTL if remember else SESSION_SHORT
        tok = secrets.token_urlsafe(32)
        purge_sessions()
        _sessions[tok_hash(tok)] = {"exp": now + ttl, "created": now, "last": now,
                                    "ip": ip, "remember": remember}
        save_sessions()
        audit(d, "登录成功", "记住 %s" % ("7 天" if remember else "本次"), ip); save_data(d)
        sec = "; Secure" if self._is_secure() else ""
        # ★ 不勾「记住我」→ 不带 Max-Age（会话 Cookie，关浏览器就失效）
        age = ("; Max-Age=%d" % ttl) if remember else ""
        return self._json(200, {"ok": True, "remember": remember, "expires_in": ttl}, {"Set-Cookie":
            "ai_keys_session=%s; Path=/; HttpOnly; SameSite=Strict%s%s" % (tok, age, sec)})

    def _create(self, body):
        name = (body.get("name") or "").strip()
        url = (body.get("base_url") or "").strip().rstrip("/")
        pw = (body.get("api_key") or "").strip()
        if not name or not url or not pw:
            return self._err(400, "名称 / Base URL / API Key 均为必填")

        # ★ 保存前先测一次：通了才添加，不通直接报错不落库
        tested = None
        if not body.get("skip_test"):
            level, msg, kind, count, ms = probe_new_key(url, pw)
            tested = {"level": level, "msg": msg, "kind": kind, "count": count, "ms": ms}
            if level == "fail":
                return self._json(400, {
                    "error": "检测未通过，未添加：%s" % msg,
                    "test": tested})

        with _lock:
            d = load_data()
            prio = None
            try:
                prio = int(body.get("priority")) if body.get("priority") not in (None, "") else None
            except Exception:
                prio = None
            if prio is None:
                prio = 1 + max([x.get("priority", 0) for x in d["keys"]] or [0])
            k = {"id": secrets.token_hex(8), "name": name,
                 "provider": (body.get("provider") or "").strip(),
                 "base_url": url, "key_enc": encrypt(MASTER, pw), "key_hint": key_hint(pw),
                 "models": body.get("models") or [], "tags": body.get("tags") or [],
                 "note": body.get("note") or "", "enabled": bool(body.get("enabled", True)),
                 "priority": prio, "health": blank_health(),
                 "created": now_str(), "updated": now_str(),
                 "last_test": ({"at": now_str(),
                                "ok": tested["level"] == "ok",
                                "msg": tested["msg"]} if tested else None)}
            d["keys"].insert(0, k)
            audit(d, "新增密钥", "%s（顺序 %d）%s" % (name, prio,
                  " · " + tested["msg"] if tested else ""), self._ip()); save_data(d)
        return self._json(200, {"ok": True, "id": k["id"], "test": tested})

    def _update(self, kid, body):
        with _lock:
            d = load_data()
            k = next((x for x in d["keys"] if x["id"] == kid), None)
            if not k:
                return self._err(404, "密钥不存在")
            for f in ("name", "provider", "note"):
                if f in body and body[f] is not None:
                    k[f] = str(body[f]).strip()
            if body.get("base_url"):
                k["base_url"] = str(body["base_url"]).strip().rstrip("/")
            if isinstance(body.get("models"), list):
                k["models"] = [str(x).strip() for x in body["models"] if str(x).strip()]
            if isinstance(body.get("tags"), list):
                k["tags"] = [str(x).strip() for x in body["tags"] if str(x).strip()]
            if "enabled" in body:
                k["enabled"] = bool(body["enabled"])
            if body.get("priority") not in (None, ""):
                try:
                    k["priority"] = int(body["priority"])
                except Exception:
                    pass
            if body.get("api_key"):
                k["key_enc"] = encrypt(MASTER, str(body["api_key"]).strip())
                k["key_hint"] = key_hint(str(body["api_key"]).strip())
            k["updated"] = now_str()
            audit(d, "修改密钥", k["name"], self._ip()); save_data(d)
        return self._json(200, {"ok": True})

    def _change_pw(self, body):
        old, new = body.get("old", ""), body.get("new", "")
        if len(new) < 6:
            return self._err(400, "新口令至少 6 位")
        with _lock:
            d = load_data()
            if not pw_verify(old, d["auth"]):
                return self._err(401, "当前口令不正确")
            salt, h, iters = pw_hash(new)
            d["auth"] = {"salt": salt, "hash": h, "iterations": iters}
            _sessions.clear(); save_sessions()
            audit(d, "修改口令", "所有会话已注销", self._ip()); save_data(d)
            try:                       # ★ 同步更新口令备忘文件，别留下过期口令
                pf = os.path.join(DATA_DIR, "初始口令.txt")
                with open(pf, "w", encoding="utf-8") as f:
                    f.write(new + "\n")
                os.chmod(pf, 0o600)
            except Exception:
                pass
        return self._json(200, {"ok": True})

    def _import(self, body):
        items = body.get("keys") if isinstance(body, dict) else body
        if not isinstance(items, list):
            return self._err(400, "格式错误：需要 keys 数组")
        added = updated = 0
        with _lock:
            d = load_data()
            for it in items:
                name = (it.get("name") or "").strip()
                url = (it.get("base_url") or "").strip().rstrip("/")
                pw = (it.get("api_key") or "").strip()
                if not (name and url and pw):
                    continue
                old = next((x for x in d["keys"] if x["name"] == name and x["base_url"] == url), None)
                if old:
                    old.update({"provider": it.get("provider") or old["provider"],
                                "key_enc": encrypt(MASTER, pw), "key_hint": key_hint(pw),
                                "models": it.get("models") or old["models"],
                                "tags": it.get("tags") or old["tags"],
                                "note": it.get("note", old["note"]),
                                "enabled": bool(it.get("enabled", True)),
                                "updated": now_str()})
                    updated += 1
                else:
                    d["keys"].insert(0, {"id": secrets.token_hex(8), "name": name,
                        "provider": it.get("provider") or "", "base_url": url,
                        "key_enc": encrypt(MASTER, pw), "key_hint": key_hint(pw),
                        "models": it.get("models") or [], "tags": it.get("tags") or [],
                        "note": it.get("note") or "", "enabled": bool(it.get("enabled", True)),
                        "created": now_str(), "updated": now_str(), "last_test": None})
                    added += 1
            audit(d, "导入备份", "新增 %d 更新 %d" % (added, updated), self._ip()); save_data(d)
        return self._json(200, {"ok": True, "added": added, "updated": updated})

    # ── 上游调用 ──
    def _upstream(self, base_url, api_key, sub, timeout=20):
        url = base_url.rstrip("/") + sub
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "AIKeyHub/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    def _get_key(self, kid):
        d = load_data()
        k = next((x for x in d["keys"] if x["id"] == kid), None)
        if not k:
            return None, None, None
        try:
            return k, decrypt(MASTER, k["key_enc"]), d
        except Exception:
            return k, None, d

    def _test(self, kid):
        k, real, d = self._get_key(kid)
        if not k:
            return self._err(404, "密钥不存在")
        if real is None:
            return self._json(200, {"ok": False, "msg": "解密失败"})
        # ★ 真发一条对话消息来判断（不再是只看 /models 能不能列出来）
        model = resolve_test_model(k, real)
        if not model:
            m2 = "该密钥还没登记模型名 —— 请先点「✏️ 编辑」填写模型后重试"
            k["last_test"] = {"at": now_str(), "ok": False, "msg": m2}
            with _lock:
                save_data(d)
            return self._json(200, {"ok": False, "msg": m2, "need_model": True})
        ok, kind, secs, msg, reply, ms = test_chat(k["base_url"], real, model)
        with _lock:
            # ★ 重新读盘再合并：测试要花几十秒，期间可能有人改了别的密钥
            fresh = load_data()
            kk = next((x for x in fresh["keys"] if x["id"] == kid), None)
            if kk is None:
                return self._json(200, {"ok": ok, "msg": msg})
            if ok:
                mark_ok(kk)                     # 通了 → 顺手清冷却，恢复参与调度
                kk["last_test"] = {"at": now_str(), "ok": True,
                                   "msg": "对话正常 · %s · %dms" % (model, ms)}
                audit(fresh, "手动测试 ✅", "%s 对话正常（%s · %dms）" % (kk["name"], model, ms),
                      self._ip())
            else:
                mark_fail(kk, kind, secs, msg)  # 不通 → 按类型冷却（同网关逻辑）
                kk["last_test"] = {"at": now_str(), "ok": False, "msg": msg}
                audit(fresh, "手动测试 ❌", "%s 不可用（%s）→ 冷却 %s"
                      % (kk["name"], msg[:60], _fmt_secs(secs)), self._ip())
            save_data(fresh)
        if ok:
            return self._json(200, {"ok": True, "model": model, "ms": ms,
                                    "reply": reply, "msg": "对话正常"})
        return self._json(200, {"ok": False, "msg": msg, "kind": kind, "cooldown": secs})

    def _pull(self, kid):
        k, real, d = self._get_key(kid)
        if not k:
            return self._err(404, "密钥不存在")
        if real is None:
            return self._json(200, {"ok": False, "msg": "解密失败"})
        try:
            j = self._upstream(k["base_url"], real, "/models", timeout=20)
            ids = sorted({m.get("id") for m in (j.get("data") or []) if m.get("id")})
            return self._json(200, {"ok": True, "models": ids})
        except urllib.error.HTTPError as e:
            return self._json(200, {"ok": False, "msg": "HTTP %s" % e.code})
        except Exception as e:
            return self._json(200, {"ok": False, "msg": "%s: %s" % (type(e).__name__, str(e)[:150])})

    # ── OpenAI 兼容网关 ──
    def _gw_auth(self):
        d = load_data()
        want = d["settings"].get("gateway_token") or ""
        if not want:
            return None
        h = self.headers.get("Authorization") or ""
        tok = h[7:].strip() if h.lower().startswith("bearer ") else (self.headers.get("x-api-key") or "")
        if hmac.compare_digest(tok, want):
            return d
        return None

    def _gw_candidates(self, d, model):
        """按【顺序】排出候选密钥；冷却中的排到最后（全冷却时也会尝试，避免硬失败）"""
        keys = [k for k in d["keys"] if k["enabled"]]
        if not keys:
            return []
        ml = (model or "").lower()

        def tier(k):
            ms = [m.lower() for m in (k.get("models") or [])]
            if not ml:
                return 0
            if ml in ms:
                return 0
            if not ms:                      # 没登记模型 → 可能支持，作为第二梯队
                return 1
            if any(m.startswith(ml) or ml.startswith(m) for m in ms):
                return 0
            return 2

        live = [k for k in keys if not cooling(k) and not pending_probe(k)]
        pool = live if live else keys       # 全在冷却 → 仍然按顺序硬试
        pool.sort(key=lambda k: (tier(k), k.get("priority", 999)))
        return pool

    def _gw_save(self, d, action, detail, src_k=None):
        """★ 只把「这一个密钥的健康状态 + 日志」合并进最新数据，避免整体覆盖。
           ★ 必须传【对象本身】而不是 id：d["keys"] 在循环中被重绑过，
             按 id 查会查到没被标记过的新对象，把冷却状态丢掉。"""
        with _lock:
            fresh = load_data()
            if src_k is not None:
                dst = next((x for x in fresh["keys"] if x["id"] == src_k["id"]), None)
                if dst is not None:
                    dst["health"] = src_k.get("health") or blank_health()
            audit(fresh, action, detail, self._ip())
            save_data(fresh)

    def _gw_stream(self, r, k, n):
        try:
            first = r.read(1)               # 先探一个字节，失败还能切下一家
        except Exception:
            r.close()
            return self._json(502, {"error": {"message": "上游流中断"}})
        self.send_response(200)
        self.send_header("Content-Type", r.headers.get("Content-Type", "text/event-stream"))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-AIKeyHub-Provider", urllib.parse.quote(k.get("name", "")))
        self.send_header("X-AIKeyHub-Attempts", str(n))
        self.send_header("Connection", "close")
        self._sec_headers()
        self.end_headers()
        self.close_connection = True
        try:
            if first:
                self.wfile.write(first); self.wfile.flush()
            while True:
                chunk = r.read(2048)
                if not chunk:
                    break
                self.wfile.write(chunk); self.wfile.flush()
        except Exception:
            pass
        finally:
            r.close()

    def _gw_chat(self, d, body):
        """★ 按顺序尝试，失败/限速/欠费自动跳过下一家"""
        alias = (d["settings"].get("model_alias") or "auto").strip()
        model = (body.get("model") or "").strip()
        # ★ 客户端填「设置里配的那个模型名」= 综合模型（自动挑可用密钥）
        auto = (not model) or model.lower() in ("auto", "综合", "自动") or model == alias
        if "/" in model and not auto:
            prov, _, mid = model.partition("/")
            model = mid
            auto = False
            body = dict(body); body["model"] = mid
        cands = self._gw_candidates(d, "" if auto else model)
        if not cands:
            return self._json(503, {"error": {"message": "没有可用的已启用密钥",
                                              "type": "no_available_key"}})
        stream = bool(body.get("stream"))
        attempts = []
        for idx, k in enumerate(cands):
            try:
                real = decrypt(MASTER, k["key_enc"])
            except Exception:
                mark_fail(k, "other", 600, "本地解密失败")
                attempts.append({"provider": k["name"], "error": "本地解密失败"})
                continue

            payload = dict(body)
            if auto:
                payload["model"] = (k.get("models") or [model or "auto"])[0]

            url = k["base_url"].rstrip("/") + "/chat/completions"
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"), method="POST",
                headers={"Authorization": "Bearer " + real,
                         "Content-Type": "application/json",
                         "Accept": "text/event-stream" if stream else "application/json",
                         "User-Agent": "AIKeyHub/1.0"})
            t0 = time.time()
            try:
                r = urllib.request.urlopen(req, timeout=600)
            except urllib.error.HTTPError as e:
                raw = e.read().decode("utf-8", "replace")
                kind, secs, why = classify_error(e.code, raw)
                mark_fail(k, kind, secs, short_err(e.code, raw))
                attempts.append({"provider": k["name"], "status": e.code,
                                 "kind": kind, "cooldown": secs, "error": raw[:200]})
                self._gw_save(d, "故障转移 ⏭", "%s 失败(%s) → 尝试下一个 · %s"
                              % (k["name"], why, model or "auto"), k)
                continue
            except Exception as e:
                kind, secs, why = classify_error(0, str(e))
                mark_fail(k, kind, secs, str(e)[:150])
                attempts.append({"provider": k["name"], "kind": kind,
                                 "cooldown": secs, "error": str(e)[:200]})
                self._gw_save(d, "故障转移 ⏭", "%s 网络失败 → 尝试下一个 · %s"
                              % (k["name"], model or "auto"), k)
                continue

            # ✅ 这家成功
            ms = int((time.time() - t0) * 1000)
            mark_ok(k)
            self._gw_save(d, "网关转发 ✅", "%s ← %s · %dms · 第%d次尝试"
                          % (model or "auto", k["name"], ms, idx + 1), k)
            if stream:
                return self._gw_stream(r, k, idx + 1)
            data = r.read()
            ct = r.headers.get("Content-Type", "application/json")
            r.close()
            return self._send(200, data, ct, {
                "X-AIKeyHub-Provider": urllib.parse.quote(k.get("name", "")),
                "X-AIKeyHub-Attempts": str(idx + 1)})

        self._gw_save(d, "网关失败 ❌", "全部 %d 个密钥都不可用 · %s" % (len(attempts), model or "auto"))
        return self._json(502, {"error": {
            "message": "所有密钥均不可用（已依次尝试 %d 个）" % len(attempts),
            "type": "all_keys_failed", "attempts": attempts}})

    def _reset_health(self, kid):
        with _lock:
            d = load_data()
            k = next((x for x in d["keys"] if x["id"] == kid), None)
            if not k:
                return self._err(404, "密钥不存在")
            heal(k)
            audit(d, "重置健康状态", k["name"], self._ip()); save_data(d)
        return self._json(200, {"ok": True})

    def _move(self, kid, body):
        direction = (body.get("direction") or "").lower()
        with _lock:
            d = load_data()
            order = sorted(d["keys"], key=lambda x: x.get("priority", 999))
            i = next((n for n, x in enumerate(order) if x["id"] == kid), None)
            if i is None:
                return self._err(404, "密钥不存在")
            j = i - 1 if direction == "up" else i + 1
            if not (0 <= j < len(order)):        # ★ 已在两端 → 直接返回，别越界
                return self._json(200, {"ok": True, "moved": False})
            order[i]["priority"], order[j]["priority"] = \
                order[j].get("priority", 999), order[i].get("priority", 999)
            # 顺序值可能相等（比如都是默认值），改用显式重排
            if order[i]["priority"] == order[j]["priority"]:
                for n, x in enumerate(order):
                    x["priority"] = n + 1
            for n, x in enumerate(sorted(order, key=lambda y: y.get("priority", 999))):
                x["priority"] = n + 1
            audit(d, "调整顺序", "%s ↔ %s" % (order[j]["name"], order[i]["name"]), self._ip())
            save_data(d)
        return self._json(200, {"ok": True, "moved": True})

    def _save_settings(self, body):
        """★ 保存「客户端连接时填写的模型名称」"""
        alias = (body.get("model_alias") or "").strip()
        if not alias:
            return self._err(400, "模型名称不能为空")
        if len(alias) > 64:
            return self._err(400, "模型名称太长（最多 64 个字符）")
        if any(c.isspace() for c in alias):
            return self._err(400, "模型名称不能包含空格")
        with _lock:
            d = load_data()
            old = d["settings"].get("model_alias", "auto")
            d["settings"]["model_alias"] = alias
            audit(d, "修改网关模型名", "%s → %s" % (old, alias), self._ip())
            save_data(d)
        return self._json(200, {"ok": True, "model_alias": alias})

    def _fetch_models(self, body):
        """★ 用【表单里当前填的】Base URL + API Key 实时拉模型列表
           —— 新增时还没保存，所以不能只靠 key id；Key 留空则回退到已存的明文"""
        url = (body.get("base_url") or "").strip().rstrip("/")
        pw = (body.get("api_key") or "").strip()
        if not pw and body.get("id"):
            _, real, _ = self._get_key(body["id"])
            pw = real or ""
        if not url:
            return self._json(200, {"ok": False, "msg": "请先填写 Base URL"})
        if not pw:
            return self._json(200, {"ok": False, "msg": "请先填写 API Key"})
        try:
            j = self._upstream(url, pw, "/models", timeout=20)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")[:300]
            kind, secs, why = classify_error(e.code, raw)
            if e.code in (404, 405):
                return self._json(200, {"ok": False, "msg": "该服务没有 /models 接口（HTTP %d），请手动填写模型名" % e.code})
            return self._json(200, {"ok": False, "msg": "%s（%s）" % (why, short_err(e.code, raw))})
        except Exception as e:
            return self._json(200, {"ok": False, "msg": "连不上：%s" % str(e)[:130]})
        ids = sorted({str(m.get("id")) for m in (j.get("data") or []) if m.get("id")})
        if not ids:
            return self._json(200, {"ok": False, "msg": "接口通了，但没返回任何模型"})
        return self._json(200, {"ok": True, "models": ids, "count": len(ids)})

    def _test_all(self):
        """批量测试所有已启用密钥，失败自动标记冷却"""
        d = load_data()
        out = []
        for k in d["keys"]:
            if not k["enabled"]:
                continue
            # ★ 同样真发一条对话消息（先解密，再决定模型名）
            try:
                real = decrypt(MASTER, k["key_enc"])
            except Exception:
                kind, secs, why = classify_error(0, "本地解密失败")
                mark_fail(k, kind, secs, "本地解密失败")
                out.append({"name": k["name"], "ok": False, "msg": why, "cooldown": secs})
                continue
            model = resolve_test_model(k, real)
            if not model:
                out.append({"name": k["name"], "ok": False, "need_model": True,
                            "msg": "未登记模型名（请先编辑填写）"})
                continue
            ok, kind, secs, msg, reply, ms = test_chat(k["base_url"], real, model)
            if ok:
                mark_ok(k)
                out.append({"name": k["name"], "ok": True, "model": model,
                            "ms": ms, "reply": reply})
            else:
                mark_fail(k, kind, secs, msg)
                out.append({"name": k["name"], "ok": False, "msg": msg,
                            "kind": kind, "cooldown": secs})
        with _lock:                       # ★ 只合并 health，别覆盖并发新增
            fresh = load_data()
            hmap = {x["id"]: x.get("health") for x in d["keys"]}
            for x in fresh["keys"]:
                if hmap.get(x["id"]):
                    x["health"] = hmap[x["id"]]
            save_data(fresh)
        return self._json(200, {"results": out})

    def _gateway(self, path):
        d = self._gw_auth()
        if d is None:
            return self._json(401, {"error": {"message": "无效的网关令牌",
                                              "type": "invalid_request_error"}})
        if path.rstrip("/") == "/v1/models":
            alias = (d["settings"].get("model_alias") or "auto").strip()
            out = [{"id": alias, "object": "model", "created": 0,
                    "owned_by": "综合网关（自动挑可用密钥）"}]
            seen = {alias}
            for k in d["keys"]:
                if not k["enabled"]:
                    continue
                for m in (k["models"] or []):
                    if m in seen:
                        continue
                    seen.add(m)
                    out.append({"id": m, "object": "model", "created": 0,
                                "owned_by": k["provider"] or k["name"]})
            return self._json(200, {"object": "list", "data": out})

        if not path.rstrip("/").endswith("/chat/completions"):
            return self._json(404, {"error": {"message": "暂不支持的网关路径: " + path}})

        try:
            body = self._read_json()
        except ValueError as e:
            return self._json(400, {"error": {"message": str(e)}})
        return self._gw_chat(d, body)

    # ── 静态 ──
    def _favicon(self, p):
        """网站图标：.ico 找不到就用 32px PNG 顶上（浏览器都认）"""
        MIME = {".png": "image/png", ".ico": "image/x-icon"}
        cand = {"favicon.ico": ["favicon.ico", "favicon-32.png"],
                "favicon-16.png": ["favicon-16.png", "favicon-32.png"],
                "favicon-32.png": ["favicon-32.png"],
                "favicon-180.png": ["favicon-180.png", "favicon-32.png"],
                "apple-touch-icon.png": ["favicon-180.png"]}.get(p, [p.lstrip("/")])
        for n in cand:
            fp = os.path.join(STATIC_DIR, n)
            if os.path.isfile(fp):
                with open(fp, "rb") as f:
                    data = f.read()
                ct = MIME.get(os.path.splitext(n)[1].lower(), "application/octet-stream")
                return self._send(200, data, ct, extra={"Cache-Control": "public, max-age=86400"})
        return self._send(404, b"", "text/plain")

    def _static(self, name):
        path = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(path):
            return self._err(404, "文件不存在")
        with open(path, "rb") as f:
            data = f.read()
        return self._send(200, data, "text/html; charset=utf-8")


# ══════════════════════════ TLS Server ══════════════════════════
class SecureServer(ThreadingHTTPServer):
    """★ 同一个端口同时支持 HTTPS 和普通 HTTP：
       看连接的第一个字节 —— 0x16 是 TLS ClientHello → 套 TLS；否则当普通 HTTP 处理。
       这样客户端就算拒绝自签证书，也能改用 http:// 连上（不用改端口/安全组）。"""
    daemon_threads = True
    allow_reuse_address = True
    is_https = False

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.ssl_ctx is None:
            return sock, addr
        sock.settimeout(15)
        try:
            peek = sock.recv(1, socket.MSG_PEEK)
        except Exception:
            try: sock.close()
            except Exception: pass
            raise
        if peek == b"\x16":                      # TLS 握手
            try:
                sock = self.ssl_ctx.wrap_socket(sock, server_side=True)
                sock.settimeout(None)
                return sock, addr
            except Exception:
                try: sock.close()
                except Exception: pass
                raise
        sock.settimeout(None)                     # 普通 HTTP：原样返回
        try: sock._plain = True
        except Exception: pass
        return sock, addr


def main():
    global MASTER
    ap = argparse.ArgumentParser(description="AI 密钥管理中心")
    ap.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("-d", "--data-dir", default=DATA_DIR)
    ap.add_argument("--static", default=STATIC_DIR)
    ap.add_argument("--cert", default=os.path.join(CERT_DIR, "cert.pem"))
    ap.add_argument("--key", default=os.path.join(CERT_DIR, "key.pem"))
    ap.add_argument("--no-tls", action="store_true", help="改用纯 HTTP（不推荐）")
    ap.add_argument("--set-password", metavar="NEW", help="直接设置新口令后退出")
    ap.add_argument("--set-password-stdin", action="store_true",
                    help="从标准输入读一行作为新口令后退出（避免口令出现在 ps 里）")
    a = ap.parse_args()

    if a.set_password_stdin:
        line = sys.stdin.readline()
        if not line.strip():
            print("❌ 没有从标准输入读到口令")
            return
        a.set_password = line.rstrip("\r\n")

    for k, v in (("DATA_DIR", a.data_dir), ("STATIC_DIR", a.static)):
        globals()[k] = v
    globals()["DATA_FILE"] = os.path.join(a.data_dir, "data.json")
    globals()["MASTER_FILE"] = os.path.join(a.data_dir, "master.key")
    globals()["SESSION_FILE"] = os.path.join(a.data_dir, "sessions.json")
    load_sessions()

    MASTER = load_master()
    os.makedirs(DATA_DIR, exist_ok=True)

    with _lock:
        d = load_data()
        if not d["settings"].get("gateway_token"):
            d["settings"]["gateway_token"] = "gw-" + secrets.token_urlsafe(24)
        d["settings"].setdefault("model_alias", "auto")

        if a.set_password:
            salt, h, iters = pw_hash(a.set_password)
            d["auth"] = {"salt": salt, "hash": h, "iterations": iters}
            save_data(d)
            print("✅ 口令已设置")
            return

        if not d["auth"]:
            pw = gen_password()
            salt, h, iters = pw_hash(pw)
            d["auth"] = {"salt": salt, "hash": h, "iterations": iters}
            audit(d, "系统初始化", "生成初始口令", "local")
            save_data(d)
            with open(os.path.join(DATA_DIR, "初始口令.txt"), "w", encoding="utf-8") as f:
                f.write(pw + "\n")
            os.chmod(os.path.join(DATA_DIR, "初始口令.txt"), 0o600)
            print("=" * 58)
            print("  🔐 初始访问口令： " + pw)
            print("  （已同时保存到 %s/初始口令.txt）" % DATA_DIR)
            print("=" * 58)
        save_data(d)

    handler = Handler
    srv = SecureServer(("0.0.0.0", a.port), handler)
    srv.ssl_ctx = None
    scheme = "http"
    if not a.no_tls and os.path.exists(a.cert) and os.path.exists(a.key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.cert, a.key)
        srv.ssl_ctx = ctx
        srv.is_https = True
        scheme = "https"
    threading.Thread(target=probe_loop, daemon=True).start()   # ★ 冷却到期主动检测
    print("🎛️  AI 密钥管理中心已启动")
    print("    端口 %d 同时支持：https:// （自签证书）和 http:// （给不接受自签证书的客户端）"
          % a.port)
    print("    数据: %s" % DATA_DIR)
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    MASTER = b""
    main()
