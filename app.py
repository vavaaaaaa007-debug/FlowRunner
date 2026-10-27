import os, sys, json, subprocess, sqlite3, threading, time, datetime, pathlib, shutil, re, itertools
import hmac, hashlib, base64, struct, urllib.parse, secrets
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import uvicorn
import flow_driver as fd

BASE = pathlib.Path(getattr(sys, "_MEIPASS", pathlib.Path(__file__).parent))  # 打包后资源在 _MEIPASS

def user_data_dir():
    """数据（账号库、登录状态、下载文件）放在每个人自己的用户目录，不放在程序目录里。
    可用环境变量 FLOW_DATA 指定别的位置。"""
    if os.getenv("FLOW_DATA"): return pathlib.Path(os.environ["FLOW_DATA"])
    home = pathlib.Path.home()
    if sys.platform == "darwin": base = home / "Library" / "Application Support"
    elif sys.platform.startswith("win"): base = pathlib.Path(os.getenv("APPDATA") or home / "AppData" / "Roaming")
    else: base = pathlib.Path(os.getenv("XDG_DATA_HOME") or home / ".local" / "share")
    return base / "FlowRunner"

DATA = user_data_dir(); PROFILES = DATA / "profiles"; OUT = DATA / "outputs"
for d in (PROFILES, OUT): d.mkdir(parents=True, exist_ok=True)
# 数据目录仅本人可访问（Mac/Linux；Windows 上靠用户目录 ACL，本程序不改 ACL）
for _d in (DATA, PROFILES, OUT):
    try: os.chmod(_d, 0o700)
    except Exception: pass
DB = sqlite3.connect(DATA / "pool.db", check_same_thread=False)
DB.row_factory = sqlite3.Row
try: os.chmod(DATA / "pool.db", 0o600)  # 仅本人可读（Mac/Linux）
except Exception: pass
LOCK = threading.Lock()
BUSY = set()  # 正在使用的账号 id
WORKERS = int(os.getenv("WORKERS", "2"))
today = lambda: str(datetime.date.today())

# ---- 主密码（方案 C）+ 凭据静态加密（Fernet）----
# 账号池的密码 / TOTP 密钥以 Fernet 密文存进 pool.db，加密密钥由用户
# 设定的「主密码」派生，绝不以明文落盘：
#   * 首次使用：设置主密码（≥8 位），程序用 PBKDF2-HMAC-SHA256
#     （60 万次迭代，随机 16 字节盐）从主密码派生 32 字节密钥；
#   * 每次启动 / 每次打开新浏览器会话：输入主密码解锁后才能进入
#     账号池；密钥只存在内存里，重启、锁定后即失效；
#   * 磁盘上只存盐 + 一段校验密文（.master.json，0600），不存主密码
#     本身，也不存可直接解密的密钥。
# 忘记主密码 = 无法解密已存的账号密码/TOTP，只能删库重新填写账号，
# 这是主密码方案的固有代价（见 README）。请把主密码记在密码管理器里。
# 旧的 .secret.key / FLOW_SECRET_KEY 只在「首次设置主密码」时作为
# 迁移来源（解密旧密文再用主密码重加密），迁移成功后 .secret.key
# 会被删除；此后 FLOW_SECRET_KEY 不再生效，不要再设置它。
_MASTER_FILE = DATA / ".master.json"
_PBKDF2_ITERS = 600_000
_CHECK_PLAINTEXT = b"flowrunner-master-check-v1"
FERNET = None            # 当前解锁后的 Fernet 实例，只在内存里；锁定后为 None
_SESSION_TOKEN = None    # 解锁后发给浏览器的会话令牌（sessionStorage），重启/锁定后失效
_LOCKED = True
_LEGACY_FERNET = None    # 旧方案的密钥（.secret.key / FLOW_SECRET_KEY），仅用于首次迁移
_FAILS = {"n": 0, "until": 0.0}  # 解锁失败计数与锁定截止时间（防暴力猜测）

def _derive_fernet(password: str, salt: bytes) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERS)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))

def _read_master():
    try:
        d = json.loads(_MASTER_FILE.read_text())
        salt = base64.b64decode(d["salt"]); check = d["check"]
        if len(salt) != 16 or not isinstance(check, str): return None
        return {"salt": salt, "check": check, "iters": int(d.get("iters", _PBKDF2_ITERS))}
    except Exception:
        return None

def _has_master() -> bool:
    return _read_master() is not None

def _write_master(salt: bytes, check: str):
    _MASTER_FILE.write_text(json.dumps({"salt": base64.b64encode(salt).decode(),
                                        "check": check, "iters": _PBKDF2_ITERS}))
    try: os.chmod(_MASTER_FILE, 0o600)
    except Exception: pass

def _is_locked() -> bool:
    return _LOCKED or FERNET is None

def _valid_session(request: Request) -> bool:
    if _SESSION_TOKEN is None: return False
    tok = request.headers.get("x-flow-unlock", "")
    if tok and secrets.compare_digest(tok, _SESSION_TOKEN): return True
    # /api/file 的预览/下载是 <a>/<img> 标签发出的，带不了自定义请求头，
    # 只允许该接口用查询参数传令牌（本机服务、会话令牌、阅后即焚的用法）。
    if request.url.path == "/api/file":
        tok = request.query_params.get("unlock_token", "")
        if tok and secrets.compare_digest(tok, _SESSION_TOKEN): return True
    return False

def _lock():
    global FERNET, _SESSION_TOKEN, _LOCKED
    FERNET = None; _SESSION_TOKEN = None; _LOCKED = True

def _unlock_with(password: str) -> str:
    """用主密码解锁：派生密钥并解密校验值，成功才把密钥放进内存。"""
    global FERNET, _SESSION_TOKEN, _LOCKED
    m = _read_master()
    if not m: raise ValueError("尚未设置主密码")
    f = _derive_fernet(password, m["salt"])
    try: f.decrypt(m["check"].encode())
    except InvalidToken: raise ValueError("主密码不正确")
    FERNET = f; _LOCKED = False
    _SESSION_TOKEN = secrets.token_urlsafe(32)
    _FAILS["n"] = 0; _FAILS["until"] = 0.0
    return _SESSION_TOKEN

def _load_legacy_fernet():
    """只读旧密钥，不再自动生成 .secret.key（主密码方案下不再需要它）。"""
    env_key = os.getenv("FLOW_SECRET_KEY")
    if env_key:
        try: return Fernet(env_key.strip().encode())
        except Exception: return None
    kf = DATA / ".secret.key"
    if kf.exists():
        try: return Fernet(kf.read_bytes().strip())
        except Exception: return None
    return None

def _decrypt_with(fernet, v):
    """用指定密钥解密一个字段；无 enc:v1: 前缀的是旧明文，直接返回原文。"""
    if not v: return ""
    if isinstance(v, str) and v.startswith(_ENC_PREFIX):
        if fernet is None: raise ValueError("旧凭据无法解密：缺少旧密钥（.secret.key 或 FLOW_SECRET_KEY）")
        return fernet.decrypt(v[len(_ENC_PREFIX):].encode()).decode()
    return v

def _reencrypt_all(old_fernet, new_fernet):
    """把全部账号的 password/totp 用新密钥重加密（设置主密码 / 改主密码时用）。"""
    try:
        rows = DB.execute("SELECT id, password, totp FROM accounts").fetchall()
    except sqlite3.OperationalError:
        return
    for r in rows:
        pw = _decrypt_with(old_fernet, r["password"] or "")
        tp = _decrypt_with(old_fernet, r["totp"] or "")
        DB.execute("UPDATE accounts SET password=?, totp=? WHERE id=?",
                   (_ENC_PREFIX + new_fernet.encrypt(pw.encode()).decode() if pw else "",
                    _ENC_PREFIX + new_fernet.encrypt(tp.encode()).decode() if tp else "", r["id"]))
    DB.commit()
    try: DB.execute("VACUUM")  # 擦除旧密文/明文在空闲页里的残留
    except Exception: pass

_ENC_PREFIX = "enc:v1:"

def enc_value(v):
    if not v: return ""
    if FERNET is None: raise RuntimeError("账号池未解锁，请先输入主密码")
    return _ENC_PREFIX + FERNET.encrypt(str(v).encode()).decode()

def dec_value(v):
    """解密；无前缀的是修复前的旧明文，返回原文（调用方应在写回时重新加密）。"""
    if not v: return ""
    if FERNET is None: raise RuntimeError("账号池未解锁，请先输入主密码")
    if isinstance(v, str) and v.startswith(_ENC_PREFIX):
        try: return FERNET.decrypt(v[len(_ENC_PREFIX):].encode()).decode()
        except InvalidToken: raise ValueError("凭据无法解密：主密码可能已更换，请重新填写密码")
    return v

def _migrate_secrets():
    """把旧明文 password/totp 就地改写为密文（解锁后调用一次）。"""
    if FERNET is None: return
    try:
        rows = DB.execute("SELECT id, password, totp FROM accounts").fetchall()
    except sqlite3.OperationalError:
        return
    migrated = False
    for r in rows:
        pw, tp = r["password"] or "", r["totp"] or ""
        if (pw and not pw.startswith(_ENC_PREFIX)) or (tp and not tp.startswith(_ENC_PREFIX)):
            DB.execute("UPDATE accounts SET password=?, totp=? WHERE id=?",
                       (enc_value(pw) if pw else "", enc_value(tp) if tp else "", r["id"]))
            migrated = True
    DB.commit()
    if migrated:
        # UPDATE 不会擦除旧明文在 SQLite 空闲页里的残留，VACUUM 重写
        # 整个库文件，把旧明文彻底清掉。
        try: DB.execute("VACUUM")
        except Exception: pass

def q(sql, args=(), one=False):
    with LOCK:
        cur = DB.execute(sql, args); DB.commit()
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows

# ---- 输入上限（防 DoS / 内存耗尽）----
MAX_UPLOAD_BYTES = 20 * 1024 * 1024          # 单张图片 20 MB
MAX_PROMPT_CHARS = 20000
MAX_CLIP_CHARS = 100
MAX_BULK_ACCOUNTS = 200
ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
# /api/file 只允许返回视频/图片，绝不返回 .html/.db/.json 等（防存储型 XSS 与任意文件读取）
ALLOWED_SERVE_EXTS = {".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime",
                       ".m4v": "video/mp4", ".png": "image/png", ".jpg": "image/jpeg",
                       ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif",
                       ".bmp": "image/bmp"}

def _looks_like_image(head: bytes, ext: str) -> bool:
    if ext == ".png": return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in (".jpg", ".jpeg"): return head.startswith(b"\xff\xd8\xff")
    if ext == ".gif": return head.startswith(b"GIF8")
    if ext == ".webp": return head.startswith(b"RIFF") and head[8:12] == b"WEBP"
    if ext == ".bmp": return head.startswith(b"BM")
    return False

# ---- 模型与点数（Flow 调价时只改这里；index.html 通过 /api/meta 读取）----
DEFAULT_MODEL = "Omni 1.1 Flash"
COST = {  # 720p：模型 -> {秒数: 每个视频的点数}
    "Omni 1.1 Flash": {4: 7, 6: 10, 8: 12, 10: 15},
    "Veo 3.1 - Lite": {8: 10},
    "Veo 3.1 - Fast": {8: 20},
    "Veo 3.1 - Quality": {8: 100},
}
COST_360 = {4: 4, 6: 5, 8: 6, 10: 7}  # Omni 360p，团队不用，仅记录
DAILY_POINTS = 50                      # 每个账号每天的点数
DEFAULT_COST = COST[DEFAULT_MODEL][10]
RATIOS = ("16:9", "9:16")

def norm_job(model, seconds):
    """校正模型/秒数，返回 (模型, 秒数, 点数)。Veo 只有 8 秒；Omni 默认 10 秒。"""
    if model not in COST: model = DEFAULT_MODEL
    opts = COST[model]
    if seconds not in opts: seconds = 10 if 10 in opts else next(iter(opts))
    return model, seconds, opts[seconds]

DB.executescript("""
CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY, name TEXT UNIQUE, daily_limit INT DEFAULT 50,
  used INT DEFAULT 0, last_reset TEXT, status TEXT DEFAULT 'need_login');
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, prompt TEXT, status TEXT DEFAULT 'pending',
  account TEXT, output TEXT, error TEXT, tries INT DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY, created TEXT DEFAULT CURRENT_TIMESTAMP, folder TEXT, n INT DEFAULT 0);
""")
for _s in ("ALTER TABLE tasks ADD COLUMN image TEXT", "ALTER TABLE tasks ADD COLUMN name TEXT",
           "ALTER TABLE tasks ADD COLUMN duration TEXT DEFAULT 'omni'", "ALTER TABLE accounts ADD COLUMN enabled INT DEFAULT 1",
           "ALTER TABLE accounts ADD COLUMN password TEXT", "ALTER TABLE accounts ADD COLUMN totp TEXT",
           "ALTER TABLE tasks ADD COLUMN model TEXT", "ALTER TABLE tasks ADD COLUMN tail TEXT",
           "ALTER TABLE tasks ADD COLUMN mode TEXT", "ALTER TABLE tasks ADD COLUMN seconds INT",
           "ALTER TABLE tasks ADD COLUMN ratio TEXT", "ALTER TABLE tasks ADD COLUMN cost INT",
           "ALTER TABLE tasks ADD COLUMN batch INT", "ALTER TABLE tasks ADD COLUMN clip TEXT",
           "ALTER TABLE tasks ADD COLUMN parent INT"):
    try: DB.execute(_s)
    except sqlite3.OperationalError: pass
# 启动时保持锁定：主密码只在内存里，重启后必须重新输入。
# 旧密钥只保留在 _LEGACY_FERNET 里，供「首次设置主密码」迁移旧凭据用；
# 明文迁移不在启动时做，解锁/设置主密码时才做（那时密钥才在内存里）。
_LEGACY_FERNET = _load_legacy_fernet()
q("UPDATE tasks SET status='pending' WHERE status='running'")  # 异常退出后恢复

SF = DATA / "settings.json"
DEF = {"download_dir": str(pathlib.Path.home() / "Downloads" / "FlowRunner"), "toast": 5, "sound": True}
def settings():
    try: return {**DEF, **json.loads(SF.read_text())}
    except Exception: return dict(DEF)

def safe(n): return re.sub(r'[\\/:*?"<>|]', "_", (n or "").strip())

def finalize(path, t):
    """把下载好的文件改名为「片段名称.扩展名」，同名时加 (2)。"""
    p = pathlib.Path(path); base = safe(t["clip"]) or f"task{t['id']}"
    np = p.with_name(base + p.suffix); k = 2
    while np.exists() and np != p: np = p.with_name(f"{base}({k}){p.suffix}"); k += 1
    # 防御：改名结果必须仍在原目录内（防下载文件名含穿越成分时逃逸）
    if np.resolve().parent != p.resolve().parent:
        np = p.with_name(f"task{t['id']}" + p.suffix)
    p.rename(np); return str(np)

def folder_of(t):
    if t["batch"]:
        b = q("SELECT folder FROM batches WHERE id=?", (t["batch"],), one=True)
        if b: return pathlib.Path(b["folder"])
    return pathlib.Path(settings()["download_dir"]) / today()

def open_path(p, select=False):
    """用系统文件管理器打开路径。只接受已存在的绝对路径，拒绝以 - 开头的
    参数（防 open/explorer/xdg-open 的选项注入）；用列表形式传参，不走 shell。"""
    pp = pathlib.Path(p)
    if not pp.is_absolute(): raise ValueError("路径必须是绝对路径")
    if pp.name.startswith("-"): raise ValueError("路径名非法")
    if not pp.exists(): raise FileNotFoundError(str(p))
    p = str(pp)
    if sys.platform == "darwin": subprocess.Popen(["open", "-R", p] if select else ["open", p])
    elif sys.platform.startswith("win"): subprocess.Popen(["explorer", "/select,", p] if select else ["explorer", p])
    else: subprocess.Popen(["xdg-open", str(pathlib.Path(p).parent if select else p)])

def worker():
    while True:
        if _is_locked():
            time.sleep(2); continue  # 账号池锁定期间不取新任务
        with LOCK:
            DB.execute("UPDATE accounts SET used=0,last_reset=? WHERE IFNULL(last_reset,'')!=?", (today(), today()))
            # 参数化 NOT IN（原先是 f-string 拼接 BUSY，虽为 int 集合仍改掉该模式）
            if BUSY:
                ph = ",".join("?" for _ in BUSY)
                accs = DB.execute(f"SELECT * FROM accounts WHERE status='ok' AND enabled=1 AND id NOT IN ({ph}) "
                                  "ORDER BY used", tuple(BUSY)).fetchall()
            else:
                accs = DB.execute("SELECT * FROM accounts WHERE status='ok' AND enabled=1 ORDER BY used").fetchall()
            t = a = None
            if accs:  # 按提交顺序找第一个「有账号点数够用」的任务；点数不够的先跳过，不堵住后面便宜的
                for tt in DB.execute("SELECT * FROM tasks WHERE status='pending' ORDER BY id").fetchall():
                    c = tt["cost"] or DEFAULT_COST
                    a = next((x for x in accs if x["daily_limit"] - x["used"] >= c), None)
                    if a: t = tt; break
            if t and a:
                BUSY.add(a["id"])
                DB.execute("UPDATE tasks SET status='running',account=? WHERE id=?", (a["name"], t["id"]))
            DB.commit()
        if not (t and a):
            time.sleep(2); continue
        try:
            tmp = fd.generate(PROFILES / a["name"], t["prompt"], folder_of(t), image=t["image"], tail=t["tail"],
                              mode=t["mode"] or "asset", model=t["model"] or DEFAULT_MODEL,
                              seconds=t["seconds"] or 10, ratio=t["ratio"] or "9:16")
            path = finalize(tmp, t)
            q("UPDATE tasks SET status='done',output=?,error=NULL WHERE id=?", (path, t["id"]))
            q("UPDATE accounts SET used=used+? WHERE id=?", (t["cost"] or DEFAULT_COST, a["id"]))
        except fd.NeedLogin:
            q("UPDATE accounts SET status='need_login' WHERE id=?", (a["id"],))
            q("UPDATE tasks SET status='pending' WHERE id=?", (t["id"],))
        except fd.QuotaExhausted:
            q("UPDATE accounts SET used=daily_limit WHERE id=?", (a["id"],))
            q("UPDATE tasks SET status='pending' WHERE id=?", (t["id"],))
        except Exception as e:
            n = t["tries"] + 1
            q("UPDATE tasks SET status=?,tries=?,error=? WHERE id=?",
              ("failed" if n >= 2 else "pending", n, str(e)[:300], t["id"]))
        finally:
            BUSY.discard(a["id"])

# 不暴露 /docs、/redoc、/openapi.json：本机小工具不需要交互式 API 文档，
# 关掉可少一个枚举接口的入口。
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

def _host_ok(host_header: str) -> bool:
    """Host 必须是本机。防 DNS 重绑定：攻击者域名解析到 127.0.0.1 时，
    浏览器发来的 Host 会是攻击者域名，直接拒绝。"""
    h = (host_header or "").strip().lower()
    if "@" in h: h = h.rsplit("@", 1)[-1]
    if h.startswith("["):
        end = h.find("]")
        if end < 0: return False
        return h[1:end] in _LOCAL_HOSTS
    return h.split(":", 1)[0] in _LOCAL_HOSTS

def _origin_ok(origin: str) -> bool:
    try:
        u = urllib.parse.urlparse(origin)
        return u.hostname in _LOCAL_HOSTS and u.port in (None, 8765)
    except Exception:
        return False

@app.middleware("http")
async def _local_only(request: Request, call_next):
    # 1) Host 校验：所有请求都必须发给本机
    if not _host_ok(request.headers.get("host", "")):
        return JSONResponse({"detail": "仅允许本机访问"}, status_code=403)
    # 2) CSRF 校验：浏览器跨站 POST/DELETE 一定带 Origin/Referer，
    #    非本机来源直接拒绝；无 Origin 的请求（curl、本机脚本）放行。
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        for hdr in ("origin", "referer"):
            v = request.headers.get(hdr)
            if v and not _origin_ok(v):
                return JSONResponse({"detail": "跨站请求被拒绝"}, status_code=403)
    # 3) 主密码锁：/api/lock/* 自身除外，其余 /api/* 必须已解锁且持有
    #    本次会话的令牌；未解锁返回 423，前端据此弹出锁屏。
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/lock/"):
        if _is_locked() or not _valid_session(request):
            return JSONResponse({"detail": "账号池未解锁，请先输入主密码"}, status_code=423)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

class NewAcc(BaseModel):
    name: str = Field(max_length=128)
    password: str = Field(default="", max_length=512)
    totp: str = Field(default="", max_length=512)
    daily_limit: int = Field(default=0, ge=0, le=10000)
class BulkAcc(BaseModel):
    items: list[NewAcc] = Field(default_factory=list, max_length=MAX_BULK_ACCOUNTS)

def totp(secret, step=30, digits=6):
    """标准 TOTP（RFC 6238），返回 (验证码, 剩余秒数)。"""
    s = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(s, casefold=True)
    now = int(time.time())
    h = hmac.new(key, struct.pack(">Q", now // step), hashlib.sha1).digest()
    o = h[-1] & 15
    n = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 10 ** digits
    return f"{n:0{digits}d}", step - now % step

def clean_totp(s):
    s = (s or "").strip()
    if s.lower().startswith("otpauth://"):  # 也支持直接粘贴二维码里的链接
        s = urllib.parse.parse_qs(urllib.parse.urlparse(s).query).get("secret", [""])[0]
    return s.replace(" ", "").replace("-", "").upper()

def valid_name(n): return bool(n) and n not in (".", "..") and not any(c in n for c in '/\\:*?"<>|')

def upsert_acc(a):
    n = a.name.strip()
    if not valid_name(n): return "bad"
    pw, tp = a.password, clean_totp(a.totp)
    row = q("SELECT id FROM accounts WHERE name=?", (n,), one=True)
    if row:  # 已存在：只更新填写了的字段
        if pw: q("UPDATE accounts SET password=? WHERE id=?", (enc_value(pw), row["id"]))
        if tp: q("UPDATE accounts SET totp=? WHERE id=?", (enc_value(tp), row["id"]))
        if a.daily_limit > 0: q("UPDATE accounts SET daily_limit=? WHERE id=?", (a.daily_limit, row["id"]))
        return "updated"
    q("INSERT INTO accounts(name,password,totp,daily_limit) VALUES(?,?,?,?)",
      (n, enc_value(pw), enc_value(tp), a.daily_limit if a.daily_limit > 0 else DAILY_POINTS))
    return "added"
@app.get("/")
def index(): return FileResponse(BASE / "index.html")

# ---- 主密码锁：设置 / 解锁 / 改密 / 再锁定 ----
class MasterSetup(BaseModel):
    password: str = Field(min_length=8, max_length=128)
    confirm: str = Field(min_length=8, max_length=128)
class MasterUnlock(BaseModel):
    password: str = Field(min_length=1, max_length=128)
class MasterChange(BaseModel):
    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
    confirm: str = Field(min_length=8, max_length=128)

@app.get("/api/lock/status")
def lock_status():
    return {"locked": _is_locked(), "has_master": _has_master()}

@app.post("/api/lock/setup")
def lock_setup(b: MasterSetup):
    global FERNET, _SESSION_TOKEN, _LOCKED
    if _has_master(): raise HTTPException(400, "已设置过主密码，请用解锁或改密")
    if b.password != b.confirm: raise HTTPException(400, "两次输入的主密码不一致")
    salt = os.urandom(16)
    fernet = _derive_fernet(b.password, salt)
    check = fernet.encrypt(_CHECK_PLAINTEXT).decode()
    try: _reencrypt_all(_LEGACY_FERNET, fernet)  # 旧凭据（旧密钥/明文）转为主密码加密
    except ValueError as e: raise HTTPException(400, str(e))
    _write_master(salt, check)
    FERNET = fernet; _LOCKED = False
    _SESSION_TOKEN = secrets.token_urlsafe(32)
    try: (DATA / ".secret.key").unlink(missing_ok=True)  # 旧密钥文件不再需要，删掉
    except Exception: pass
    return {"token": _SESSION_TOKEN}

@app.post("/api/lock/unlock")
def lock_unlock(b: MasterUnlock):
    if time.time() < _FAILS["until"]:
        raise HTTPException(429, "尝试次数过多，请 60 秒后再试")
    if not _has_master(): raise HTTPException(400, "尚未设置主密码，请先设置")
    try:
        token = _unlock_with(b.password)
    except ValueError:
        _FAILS["n"] += 1
        if _FAILS["n"] >= 5:
            _FAILS["n"] = 0; _FAILS["until"] = time.time() + 60
            raise HTTPException(429, "尝试次数过多，请 60 秒后再试")
        raise HTTPException(401, "主密码不正确")
    _migrate_secrets()  # 解锁后顺手把残留的旧明文行也加密掉
    return {"token": token}

@app.post("/api/lock/change")
def lock_change(b: MasterChange, request: Request):
    global FERNET, _SESSION_TOKEN
    if _is_locked() or not _valid_session(request):
        raise HTTPException(423, "账号池未解锁，请先输入主密码")
    if b.new_password != b.confirm: raise HTTPException(400, "两次输入的新主密码不一致")
    m = _read_master()
    try: _derive_fernet(b.old_password, m["salt"]).decrypt(m["check"].encode())
    except Exception: raise HTTPException(401, "旧主密码不正确")
    salt = os.urandom(16)
    new_fernet = _derive_fernet(b.new_password, salt)
    check = new_fernet.encrypt(_CHECK_PLAINTEXT).decode()
    _reencrypt_all(FERNET, new_fernet)
    _write_master(salt, check)
    FERNET = new_fernet
    _SESSION_TOKEN = secrets.token_urlsafe(32)
    return {"token": _SESSION_TOKEN}

@app.post("/api/lock/lock")
def lock_lock(request: Request):
    if _is_locked() or not _valid_session(request):
        raise HTTPException(423, "账号池未解锁，请先输入主密码")
    _lock()
    return {"locked": True}

@app.get("/api/accounts")
def accounts():
    out = []
    for r in q("SELECT * FROM accounts ORDER BY id"):  # 列表里不返回密码和密钥，只给「是否已填」
        d = dict(r); d["has_pw"] = bool(d.pop("password", None)); d["has_totp"] = bool(d.pop("totp", None)); out.append(d)
    return out

@app.post("/api/accounts")
def add_acc(a: NewAcc):
    if upsert_acc(a) == "bad": raise HTTPException(400, "账号名无效")

@app.post("/api/accounts/bulk")
def add_bulk(b: BulkAcc):
    r = {"added": 0, "updated": 0, "bad": 0}
    for a in b.items: r[upsert_acc(a)] += 1
    return r

@app.get("/api/accounts/{aid}/secret/{kind}")
def secret(aid: int, kind: str):
    a = q("SELECT * FROM accounts WHERE id=?", (aid,), one=True)
    if not a: raise HTTPException(404, "账号不存在")
    if kind == "password":
        if not a["password"]: raise HTTPException(400, "这个账号没有填写密码")
        try: return {"value": dec_value(a["password"])}
        except ValueError: raise HTTPException(400, "密码无法解密：凭据加密密钥可能已更换，请重新填写密码")
    if kind == "totp":
        if not a["totp"]: raise HTTPException(400, "这个账号没有填写二步验证密钥")
        try: code, left = totp(dec_value(a["totp"]))
        except ValueError: raise HTTPException(400, "二步验证密钥无法解密：凭据加密密钥可能已更换，请重新填写")
        except Exception: raise HTTPException(400, "二步验证密钥格式不正确")
        return {"value": code, "left": left}
    raise HTTPException(404)

@app.post("/api/accounts/{aid}/login")
def login(aid: int):
    a = q("SELECT * FROM accounts WHERE id=?", (aid,), one=True)
    if not a: raise HTTPException(404)
    def run():
        fd.login(PROFILES / a["name"])  # 阻塞到你关闭窗口
        q("UPDATE accounts SET status='ok' WHERE id=?", (aid,))
    threading.Thread(target=run, daemon=True).start()

@app.post("/api/accounts/{aid}/mark_ok")
def mark_ok(aid: int): q("UPDATE accounts SET status='ok' WHERE id=?", (aid,))

@app.delete("/api/accounts/{aid}")
def del_acc(aid: int):
    a = q("SELECT * FROM accounts WHERE id=?", (aid,), one=True)
    if a:
        q("DELETE FROM accounts WHERE id=?", (aid,))
        shutil.rmtree(PROFILES / a["name"], ignore_errors=True)

@app.get("/api/meta")
def meta(): return {"cost": COST, "default_model": DEFAULT_MODEL, "daily_points": DAILY_POINTS}

@app.get("/api/tasks")
def tasks(): return [dict(r) for r in q("SELECT * FROM tasks ORDER BY id DESC LIMIT 1000")]

@app.get("/api/batches")
def batches(): return [dict(r) for r in q("SELECT * FROM batches ORDER BY id DESC LIMIT 200")]

class NewBatch(BaseModel): names: list[str] = Field(default_factory=list, max_length=500)

def conflict(folder, names):
    """这个文件夹里（已有文件或已提交的任务）是否已经有同名片段。"""
    if folder.exists() and any(f.stem in names for f in folder.iterdir() if f.is_file()): return True
    rows = q("SELECT t.clip FROM tasks t JOIN batches b ON t.batch=b.id WHERE b.folder=?", (str(folder),))
    return any(r["clip"] in names for r in rows)

@app.post("/api/batches")
def new_batch(b: NewBatch):
    """提交时先定好这一批的文件夹：当天日期；有重名就整批放进 日期_2、日期_3……"""
    names = {safe(n)[:MAX_CLIP_CHARS] for n in b.names if n.strip()}
    root = pathlib.Path(settings()["download_dir"]); base = today()
    for k in range(1, 200):
        cand = root / (base if k == 1 else f"{base}_{k}")
        if not conflict(cand, names): break
    cand.mkdir(parents=True, exist_ok=True)
    with LOCK:
        cur = DB.execute("INSERT INTO batches(folder,n) VALUES(?,?)", (str(cand), len(b.names))); DB.commit()
    return {"id": cur.lastrowid, "folder": cand.name}

_UC = itertools.count(1)
async def save_up(f):
    """保存上传图片：只接受图片扩展名 + 文件头魔数，分块读、限 20MB。
    拒绝 .html/.svg 等可执行内容，防上传文件后经 /api/file 在本站
    源内执行脚本（存储型 XSS）。"""
    if not (f and f.filename): return None
    name = pathlib.Path(f.filename).name
    ext = pathlib.Path(name).suffix.lower()
    if ext not in ALLOWED_IMAGE_EXTS:
        raise HTTPException(400, f"只支持图片文件（{', '.join(sorted(ALLOWED_IMAGE_EXTS))}）")
    d = DATA / "uploads"; d.mkdir(exist_ok=True)
    p = d / f"{int(time.time()*1000)}_{next(_UC)}_{name}"
    total = 0; head = b""
    with p.open("wb") as out:
        while True:
            chunk = await f.read(1024 * 1024)
            if not chunk: break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                out.close(); p.unlink(missing_ok=True)
                raise HTTPException(400, "图片超过 20 MB")
            if len(head) < 12: head += chunk[:12 - len(head)]
            out.write(chunk)
    if not _looks_like_image(head, ext):
        p.unlink(missing_ok=True)
        raise HTTPException(400, "文件内容不是图片（扩展名与文件头不符）")
    try: os.chmod(p, 0o600)
    except Exception: pass
    return str(p)

@app.post("/api/tasks/add")
async def add_task(batch: int = Form(0), clip: str = Form(""), prompt: str = Form(""), model: str = Form(DEFAULT_MODEL),
                   mode: str = Form("asset"), seconds: int = Form(10), ratio: str = Form("9:16"),
                   image: UploadFile | None = File(None), tail: UploadFile | None = File(None)):
    model, seconds, cost = norm_job(model, seconds)
    if mode not in ("asset", "frame"): mode = "asset"
    if ratio not in RATIOS: ratio = "9:16"
    prompt = prompt.strip()
    if len(prompt) > MAX_PROMPT_CHARS: raise HTTPException(400, "提示词过长")
    clip = clip.strip()[:MAX_CLIP_CHARS]
    img = await save_up(image); tl = await save_up(tail) if mode == "frame" else None
    if not (prompt or img): raise HTTPException(400, "提示词和图片至少填一个")
    q("INSERT INTO tasks(prompt,image,tail,mode,model,seconds,ratio,cost,batch,clip) VALUES(?,?,?,?,?,?,?,?,?,?)",
      (prompt, img, tl, mode, model, seconds, ratio, cost, batch or None, clip))

@app.post("/api/tasks/{tid}/regen")
def regen(tid: int):
    """重生：复制一份同样的任务，片段名称加后缀（01-1 → 01-1-1 → 01-1-2），旧结果保留。"""
    t = q("SELECT * FROM tasks WHERE id=?", (tid,), one=True)
    if not t: raise HTTPException(404)
    root = t["parent"] or t["id"]
    base = re.sub(r"-\d+$", "", t["clip"] or "") if t["parent"] else (t["clip"] or f"task{t['id']}")
    folder = folder_of(t); k = 1
    while q("SELECT 1 FROM tasks WHERE batch IS ? AND clip=?", (t["batch"], f"{base}-{k}"), one=True) \
            or (folder / f"{safe(base)}-{k}.mp4").exists(): k += 1
    q("INSERT INTO tasks(prompt,image,tail,mode,model,seconds,ratio,cost,batch,clip,parent) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
      (t["prompt"], t["image"], t["tail"], t["mode"], t["model"], t["seconds"], t["ratio"], t["cost"], t["batch"],
       f"{base}-{k}", root))

@app.post("/api/tasks/clear_finished")
def clear_finished():
    with LOCK:
        cur = DB.execute("DELETE FROM tasks WHERE status IN ('done','failed')")
        DB.execute("DELETE FROM batches WHERE id NOT IN (SELECT DISTINCT batch FROM tasks WHERE batch IS NOT NULL)")
        DB.commit()
    return {"deleted": cur.rowcount}

@app.post("/api/tasks/retry_failed")
def retry(): q("UPDATE tasks SET status='pending',tries=0 WHERE status='failed'")

@app.post("/api/batches/{bid}/retry_failed")
def retry_batch(bid: int): q("UPDATE tasks SET status='pending',tries=0,error=NULL WHERE status='failed' AND batch=?", (bid,))

@app.post("/api/batches/{bid}/reveal")
def reveal_batch(bid: int):
    b = q("SELECT folder FROM batches WHERE id=?", (bid,), one=True)
    if not b: raise HTTPException(404)
    p = pathlib.Path(b["folder"]); p.mkdir(parents=True, exist_ok=True)
    try: open_path(p)
    except (ValueError, FileNotFoundError): raise HTTPException(400, "文件夹路径无效")

def _safe_roots():
    """ /api/file 的允许根目录：过滤掉文件系统根、用户主目录、数据目录
    本身（防 download_dir 被改成 / 或 ~ 后读任意文件）。"""
    home = pathlib.Path.home().resolve()
    data = DATA.resolve()
    roots = [OUT, DATA / "uploads", pathlib.Path(settings()["download_dir"])] + [pathlib.Path(r["folder"]) for r in q("SELECT folder FROM batches")]
    out = []
    for r in roots:
        try: rr = r.resolve()
        except Exception: continue
        # 跳过：文件系统根、主目录本身、数据目录本身、数据目录的祖先
        # （祖先目录会把 pool.db 等一并暴露）。注意 OUT / uploads 本身
        # 在 DATA 之内，是合法的服务根，不要误拦。
        if str(rr) == rr.anchor or rr == home or rr == data or rr in data.parents:
            continue
        out.append(rr)
    return out

@app.get("/api/file")
def file(path: str, dl: int = 0):
    p = pathlib.Path(path).resolve()
    ext = p.suffix.lower()
    if ext not in ALLOWED_SERVE_EXTS:
        raise HTTPException(403, "不支持的文件类型")
    if not p.is_file(): raise HTTPException(404)
    roots = _safe_roots()
    if not any(p.is_relative_to(r) for r in roots): raise HTTPException(404)
    disp = "attachment" if dl else "inline"
    return FileResponse(p, filename=p.name, media_type=ALLOWED_SERVE_EXTS[ext],
                        headers={"Content-Disposition": f'{disp}; filename="{p.name}"',
                                 "X-Content-Type-Options": "nosniff"})

def _valid_download_dir(v):
    """下载目录校验：必须是绝对路径，不能是根目录、主目录、数据目录
    或其父级/子级（防 /api/settings 改目录后经 /api/file 读任意文件）。"""
    try: p = pathlib.Path(v).expanduser().resolve()
    except Exception: return False
    home = pathlib.Path.home().resolve()
    data = DATA.resolve()
    if str(p) == p.anchor: return False
    if p == home or p == data: return False
    if data in p.parents or p in data.parents: return False
    return True

@app.get("/api/settings")
def get_settings(): return settings()

@app.post("/api/settings")
def set_settings(s: dict):
    # 只接受已知字段，忽略其它键（原先任意键都会被持久化进 settings.json）
    allowed = {}
    if "download_dir" in s:
        v = str(s["download_dir"] or "").strip()
        if not v or not _valid_download_dir(v):
            raise HTTPException(400, "下载目录无效：不能是根目录、主目录或数据目录")
        allowed["download_dir"] = v
    if "toast" in s:
        try: allowed["toast"] = max(1, min(30, int(s["toast"])))
        except Exception: raise HTTPException(400, "toast 无效")
    if "sound" in s: allowed["sound"] = bool(s["sound"])
    cur = {**settings(), **allowed}
    pathlib.Path(cur.get("download_dir") or DEF["download_dir"]).mkdir(parents=True, exist_ok=True)
    SF.write_text(json.dumps(cur))
    try: os.chmod(SF, 0o600)
    except Exception: pass

@app.post("/api/accounts/{aid}/toggle")
def toggle(aid: int): q("UPDATE accounts SET enabled=1-IFNULL(enabled,1) WHERE id=?", (aid,))

@app.delete("/api/tasks/{tid}")
def del_task(tid: int): q("DELETE FROM tasks WHERE id=?", (tid,))

@app.post("/api/tasks/{tid}/redo")
def redo(tid: int): q("UPDATE tasks SET status='pending',tries=0,output=NULL,error=NULL WHERE id=?", (tid,))

@app.post("/api/tasks/{tid}/reveal")
def reveal(tid: int):
    t = q("SELECT output FROM tasks WHERE id=?", (tid,), one=True)
    if not t or not t["output"]: raise HTTPException(404)
    try: open_path(t["output"], select=True)
    except (ValueError, FileNotFoundError): raise HTTPException(404)

@app.post("/api/open_dir")
def open_dir():
    d = pathlib.Path(settings()["download_dir"]); d.mkdir(parents=True, exist_ok=True)
    try: open_path(d)
    except (ValueError, FileNotFoundError): raise HTTPException(400, "下载目录无效")

if __name__ == "__main__":
    for _ in range(WORKERS): threading.Thread(target=worker, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8765)
