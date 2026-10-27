# FlowRunner 安全审核报告

- 审核日期：2026-10-27
- 审核范围：`FlowRunner.zip` 全部 6 个文件（`app.py` 352 行、`flow_driver.py` 104 行、`index.html` 445 行、`requirements.txt`、`README.md`、`.gitignore`），无 `.git` 历史、无 CI 配置、无其他代码。
- 审核方式：逐文件通读 + `pip-audit`（全新安装实测）+ OSV.dev API 逐包核查 + WebSearch（GitHub Advisory / NVD / 官方 changelog 交叉核对）。
- 结论：发现 1 个 Critical 级凭据问题、多个 High 级问题，**能安全修复的已全部直接修复并通过冒烟测试**；剩余 4 个问题需要开发者定夺（§四），未擅自决定。

---

## 一、项目概况

| 项 | 内容 |
|---|---|
| 语言 / 框架 | Python 3.10+，FastAPI + Uvicorn + Playwright（系统 Chrome），SQLite（`pool.db`），无前端构建 |
| 入口 | `python app.py`，只监听 `127.0.0.1:8765`（未改动，正确） |
| 直接依赖（修复前） | `fastapi`、`uvicorn`、`python-multipart`、`playwright`，**全部无版本约束，无 lock 文件** |
| 间接依赖（2026-10-27 全新安装实测） | `starlette 1.10.0`、`pydantic 2.14.1`、`anyio 4.15.1`、`h11 0.16.0`、`click 8.5.0`、`greenlet 3.5.6`、`pyee 14.0.0`、`python-multipart 0.0.32`、`playwright 1.64.1`、`fastapi 0.162.0`、`uvicorn 0.54.0` |
| 数据 | Google 账号密码 + TOTP 密钥、Playwright 登录态（`profiles/`）、上传图片、生成视频，均在用户数据目录（`~/Library/Application Support/FlowRunner` 等），可用 `FLOW_DATA` 改位置 |
| 不在范围内 | 无 CI/CD、无浏览器扩展、无桌面壳、无 Dockerfile；`flow_driver.py` 的 `TODO 校准` 选择器是占位符，未实测真实 Flow 页面 |

### 依赖漏洞核查结果

`pip-audit` 对全新安装（上述最新版）的结论：**项目依赖 0 个已知漏洞**。唯一报出的是环境自带的 `pip 24.0` 本身（12 条重复记录，修复版 `pip>=26.2`），不是项目依赖，见 D-04。

但因为 `requirements.txt` 原先**没有任何版本约束**，旧环境 / 任意时间点的安装都可能装到已知高危版本，且无法从仓库反推实际装了哪个版本。这是本次依赖部分的核心问题。下面是与本项目**实际可达**的漏洞（`UploadFile` 走 multipart 解析，`/api/file` 走 `FileResponse`）：

| 依赖 | 漏洞 | 严重性 | 修复版 | 本项目是否可达 |
|---|---|---|---|---|
| python-multipart | GHSA-pp6c-gr5w-3c5g：无界 multipart part header 导致 DoS，CVE-2026-42561，CVSS 7.5 | High | `>=0.0.27` | 是（`/api/tasks/add` 上传图片） |
| python-multipart | GHSA-mj87-hwqh-73pj：大 preamble/epilogue 导致 DoS，CVE-2026-40347 | Medium | `>=0.0.26` | 是，同上 |
| python-multipart | GHSA-5rvq-cxj2-64vf / GHSA-6jv3-5f52-599m / GHSA-vffw-93wf-4j4q：分号解析二次时间 DoS 与参数走私 | High/Medium | `>=0.0.30` | 是，同上 |
| python-multipart | GHSA-v9pg-7xvm-68hf：负 Content-Length 导致整包缓存在内存 | Medium | `>=0.0.31` | 是，同上 |
| python-multipart | GHSA-wp53-j4wj-2cfg：非默认配置下任意文件写（本项目未用 `UPLOADDIR/UPLOADKEEPFILENAME`，**不可达**，仅作记录） | High | `>=0.0.22` | 否 |
| python-multipart | GHSA-2jv5-9r88-3w3p：Content-Type ReDoS；GHSA-59g5-xgcq-4qw3：boundary 畸形 DoS | High | `>=0.0.7` / `>=0.0.18` | 是，同上 |
| starlette（经 fastapi 间接） | GHSA-7f5h-v6xp-fcq8：`FileResponse` Range 头合并 O(n²) DoS，CVSS 7.5 | High | `>=0.49.1` | 是（`/api/file` 正是 `FileResponse`） |
| starlette | GHSA-86qp-5c8j-p5mr / CVE-2026-48710 BadHost：缺 Host 校验，`request.url.path` 被污染，可绕过路径安全检查 | Medium（发现者定性为 Critical，CVSS 6.5） | `>=1.0.1` | 是（本项目新增的 Host 校验与之互补，见 C-02） |
| starlette | GHSA-82w8-qh3p-5jfq：`request.form()` 限制对 urlencoded 失效导致 DoS；GHSA-f96h-pmfr-66vw / CVE-2024-47874：无文件名表单字段无大小限制导致 DoS，CVSS 7.5；GHSA-2c2j-9gv5-cj73：大文件 multipart DoS | High | `>=1.3.1` / `>=0.40.0` / `>=0.47.2` | 是（表单 + 上传） |
| starlette | GHSA-v5gw-mw7f-84px / GHSA-wqp7-x3pw-xc5r：`StaticFiles` 路径穿越 / UNC SSRF（本项目**未用 StaticFiles**，不可达，仅作记录） | — | — | 否 |
| fastapi | GHSA-8h2j-cgx8-6xv7：CSRF（框架层面无内置防护，见 C-02）；PYSEC-2024-38 / CVE-2024-24762：Content-Type ReDoS | — | `>=0.65.2` / `>=0.109.1` | 部分（CSRF 是本项目真实风险，已修） |
| uvicorn | GHSA-33c7-2mpw-hg34 / GHSA-f97h-2pfx-f59f：日志注入 / 响应拆分 | — | `>=0.11.7` | 低（本地服务） |
| pydantic / anyio | GHSA-mr82-8j83-vxmv（ReDoS，`>=2.4.0`）、anyio 三项（TLS IDNA  spoofing 等，`>=4.14.2`） | — | 已覆盖 | 低（本项目未直接用相关功能） |
| playwright | OSV.dev 对 PyPI `playwright` 查无记录；WebSearch 提到的 CVE-2025-59288（Playwright 签名校验，修复版 1.55.1）**待确认**：现有资料未明确区分是浏览器驱动包还是 GitHub 侧组件，未据此编造结论 | 待确认 | `>=1.55.1`（本次已钉到 1.64.1，覆盖该修复版） | 待确认 |

无停止维护或疑似仿冒的依赖：4 个直接依赖均为官方主流包。`python-multipart` 在 2026 年仍有安全更新（0.0.32），不属于停更。

---

## 二、问题汇总表

| 编号 | 类别 | 严重级别 | 位置 | 状态 |
|---|---|---|---|---|
| C-01 | 密钥 | **Critical** | `app.py:67,172-176`（修复前）：密码 + TOTP 密钥明文存 `pool.db` | 已修复（加密 + 迁移 + VACUUM） |
| C-02 | 代码 | High | `app.py`（修复前）：无鉴权、无 CSRF、无 Host 校验，任意本机网页可跨站调用全部 API | 已修复（Host + Origin 校验、安全头、关闭 `/docs`） |
| C-03 | 代码 | High | `app.py:316-320`（修复前）`/api/file`：任意文件读取 | 已修复（扩展名白名单 + 安全根目录 + settings 校验） |
| C-04 | 代码 | High | `app.py:264-267`（修复前）`save_up`：上传不限类型/大小，整包读入内存 | 已修复（扩展名 + 文件头魔数 + 20 MB 流式上限） |
| C-05 | 代码 | Medium | `app.py:330-335`（修复前）`/api/settings`：任意键持久化、下载目录可设为 `/` | 已修复（白名单字段 + 目录校验） |
| C-06 | 代码 | Low | `app.py:98-102`（修复前）`open_path`：路径可作 `open/explorer/xdg-open` 的选项 | 已修复（绝对路径 + 存在性 + 拒绝 `-` 开头） |
| C-07 | 代码 | Medium | `flow_driver.py:100`（修复前）：`suggested_filename` 直接拼路径 | 已修复（只取 basename + 父目录校验） |
| C-08 | 代码 | Low | `flow_driver.py:32-33,58-66`：模型/比例拼进 Playwright 选择器 | 已修复（驱动内白名单校验，纵深防御） |
| C-09 | 代码 | Low | `app.py:109`（修复前）：worker 用 f-string 拼 `NOT IN (...)` | 已修复（参数化） |
| C-10 | 代码 | Low | `index.html:201`（修复前）：`esc()` 不转义单引号 | 已修复 |
| C-11 | 代码 | Medium | `app.py`（修复前）：`prompt`、批量账号、任务名无长度/数量上限 | 已修复（见 §三） |
| D-01 | 依赖 | High | `requirements.txt`（修复前）：4 个依赖零版本约束，无 lock 文件 | 已修复（钉下限 + 注释修复版依据） |
| D-02 | 依赖 | High | python-multipart 旧版多个 DoS / 参数走私（见 §一表） | 已修复（`>=0.0.32`） |
| D-03 | 依赖 | High | starlette 旧版 FileResponse Range DoS、BadHost、表单限制失效 | 已修复（`fastapi>=0.162.0`，带 `starlette 1.10.0`） |
| D-04 | 依赖 | Low | 环境 `pip 24.0` 本身有 12 条漏洞记录（`pip-audit` 报出） | 建议关注（非项目依赖，见 §五） |
| S-01 | 密钥 | — | 全仓库硬编码密钥扫描：无 API Key / Token / 私钥 / 连接串 | 无问题（已核查，见 §三末） |
| S-02 | 密钥 | High | **已泄露过的旧明文数据库**：若旧 `pool.db` 离开过本机，必须轮换 | **待开发者决定**（§四第 2 项） |

**逐文件审查后确认无问题 / 不可达的项**：SQL 注入（其余查询均为参数化）、命令注入（无 `shell=True` / `os.system` / `eval` / `exec`）、NoSQL/模板注入（无模板引擎）、不安全反序列化（无 `pickle`/`yaml.load`）、zip slip（无解压逻辑）、弱加密（TOTP 是标准 RFC 6238 HMAC-SHA1，非自造加密；无 TLS 校验关闭）、SSRF（`FLOW_URL` 只来自操作者环境变量，不来自 API 输入）、开放重定向/过宽 CORS（未启用 CORS 中间件）、CI/CD（无 workflow 文件）、浏览器扩展/桌面 IPC（不适用）。前端 `index.html` 的用户数据渲染点均经 `esc()` 转义（账号名、任务名、提示词、错误信息、文件夹名），未发现可利用的 XSS；唯一真实的 XSS 路径是 C-04 的上传 `.html` 经 `/api/file` 在本站源内执行，已修复。

---

## 三、已修复的问题及具体改动

### C-01 凭据明文存储 → Fernet 静态加密（`app.py`）

- 改动：新增 `cryptography` 依赖；`_load_fernet()` / `enc_value()` / `dec_value()` / `_migrate_secrets()`。
  - 密钥来源：优先环境变量 `FLOW_SECRET_KEY`，否则用数据目录的 `.secret.key`（首次启动自动生成，`0600`）。
  - `password` / `totp` 列现存 `enc:v1:<Fernet密文>`，`/api/accounts` 列表仍只返回 `has_pw` / `has_totp`，`/secret/password` 解密后返回原文（复制按钮功能不变），`/secret/totp` 只返回当次验证码（不变，从不返回原始密钥）。
  - 启动时自动迁移旧明文行并 `VACUUM` 重写库文件（`UPDATE` 本身不擦除 SQLite 空闲页里的旧明文残留）。
  - 数据目录（`DATA` / `profiles` / `outputs`）补 `0700`，`pool.db` / `settings.json` / 上传文件补 `0600`。
- 验证：新建账号后直接读 `pool.db`，密码与 TOTP 均不在文件中；`/secret/password` 仍返回原文，`/secret/totp` 仍返回 6 位码；用旧明文库启动，行被改写为 `enc:v1:…` 且接口仍能解密（见 §六测试记录）。
- 局限（诚实说明）：密钥文件与数据库在同一目录，**只防“只丢了 `pool.db` 单个文件”的泄露**；整个数据目录被复制走仍能解密。更强的方案见 §四第 1 项。

### C-02 无鉴权 + CSRF + DNS 重绑定（`app.py`）

- 背景：服务无任何鉴权是本机小工具的原有设计，但浏览器里的任意网页在服务运行时都能向 `127.0.0.1:8765` 发简单 POST（`fetch` 跨站读会被 CORS 挡住，**写操作不会被挡**），可删账号、改设置、打开文件夹。
- 改动：新增 `_local_only` 中间件——
  1. 所有请求校验 `Host` 必须为 `127.0.0.1` / `localhost` / `::1`（防 DNS 重绑定：攻击者域名解析到 127.0.0.1 时 Host 不是本机，直接 403）；
  2. `POST/PUT/PATCH/DELETE` 若带 `Origin` / `Referer`，必须为本机 `:8765`，否则 403；无 Origin 的请求（curl、本机脚本）放行；
  3. 全站加 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`，`/api/*` 加 `Cache-Control: no-store`；
  4. 关闭 FastAPI 默认文档：`FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`（`/docs` 现返回 404）。
- 验证：`Origin: https://evil.example` 的 POST 得 403；`Host: evil.example` 得 403；本机 Origin 的 POST 得 200；`GET /` 与 `/api/meta` 正常。

### C-03 `/api/file` 任意文件读取（`app.py`）

- 原问题：`any(r.resolve() in p.parents …)` 只校验“在某个根目录下”，而根目录之一是用户可通过 `/api/settings` 任意指定的 `download_dir`——把它设为 `/` 就能读任意文件；且未校验扩展名、未校验 `is_file()`，符号链接解析后也可能逃逸（`p.resolve()` 跟随链接，但根目录本身可被改）。
- 改动：`_safe_roots()` 过滤掉文件系统根、主目录本身、数据目录本身及其祖先；`/api/file` 只允许视频/图片扩展名（`.mp4/.webm/.mov/.m4v/.png/.jpg/.jpeg/.webp/.gif/.bmp`），其余一律 403；要求 `is_file()` 且 `is_relative_to(根目录)`；显式设置 `media_type` 与 `Content-Disposition`（预览 `inline`、下载 `attachment`），绝不以 `text/html` 返回。
- 验证：下载目录内的 `.mp4` 200、`video/mp4`；同目录 `.html` 403；目录外 `.mp4` 404；`/etc/passwd` 403；指向目录外文件的符号链接 404。

### C-04 上传文件存储型 XSS + 内存 DoS（`app.py`）

- 原问题：`save_up` 对 `await f.read()` 整包读入内存、无大小限制、无类型校验；上传 `.html` 后经 `/api/file` 在 `127.0.0.1:8765` 源内以 `text/html` 打开，可执行脚本并调用全部无鉴权 API。
- 改动：只接受 `.png/.jpg/.jpeg/.webp/.gif/.bmp`，并校验文件头魔数（PNG/JPEG/GIF/WebP/BMP 签名）；分块读、单文件上限 20 MB，超限删除临时文件并报 400；上传文件 `0600`。
- 验证：1×1 真 PNG 通过并建任务；文本冒充的 `.png` 400；`.html` 400。

### C-05 `/api/settings` 任意目录与任意键（`app.py`）

- 改动：只接受 `download_dir` / `toast` / `sound` 三个已知字段；`download_dir` 必须是绝对路径，且不能是根目录、主目录、数据目录或其父级/子级，否则 400；`toast` 钳制在 1–30。
- 验证：`download_dir: "/"` 得 400；合法目录得 200 且未知键被丢弃。

### C-06–C-11 其他代码修复

- C-06 `open_path`：要求绝对路径、文件存在、文件名不以 `-` 开头；仍用列表传参、不走 shell。
- C-07 `flow_driver.py`：`_safe_download_name()` 只取 `suggested_filename` 的 basename，空名/`..` 时 fallback 为 `video.mp4`，保存前校验父目录仍为输出目录。
- C-08 `flow_driver.py`：`generate()` 开头白名单校验 `model`（4 个已知值）、`ratio`、`mode`、`seconds`，再拼进选择器；非法值直接 `ValueError`（实测含引号的模型名被拒）。
- C-09 worker 的 `NOT IN (…)` 由 f-string 拼接改为参数化占位符。
- C-10 `index.html`：`esc()` 增加单引号转义（`'` → `&#x27;`），覆盖单引号属性上下文。
- C-11 输入上限：`NewAcc`（名 ≤128、密码/TOTP ≤512、每日点数 0–10000）、批量 ≤200 个、`NewBatch.names` ≤500、`prompt` ≤20000 字符、`clip` 截断至 100 字符。

### D-01–D-03 依赖钉版（`requirements.txt`）

```
fastapi>=0.162.0
uvicorn>=0.54.0
python-multipart>=0.0.32
playwright>=1.64.1
cryptography>=50.0.2
```

下限即 2026-10-27 实测最新版，覆盖 §一表中全部已确认修复版；注释中写明了每个下限对应的 GHSA 编号。`pip-audit` 对该组合复核为项目依赖 0 漏洞。

### 密钥扫描 S-01（无硬编码密钥）

- 全仓库 grep `api_key/access_key/secret/token/password=/AKIA/ghp_/sk-/BEGIN PRIVATE`：除 `totp(secret)` 函数名与 `/secret/` 接口名外无命中；无 `.env`、无证书/私钥、无连接串、无 Webhook 地址。
- `.gitignore` 已忽略 `data/`、`*.db`、`*.sqlite`、`.env`；本次追加 `.secret.key`。新增只含变量名的 `.env.example`（`FLOW_DATA`、`FLOW_SECRET_KEY` 等，无真实值）。
- `README.md` 的“明文存储”警告已更新为加密后的准确描述 + 密钥文件警告 + 不要暴露服务的警告。

---

## 四、需要开发者决定的问题

### 1. 凭据加密密钥放哪里（C-01 的后续）

已实施的本地密钥文件方案是“零摩擦、可迁移”的折中，**不是**最强方案。请选一个：

| 方案 | 做法 | 优点 | 代价 |
|---|---|---|---|
| A（已实施，建议接受） | 保持现状：`.secret.key` 在数据目录，`0600` | 无感升级、已自动迁移旧数据 | 整个数据目录被复制走仍能解密 |
| B（已支持，可随时切） | 用环境变量 `FLOW_SECRET_KEY`（见 `.env.example` 生成方法），密钥不放数据目录 | 密钥与数据库分离，单目录泄露也解不开 | 每次启动要先注入环境变量；密钥丢了旧数据永久无法解密 |
| C（未实施） | 系统钥匙串（macOS Keychain / Windows DPAPI / Linux Secret Service）或启动时输主密码 | 最强，符合“密钥不落盘明文文件”的要求 | 需新增依赖与启动流程，改动较大；主密码方案还会每次启动都问一次 |

**我的建议**：接受 A，同时把密钥再备份一份到你自己的密码管理器（不要放网盘明文）；如果这台电脑会借给别人用或数据目录会同步，再选 B 或 C。**不要在 A/B/C 之外再把密钥写进代码或 `.env` 提交。**

### 2. 旧明文数据库是否已经泄露——要不要轮换全部账号（S-02）

- **如果旧 `pool.db` 从未离开过这台电脑**（没发给别人、没同步网盘、没进备份/聊天记录）：本次迁移 + VACUUM 后即可，无需轮换。
- **如果它离开过本机，哪怕一次**：只删代码/只加密新库**不够**。必须去 Google 账号逐个**改密码并重置二步验证（重新扫码换密钥）**，因为旧文件里的明文密码和 TOTP 密钥在别人手里永久有效。
- 请确认属于哪种情况；如不确定，按“已泄露”处理最稳妥。

### 3. 要不要给本地服务加访问口令

现状（建议暂缓）：依赖 `127.0.0.1` 绑定 + Host/Origin 校验，防住了“恶意网页跨站调用”这一主要向量，但**同一台电脑上的任何本地程序**仍可直接调用 API（这是无鉴权本机工具的固有属性，加口令也只能防浏览器跨站，不能防本地恶意程序）。
- 如需加：启动时生成随机 Token、前端每次请求带 `Authorization` 头，改动中等，我可以做。
- 如服务永远只在本机浏览器用：不加，现状已够。

### 4. 依赖版本策略

本次用 `>=当日最新版` 的下限写法（全新安装本来就会装到这些版本），已实测通过。如你偏保守，可把下限放宽到“仅覆盖修复版”（如 `python-multipart>=0.0.32` 不变、`fastapi>=0.115.3` 等），但那样新装环境仍可能装到未经本次实测的组合，需重跑测试。请确认接受当前钉版。

---

## 五、剩余风险与后续建议

1. **无鉴权的本机服务（固有）**：不要用反向代理把它暴露到局域网/公网，不要改 `host="0.0.0.0"`；一旦暴露，C-02 的修复（Host/Origin）会被绕过——Host 校验只认本机名，局域网访问会直接 403，但若你为此放宽校验，全部 API 将无鉴权暴露。
2. **Playwright 浏览器上下文**：`login()` 打开的是真实 Chrome 持久上下文并访问 Google Flow，登录态（cookies）存在 `profiles/<账号名>/`，与数据库同等敏感，不要分享该目录。`flow_driver.py` 的选择器仍是 `TODO 校准` 占位符，校准时只改 `SEL`，不要把账号密码写进选择器或日志。
3. **TOTP 与密码的复制接口**：`/api/accounts/{id}/secret/password` 按设计返回明文密码（供复制按钮用），这是功能需要；风险已被 Host/Origin + 本机绑定收敛，见 §四第 3 项。
4. **依赖维护**：`requirements.txt` 仍无 lock 文件，建议后续跑一次 `pip freeze > requirements.lock`（或 `pip-compile`）并定期 `pip-audit`；本次 `pip-audit` 报出的 `pip 24.0` 自身漏洞（修复版 `pip>=26.2`）请在装机上升级 pip，与项目无关。
5. **备份**：备份数据目录时请用加密备份；不要把 `pool.db` / `.secret.key` / `profiles/` 明文同步到网盘。
6. **后续复核**：Flow 改版校准选择器后、或升级 FastAPI/Starlette 大版本时，重跑 §六的冒烟测试。

---

## 六、测试记录（修复后实测）

环境：Python 3.12.3，全新 venv，按修复后 `requirements.txt` 安装（`fastapi 0.162.0` / `uvicorn 0.54.0` / `python-multipart 0.0.32` / `playwright 1.64.1` / `starlette 1.10.0` / `pydantic 2.14.1` / `cryptography` 已装），`FLOW_DATA` 指向临时目录，`python -m py_compile app.py flow_driver.py` 通过。

| 测试 | 结果 |
|---|---|
| `pip-audit`（修复后依赖） | 项目依赖 0 漏洞；仅报环境 `pip 24.0` 自身 |
| 新建账号，读 `pool.db` | 密码、TOTP 均不在文件中，存为 `enc:v1:…`；文件权限 600 |
| `/secret/password`、`/secret/totp` | 返回原文密码与 6 位验证码，列表接口仍不返回密码 |
| 旧明文库启动迁移 | 明文行改写为 `enc:v1:…`，`VACUUM` 后文件中无旧明文残留，接口仍能解密 |
| CSRF：`Origin: https://evil.example` POST | 403 |
| DNS 重绑定：`Host: evil.example` | 403 |
| 本机 Origin POST | 200 |
| `GET /docs` | 404；响应含 `nosniff` / `DENY` / `no-referrer` / `no-store` |
| `download_dir: "/"` | 400；合法目录 200 且未知键被丢弃 |
| 上传真 PNG | 200，任务创建 |
| 上传文本冒充 `.png` | 400（文件头不符） |
| 上传 `.html` | 400 |
| `/api/file` 下载目录内 `.mp4` | 200，`video/mp4` |
| `/api/file` 同目录 `.html` | 403 |
| `/api/file` 目录外 `.mp4`、`/etc/passwd`、符号链接逃逸 | 404 / 403 / 404 |
| `flow_driver._safe_download_name('../../etc/passwd')` | 返回 `passwd`（basename），非法模型名被 `ValueError` 拒绝 |

未实测：真实 Flow 页面生成流程（选择器为占位符，需开发者用真实页面校准；与本次安全修复无关）。

---

## 附：改动文件清单

- `app.py`：凭据加密 + 迁移 + VACUUM、Host/Origin 中间件、安全头、关闭 API 文档、上传校验、`/api/file` 白名单、`settings` 白名单与目录校验、`open_path` 校验、SQL 参数化、输入上限、目录权限。
- `flow_driver.py`：下载文件名净化、模型/比例/模式/时长白名单校验。
- `index.html`：`esc()` 增加单引号转义。
- `requirements.txt`：钉死 5 个依赖下限并注释修复版依据。
- `.gitignore`：追加 `.secret.key`。
- `.env.example`（新增）：只含变量名的配置示例。
- `README.md`：更新凭据存储说明与服务暴露警告。
- `SECURITY_AUDIT_REPORT.md`（新增）：本报告。

---

## 附录：主密码方案 C（2026-10-27 补充，开发者已选定）

开发者选择方案 C：用户自己设定账号池主密码，每次使用先输入主密码再进入账号池。已实现并实测。

### 实现

- **派生**：PBKDF2-HMAC-SHA256，60 万次迭代，随机 16 字节盐，派生 32 字节 Fernet 密钥。磁盘只存盐 + 校验密文（`DATA/.master.json`，0600），不存主密码、不存可直接解密的密钥。
- **流程**：首次打开 → 设置主密码（≥8 位，两次确认）→ 以后每次启动程序、每次打开新浏览器页签都要重新输入；右上角「🔒 锁定」或设置页可随时再锁。密钥只在内存里，重启/锁定后失效。
- **锁定范围**：全部 `/api/*`（除 `/api/lock/*` 自身）未解锁时返回 423；worker 在锁定期间不取新任务；会话令牌放 `sessionStorage`（关标签页即失效），`fetch` 自动带 `X-Flow-Unlock` 请求头；`<a>/<img>` 的预览/下载链接改用 `unlock_token` 查询参数。
- **改密**：设置页「修改主密码」，验旧密码后全部账号凭据用新主密码重加密，旧会话令牌失效。
- **防猜**：连续 5 次输错锁定 60 秒（返回 429），之后才能再试。
- **旧数据迁移**：设置主密码时，旧 `.secret.key` / `FLOW_SECRET_KEY` 加密的凭据和旧明文行都会被解密后用主密码重加密，迁移成功后 `.secret.key` 被删除；此后 `FLOW_SECRET_KEY` 不再生效。
- **忘记主密码的后果**：已存账号密码/TOTP 永久无法解密，只能删除 `pool.db` 和 `.master.json` 后重新填写账号。请把主密码记在密码管理器里。

### 实测（2026-10-27）

| 测试 | 结果 |
|---|---|
| 启动后 `/api/lock/status` | `locked=true, has_master=false`；`/api/accounts` 423 |
| 设置主密码（太短 / 两次不一致） | 422 / 400 拒绝；一致时成功发令牌 |
| 错主密码解锁 | 401；连续 5 次后 429，60 秒内正确密码也 429 |
| 解锁后增删账号、复制密码/TOTP | 正常；`pool.db` 中无账号密码、主密码明文 |
| 锁定后旧令牌调接口 | 423 |
| 重启后 | `locked=true, has_master=true`，须重新输入主密码，账号数据仍在 |
| 改主密码 | 旧密码 401；改后旧令牌 423，旧主密码 401，新主密码 200，账号密码仍可解密 |
| 旧库迁移（1 个旧密钥加密 + 1 个明文账号） | 设置主密码后两者均可解密，库中无旧明文/旧密钥残留，`.secret.key` 已删 |
| `/api/file` 预览 | 无令牌 423；`unlock_token` 查询参数或请求头令牌均 200 |
