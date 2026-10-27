"""Flow 页面自动化。所有页面相关的选择器都集中在 SEL 里，Flow 改版时只改这里。
注意：SEL 里的值是占位示例，需要用真实页面校准（见 README）。"""
import os, pathlib, time
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

FLOW_URL = os.getenv("FLOW_URL", "https://labs.google/fx/tools/flow")
HEADLESS = os.getenv("HEADLESS", "0") == "1"
GEN_TIMEOUT = int(os.getenv("GEN_TIMEOUT", "300")) * 1000

SEL = {
    # —— 上传 / 提示词 ——
    "image_input": "input[type=file]",               # TODO 校准：首帧/素材图上传（可能需先点上传按钮）
    "tail_input": "input[type=file] >> nth=1",       # TODO 校准：尾帧图上传（「帧」模式）
    "prompt_box": "textarea",                        # TODO 校准：提示词输入框
    # —— 参数面板（点开底部「视频 · 720p · 8 秒 · x1」那个小胶囊弹出）——
    "settings_open": "button:has-text('x1')",        # TODO 校准：打开参数面板的按钮
    "type_video": "button:has-text('视频')",         # TODO 校准：类型 = 视频
    "mode_asset": "button:has-text('素材')",         # TODO 校准：素材模式
    "mode_frame": "button:has-text('帧')",           # TODO 校准：帧模式（首尾帧）
    "ratio": "button:has-text('{r}')",               # TODO 校准：画面比例，{r} = 16:9 / 9:16
    "model_menu": "[role=combobox], button:has-text('Omni'), button:has-text('Veo')",  # TODO 校准：模型下拉
    "model_opt": "[role=option]:has-text('{m}')",    # TODO 校准：模型选项，{m} = 模型名
    "res_720": "button:has-text('720p')",            # TODO 校准：Omni 分辨率 720p（团队固定用 720p）
    "dur_opt": "button:has-text('{n} 秒')",          # TODO 校准：Omni 时长，{n} = 4/6/8/10
    "count_x1": "button:has-text('x1')",             # TODO 校准：数量固定 x1
    # —— 生成 / 结果 ——
    "generate_btn": "button:has-text('Generate')",   # TODO 校准：生成按钮
    "quota_msg": "text=/limit|quota|额度/i",          # TODO 校准：额度用尽提示
    "result_video": "video",                         # TODO 校准：生成结果元素
    "download_btn": "button:has-text('Download')",   # TODO 校准：下载按钮
}


class NeedLogin(Exception): pass
class QuotaExhausted(Exception): pass


def _ctx(p, profile):
    return p.chromium.launch_persistent_context(
        str(profile), channel="chrome", headless=HEADLESS, accept_downloads=True)


def login(profile):
    """打开该账号的专属窗口，由人工登录；关闭窗口即保存登录态。"""
    with sync_playwright() as p:
        ctx = _ctx(p, profile)
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        page.goto(FLOW_URL)
        try:
            while ctx.pages:
                time.sleep(1)
        except Exception:
            pass


def _click(page, key, **fmt):
    page.locator(SEL[key].format(**fmt)).first.click()


def _safe_download_name(suggested):
    """下载文件名来自远端页面，不可直接拼进路径：只取 basename，
    拒绝空名 / . / ..，防 ../ 穿越到输出目录之外。"""
    name = pathlib.Path(suggested or "").name
    if not name or name in (".", ".."):
        name = "video.mp4"
    return name


def generate(profile, prompt, out_dir, image=None, tail=None, mode="asset",
             model="Omni 1.1 Flash", seconds=10, ratio="9:16"):
    """mode: asset=素材 / frame=帧。Omni 固定 720p、x1，可选 4/6/8/10 秒；Veo 固定 720p、8 秒，不用选。"""
    # 白名单校验：model / ratio / mode 会被拼进页面选择器（SEL 的 {m}/{r}），
    # 未校验的值可注入选择器语法；只接受已知值。
    _ALLOWED_MODELS = {"Omni 1.1 Flash", "Veo 3.1 - Lite", "Veo 3.1 - Fast", "Veo 3.1 - Quality"}
    if model not in _ALLOWED_MODELS:
        raise ValueError(f"未知模型：{model}")
    if ratio not in ("16:9", "9:16"):
        raise ValueError(f"未知画面比例：{ratio}")
    if mode not in ("asset", "frame"):
        raise ValueError(f"未知模式：{mode}")
    if seconds not in (4, 6, 8, 10):
        raise ValueError(f"未知时长：{seconds}")
    out_dir = pathlib.Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        ctx = _ctx(p, profile)
        try:
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            page.goto(FLOW_URL, wait_until="domcontentloaded")
            if "accounts.google.com" in page.url:
                raise NeedLogin()
            # 参数面板：视频 → 素材/帧 → 画面比例 → 模型 →（Omni：720p + 时长）→ x1
            _click(page, "settings_open")
            _click(page, "type_video")
            _click(page, "mode_frame" if mode == "frame" else "mode_asset")
            _click(page, "ratio", r=ratio)
            _click(page, "model_menu")
            _click(page, "model_opt", m=model)
            if model.startswith("Omni"):
                _click(page, "res_720")
                _click(page, "dur_opt", n=seconds)
            _click(page, "count_x1")
            page.keyboard.press("Escape")  # 收起面板
            if image:
                page.set_input_files(SEL["image_input"], image)
            if mode == "frame" and tail:
                page.set_input_files(SEL["tail_input"], tail)
            if prompt:
                page.fill(SEL["prompt_box"], prompt)
            page.click(SEL["generate_btn"])
            if page.locator(SEL["quota_msg"]).count():
                raise QuotaExhausted()
            try:
                page.wait_for_selector(SEL["result_video"], timeout=GEN_TIMEOUT)
            except PWTimeout:
                if page.locator(SEL["quota_msg"]).count():
                    raise QuotaExhausted()
                raise
            with page.expect_download(timeout=60000) as dl:
                page.click(SEL["download_btn"])
            path = out_dir / f"{int(time.time()*1000)}_{_safe_download_name(dl.value.suggested_filename)}"
            if path.resolve().parent != out_dir.resolve():
                raise ValueError("下载文件名非法")
            dl.value.save_as(path)
            return str(path)
        finally:
            ctx.close()
