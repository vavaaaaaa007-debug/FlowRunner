# Flow Runner

本地批量调度 Google Flow 生成视频：账号池、点数、批次队列。

## 运行
1. 安装 Python 3.10+，以及本机的 Google Chrome（程序直接用系统 Chrome，不需要 `playwright install`）。
2. `pip install -r requirements.txt`
3. `python app.py`，终端会停在那里，**保持不关**。
4. 浏览器打开 http://127.0.0.1:8765 使用（不要直接双击 index.html）。

更新文件后需要先关掉再重新运行 `python app.py`。

## 数据位置
账号库、登录状态、上传的图片放在每个人自己的用户目录：
- Mac：`~/Library/Application Support/FlowRunner`
- Windows：`%APPDATA%\FlowRunner`

可用环境变量 `FLOW_DATA` 指定其它位置。视频默认保存到 `~/Downloads/FlowRunner`（可在「设置」里改）。

## 注意
- **账号池主密码**：第一次打开会先让你设定一个主密码（至少 8 位），以后每次启动程序、每次打开新标签页，都要先输入主密码才能进入账号池；右上角「🔒 锁定」可随时再锁上。主密码用来加密账号池里的 Google 密码和二步验证密钥（PBKDF2 派生，磁盘上只存盐和校验值，不存主密码本身）。
- **忘记主密码无法找回**：已存的账号密码和二步验证密钥将永久无法解密，只能删除数据目录里的 `pool.db` 和 `.master.json` 后重新填写账号。请把主密码记在密码管理器里。
- 密码和二步验证密钥以加密形式存在本机数据库里。**仍不要把数据目录发给别人或传到网盘**。已经把旧数据目录（修复前是明文）发给过别人或同步到网盘的，**请立即去 Google 账号改密码、重置二步验证**，只删文件不够。
- 服务只监听 127.0.0.1:8765，且拒绝非本机 Host / 跨站 Origin 的请求；不要用反向代理把它暴露到局域网或公网，也不要改 `host="0.0.0.0"`。
- `flow_driver.py` 里带 `TODO 校准` 的页面选择器是占位的，需要用真实的 Flow 页面校准。
- 点数表在 `app.py` 最前面的 `COST`，Flow 调价时只改这里。

## 安全审核
见 `SECURITY_AUDIT_REPORT.md`（2026-10-27）：依赖、代码与凭据的完整审核与修复记录。
