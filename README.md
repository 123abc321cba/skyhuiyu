# sky·徽遇（SkyHuiyu）

手机贴 NFC 徽章 → 局域网加密上传 → 电脑收下 → 用玩家自己的游戏会话把徽章验到官方账号上。
Windows / Android / iOS 三端源码都在这里；Windows 与 Android 提供预编译包，
iOS 需在 macOS 上用 Xcode 构建（Windows 上无法编译）。

> 非官方项目，与网易、thatgamecompany 及其关联方没有任何关系。
> 本项目代码为自行实现，未包含第三方项目的源码；使用的开源依赖归各自作者所有。

---

## 功能

- **端到端加密的局域网直传**：P-256 ECDH → HKDF-SHA256 → AES-256-GCM，
  手机与电脑之间不经过任何服务器。
- **二维码配对 + 公钥固定**：二维码里的公钥是唯一可信来源，握手时逐字节比对，防中间人。
- **离线徽章图鉴**：115 种徽章的中文名、图标、冷却与效果说明，贴卡即认，
  不用联网也能显示「恶作剧皮皮猫毛绒玩具」而不是一串 SKU。
- **自带抓取栈**（Windows）：本机 CA、单端口 PAC 代理、443 透传、hosts 自动还原，
  不依赖任何第三方抓包工具。
- **两种提交方式**：`local` 只入库；`netease` 用自己实现的信封协议直连官方接口，
  并在验章后核对库存，避免"提示存了、其实没存"。
- **失败可对账**：每次提交都写一条 injection 记录（含 request_id 与原始回包）。

---

## 目录结构

```
SkyHuiyu/
├─ README.md
├─ LICENSE                        MIT
├─ release/                       编译产物（exe / apk + 校验和）
├─ pc/
│  ├─ 源码/                       Python 包、测试、构建脚本
│  └─ 程序/                       启动.bat / 抓取会话.bat（exe 见 Releases）
├─ android/
│  ├─ 源码/                       Gradle 工程 + Kotlin 源码
│  └─ 安装包/                     skyhuiyu-2.0.0-debug.apk
└─ ios/
   └─ 源码/                       Swift / Xcode 工程
```

---

## 快速开始

### Windows

1. 从 Releases 下载 `skyhuiyu-2.0.0-win64.exe` 放到 `pc\程序\`，双击 `启动.bat`（或直接运行 exe）。
2. 程序会打开独立窗口（WebView2），面板上显示配对二维码。
3. 手机 App 扫码配对 → 贴卡 → 徽章出现在面板里。
4. 需要真正验章时，先在面板「抓取新会话」里点一次「轻量抓取」，按提示在官方平台登录。

### Android

安装 `release/skyhuiyu-2.0.0-debug.apk`（debug 签名，可直接安装）。
需要 Android 8.0+ 且支持 NFC。

### iOS

源码在 `ios/源码/`，需在 macOS 上用 Xcode 构建并自签（AltStore / Sideloadly / 开发者证书）。
iOS 17+，需要 NFC。预编译 IPA 不随仓库提供。

---

## 使用流程

1. **配对**：手机扫电脑面板上的二维码。二维码里带电脑的公钥、局域网地址与端口。2.0 起配对密钥参数已更新，电脑端与手机端需要同版本。
2. **贴卡**：手机读取徽章 NDEF 里的链接（`https://sky.thatg.co/?s=…&c=…`），
   用协商好的会话密钥加密后发到电脑。
3. **入库**：电脑解密、去重、按 uid 只保留最新一条，并从链接里的 `s=` 解析 SKU，
   匹配本地图鉴显示名称与图标。
4. **验章（可选）**：`backend=netease` 时，电脑用抓到的游戏会话调用官方接口，
   再把结果写回面板与手机。

徽章链接本身就是凭证：签名在 `s=`、目标账号在 `u=`、计数器在 `c=`。
电脑只是替玩家把这条链接提交给官方。

---

## 抓取游戏会话

官方接口只认游戏客户端自己的会话，所以需要先抓一份：

```powershell
skyhuiyu.exe --capture enable      # 需要管理员：要写 hosts / 改系统代理 / 装本机 CA
skyhuiyu.exe --capture status
skyhuiyu.exe --capture disable     # 也可直接 Ctrl+C，会还原
```

抓取栈做四件事：

1. 生成一张本机 CA 并装进 `CurrentUser\ROOT`（只装一次，会弹一次 Windows 安全警告）。
2. 起一个单端口 MITM 代理，同一个端口同时提供 PAC 与代理。
3. 需要时把 `ma75.update.netease.com` 临时指向本机，并清一次 CEF 解析缓存。
4. 从登录请求头 / 登录响应里取会话，落库后立刻撤掉 hosts。

退出时还原系统代理、hosts 与登录票据，机器上不留常驻项。

---

## 从源码构建

### PC（Python 3.11+）

```powershell
cd pc\源码
pip install -r requirements.txt
python -m PyInstaller --noconfirm --clean skyhuiyu.spec
# 产物：dist\skyhuiyu.exe
```

也可以直接跑源码：

```powershell
python entry.py            # 独立窗口
python entry.py --browser  # 用系统浏览器打开面板
```

### Android（JDK 17+，Android SDK 34）

```bash
cd android/源码
gradle assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk
```

若工程路径含中文（例如 `D:\开发\...`），AGP 会拒绝构建：把工程复制到纯 ASCII 路径再构建，
或在 `gradle.properties` 里加 `android.overridePathCheck=true`。

### iOS（macOS + Xcode）

```bash
cd ios/源码
xcodebuild -project SkyHuiyu.xcodeproj -scheme SkyHuiyu \
  -configuration Release -sdk iphoneos \
  -archivePath build/SkyHuiyu.xcarchive archive
```

导出的 IPA 是未签名的，安装前需要自签。

**没有 Mac：用 GitHub Actions 打包。** 仓库自带 `.github/workflows/ios.yml`：

1. 把仓库推到 GitHub。
2. 打开 **Actions → Build iOS IPA → Run workflow**（版本号可留空，自动读工程里的
   `MARKETING_VERSION`）。
3. 跑完在本次 run 页面底部 **Artifacts** 下载 `SkyHuiyu-<版本>-ipa`。
4. 推一个 `v*` tag（例如 `v2.0.0`）时，会自动把 IPA 与 SHA256 附到对应的 Release。

产物是未签名 IPA，用 AltStore / Sideloadly / 开发者证书签名后安装；
NFC 需要开发者账号在 App ID 上开启 **NFC Tag Reading** capability，并在签名时带上
`ios/源码/SkyHuiyu/SkyHuiyu.entitlements` 里的 `com.apple.developer.nfc.readersession.formats`。

---

## 命令行

```text
skyhuiyu.exe                      起服务 + 打开面板
skyhuiyu.exe --no-browser         只起服务
skyhuiyu.exe --browser            用系统浏览器打开面板
skyhuiyu.exe --check              体检：CA / 代理 / hosts / 会话 / 端口
skyhuiyu.exe --print-qr           终端打印配对二维码
skyhuiyu.exe --backend local      只入库（默认）
skyhuiyu.exe --backend netease    自己调官方接口
skyhuiyu.exe --capture enable     抓取游戏会话（管理员）
skyhuiyu.exe --capture disable    还原
skyhuiyu.exe --badge-qr <id>      把某枚徽章渲染成二维码
```

---

## 数据与隐私

- 数据目录：`%APPDATA%\SkyHuiyu\`
  （`skyhuiyu.db`、`config.json`、本机 CA、日志）。
- 会话 token 存在本地 SQLite 里，**不加密**：这是本机工具，请不要把数据目录同步到网盘。
- 抓包样本默认只落在本机 `capture-bodies\`，不会上传。
- 面板默认监听 `0.0.0.0:8765`，供同网段手机连接；配对需要扫二维码。
  如果只在单机使用，可在 `config.json` 里把 `bind` 改成 `127.0.0.1`。

---

## 测试

测试都在 `pc\源码\tests\`，不需要游戏、不需要联网：

```powershell
cd pc\源码
python tests\test_crypto.py
python tests\test_envelope.py
python tests\test_capture.py     # 会真的装/删一次本机 CA，并临时改系统代理（会自动还原）
```

`test_capture.py` 覆盖 PAC 文本、authinfo 解析、CA 签发、hosts 增删、WinINet 下发/还原、
代理端到端（PAC 同端口、明文 HTTP、CONNECT MITM）。

---

## 第三方依赖

PC：`aiohttp`、`cryptography`、`qrcode`、`Pillow`、`pywebview`（均为 MIT/BSD/Apache 系许可证）。
Android：AndroidX、Material、OkHttp、ZXing embedded。
iOS：仅系统框架（CryptoKit / Security / Network / SwiftUI）。

---

## 许可证

MIT，见 [LICENSE](LICENSE)。
