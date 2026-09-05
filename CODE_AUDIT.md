# Spectre 代码审计报告

> 审计对象：`src/`（Rust 发送端）与 `scripts/decode.py`（Python 接收端）
> 审计目的：开源发布前的安全性、健壮性、可维护性审查
> 审计时间：2026-08-28
> 结论：核心链路可运行，存在 2 个高风险安全问题与若干健壮性缺陷，建议在发布前修复。

---

## 一、审计范围

| 文件 | 说明 |
|------|------|
| `src/main.rs` | 入口：参数解析、采集编排、调用外带 |
| `src/collect.rs` | 系统信息采集（主机/CPU/内存/进程/软件/磁盘/网卡） |
| `src/crypto.rs` | ChaCha20-Poly1305 加密 + Base32 编码 |
| `src/exfil.rs` | HTTPS 回连外带 + DNS 分片外带 |
| `scripts/decode.py` | 接收端：加密串/日志 → 解密 → JSON |

---

## 二、审计结论概览

| 编号 | 类型 | 严重度 | 一句话描述 |
|------|------|--------|-----------|
| HIGH-1 | 安全 | 🔴 高 | 硬编码 27 字节演示密钥，端到端加密形同虚设 |
| HIGH-2 | 安全 | 🔴 高 | 关闭 TLS 证书校验，配合固定密钥可被中间人/逆向全量还原 |
| MED-1 | 健壮性 | 🟠 中 | `--key` 传入奇数长度 hex 会触发 panic |
| MED-2 | 架构 | 🟡 低 | DNS 分片外带的标签顺序无保证（主用 HTTPS 规避） |
| MED-3 | 健壮性 | 🟡 低 | `get_memory`/`get_processes` 重复创建 `System` 实例，性能浪费 |
| LOW-1 | 健壮性 | 🟢 低 | 小写 `--key`/十六进制大小写与异常输入的处理 |

---

## 三、详细发现

### 🔴 HIGH-1：硬编码加密密钥（默认密钥写死且长度不匹配）

**位置**：
- Rust 发送端：`src/main.rs:48-53`
- Python 接收端：`scripts/decode.py:39`

**代码**：
```rust
// src/main.rs
for (i, b) in b"spectre-demo-key-32bytes-!".iter().enumerate() {
    if i < crypto::KEY_LEN { key[i] = *b; }
}
```
```python
# decode.py
DEMO_KEY = bytes(b"spectre-demo-key-32bytes-!").ljust(32, b"\x00")
```

**问题**：
- 密钥 `spectre-demo-key-32bytes-!` 实际只有 **27 字节**，靠补零凑到 32 字节，属于硬编码、公开、可推断的固定值。
- 开源项目中该密钥直接暴露在仓库里，任何拿到源码/二进制的人都能用已知密钥解出全部采集到的明文。
- 端到端加密（ChaCha20-Poly1305）在此场景下**失去意义**。

**影响**：加密形同虚设；攻击者/逆向者可无缝还原所有采集数据（主机名、进程、用户、网络等敏感信息）。

**修复建议**：
1. 移除默认密钥，强制要求 `--key` 传入真正的 32 字节随机值。
2. 若需保留演示密钥，必须在 README 显著标注「仅用于本地联调，部署前必须替换」。
3. 生成密钥建议：`openssl rand -hex 32`，运行时通过 `--key` 注入，避免写死。

---

### 🔴 HIGH-2：关闭服务端 TLS 证书校验

**位置**：`src/exfil.rs:24-74`（`permissive_tls_config` / `AcceptAll` 验证器）

**代码**：
```rust
impl rustls::client::danger::ServerCertVerifier for AcceptAll {
    fn verify_server_cert(&self, ...) -> Result<...> {
        Ok(rustls::client::danger::ServerCertVerified::assertion()) // 一律放行
    }
    ...
}
```

**问题**：
- 自定义验证器对**所有证书无条件放行**，任何中间人（MITM）都可劫持连接。
- 数据虽经 ChaCha20 加密，但配合 HIGH-1 的固定密钥，等同于明文可控。
- 关闭证书校验是杀软行为 ML 的典型规避信号（曾触发 `Behavior:Win32/DefenseEvasion.A!ml`）。

**背景说明**：
- 引入该逻辑的初衷是突破沙箱 TLS 中间人劫持（微步报 `UnknownIssuer`），属「沙箱穿透」与「安全校验」的两难选择。

**修复建议（三选一或组合）**：
1. **保留默认严格校验**：数据本身已加密，多数场景无需关闭校验；若沙箱劫持导致失败，改用 DNSLOG 外带（DDoS 查询通常放行）。
2. **条件启用**：仅当检测到沙箱特征（如异常主机名/进程/时间）时才启用宽松校验。
3. **至少配合随机密钥**：若必须关闭校验，务必先解决 HIGH-1，否则等于明文传输。

---

### 🟠 MED-1：`--key` 解析存在 panic 风险

**位置**：`src/main.rs:31-36`（`parse_key`）

**代码**：
```rust
let bytes = (0..s.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&s[i..i + 2], 16)) // s 为奇数长时 i+2>len 越界
    ...
```

**问题**：
- 输入**奇数长度**字符串时，最后一步 `i+2 > s.len()` 会触发 `slice index out of bounds` → **panic 崩溃**，而非优雅报错。

**复现**：
```powershell
.\spectre.exe --key abc   # panic: index out of bounds
```

**修复建议**：
```rust
fn parse_key(s: &str) -> Option<[u8; crypto::KEY_LEN]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()?;
    ...
}
```

---

### 🟡 MED-2：DNS 分片外带的标签顺序无保证

**位置**：`src/exfil.rs:130-146`、`scripts/decode.py:77-96`

**问题**：
- DNS 分片依赖平台记录顺序，`decode.py --reverse` 只是人工猜测（后台通常倒序）。
- 若平台乱序/丢片记录，解密必然失败。

**影响**：DNS 分片外带可靠性低，仅适合作为备用通道。

**建议**：主用 HTTPS 回连（顺序有保证）；DNS 分片仅作应急。若依赖 DNS，可在每个标签前加入**序号前缀**以支持乱序重组。

---

### 🟡 MED-3：重复创建 `System` 实例，性能浪费

**位置**：`src/collect.rs:154-158`、`161-173`

**代码**：
```rust
fn get_memory()   { let mut sys = sysinfo::System::new_all(); ... }
fn get_processes(){ let mut sys = sysinfo::System::new_all(); ... }
```

**问题**：
- 每次调用都 `new_all()` 全量刷新，多次创建开销较大（尤其在沙箱/内存受限环境）。

**建议**：在 `collect()` 中创建**一次** `System::new_all()` 并复用，分别 `refresh_memory()` / `refresh_processes()`。

---

### 🟢 LOW-1：输入校验与异常处理

- `parse_key` 未校验十六进制字符合法性（`bytes.fromhex` 在 Python 端有校验，Rust 端靠 `from_str_radix` 兜底，但越界 panic 未规避）。
- `decode.py` 的 `decrypt_direct` 中 `base64.b64decode` 若遇非法输入会抛异常，未统一包裹进 try（仅 decrypt 有 try）。
- `collect.rs` 的 `get_outbound_ip` 硬编码 `8.8.8.8:53`，在无外网环境返回空串（可接受，但可考虑配置化）。

---

## 四、验证清单（供维护者复测）

```powershell
# 1. 复现 parse_key panic
.\spectre.exe --key abc123              # 预期：panic（修复后应优雅报错）

# 2. 验证密钥长度
python -c "k=b'spectre-demo-key-32bytes-!'; print(len(k))"   # 预期：27（应为 32）

# 3. 正常链路 dry-run
.\spectre.exe --dry-run                 # 预期：打印采集 JSON，不外带

# 4. 接收端解码（用演示密钥，仅本地测试）
python scripts/decode.py --raw "<demo加密串>" --needles "hostname"
```

---

## 五、修复优先级建议

| 优先级 | 编号 | 处理 |
|--------|------|------|
| P0（发布前必改） | HIGH-1 | 移除硬编码演示密钥，token 由 `--key` 注入 |
| P0（发布前必改） | MED-1 | `parse_key` 增加长度与 hex 校验，杜绝 panic |
| P1（建议） | HIGH-2 | 权衡 TLS 校验；若保留，先确保无线索密钥 |
| P2（可选） | MED-3 | 复用 `System` 实例优化性能 |
| P3（可选） | MED-2 / LOW-1 | DNS 分片加序号、统一异常处理 |

---

## 六、声明

本审计仅针对代码质量与安全风险，不构成对项目用途的背书。项目仅限**明确授权范围内**的安全研究与防御验证使用，使用者需自行承担合规责任。
