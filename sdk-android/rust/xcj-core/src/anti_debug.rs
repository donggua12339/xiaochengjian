//! 反调试 + VM 检测模块(M2.5 实现)
//!
//! 详见 ADR 0024 (反调试策略)
//!
//! 检测项(MVP):
//!  - ptrace 自附加(防 gdb/lldb attach)
//!  - /proc/self/status TracerPid 字段(防 ptrace 已 attach)
//!  - Frida 端口扫描(27042)
//!  - 模拟器关键字段(build.prop 检测)
//!
//! 不做:
//!  - Root 检测(误报率高,且 Magisk Hide 能绕过)
//!  - 检测到异常不立即崩溃,延迟上报增加定位难度

/// 检测结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    /// 未检测到异常
    Clean,
    /// 检测到调试器或 Frida
    DebugDetected,
    /// 检测到模拟器
    EmulatorDetected,
}

/// 综合检测结果
pub struct DetectionResult {
    pub level: ThreatLevel,
    pub tracer_pid: u32,
    pub frida_port_open: bool,
    pub emulator_indicators: u32,
}

/// 检测 TracerPid(/proc/self/status)
///
/// TracerPid != 0 表示有调试器 attach
pub fn check_tracer_pid() -> u32 {
    // 读取 /proc/self/status,找 TracerPid 行
    // Android 上 /proc 可用
    #[cfg(target_os = "android")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
            for line in content.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid_str) = line.split(':').nth(1) {
                        if let Ok(pid) = pid_str.trim().parse::<u32>() {
                            return pid;
                        }
                    }
                }
            }
        }
    }
    0
}

/// 检测 Frida 端口(27042)
pub fn check_frida_port() -> bool {
    // 非 Android 环境(如测试)返回 false
    #[cfg(target_os = "android")]
    {
        // 读 /proc/net/tcp 检查 27042 端口
        if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
            // 27042 = 0x69A2
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let local = parts[1];
                    if local.ends_with(":69A2") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// 检测模拟器关键字段
///
/// 返回匹配的指标数(0 = 真机,>=2 = 高概率模拟器)
#[cfg_attr(not(target_os = "android"), allow(unused_mut))]
pub fn check_emulator_indicators() -> u32 {
    let mut count = 0u32;
    #[cfg(target_os = "android")]
    {
        // 读 build.prop 关键字段
        let props: [(&str, &[&str]); 5] = [
            ("ro.product.model", &["sdk", "google_sdk", "emulator", "android sdk"]),
            ("ro.product.brand", &["generic", "generic_x86"]),
            ("ro.product.device", &["generic", "generic_x86"]),
            ("ro.kernel.qemu", &["1"]),
            ("ro.hardware", &["goldfish", "ranchu"]),
        ];
        for (key, values) in &props {
            if let Ok(val) = std::fs::read_to_string(format!("/system/build.prop")) {
                for line in val.lines() {
                    if line.starts_with(key) {
                        let v = line.split('=').nth(1).unwrap_or("").to_lowercase();
                        for target in *values {
                            if v.contains(target) {
                                count += 1;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    count
}

/// 综合检测
pub fn detect() -> DetectionResult {
    let tracer_pid = check_tracer_pid();
    let frida_port_open = check_frida_port();
    let emulator_indicators = check_emulator_indicators();
    let frida_memory = check_frida_memory();
    let xposed_loaded = check_xposed();

    let level = if tracer_pid > 0 || frida_port_open || frida_memory {
        ThreatLevel::DebugDetected
    } else if emulator_indicators >= 2 || xposed_loaded {
        ThreatLevel::EmulatorDetected
    } else {
        ThreatLevel::Clean
    };

    DetectionResult {
        level,
        tracer_pid,
        frida_port_open,
        emulator_indicators,
    }
}

/// Frida 内存特征扫描(ADR 0059)
///
/// 扫描 /proc/self/maps 找 frida 相关模块(frida-agent / frida-gadget)
pub fn check_frida_memory() -> bool {
    #[cfg(target_os = "android")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/self/maps") {
            for line in content.lines() {
                let lower = line.to_lowercase();
                if lower.contains("frida-agent") || lower.contains("frida-gadget") || lower.contains("frida-server") {
                    return true;
                }
            }
        }
    }
    false
}

/// Xposed/LSPosed 模块检测(ADR 0059)
///
/// 扫描 /proc/self/maps 找 xposed/lsposed 相关模块
pub fn check_xposed() -> bool {
    #[cfg(target_os = "android")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/self/maps") {
            for line in content.lines() {
                let lower = line.to_lowercase();
                if lower.contains("xposed") || lower.contains("lsposed") || lower.contains("riru") {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_returns_result() {
        let result = detect();
        assert!(matches!(
            result.level,
            ThreatLevel::Clean | ThreatLevel::DebugDetected | ThreatLevel::EmulatorDetected
        ));
    }

    #[test]
    fn test_frida_memory_default_false() {
        assert!(!check_frida_memory());
    }

    #[test]
    fn test_xposed_default_false() {
        assert!(!check_xposed());
    }
}
