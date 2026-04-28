use std::{
    collections::BTreeMap,
    ffi::{CStr, CString, OsStr},
    fs, io,
    mem::{size_of, zeroed},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::android::ksucalls::ksuctl;
use crate::ksu_uapi;

const KPM_DIR: &str = "/data/adb/kpm";
const KPM_DISABLE_FILE: &str = "/data/adb/kpm.disabled";
const KPM_DIR_MODE: u32 = 0o700;

struct KpmDirStatus {
    exists: bool,
    is_dir: bool,
    is_symlink: bool,
    mode: Option<u32>,
}

struct KpmCaps {
    loader_version: String,
    abi_version: u32,
    feature_bits: u64,
}

impl KpmDirStatus {
    fn ok(&self) -> bool {
        self.exists && self.is_dir && !self.is_symlink && self.mode == Some(KPM_DIR_MODE)
    }
}

fn kernel_error(ret: i32) -> io::Error {
    io::Error::from_raw_os_error(ret.checked_neg().unwrap_or(ret))
}

fn ensure_kpm_ret(action: &str, ret: i32) -> Result<()> {
    if ret < 0 {
        bail!("{action}: {} ({ret})", kernel_error(ret));
    }
    Ok(())
}

fn run_kpm_cmd(control_code: u8, arg1: u64, arg2: u64) -> Result<i32> {
    let mut ret = -1;
    let mut cmd = ksu_uapi::ksu_kpm_cmd {
        control_code,
        arg1,
        arg2,
        result_code: &raw mut ret as u64,
    };

    ksuctl(ksu_uapi::KSU_IOCTL_KPM_RUST, &raw mut cmd)?;
    Ok(ret)
}

pub fn load_module<P>(path: P, args: Option<&str>) -> Result<()>
where
    P: AsRef<Path>,
{
    let path = CString::new(path.as_ref().to_string_lossy().to_string())?;
    let args = args.map_or_else(|| CString::new(String::new()), CString::new)?;

    let ret = run_kpm_cmd(
        ksu_uapi::KSU_KPM_LOAD_RUST,
        path.as_ptr() as u64,
        args.as_ptr() as u64,
    )?;
    ensure_kpm_ret("Failed to load kpm", ret)
}

fn list_modules_string() -> Result<String> {
    let mut buf = vec![0u8; 1024];

    let ret = run_kpm_cmd(
        ksu_uapi::KSU_KPM_LIST_RUST,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )?;
    ensure_kpm_ret("Failed to get kpm list", ret)?;

    Ok(buf2str(&buf))
}

pub fn list(json_output: bool) -> Result<()> {
    let modules = list_modules_string()?;

    if json_output {
        let items: Vec<&str> = modules
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        println!("{}", json!({ "modules": items }));
    } else {
        println!("{modules}");
    }
    Ok(())
}

pub fn unload_module(name: String) -> Result<()> {
    let name = CString::new(name)?;

    let ret = run_kpm_cmd(ksu_uapi::KSU_KPM_UNLOAD_RUST, name.as_ptr() as u64, 0)?;
    ensure_kpm_ret("Failed to unload kpm", ret)
}

pub fn info(name: &str) -> Result<()> {
    let info = info_string(name)?;
    println!("{info}");
    Ok(())
}

fn info_string(name: &str) -> Result<String> {
    let name = CString::new(name)?;
    let mut buf = vec![0u8; 1024];

    let ret = run_kpm_cmd(
        ksu_uapi::KSU_KPM_INFO_RUST,
        name.as_ptr() as u64,
        buf.as_mut_ptr() as u64,
    )?;
    ensure_kpm_ret("Failed to get kpm info", ret)?;

    Ok(buf2str(&buf))
}

pub fn control(name: String, args: String) -> Result<i32> {
    let name = CString::new(name)?;
    let args = CString::new(args)?;

    let ret = run_kpm_cmd(
        ksu_uapi::KSU_KPM_CONTROL_RUST,
        name.as_ptr() as u64,
        args.as_ptr() as u64,
    )?;
    ensure_kpm_ret("Failed to control kpm", ret)?;

    Ok(ret)
}

fn num_value() -> Result<i32> {
    let ret = run_kpm_cmd(ksu_uapi::KSU_KPM_NUM_RUST, 0, 0)?;
    ensure_kpm_ret("Failed to get kpm num", ret)?;
    Ok(ret)
}

fn caps_value() -> Result<KpmCaps> {
    let mut caps: ksu_uapi::ksu_kpm_caps = unsafe { zeroed() };

    let ret = run_kpm_cmd(
        ksu_uapi::KSU_KPM_CAPS_RUST,
        &raw mut caps as u64,
        size_of::<ksu_uapi::ksu_kpm_caps>() as u64,
    )?;
    ensure_kpm_ret("Failed to get kpm caps", ret)?;

    let loader_version = unsafe { CStr::from_ptr(caps.loader_version.as_ptr()) }
        .to_string_lossy()
        .trim()
        .to_string();
    if loader_version.is_empty() {
        bail!("KPM: invalid caps version response");
    }

    Ok(KpmCaps {
        loader_version,
        abi_version: caps.abi_version,
        feature_bits: caps.feature_bits,
    })
}

fn audit_string() -> Result<String> {
    let mut buf = vec![0u8; 8192];

    let ret = run_kpm_cmd(
        ksu_uapi::KSU_KPM_AUDIT_RUST,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )?;
    ensure_kpm_ret("Failed to get kpm audit", ret)?;

    Ok(buf2str(&buf))
}

pub fn num() -> Result<i32> {
    let ret = num_value()?;
    println!("{ret}");
    Ok(ret)
}

fn version_string() -> Result<String> {
    let mut buf = vec![0u8; 1024];

    let ret = run_kpm_cmd(
        ksu_uapi::KSU_KPM_VERSION_RUST,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )?;
    ensure_kpm_ret("Failed to get kpm version", ret)?;

    let ver = buf2str(&buf).trim().to_string();
    if ver.is_empty() {
        bail!("KPM: invalid version response");
    }
    Ok(ver)
}

pub fn version(json_output: bool) -> Result<()> {
    let ver = version_string()?;

    if json_output {
        println!("{}", json!({ "loader_version": ver }));
    } else {
        println!("{ver}");
    }
    Ok(())
}

pub fn check_version() -> Result<String> {
    let ver = version_string()?;
    log::info!("KPM: version check ok: {ver}");
    Ok(ver)
}

fn ensure_dir() -> Result<()> {
    let dir = Path::new(KPM_DIR);

    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }

    let metadata = fs::symlink_metadata(dir)?;
    if metadata.file_type().is_symlink() {
        bail!("KPM dir must not be a symlink: {KPM_DIR}");
    }
    if !metadata.is_dir() {
        bail!("KPM path is not a directory: {KPM_DIR}");
    }

    if metadata.permissions().mode() & 0o777 != KPM_DIR_MODE {
        fs::set_permissions(dir, fs::Permissions::from_mode(KPM_DIR_MODE))?;
    }

    Ok(())
}

fn inspect_kpm_dir() -> KpmDirStatus {
    let dir = Path::new(KPM_DIR);

    fs::symlink_metadata(dir).map_or_else(
        |_| KpmDirStatus {
            exists: false,
            is_dir: false,
            is_symlink: false,
            mode: None,
        },
        |metadata| KpmDirStatus {
            exists: true,
            is_dir: metadata.is_dir(),
            is_symlink: metadata.file_type().is_symlink(),
            mode: Some(metadata.permissions().mode() & 0o777),
        },
    )
}

fn kernel_release() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .to_string())
}

pub fn doctor(json_output: bool) -> Result<()> {
    let caps = caps_value().map_err(|e| e.to_string());
    let loader_version = caps
        .as_ref()
        .map(|caps| caps.loader_version.clone())
        .or_else(|_| version_string())
        .map_err(|e| e.to_string());
    let modules_loaded = num_value().map_err(|e| e.to_string());
    let kernel_release = kernel_release().map_err(|e| e.to_string());
    let dir = inspect_kpm_dir();
    let safe_mode = crate::android::utils::is_safe_mode();
    let autoload_disabled = Path::new(KPM_DISABLE_FILE).exists();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "loader_version": loader_version.as_ref().ok(),
                "loader_version_error": loader_version.as_ref().err(),
                "loader_abi_version": caps.as_ref().ok().map(|caps| caps.abi_version),
                "loader_feature_bits": caps.as_ref().ok().map(|caps| format!("0x{:x}", caps.feature_bits)),
                "loader_caps_error": caps.as_ref().err(),
                "kernel_release": kernel_release.as_ref().ok(),
                "kernel_release_error": kernel_release.as_ref().err(),
                "kernel_arch": std::env::consts::ARCH,
                "modules_loaded": modules_loaded.as_ref().ok(),
                "modules_loaded_error": modules_loaded.as_ref().err(),
                "kpm_dir": {
                    "path": KPM_DIR,
                    "exists": dir.exists,
                    "is_dir": dir.is_dir,
                    "is_symlink": dir.is_symlink,
                    "mode": dir.mode.map(|mode| format!("{mode:o}")),
                    "expected_mode": format!("{KPM_DIR_MODE:o}"),
                    "ok": dir.ok(),
                },
                "autoload_disabled": autoload_disabled,
                "autoload_disable_file": KPM_DISABLE_FILE,
                "safe_mode": safe_mode,
            }))?
        );
    } else {
        match &loader_version {
            Ok(ver) => println!("loader_version={ver}"),
            Err(err) => println!("loader_version_error={err}"),
        }
        match &caps {
            Ok(caps) => {
                println!("loader_abi_version={}", caps.abi_version);
                println!("loader_feature_bits=0x{:x}", caps.feature_bits);
            }
            Err(err) => println!("loader_caps_error={err}"),
        }
        match &kernel_release {
            Ok(release) => println!("kernel_release={release}"),
            Err(err) => println!("kernel_release_error={err}"),
        }
        println!("kernel_arch={}", std::env::consts::ARCH);
        match &modules_loaded {
            Ok(num) => println!("modules_loaded={num}"),
            Err(err) => println!("modules_loaded_error={err}"),
        }
        println!("kpm_dir={KPM_DIR}");
        println!("kpm_dir_exists={}", dir.exists);
        println!("kpm_dir_is_dir={}", dir.is_dir);
        println!("kpm_dir_is_symlink={}", dir.is_symlink);
        println!(
            "kpm_dir_mode={}",
            dir.mode
                .map_or_else(|| "missing".to_string(), |mode| format!("{mode:o}"))
        );
        println!("kpm_dir_expected_mode={KPM_DIR_MODE:o}");
        println!("kpm_dir_ok={}", dir.ok());
        println!("autoload_disabled={autoload_disabled}");
        println!("autoload_disable_file={KPM_DISABLE_FILE}");
        println!("safe_mode={safe_mode}");
    }

    Ok(())
}

fn parse_kv_lines(input: &str) -> BTreeMap<String, String> {
    input
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn module_sha256(info: &BTreeMap<String, String>) -> (Option<String>, Option<String>) {
    let Some(source_path) = info.get("source_path").filter(|path| !path.is_empty()) else {
        return (None, Some("missing source_path".to_string()));
    };

    match fs::read(source_path) {
        Ok(bytes) => (Some(sha256::digest(&bytes)), None),
        Err(err) => (None, Some(err.to_string())),
    }
}

pub fn audit(json_output: bool) -> Result<()> {
    let kernel_audit = audit_string().map_err(|e| e.to_string());
    let module_names = list_modules_string()
        .map(|modules| {
            modules
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string())
                .collect::<Vec<_>>()
        })
        .map_err(|e| e.to_string());

    let module_reports = module_names
        .as_ref()
        .map(|names| {
            names
                .iter()
                .map(|name| {
                    let info = info_string(name).map(|raw| parse_kv_lines(&raw));
                    match info {
                        Ok(info) => {
                            let (sha256, sha256_error) = module_sha256(&info);
                            json!({
                                "name": name,
                                "info": info,
                                "sha256": sha256,
                                "sha256_error": sha256_error,
                            })
                        }
                        Err(err) => json!({
                            "name": name,
                            "info_error": err.to_string(),
                        }),
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "kernel_audit": kernel_audit.as_ref().ok(),
                "kernel_audit_error": kernel_audit.as_ref().err(),
                "module_list_error": module_names.as_ref().err(),
                "modules": module_reports,
            }))?
        );
    } else {
        match &kernel_audit {
            Ok(audit) => println!("{audit}"),
            Err(err) => println!("kernel_audit_error={err}"),
        }
        if let Err(err) = &module_names {
            println!("module_list_error={err}");
        }
        for report in module_reports {
            println!("{report}");
        }
    }

    Ok(())
}

pub fn autoload_status(json_output: bool) -> Result<()> {
    let dir = inspect_kpm_dir();
    let disabled = Path::new(KPM_DISABLE_FILE).exists();
    let disable_reason = fs::read_to_string(KPM_DISABLE_FILE).ok();

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "autoload_disabled": disabled,
                "autoload_disable_file": KPM_DISABLE_FILE,
                "autoload_disable_reason": disable_reason.as_deref(),
                "kpm_dir": {
                    "path": KPM_DIR,
                    "exists": dir.exists,
                    "is_dir": dir.is_dir,
                    "is_symlink": dir.is_symlink,
                    "mode": dir.mode.map(|mode| format!("{mode:o}")),
                    "expected_mode": format!("{KPM_DIR_MODE:o}"),
                    "ok": dir.ok(),
                },
            }))?
        );
    } else {
        println!("autoload_disabled={disabled}");
        println!("autoload_disable_file={KPM_DISABLE_FILE}");
        if let Some(reason) = disable_reason {
            print!("autoload_disable_reason={reason}");
            if !reason.ends_with('\n') {
                println!();
            }
        }
        println!("kpm_dir={KPM_DIR}");
        println!("kpm_dir_ok={}", dir.ok());
    }

    Ok(())
}

pub fn autoload_disable(reason: Option<String>) -> Result<()> {
    let marker = reason.map_or_else(
        || "autoload disabled by user\n".to_string(),
        |reason| format!("autoload disabled by user: {reason}\n"),
    );
    fs::write(KPM_DISABLE_FILE, marker)
        .with_context(|| format!("Failed to write {KPM_DISABLE_FILE}"))?;
    Ok(())
}

pub fn autoload_enable() -> Result<()> {
    match fs::remove_file(KPM_DISABLE_FILE) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("Failed to remove {KPM_DISABLE_FILE}")),
    }
}

pub fn autoload_now() -> Result<()> {
    check_version()?;
    ensure_dir()?;
    load_all_modules()
}

pub fn booted_load() -> Result<()> {
    check_version()?;
    ensure_dir()?;

    if crate::android::utils::is_safe_mode() {
        log::warn!("KPM: safe-mode - all modules won't load");
        return Ok(());
    }

    if Path::new(KPM_DISABLE_FILE).exists() {
        log::warn!("KPM: autoload disabled by {KPM_DISABLE_FILE}");
        return Ok(());
    }

    if let Err(err) = load_all_modules() {
        let marker = format!("autoload disabled after boot failure: {err}\n");
        if let Err(write_err) = fs::write(KPM_DISABLE_FILE, marker) {
            log::error!("KPM: failed to write {KPM_DISABLE_FILE}: {write_err}");
        }
        return Err(err);
    }

    Ok(())
}

fn load_all_modules() -> Result<()> {
    let dir = Path::new(KPM_DIR);
    let mut modules = Vec::new();
    let mut failures = 0;

    if !dir.is_dir() {
        return Ok(());
    }

    for entry in dir.read_dir()? {
        let p = entry?.path();

        if p.extension() != Some(OsStr::new("kpm")) {
            continue;
        }

        match fs::symlink_metadata(&p) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                failures += 1;
                log::error!("KPM: refusing symlink autoload module {}", p.display());
            }
            Ok(metadata) if metadata.is_file() => modules.push(p),
            Ok(_) => {
                failures += 1;
                log::error!("KPM: refusing non-file autoload module {}", p.display());
            }
            Err(err) => {
                failures += 1;
                log::error!("KPM: failed to inspect {}: {err}", p.display());
            }
        }
    }

    modules.sort();

    for p in modules {
        if let Err(e) = load_module(&p, None) {
            failures += 1;
            log::error!("KPM: failed to load {}: {e}", p.display());
        }
    }

    if failures > 0 {
        bail!("KPM: {failures} module(s) failed to load");
    }
    Ok(())
}

/// Convert zero-padded kernel buffer to owned String.
/// DON'T REMOVE!!! we must use this method, because kernel use \0 to end of buffer
/// if directly to_string_lossy, we will get a lot of uninit data
/// refer: res = copy_to_user(arg1, &buffer, len + 1);
fn buf2str(buf: &[u8]) -> String {
    // SAFETY: buffer is always NUL-terminated by kernel.
    unsafe {
        CStr::from_ptr(buf.as_ptr().cast())
            .to_string_lossy()
            .into_owned()
    }
}
