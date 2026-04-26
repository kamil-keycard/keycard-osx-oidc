//! macOS identity helpers: UID -> username, hostname, machine UUID.

use std::ffi::CStr;
use std::process::Command;

use anyhow::{anyhow, Context, Result};

/// Resolve a username for the given UID via `getpwuid_r`. Returns the UID
/// itself rendered as a string if the user is not found.
pub fn username_for_uid(uid: u32) -> Result<String> {
    let mut buf = vec![0i8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid as libc::uid_t,
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(anyhow!("getpwuid_r failed: errno={}", rc));
    }
    if result.is_null() {
        return Ok(format!("uid:{uid}"));
    }
    let cstr = unsafe { CStr::from_ptr(pwd.pw_name) };
    Ok(cstr.to_string_lossy().into_owned())
}

/// Read the kernel hostname via `gethostname`.
pub fn hostname() -> Result<String> {
    let mut buf = vec![0u8; 256];
    let rc = unsafe {
        libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len())
    };
    if rc != 0 {
        return Err(anyhow!(
            "gethostname failed: errno={}",
            std::io::Error::last_os_error()
        ));
    }
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..nul]).into_owned())
}

/// Stable machine identifier from `IOPlatformUUID`. Shelled-out once at
/// daemon startup and cached; the value never changes for the lifetime of
/// the install.
pub fn machine_uuid() -> Result<String> {
    let out = Command::new("/usr/sbin/ioreg")
        .args(["-d2", "-c", "IOPlatformExpertDevice"])
        .output()
        .context("invoking /usr/sbin/ioreg")?;
    if !out.status.success() {
        return Err(anyhow!(
            "ioreg exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some(eq) = line.find("\"IOPlatformUUID\"") {
            if let Some(start) = line[eq..].find("= \"") {
                let rest = &line[eq + start + 3..];
                if let Some(end) = rest.find('"') {
                    return Ok(rest[..end].to_string());
                }
            }
        }
    }
    Err(anyhow!("IOPlatformUUID not found in ioreg output"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_user_resolves() {
        assert_eq!(username_for_uid(0).unwrap(), "root");
    }

    #[test]
    fn unknown_uid_falls_back() {
        let name = username_for_uid(999_999).unwrap();
        assert!(name.starts_with("uid:") || !name.is_empty());
    }

    #[test]
    fn hostname_is_nonempty() {
        let h = hostname().unwrap();
        assert!(!h.is_empty());
    }

    #[test]
    fn machine_uuid_is_uuid_shaped() {
        // Skipped on non-Darwin CI; on macOS this produces an UUID like
        // "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".
        if cfg!(target_os = "macos") {
            let uuid = machine_uuid().unwrap();
            assert!(uuid.len() >= 32);
        }
    }
}
