//! Tailscale: how the user's other devices (their phone) reach the proxies here, so a machine
//! answers there while it sleeps, as it does on this computer. Plain HTTP to this computer's
//! tailnet address, as T3's own LAN pairing does: Tailscale encrypts the way. The address comes
//! from Tailscale itself, never from the interfaces: 100.64.0.0/10 is shared address space,
//! which other VPNs and networks use too.

use crate::process::command;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::watch;

/// How often Tailscale's state is read: it connects, disconnects and logs in on its own.
const POLL: Duration = Duration::from_secs(15);

/// Tailscale's address ranges: 100.64.0.0/10 and fd7a:115c:a1e0::/48.
pub fn is_tailnet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            a == 100 && (64..128).contains(&b)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

/// This computer on the tailnet: its address, and the index of Tailscale's tunnel interface
/// that holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tunnel {
    pub ip: Ipv4Addr,
    pub interface: u32,
}

/// The tunnel while Tailscale runs here, else `None`; it changes as Tailscale does, a new tunnel
/// interface with the same address included. The first call starts reading Tailscale's state,
/// so it needs the runtime.
pub fn tunnel() -> watch::Receiver<Option<Tunnel>> {
    static TUNNEL: OnceLock<watch::Sender<Option<Tunnel>>> = OnceLock::new();
    TUNNEL
        .get_or_init(|| {
            let (tx, _) = watch::channel(None);
            // Only macOS holds a listener to the tunnel: elsewhere nothing needs Tailscale's state.
            if cfg!(target_os = "macos") {
                let poller = tx.clone();
                tokio::spawn(async move {
                    loop {
                        // Nobody listens (no machine left): Tailscale is not asked.
                        if poller.receiver_count() > 0 {
                            let now = read_tunnel().await;
                            poller.send_if_modified(|t| std::mem::replace(t, now) != now);
                        }
                        tokio::time::sleep(POLL).await;
                    }
                });
            }
            tx
        })
        .subscribe()
}

/// Tailscale's address and the one tunnel that holds it, read between two readings of
/// Tailscale's state that agree: Tailscale still holds the address the interface was found by,
/// not another VPN that took it over in between.
async fn read_tunnel() -> Option<Tunnel> {
    let ip = own_ipv4().await?;
    let interface = interface_of(ip)?;
    (own_ipv4().await? == ip && interface_of(ip)? == interface).then_some(Tunnel { ip, interface })
}

/// What `tailscale status --json` says about this computer.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Status {
    backend_state: String,
    /// Whether Tailscale runs a kernel tunnel; in userspace it holds no interface of its own.
    #[serde(rename = "TUN", default)]
    tun: bool,
    #[serde(rename = "Self")]
    this: Option<Peer>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Peer {
    #[serde(default, rename = "TailscaleIPs")]
    tailscale_ips: Vec<IpAddr>,
}

async fn own_ipv4() -> Option<Ipv4Addr> {
    let cli = cli()?;
    let out = command(cli)
        .args(["status", "--json", "--peers=false"])
        // The macOS app's executable is the GUI too; started from the Finder or at login, as
        // t3boat is, it would pick the GUI without this.
        .env("TAILSCALE_BE_CLI", "1")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(10), out).await.ok()?.ok()?;
    parse_status(&out.stdout)
}

fn parse_status(json: &[u8]) -> Option<Ipv4Addr> {
    let status: Status = serde_json::from_slice(json).ok()?;
    if status.backend_state != "Running" || !status.tun {
        return None;
    }
    status.this?.tailscale_ips.into_iter().find_map(|ip| match ip {
        IpAddr::V4(v4) if is_tailnet(ip) => Some(v4),
        _ => None,
    })
}

/// Tailscale's CLI: on PATH, or inside the macOS app, which does not put it on PATH. Looked up
/// on every poll, so installing or moving Tailscale needs no restart here.
fn cli() -> Option<PathBuf> {
    which::which("tailscale").ok().or_else(|| {
        ["/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
    })
}

/// The index of Tailscale's tunnel, the one interface that holds `ip`, Tailscale's address for
/// this computer. `None` when no tunnel (`utun*`) holds it, or more than one interface does:
/// another VPN gave this computer the same address, and which one a packet came in on matters.
#[cfg(target_os = "macos")]
fn interface_of(ip: Ipv4Addr) -> Option<u32> {
    let mut holders: Vec<(String, u32)> = Vec::new();
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `addrs` with a list freed below; each entry is read while it lives.
    unsafe {
        if libc::getifaddrs(&mut addrs) != 0 {
            return None;
        }
        let mut cur = addrs;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                if Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) == ip {
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                    holders.push((name, libc::if_nametoindex(ifa.ifa_name)));
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(addrs);
    }
    match holders.as_slice() {
        [(name, index)] if name.starts_with("utun") && *index != 0 => Some(*index),
        _ => None,
    }
}

/// Other systems cannot hold a socket to one interface without privileges: no tunnel, so the
/// proxy is never reachable from other devices there.
#[cfg(not(target_os = "macos"))]
fn interface_of(_ip: Ipv4Addr) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_tailscale_addresses() {
        for ip in ["100.64.0.1", "100.121.195.78", "100.127.255.255", "fd7a:115c:a1e0::1"] {
            assert!(is_tailnet(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["100.63.255.255", "100.128.0.0", "192.168.0.10", "127.0.0.1", "fd7a:115c:a1e1::1", "::1"] {
            assert!(!is_tailnet(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn reads_the_address_only_while_tailscale_runs() {
        let status = |state: &str| {
            format!(r#"{{"BackendState":"{state}","TUN":true,"Self":{{"TailscaleIPs":["fd7a:115c:a1e0::1","100.121.195.78"]}}}}"#)
        };
        assert_eq!(parse_status(status("Running").as_bytes()), Some(Ipv4Addr::new(100, 121, 195, 78)));
        // Userspace networking: an address, but no tunnel of Tailscale's to hold it.
        assert_eq!(parse_status(status("Running").replace(r#""TUN":true"#, r#""TUN":false"#).as_bytes()), None);
        assert_eq!(parse_status(status("Stopped").as_bytes()), None);
        assert_eq!(parse_status(status("NeedsLogin").as_bytes()), None);
        assert_eq!(parse_status(br#"{"BackendState":"Running","Self":null}"#), None);
        assert_eq!(parse_status(b"not json"), None);
    }
}
