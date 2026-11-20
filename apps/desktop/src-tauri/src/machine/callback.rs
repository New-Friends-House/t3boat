//! The browser's OAuth redirect after "Authorize", passed on to the login waiting on the machine.
//! The login's callback address is `localhost:<port>` on the machine; this app listens on the same
//! port here and replays each request there with `boat exec`, answering the browser with the
//! machine's reply. No tunnel process: the port belongs to this app's own socket, so it is free
//! again the moment the sign-in ends, or the app quits or crashes mid-sign-in.

use crate::boat::Boat;
use anyhow::{anyhow, bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// A browser that opened a connection and never sent a request (a preconnect) is dropped then.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REQUEST: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;

/// Passes the browser's requests on `port` to the same port on the sandbox while it lives.
pub struct Relay(JoinHandle<()>);

impl Drop for Relay {
    fn drop(&mut self) {
        // Drops the listener with the task: the port is free again.
        self.0.abort();
    }
}

impl Relay {
    pub async fn start(boat: Boat, sandbox_id: String, port: u16) -> Result<Self> {
        let listener = match bind(port).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && clear_stale_tunnel(port) => {
                bind(port).await.map_err(|_| in_use(port))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return Err(in_use(port)),
            Err(e) => return Err(e).with_context(|| format!("listening on port {port}")),
        };
        Ok(Self(tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                // One at a time would let a silent preconnect hold up the real redirect.
                tokio::spawn(serve(boat.clone(), sandbox_id.clone(), port, stream));
            }
        })))
    }
}

/// Retries for a moment: the relay of a sign-in that just ended lets go of the port as its task
/// is cancelled, which takes a beat.
async fn bind(port: u16) -> std::io::Result<TcpListener> {
    let mut tries = 0;
    loop {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && tries < 10 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            other => return other,
        }
    }
}

fn in_use(port: u16) -> anyhow::Error {
    anyhow!("port {port} is in use on this computer by another program; close its sign-in first")
}

async fn serve(boat: Boat, sandbox_id: String, port: u16, mut stream: TcpStream) {
    let Ok(Ok(target)) = tokio::time::timeout(REQUEST_TIMEOUT, read_target(&mut stream)).await else {
        return;
    };
    let reply = match target {
        Some(target) if target.starts_with("/favicon") => respond(404, "text/plain", b"not found"),
        Some(target) => match relay(&boat, &sandbox_id, port, &target).await {
            Ok(reply) => reply,
            Err(e) => {
                tracing::warn!("passing a sign-in callback on to {sandbox_id}: {e:#}");
                let page = format!(
                    "<!doctype html><meta charset=utf-8><title>t3boat</title><p>t3boat couldn't pass this on \
                     to the machine: {}.</p><p>If the sign-in finished in t3boat, close this tab.</p>",
                    html_escape(&format!("{e:#}"))
                );
                respond(502, "text/html; charset=utf-8", page.as_bytes())
            }
        },
        None => respond(400, "text/plain", b"bad request"),
    };
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}

/// The request's target, when it is a GET this relay passes on; None for anything else.
async fn read_target(stream: &mut TcpStream) -> Result<Option<String>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("closed before a request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST {
            return Ok(None);
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.lines().next().unwrap_or_default().split(' ');
    Ok(match (parts.next(), parts.next()) {
        (Some("GET"), Some(target)) if safe_target(target) => Some(target.to_owned()),
        _ => None,
    })
}

/// What reaches the remote shell inside single quotes: an origin-form URL target only.
fn safe_target(target: &str) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || "-._~%/?&=+:@,;!*$".contains(c);
    target.starts_with('/') && target.len() <= 8192 && target.chars().all(ok)
}

/// Replays the request on the machine and turns its reply into one for the browser.
async fn relay(boat: &Boat, sandbox_id: &str, port: u16, target: &str) -> Result<Vec<u8>> {
    let script = format!(
        "f=$(mktemp); trap 'rm -f \"$f\"' EXIT; \
         curl -sS -g --max-time 30 -o \"$f\" -w '%{{http_code}}\\t%{{content_type}}\\t%{{redirect_url}}\\n' \
         'http://localhost:{port}{target}' && head -c {MAX_BODY} \"$f\""
    );
    let out = boat.exec_ok(sandbox_id, &script, 60).await?;
    let (meta, body) = out.split_once('\n').unwrap_or((&out, ""));
    let mut meta = meta.split('\t');
    let code: u16 = meta.next().and_then(|c| c.parse().ok()).ok_or_else(|| anyhow!("no reply"))?;
    let content_type = meta.next().filter(|t| header_safe(t) && !t.is_empty()).unwrap_or("text/html; charset=utf-8");
    let location = meta.next().unwrap_or_default().trim();
    if (300..400).contains(&code) && header_safe(location) && location.starts_with("http") {
        return Ok(format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .into_bytes());
    }
    Ok(respond(code, content_type, body.as_bytes()))
}

fn header_safe(value: &str) -> bool {
    !value.chars().any(|c| c.is_control())
}

fn respond(code: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut reply = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        if code < 400 { "OK" } else { "Error" },
        body.len()
    )
    .into_bytes();
    reply.extend_from_slice(body);
    reply
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Earlier t3boat versions forwarded the callback port with `boat forward`, whose ssh outlived
/// an app that quit mid-sign-in and kept the port. Ends such an orphan, and nothing else: an ssh
/// whose parent is gone, with the Boat CLI's key and exactly this local forward. True if it did.
#[cfg(unix)]
fn clear_stale_tunnel(port: u16) -> bool {
    let run = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let Some(pids) = run("lsof", &["-nP", "-t", &format!("-iTCP:{port}"), "-sTCP:LISTEN"]) else {
        return false;
    };
    let mut cleared = false;
    for pid in pids.split_whitespace().filter_map(|p| p.parse::<i32>().ok()) {
        let Some(info) = run("ps", &["-ww", "-o", "ppid=,command=", "-p", &pid.to_string()]) else { continue };
        let (ppid, command) = info.trim().split_once(' ').unwrap_or_default();
        if is_stale_tunnel(ppid.trim(), command.trim(), port) {
            tracing::info!("ending a stale sign-in tunnel on port {port} (pid {pid})");
            // SAFETY: a plain syscall on a process checked just above.
            cleared |= unsafe { libc::kill(pid, libc::SIGTERM) } == 0;
        }
    }
    cleared
}

#[cfg(not(unix))]
fn clear_stale_tunnel(_port: u16) -> bool {
    false
}

#[cfg_attr(not(unix), allow(dead_code))]
fn is_stale_tunnel(ppid: &str, command: &str, port: u16) -> bool {
    ppid == "1"
        && command.starts_with("ssh ")
        && command.contains("ascii_box")
        && command.split_whitespace().any(|w| w == format!("127.0.0.1:{port}:127.0.0.1:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_only_plain_callback_targets() {
        assert!(safe_target("/callback?code=ab-c_d.e~f%2F&state=xyz"));
        assert!(safe_target("/auth/callback?code=x&scope=openid+profile"));
        for bad in ["callback", "/x'; rm -rf ~; '", "/a b", "/a\"b", "/a`id`", "/a\\b", "/a\nb"] {
            assert!(!safe_target(bad), "{bad}");
        }
    }

    #[test]
    fn recognizes_only_orphaned_boat_tunnels() {
        let tunnel = "ssh -p 19032 -i /Users/me/.ssh/ascii_box_ed25519 -o IdentitiesOnly=yes -N \
                      -L 127.0.0.1:54545:127.0.0.1:54545 user@37.187.158.61";
        assert!(is_stale_tunnel("1", tunnel, 54545));
        assert!(!is_stale_tunnel("4242", tunnel, 54545), "its boat forward still runs");
        assert!(!is_stale_tunnel("1", tunnel, 1455), "another port");
        assert!(!is_stale_tunnel("1", "ssh -N -L 127.0.0.1:54545:127.0.0.1:54545 me@host", 54545), "not Boat's");
        assert!(!is_stale_tunnel("1", "cliproxyapi -claude-login", 54545));
    }

    async fn get(port: u16, target: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    /// Against a running sandbox: T3BOAT_LIVE_SANDBOX=<id> cargo test relays_live -- --ignored
    #[tokio::test]
    #[ignore]
    async fn relays_live() {
        let id = std::env::var("T3BOAT_LIVE_SANDBOX").unwrap();
        let boat = Boat::locate().unwrap();
        let port = 18997;
        let server = format!(
            "cat > /tmp/relay-test.py <<'EOF'\n\
             import http.server\n\
             class H(http.server.BaseHTTPRequestHandler):\n    \
             def do_GET(self):\n        \
             if self.path.startswith('/cb'):\n            \
             self.send_response(302); self.send_header('Location', 'https://example.com/done'); self.end_headers()\n        \
             else:\n            \
             b = ('hello ' + self.path).encode(); self.send_response(200); self.send_header('Content-Type', 'text/plain'); self.end_headers(); self.wfile.write(b)\n\
             http.server.HTTPServer(('127.0.0.1', {port}), H).serve_forever()\n\
             EOF\n\
             nohup python3 /tmp/relay-test.py >/dev/null 2>&1 & sleep 1"
        );
        boat.exec_ok(&id, &server, 30).await.unwrap();
        let relay = Relay::start(boat.clone(), id.clone(), port).await.unwrap();
        let redirect = get(port, "/cb?code=a-b&state=c").await;
        let page = get(port, "/page?x=1").await;
        drop(relay);
        let freed = bind(port).await.is_ok();
        let _ = boat.exec(&id, "pkill -f relay-test.py; rm -f /tmp/relay-test.py", 30).await;
        assert!(redirect.starts_with("HTTP/1.1 302") && redirect.contains("Location: https://example.com/done\r\n"), "{redirect}");
        assert!(page.starts_with("HTTP/1.1 200") && page.ends_with("hello /page?x=1"), "{page}");
        assert!(freed, "the port is free once the relay is dropped");

        // An earlier version's orphaned tunnel on the port is ended, and the relay starts.
        let port = 18996;
        let mut forward = std::process::Command::new(boat_bin())
            .args(["forward", &id, "--remote", &port.to_string(), "--local", &port.to_string()])
            .env("BOAT_NO_UPDATE", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        forward.kill().unwrap(); // the CLI only, as an app quitting mid-sign-in left it
        let _ = forward.wait();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(TcpListener::bind(("127.0.0.1", port)).await.is_err(), "the orphaned ssh holds the port");
        let relay = Relay::start(boat, id, port).await;
        assert!(relay.is_ok(), "{:?}", relay.err());
    }

    fn boat_bin() -> std::path::PathBuf {
        dirs::home_dir().unwrap().join(".ascii/bin/boat")
    }

    #[tokio::test]
    async fn answers_a_redirect_and_a_page() {
        assert!(respond(200, "text/html", b"ok").starts_with(b"HTTP/1.1 200 OK\r\n"));
        let r = String::from_utf8(respond(502, "text/plain", b"x")).unwrap();
        assert!(r.contains("Content-Length: 1\r\n") && r.ends_with("\r\n\r\nx"));
    }
}
