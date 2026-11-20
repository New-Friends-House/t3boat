//! Signing an agent in on a machine with the vendor's own CLI login, or, on a machine whose agents
//! use CLIProxyAPI, adding an account to the proxy there with its own login. Either login runs on
//! the machine; this app takes the browser's redirect after "Authorize" on the same localhost port
//! and passes it on to the machine (`callback`): no code to paste, and the credential is created on
//! the machine and stays there. This computer's own logins are never touched.

use super::callback::Relay;
use super::MachineRuntime;
use crate::proxy::upstream;
use anyhow::{anyhow, bail, Context, Result};
use std::time::{Duration, Instant};

const URL_TIMEOUT: Duration = Duration::from_secs(30);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug)]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    /// By the provider's display name, as `signedOut` lists it.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Claude" => Some(Self::Claude),
            "Codex" => Some(Self::Codex),
            _ => None,
        }
    }

    /// The vendor's name in CLIProxyAPI, as its credential files have it.
    pub fn cliproxy_type(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

/// Which login a sign-in runs on the machine.
#[derive(Clone, Copy, Debug)]
enum Login {
    /// The agent's own CLI login.
    Vendor(Agent),
    /// CLIProxyAPI's login for the agent's vendor, which adds an account to the proxy.
    Cliproxy(Agent),
}

impl Login {
    fn agent(self) -> Agent {
        match self {
            Self::Vendor(a) | Self::Cliproxy(a) => a,
        }
    }

    /// Starts the login in the background in a new temp dir and prints the dir. Its sign-in URL
    /// lands in `out` there: as the CLI hands it to $BROWSER, or as the proxy prints it.
    fn start(self) -> String {
        match self {
            // The CLI hands the sign-in URL to $BROWSER; this one records it instead.
            Self::Vendor(agent) => format!(
                "d=$(mktemp -d); printf '#!/bin/sh\\necho \"$1\" > %s/out\\n' \"$d\" > \"$d/browser\"; \
                 chmod +x \"$d/browser\"; \
                 BROWSER=\"$d/browser\" nohup script -qfec '{}' \"$d/log\" >/dev/null 2>&1 & echo \"$d\"",
                vendor_login(agent)
            ),
            // Prints the URL with -no-browser. With stdin closed it never waits on a pasted one.
            Self::Cliproxy(agent) => format!(
                "d=$(mktemp -d); nohup {CLIPROXY_BIN} -config {CLIPROXY_CONFIG} -{}-login -no-browser \
                 </dev/null >\"$d/out\" 2>&1 & echo $! > \"$d/pid\"; echo \"$d\"",
                agent.cliproxy_type()
            ),
        }
    }

    /// Exits 0 once signed in, 2 once the login gave up.
    fn status(self, dir: &str) -> String {
        match self {
            Self::Vendor(Agent::Claude) => "claude auth status >/dev/null 2>&1".to_owned(),
            Self::Vendor(Agent::Codex) => "codex login status >/dev/null 2>&1".to_owned(),
            Self::Cliproxy(_) => format!(
                "grep -q 'authentication successful' '{dir}/out' && exit 0; \
                 kill -0 \"$(cat '{dir}/pid')\" 2>/dev/null && exit 1; exit 2"
            ),
        }
    }

    fn stop(self, dir: &str) -> String {
        let kill = match self {
            Self::Vendor(agent) => format!("pkill -f '{}'", vendor_login(agent)),
            Self::Cliproxy(_) => format!("kill \"$(cat '{dir}/pid')\" 2>/dev/null"),
        };
        format!("{kill}; rm -rf '{dir}'")
    }
}

fn vendor_login(agent: Agent) -> &'static str {
    match agent {
        Agent::Claude => "claude auth login",
        Agent::Codex => "codex login",
    }
}

const CLIPROXY_BIN: &str = "\"$HOME/.t3boat/cliproxy/bin/cli-proxy-api\"";
const CLIPROXY_CONFIG: &str = "\"$HOME/.t3boat/cliproxy/config.yaml\"";

impl MachineRuntime {
    /// On a machine whose agents use CLIProxyAPI, this adds an account to the proxy there.
    pub async fn sign_in(&self, agent: Agent) -> Result<()> {
        self.ensure_awake().await?;
        let login = if self.record().cliproxy { Login::Cliproxy(agent) } else { Login::Vendor(agent) };
        let id = self.sandbox_id();
        let boat = &self.shared.boat;
        let dir = boat.exec_ok(&id, &login.start(), 30).await?;
        let dir = dir.lines().last().unwrap_or_default().trim().to_owned();
        // The machine must not fall asleep while the person is in the browser.
        let result = self.kept_awake(self.finish_sign_in(login, &dir)).await;
        let _ = boat.exec(&id, &login.stop(&dir), 30).await;
        result?;
        if let Login::Cliproxy(_) = login {
            // The new account, as the watchdog lists it.
            if let Ok(s) = self.watchdog_get("/status").await {
                self.on_watchdog_status(s).await;
            }
        }
        self.refresh_providers().await;
        Ok(())
    }

    /// T3 re-checks the providers and tells T3 Code; a sign-in nudge goes away with it, and the
    /// recorded config learns it too.
    pub(super) async fn refresh_providers(&self) {
        let refreshed = upstream::call(
            &self.upstream_url(),
            &self.upstream_token(),
            "server.refreshProviders",
            serde_json::json!({}),
        )
        .await;
        if let Ok(result) = refreshed {
            self.cache.lock().unwrap().fold_providers(&result["providers"]);
            self.save_cache();
        }
    }

    async fn finish_sign_in(&self, login: Login, dir: &str) -> Result<()> {
        let agent = login.agent();
        let id = self.sandbox_id();
        let boat = &self.shared.boat;
        let started = Instant::now();
        let url = loop {
            let out = boat.exec(&id, &format!("cat '{dir}/out' 2>/dev/null"), 30).await?;
            // The proxy prints more than the URL.
            let words = out.stdout.split_whitespace();
            if let Some(url) = words.filter(|w| w.starts_with("https://")).find(|w| callback_port(w).is_some()) {
                break url.to_owned();
            }
            if started.elapsed() > URL_TIMEOUT {
                bail!("the {agent:?} login did not start on the machine");
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        };
        let port = callback_port(&url).ok_or_else(|| anyhow!("the {agent:?} login has no local callback"))?;
        let _relay = Relay::start(boat.clone(), id.clone(), port)
            .await
            .with_context(|| format!("taking the {agent:?} sign-in's redirect on port {port}"))?;
        crate::app::open_url(&url)?;
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            match boat.exec(&id, &login.status(dir), 30).await?.exit_code {
                Some(0) => return Ok(()),
                Some(2) => {
                    let out = boat.exec(&id, &format!("tail -n 5 '{dir}/out' 2>/dev/null"), 30).await?;
                    bail!("the {agent:?} sign-in failed: {}", last_line(&out.stdout));
                }
                _ => {}
            }
            if started.elapsed() > LOGIN_TIMEOUT {
                bail!("the {agent:?} sign-in was not finished in the browser");
            }
        }
    }
}

fn last_line(out: &str) -> &str {
    out.lines().rev().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no output")
}

/// The port of a `redirect_uri=http://localhost:<port>/...` (or 127.0.0.1) parameter.
fn callback_port(url: &str) -> Option<u16> {
    let url = url::Url::parse(url).ok()?;
    let redirect = url.query_pairs().find(|(k, _)| k == "redirect_uri")?.1;
    let redirect = url::Url::parse(&redirect).ok()?;
    matches!(redirect.host_str()?, "localhost" | "127.0.0.1").then_some(())?;
    redirect.port()
}

#[cfg(test)]
mod tests {
    use super::callback_port;

    #[test]
    fn finds_the_local_callback_port() {
        let claude = "https://claude.com/cai/oauth/authorize?code=true&redirect_uri=http%3A%2F%2Flocalhost%3A43327%2Fcallback&state=x";
        let codex = "https://auth.openai.com/oauth/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback";
        let manual = "https://claude.com/cai/oauth/authorize?redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback";
        assert_eq!(callback_port(claude), Some(43327));
        assert_eq!(callback_port(codex), Some(1455));
        assert_eq!(callback_port(manual), None);
    }

    #[test]
    fn finds_the_proxy_logins_url_in_what_it_prints() {
        let out = "To authenticate from a remote machine, an SSH tunnel may be required.\n\
                   ssh -L 54545:127.0.0.1:54545 root@10.0.0.2 -p 22\n\
                   Visit the following URL to continue authentication:\n\
                   https://claude.ai/oauth/authorize?client_id=x&code=true&redirect_uri=http%3A%2F%2Flocalhost%3A54545%2Fcallback&state=y\n\
                   Waiting for Claude authentication callback...";
        let url = out.split_whitespace().filter(|w| w.starts_with("https://")).find(|w| callback_port(w).is_some());
        assert_eq!(url.and_then(callback_port), Some(54545));
        let codex = "https://auth.openai.com/oauth/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback";
        assert_eq!(callback_port(codex), Some(1455));
    }
}
