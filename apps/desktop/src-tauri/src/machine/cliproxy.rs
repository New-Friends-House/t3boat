//! CLIProxyAPI on the machine: its agents reach their models through a proxy running there, with
//! accounts signed in to it there (`cliproxy.sh` sets it up, `signin` adds accounts), so they keep
//! working with this computer off. Each machine signs its accounts in itself: Claude's and Codex's
//! OAuth refresh tokens are single-use, so one copied from elsewhere would break both holders.

use super::signin::Agent;
use super::{provision, MachineRuntime};
use crate::store::{CliproxyAccount, Machine};
use anyhow::{bail, Result};

impl MachineRuntime {
    /// Turns the proxy on or off for the machine's agents, waking it to do so. Off keeps the
    /// accounts on the machine, so turning it on again needs no new sign-in.
    pub async fn set_cliproxy(&self, on: bool) -> Result<()> {
        self.ensure_awake().await?;
        let id = self.sandbox_id();
        // The first time it downloads the proxy.
        self.kept_awake(provision::apply_cliproxy(&self.shared.boat, &id, on)).await?;
        self.update_record(|m| m.cliproxy = on);
        // Older scripts' watchdogs don't list the accounts: take this app's now, unless that
        // would restart T3 under a running agent.
        if self.record().provision_revision != provision::revision()
            && self.watchdog_get("/status?fresh").await.is_ok_and(|s| !s.busy)
            && let Err(e) = self.kept_awake(self.upgrade_if_needed()).await
        {
            tracing::warn!("upgrading {}: {e:#}", self.id());
        }
        if let Ok(s) = self.watchdog_get("/status").await {
            self.on_watchdog_status(s).await;
        }
        self.refresh_providers().await;
        Ok(())
    }

    /// Signs an account out of the proxy there: its credential file goes.
    pub async fn remove_cliproxy_account(&self, file: &str) -> Result<()> {
        if !valid_account_file(file) {
            bail!("no account file {file}");
        }
        self.ensure_awake().await?;
        self.shared
            .boat
            .exec_ok(&self.sandbox_id(), &format!("rm -f \"$HOME/.t3boat/cliproxy/auths/{file}\""), 30)
            .await?;
        if let Ok(s) = self.watchdog_get("/status").await {
            self.on_watchdog_status(s).await;
        }
        Ok(())
    }

    /// Sets the routing priority on one CLIProxyAPI account file (`0` clears the field back to
    /// default; higher values, such as `10`, are tried before lower ones). The proxy watches its
    /// auth dir, so the change takes effect without restarting it.
    pub async fn set_cliproxy_account_priority(&self, file: &str, priority: i32) -> Result<()> {
        if !valid_account_file(file) {
            bail!("no account file {file}");
        }
        let record = self.record();
        if !record.cliproxy {
            bail!("CLIProxyAPI is not enabled on {}", record.name);
        }
        self.ensure_awake().await?;
        let cmd = set_priority_command(file, priority);
        self.shared.boat.exec_ok(&self.sandbox_id(), &cmd, 30).await?;
        // Update our cached list immediately so an older watchdog (not yet upgraded while busy)
        // preserves the priority on subsequent status polls.
        self.update_record(|r| {
            if let Some(a) = r.cliproxy_accounts.iter_mut().find(|a| a.file == file) {
                a.priority = priority;
            }
        });
        if self.record().provision_revision != provision::revision()
            && self.watchdog_get("/status?fresh").await.is_ok_and(|s| !s.busy)
            && let Err(e) = self.kept_awake(self.upgrade_if_needed()).await
        {
            tracing::warn!("upgrading {}: {e:#}", self.id());
        }
        if let Ok(s) = self.watchdog_get("/status").await {
            self.on_watchdog_status(s).await;
        }
        Ok(())
    }
}

/// The accounts the agent can use through the machine's proxy, by email (or file name).
pub fn accounts_for(record: &Machine, agent: Agent) -> Vec<CliproxyAccount> {
    record
        .cliproxy_accounts
        .iter()
        .filter(|a| a.kind == agent.cliproxy_type() && !a.disabled)
        .cloned()
        .collect()
}

/// Remote shell command that atomically updates `priority` in `$HOME/.t3boat/cliproxy/auths/<file>`.
/// Uses a dot-prefixed non-`.json` temp file so CLIProxyAPI's watcher and the watchdog ignore it
/// until the atomic rename completes.
fn set_priority_command(file: &str, priority: i32) -> String {
    debug_assert!(valid_account_file(file));
    const SCRIPT: &str = r#"const fs = require("fs"), path = require("path");
const [file, raw] = process.argv.slice(1);
const priority = Number(raw);
if (!Number.isSafeInteger(priority)) { console.error("invalid priority " + raw); process.exit(1); }
const dir = path.join(process.env.HOME, ".t3boat", "cliproxy", "auths");
const target = path.join(dir, file);
if (!fs.existsSync(target)) { console.error("no account file " + file); process.exit(1); }
const data = JSON.parse(fs.readFileSync(target, "utf8"));
if (!data || typeof data !== "object" || Array.isArray(data)) { console.error("invalid account file " + file); process.exit(1); }
if (priority === 0) delete data.priority;
else data.priority = priority;
const mode = (fs.statSync(target).mode & 0o777) || 0o600;
const tmp = path.join(dir, "." + file + ".t3boat-tmp");
fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode });
fs.renameSync(tmp, target);"#;
    format!("node -e '{SCRIPT}' '{file}' {priority}")
}

/// A file name the proxy wrote, e.g. `claude-me@example.com.json`: nothing that leaves its dir or
/// means anything to the shell.
fn valid_account_file(file: &str) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-');
    file.ends_with(".json") && !file.starts_with('.') && file.chars().all(ok)
}

#[cfg(test)]
mod tests {
    use super::{set_priority_command, valid_account_file};

    #[test]
    fn account_files_stay_in_the_auth_dir() {
        for ok in ["claude-me@example.com.json", "codex-a.b+c_d-team.json"] {
            assert!(valid_account_file(ok), "{ok}");
        }
        for bad in ["../x.json", "a/b.json", "x.json; rm -rf ~", "$(id).json", ".json", "..json", "x.txt", "a b.json"] {
            assert!(!valid_account_file(bad), "{bad}");
        }
    }

    #[test]
    fn priority_command_sets_and_clears_priority_preserving_other_fields() {
        let Ok(node) = which::which("node") else { return };
        let _ = node;
        let tmp = std::env::temp_dir().join(format!("t3boat-priority-test-{}", std::process::id()));
        let auths = tmp.join(".t3boat/cliproxy/auths");
        std::fs::create_dir_all(&auths).unwrap();
        let file = "claude-me@example.com.json";
        let path = auths.join(file);
        std::fs::write(&path, r#"{"type":"claude","email":"me@example.com","token":"keep-me"}"#).unwrap();

        let run = |cmd: &str| {
            std::process::Command::new("sh")
                .args(["-c", cmd])
                .env("HOME", &tmp)
                .output()
                .unwrap()
        };

        let out = run(&set_priority_command(file, 10));
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(json["priority"], 10);
        assert_eq!(json["email"], "me@example.com");
        assert_eq!(json["token"], "keep-me");

        let out = run(&set_priority_command(file, 0));
        assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(json.get("priority").is_none());
        assert_eq!(json["token"], "keep-me");

        let missing = run(&set_priority_command("missing.json", 10));
        assert!(!missing.status.success());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
