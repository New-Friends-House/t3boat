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

/// A file name the proxy wrote, e.g. `claude-me@example.com.json`: nothing that leaves its dir or
/// means anything to the shell.
fn valid_account_file(file: &str) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-');
    file.ends_with(".json") && !file.starts_with('.') && file.chars().all(ok)
}

#[cfg(test)]
mod tests {
    use super::valid_account_file;

    #[test]
    fn account_files_stay_in_the_auth_dir() {
        for ok in ["claude-me@example.com.json", "codex-a.b+c_d-team.json"] {
            assert!(valid_account_file(ok), "{ok}");
        }
        for bad in ["../x.json", "a/b.json", "x.json; rm -rf ~", "$(id).json", ".json", "..json", "x.txt", "a b.json"] {
            assert!(!valid_account_file(bad), "{bad}");
        }
    }
}
