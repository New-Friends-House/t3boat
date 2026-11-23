//! Antigravity on a machine, signed in with T3's own sign-in (`provider.auth.*`), never through
//! CLIProxyAPI: T3 keeps its Google credential in a profile of its own for the provider, which no
//! CLI login reaches. As T3 Code's settings do, this turns the provider on, installs Google's
//! runtime there when it is missing, then starts the sign-in. Its Google page ends on an
//! Antigravity page that shows a code, not on a localhost redirect this app could take, so the
//! person pastes that code back into this app (`answer_sign_in`), which hands it to T3.

use super::MachineRuntime;
use crate::proxy::upstream;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// How the agents list and `sign_in_agent` name it: T3's name for its default instance.
pub const NAME: &str = "Antigravity";
/// T3's default instance of the driver, the one T3 Code's "Turn on" sets up.
pub const INSTANCE: &str = "antigravity";
/// The rejection of a sign-in the person cancelled; the UI says nothing more about it.
pub const CANCELLED: &str = "sign-in cancelled";
/// Google's runtime is about 230 MB, checked once downloaded.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// T3 gives up on a sign-in after 5 minutes and says so; this waits a little longer for that.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(6 * 60);

/// What the person sends a sign-in waiting for its code: the code, or `None` to cancel it, and
/// where T3's answer to it goes.
type Answer = (Option<String>, oneshot::Sender<Result<(), String>>);

/// A sign-in waiting for the code its page shows.
pub struct CodeWait {
    agent: &'static str,
    answers: mpsc::Sender<Answer>,
}

impl MachineRuntime {
    /// The agent whose sign-in waits for a code pasted into this app.
    pub fn code_wanted(&self) -> Option<&'static str> {
        self.code_wait.lock().unwrap().as_ref().map(|w| w.agent)
    }

    /// Hands the waiting sign-in the code its page showed, or cancels it (`None`). Resolves once
    /// T3 took the code; fails with T3's words when it did not, and the sign-in keeps waiting.
    pub async fn answer_sign_in(&self, code: Option<String>) -> Result<()> {
        let answers = self.code_wait.lock().unwrap().as_ref().map(|w| w.answers.clone());
        let answers = answers.ok_or_else(|| anyhow!("no sign-in on this machine waits for a code"))?;
        let (reply, answer) = oneshot::channel();
        let over = || anyhow!("the sign-in is over");
        answers.send((code, reply)).await.map_err(|_| over())?;
        answer.await.map_err(|_| over())?.map_err(|e| anyhow!(e))
    }

    pub async fn sign_in_antigravity(&self) -> Result<()> {
        self.ensure_awake().await?;
        // The machine must not fall asleep during a download or while the person is in the browser.
        let result = self.kept_awake(self.antigravity_sign_in()).await;
        // T3 Code, the row's nudge and the recorded config learn how it ended, either way.
        self.refresh_providers().await;
        result
    }

    async fn antigravity_sign_in(&self) -> Result<()> {
        self.turn_on_antigravity().await?;
        self.install_antigravity().await?;
        let started = self.t3("provider.auth.start", json!({ "instanceId": INSTANCE })).await?;
        let flow = started["flowId"].as_str().context("T3 started no Antigravity sign-in")?.to_owned();
        let waiting = self.sign_in_state(&flow, |s| s["phase"] != "starting").await?;
        if waiting["phase"] == "waiting" {
            let url = waiting["authorizationUrl"].as_str().context("T3 gave no Google sign-in link")?;
            if waiting["interaction"]["type"] != "credentials" {
                // Gemini Enterprise ends on a localhost redirect instead, which T3 Code's own
                // settings take.
                let _ = self.t3("provider.auth.cancel", json!({ "instanceId": INSTANCE, "flowId": flow })).await;
                bail!("this machine's Antigravity is set up to sign in another way: use T3 Code's settings for it");
            }
            crate::app::open_url(url)?;
            self.take_code(&flow).await?;
        }
        let end = self.sign_in_state(&flow, ended).await?;
        if end["phase"] != "succeeded" {
            bail!("{}", end["message"].as_str().unwrap_or("the Antigravity sign-in failed"));
        }
        Ok(())
    }

    /// Codes from the person, until T3 takes one or the sign-in ends without one (it expired, or
    /// the person finished it in T3 Code). `None` cancels it.
    async fn take_code(&self, flow: &str) -> Result<()> {
        let (answers, mut asked) = mpsc::channel(1);
        *self.code_wait.lock().unwrap() = Some(CodeWait { agent: NAME, answers });
        self.shared.changed();
        let left_waiting = self.sign_in_state(flow, |s| s["phase"] != "waiting");
        tokio::pin!(left_waiting);
        let result = loop {
            tokio::select! {
                state = &mut left_waiting => break state.map(drop),
                Some((code, reply)) = asked.recv() => {
                    let Some(code) = code else {
                        let _ = self.t3("provider.auth.cancel", json!({ "instanceId": INSTANCE, "flowId": flow })).await;
                        let _ = reply.send(Ok(()));
                        break Err(anyhow!(CANCELLED));
                    };
                    let response = json!({ "type": "credentials", "values": { "code": code.trim() } });
                    let payload =
                        json!({ "instanceId": INSTANCE, "flowId": flow, "interactionId": flow, "response": response });
                    match self.t3("provider.auth.respond", payload).await {
                        Ok(_) => {
                            let _ = reply.send(Ok(()));
                            break Ok(());
                        }
                        // A mistyped code: T3 says what it wants, and the person tries again.
                        Err(e) => {
                            let _ = reply.send(Err(format!("{e:#}")));
                        }
                    }
                }
            }
        };
        *self.code_wait.lock().unwrap() = None;
        self.shared.changed();
        result
    }

    /// T3 lists Antigravity but leaves it off. Turned on as T3 Code's own "Turn on" does it: the
    /// instance as configured (by default there is none: the driver's defaults), enabled.
    async fn turn_on_antigravity(&self) -> Result<()> {
        if self.antigravity_status().await?["enabled"] == true {
            return Ok(());
        }
        let settings = self.t3("server.getSettings", json!({})).await?;
        let mut instance = settings["providerInstances"][INSTANCE].clone();
        if !instance.is_object() {
            instance = json!({ "driver": "antigravity" });
        }
        instance["enabled"] = json!(true);
        if instance["config"]["enabled"] == false {
            instance["config"]["enabled"] = json!(true);
        }
        let mutation = json!({ "operation": "upsert", "instanceId": INSTANCE, "instance": instance });
        self.t3("server.updateSettings", json!({ "patch": {}, "providerInstanceMutation": mutation }))
            .await
            .context("turning Antigravity on")?;
        Ok(())
    }

    /// Google's runtime, which T3 downloads into its own tools on the machine. Never started for
    /// one that is there: T3 would download the same release again.
    async fn install_antigravity(&self) -> Result<()> {
        let installed = |s: &Value| !s["installedVersion"].is_null() && !running(s);
        let current = self.install_state(|_| true).await?;
        if installed(&current) || self.antigravity_status().await?["installed"] == true {
            return Ok(());
        }
        let started =
            if running(&current) { current } else { self.t3("provider.install.start", json!({ "instanceId": INSTANCE })).await? };
        let operation = started["operationId"].clone();
        let end = self.install_state(|s| s["operationId"] == operation && !running(s)).await?;
        if end["phase"] != "succeeded" {
            bail!(
                "installing Antigravity on the machine: {}",
                end["message"].as_str().unwrap_or("the install did not finish")
            );
        }
        Ok(())
    }

    async fn install_state(&self, done: impl Fn(&Value) -> bool) -> Result<Value> {
        let feed = "provider.install.subscribe";
        let payload = json!({ "instanceId": INSTANCE });
        let (url, token) = (self.upstream_url(), self.upstream_token());
        let (state, _) =
            upstream::subscribe_until(&url, &token, feed, payload, INSTALL_TIMEOUT, |s| done(s).then(|| s.clone()))
                .await?;
        state.context("T3 ended the Antigravity install's progress")
    }

    /// The sign-in's state once `done` says so, from T3's own feed of it. Another sign-in that
    /// replaced this one ends it.
    async fn sign_in_state(&self, flow: &str, done: impl Fn(&Value) -> bool) -> Result<Value> {
        let feed = "provider.auth.subscribe";
        let payload = json!({ "instanceId": INSTANCE });
        let (url, token) = (self.upstream_url(), self.upstream_token());
        let (state, _) = upstream::subscribe_until(&url, &token, feed, payload, SIGN_IN_TIMEOUT, |s| {
            (s["flowId"] != flow || done(s)).then(|| s.clone())
        })
        .await?;
        let state = state.context("T3 ended the Antigravity sign-in's progress")?;
        if state["flowId"] != flow {
            bail!("another Antigravity sign-in took over on the machine");
        }
        Ok(state)
    }

    /// The provider as T3 sees it now.
    async fn antigravity_status(&self) -> Result<Value> {
        let result = self.t3("server.refreshProviders", json!({ "instanceId": INSTANCE })).await?;
        let mut providers = result["providers"].as_array().into_iter().flatten();
        providers
            .find(|p| p["instanceId"] == INSTANCE)
            .cloned()
            .context("T3 on the machine has no Antigravity provider")
    }

    async fn t3(&self, tag: &str, payload: Value) -> Result<Value> {
        upstream::call(&self.upstream_url(), &self.upstream_token(), tag, payload).await
    }
}

fn running(install: &Value) -> bool {
    matches!(install["phase"].as_str(), Some("downloading" | "extracting" | "verifying"))
}

fn ended(sign_in: &Value) -> bool {
    matches!(sign_in["phase"].as_str(), Some("succeeded" | "failed" | "cancelled"))
}
