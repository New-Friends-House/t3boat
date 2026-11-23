//! One T3 Code WebSocket. While the machine runs, frames pass through to its server. While it
//! sleeps, the proxy answers what it truthfully can (nothing changes on a stopped machine) and
//! wakes the machine for everything else, bar the side information a chat shows: that waits
//! for the next wake. After a wake it closes the socket once the calls in flight are answered,
//! so T3 Code reconnects and resyncs on its own.

use super::cache::{Shell, refresh_server_time, request_key, sanitize_server_config};
use super::classify::{self, recorded_stream, recorded_unary};
use super::threads::ThreadFlags;
use super::{assets, upstream};
use crate::machine::{MachineRuntime, Power};
use anyhow::Result;
use axum::extract::ws::{CloseFrame, Message as DownMsg, WebSocket};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as UpMsg;

/// A safety net only: calls in flight, including long operations, finish first.
const CLOSE_AFTER_WAKE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_CONNECT_ATTEMPTS: u32 = 3;
/// "Service restart": T3 Code reconnects at once.
const CLOSE_RECONNECT: u16 = 1012;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Settling,
    Asleep,
    Waking,
    Connecting,
    Live,
}

struct Forwarded {
    id: Value,
    tag: String,
    key: String,
    /// The cache epoch it was asked in: the state its answer describes.
    epoch: u64,
    /// A unary read whose answer is recorded.
    record: bool,
    chunks: usize,
}

enum Internal {
    Settled(Power),
    Woke(Result<()>),
    Connected(Result<upstream::Upstream>),
    Up(Option<String>),
    /// The upstream socket is gone; the machine's power when checked after.
    UpstreamLost(Power),
    CloseNow,
}

pub async fn run(machine: Arc<MachineRuntime>, socket: WebSocket, client_query: String) {
    tracing::info!("T3 Code connected to {}", machine.id());
    let (down, mut down_rx) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut s = Session {
        m: machine,
        down,
        query: client_query,
        phase: Phase::Settling,
        up: None,
        up_task: None,
        forwarded: HashMap::new(),
        cached: HashSet::new(),
        held: Vec::new(),
        close_after_calls: false,
        connect_attempts: 0,
        tx,
    };
    s.settle();

    let mut power = s.m.subscribe_power();
    let close = loop {
        let step = tokio::select! {
            Ok(()) = power.changed() => {
                let now = *power.borrow_and_update();
                s.on_power(now)
            }
            msg = down_rx.next() => match msg {
                Some(Ok(DownMsg::Text(text))) => s.on_down(text.as_str()).await,
                Some(Ok(DownMsg::Close(_))) | None | Some(Err(_)) => break None,
                Some(Ok(_)) => Ok(None),
            },
            Some(ev) = rx.recv() => s.on_internal(ev).await,
        };
        match step {
            Ok(None) => {}
            Ok(Some(reason)) => break Some(reason),
            Err(e) => {
                tracing::warn!("session error: {e:#}");
                break Some("proxy error".to_owned());
            }
        }
    };
    tracing::info!("T3 Code socket closing ({close:?})");
    if let Some(reason) = close {
        let _ = s.down.send(DownMsg::Close(Some(CloseFrame { code: CLOSE_RECONNECT, reason: reason.into() }))).await;
    }
    s.drop_upstream();
}

struct Session {
    m: Arc<MachineRuntime>,
    down: SplitSink<WebSocket, DownMsg>,
    query: String,
    phase: Phase,
    up: Option<mpsc::UnboundedSender<UpMsg>>,
    up_task: Option<JoinHandle<()>>,
    /// Requests sent upstream on this socket, by request id.
    forwarded: HashMap<String, Forwarded>,
    /// Streams answered locally, left open.
    cached: HashSet<String>,
    /// Requests waiting for the machine.
    held: Vec<Value>,
    /// After a wake: close for a resync once no call is in flight.
    close_after_calls: bool,
    connect_attempts: u32,
    tx: mpsc::UnboundedSender<Internal>,
}

/// `Some(reason)` closes the client socket so T3 Code reconnects.
type Step = Result<Option<String>>;

pub(super) fn id_key(id: &Value) -> String {
    match id {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn exit_success(id: &Value, value: Value) -> Value {
    json!({"_tag": "Exit", "requestId": id, "exit": {"_tag": "Success", "value": value}})
}

fn exit_die(id: &Value, message: &str) -> Value {
    json!({"_tag": "Exit", "requestId": id, "exit": {"_tag": "Failure", "cause": [{"_tag": "Die", "defect": message}]}})
}

fn exit_interrupt(id: &Value) -> Value {
    json!({"_tag": "Exit", "requestId": id, "exit": {"_tag": "Failure", "cause": [{"_tag": "Interrupt", "fiberId": null}]}})
}

fn chunk(id: &Value, values: Vec<Value>) -> Value {
    json!({"_tag": "Chunk", "requestId": id, "values": values})
}

/// Effect RPC accepts one message or an array of them per frame.
pub(super) fn messages(text: &str) -> Result<Vec<Value>> {
    Ok(match serde_json::from_str::<Value>(text)? {
        Value::Array(items) => items,
        one => vec![one],
    })
}

impl Session {
    async fn send(&mut self, msg: &Value) -> Result<()> {
        self.down.send(DownMsg::text(msg.to_string())).await?;
        Ok(())
    }

    fn send_up(&self, msg: &Value) {
        if let Some(up) = &self.up {
            let _ = up.send(UpMsg::text(msg.to_string()));
        }
    }

    /// Learns whether the machine runs without blocking this socket's loop.
    fn settle(&self) {
        let m = self.m.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(Internal::Settled(m.settled_power().await));
        });
    }

    async fn on_down(&mut self, text: &str) -> Step {
        for msg in messages(text)? {
            let id = msg.get("requestId").map(id_key);
            match msg["_tag"].as_str().unwrap_or_default() {
                // Liveness of the client socket is the proxy's job, awake or not.
                "Ping" => self.send(&json!({"_tag": "Pong"})).await?,
                "Pong" => {}
                "Request" => self.on_request(msg).await?,
                "Interrupt" => {
                    let id = id.unwrap_or_default();
                    if self.forwarded.contains_key(&id) {
                        self.send_up(&msg);
                    } else if self.cached.remove(&id) || self.take_held(&id) {
                        self.send(&exit_interrupt(&msg["requestId"])).await?;
                    }
                }
                _ if self.phase == Phase::Live => self.send_up(&msg),
                _ => {}
            }
        }
        Ok(None)
    }

    fn take_held(&mut self, id: &str) -> bool {
        let before = self.held.len();
        self.held.retain(|r| id_key(&r["id"]) != id);
        before != self.held.len()
    }

    async fn on_request(&mut self, req: Value) -> Result<()> {
        let tag = req["tag"].as_str().unwrap_or_default().to_owned();
        tracing::debug!(phase = ?self.phase, "rpc {tag}");
        // Whatever becomes of the request (answered here, forwarded, held, dropped), the client
        // opens chats this way: the capture stores them so.
        if tag == "orchestration.subscribeThread"
            && let Some(flags) = ThreadFlags::from_payload(&req["payload"])
        {
            self.m.note_thread_encoding(flags);
        }
        let action = classify::is_user_action(&tag, &req["payload"]);
        match self.phase {
            // A machine about to freeze must not take new work: wait for it, then resume it on
            // a fresh upstream.
            Phase::Live if action && self.m.is_stopping() => {
                self.fail_upstream().await?;
                self.held.push(req);
                self.wake();
            }
            Phase::Live => self.forward(req),
            Phase::Asleep => self.on_asleep(req).await?,
            Phase::Settling | Phase::Waking | Phase::Connecting => self.on_waiting(req).await?,
        }
        Ok(())
    }

    /// A request while no live upstream is attached yet: background calls are answered at once
    /// during a wake or on a socket that already holds cached streams (which will close and
    /// reconnect once the machine is up), so they never wait past T3 Code's 15 s slow-request
    /// warning. On a fresh connect to a running machine (`cached` empty), they stay held for the
    /// brief handshake and go straight upstream.
    async fn on_waiting(&mut self, req: Value) -> Result<()> {
        let answer_now =
            self.phase == Phase::Waking || !self.cached.is_empty() || req["tag"] == "server.probe";
        if answer_now
            && let Some(reply) = self.answer_background(&req)
        {
            self.send(&reply).await?;
            return Ok(());
        }
        self.held.push(req);
        Ok(())
    }

    /// Answers any background requests already held before a wake started.
    async fn drain_background_held(&mut self) -> Result<()> {
        let held = std::mem::take(&mut self.held);
        for req in held {
            if let Some(reply) = self.answer_background(&req) {
                self.send(&reply).await?;
            } else {
                self.held.push(req);
            }
        }
        Ok(())
    }

    /// A request to a sleeping machine: answered locally where possible, else held. Side
    /// information waits unanswered for the next wake; anything else wakes the machine.
    async fn on_asleep(&mut self, req: Value) -> Result<()> {
        if let Some(replies) = self.answer_locally(&req) {
            for r in replies {
                self.send(&r).await?;
            }
            return Ok(());
        }
        let tag = req["tag"].as_str().unwrap_or_default();
        if !classify::is_side_info(tag, &req["payload"]) {
            tracing::info!("waking {} for {tag}", self.m.id());
            self.wake();
        }
        self.held.push(req);
        Ok(())
    }

    fn forward(&mut self, req: Value) {
        let tag = req["tag"].as_str().unwrap_or_default().to_owned();
        let payload = &req["payload"];
        let key = request_key(&tag, payload);
        let record = recorded_unary(&tag, payload);
        // Counted only when it reaches the machine: a call answered locally changes nothing.
        if classify::is_user_action(&tag, payload) {
            self.m.user_action();
        }
        let epoch = self.m.cache.lock().unwrap().epoch;
        self.forwarded
            .insert(id_key(&req["id"]), Forwarded { id: req["id"].clone(), tag, key, epoch, record, chunks: 0 });
        self.send_up(&req);
    }

    /// A call or finite stream awaits its answer from the machine.
    fn calls_in_flight(&self) -> bool {
        self.forwarded.values().any(|f| !classify::is_subscription(&f.tag))
    }

    /// Calls that never need the machine while it is not live: liveness probes, fire-and-forget
    /// signals, background probes (last answer from any epoch, or fail), and recorded side-info
    /// reads.
    fn answer_background(&self, req: &Value) -> Option<Value> {
        let id = &req["id"];
        let tag = req["tag"].as_str()?;
        let payload = &req["payload"];
        if tag == "server.probe" {
            return Some(exit_success(id, json!({})));
        }
        if classify::is_void_signal(tag) {
            return Some(exit_success(id, Value::Null));
        }
        let key = request_key(tag, payload);
        if classify::is_background_probe(tag, payload) {
            let value = self.m.cache.lock().unwrap().unary(&key, true);
            // A URL whose bytes are not on this computer would only fail to load.
            let value = value.filter(|v| {
                tag != "assets.createUrl" || assets::answer_path(self.m.dir(), v).is_some_and(|f| f.exists())
            });
            let reason = if self.phase == Phase::Waking { "machine is waking" } else { "machine is asleep" };
            return Some(value.map_or_else(|| exit_die(id, reason), |v| exit_success(id, v)));
        }
        if classify::is_side_info(tag, payload) && recorded_unary(tag, payload) {
            return self.m.cache.lock().unwrap().unary(&key, true).map(|v| exit_success(id, v));
        }
        None
    }

    /// What the proxy can answer for a sleeping machine without lying. `None`: needs the machine.
    fn answer_locally(&mut self, req: &Value) -> Option<Vec<Value>> {
        let id = &req["id"];
        let tag = req["tag"].as_str()?;
        let payload = &req["payload"];
        let open = |s: &mut Self| {
            s.cached.insert(id_key(id));
        };
        if let Some(reply) = self.answer_background(req) {
            return Some(vec![reply]);
        }
        if classify::SILENT_STREAMS.contains(&tag) {
            open(self);
            return Some(vec![]);
        }
        let key = request_key(tag, payload);
        if classify::is_connection_stream(tag) {
            let mut items = self.m.cache.lock().unwrap().stream(&key)?;
            if tag == "subscribeServerConfig" {
                items.iter_mut().for_each(refresh_server_time);
            }
            open(self);
            return Some(vec![chunk(id, items)]);
        }
        // Everything else describes state, so it is only true if the machine slept the way the
        // proxy saw it: confirmed capture, nothing run since.
        let capture = self.m.fresh_capture()?;
        match tag {
            "orchestration.subscribeShell" => {
                let synchronized = json!({"kind": "synchronized"});
                let items = match capture.shell(payload["afterSequence"].as_u64())? {
                    Shell::UpToDate => vec![synchronized],
                    Shell::Snapshot(snapshot) => vec![json!({"kind": "snapshot", "snapshot": snapshot}), synchronized],
                };
                open(self);
                Some(vec![chunk(id, items)])
            }
            "orchestration.subscribeThread" => {
                let thread = payload["threadId"].as_str()?;
                let high_water = capture.threads.get(thread).copied().unwrap_or(0);
                // The server's own rule: a cursor at the thread's high-water missed nothing.
                // Any other client gets the chat as the machine sleeps with it.
                let mut items = Vec::new();
                if payload["afterSequence"].as_u64() != Some(high_water) {
                    let body = self.m.stored_thread(&capture, thread, ThreadFlags::from_payload(payload)?)?;
                    let mut snapshot: Value = serde_json::from_slice(&body).ok()?;
                    snapshot.as_object_mut()?.insert("kind".into(), "snapshot".into());
                    items.push(snapshot);
                }
                if payload["requestCompletionMarker"].as_bool() == Some(true) {
                    items.push(json!({"kind": "synchronized"}));
                }
                open(self);
                Some(if items.is_empty() { vec![] } else { vec![chunk(id, items)] })
            }
            "orchestration.dispatchCommand" => {
                let kind = payload["type"].as_str()?;
                let wakes = classify::WAKING_COMMANDS.contains(&kind);
                if !wakes && !classify::DEFERRABLE_COMMANDS.contains(&kind) {
                    return None;
                }
                self.m.cache.lock().unwrap().deferred_commands.push(payload.clone());
                self.m.save_cache();
                if wakes {
                    tracing::info!("waking {} for {kind}", self.m.id());
                    self.wake();
                }
                Some(vec![exit_success(id, json!({"sequence": capture.sequence}))])
            }
            _ if recorded_stream(tag).is_some() => {
                let items = self.m.cache.lock().unwrap().stream(&key)?;
                open(self);
                Some(vec![chunk(id, items)])
            }
            _ if recorded_unary(tag, payload) => {
                let value = self.m.cache.lock().unwrap().unary(&key, classify::serves_last_seen(tag, payload))?;
                Some(vec![exit_success(id, value)])
            }
            _ => None,
        }
    }

    fn wake(&mut self) {
        if matches!(self.phase, Phase::Waking | Phase::Connecting) {
            return;
        }
        self.phase = Phase::Waking;
        let m = self.m.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(Internal::Woke(m.ensure_awake().await));
        });
    }

    fn connect(&mut self) {
        self.phase = Phase::Connecting;
        self.connect_attempts += 1;
        let (url, token, query) = (self.m.upstream_url(), self.m.upstream_token(), self.query.clone());
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(Internal::Connected(upstream::connect(&url, &token, &upstream::rpc_target(&query)).await));
        });
    }

    /// The machine was deleted: the socket closes. It woke for someone else: a socket parked on
    /// cached answers goes live, once what it holds went upstream.
    fn on_power(&mut self, power: Power) -> Step {
        if power == Power::Missing {
            return Ok(Some("machine deleted".into()));
        }
        if power != Power::Running || self.phase != Phase::Asleep {
            return Ok(None);
        }
        if self.held.is_empty() && !self.cached.is_empty() {
            return Ok(Some("machine woke".into()));
        }
        self.connect();
        Ok(None)
    }

    async fn on_internal(&mut self, ev: Internal) -> Step {
        match ev {
            Internal::Settled(Power::Running) => self.connect(),
            Internal::Settled(_) => self.go_asleep().await?,
            Internal::Woke(Ok(())) => self.connect(),
            Internal::Woke(Err(e)) => {
                let msg = format!("The machine could not wake: {e:#}");
                for req in std::mem::take(&mut self.held) {
                    self.send(&exit_die(&req["id"], &msg)).await?;
                }
                self.phase = Phase::Asleep;
            }
            Internal::Connected(Ok(ws)) => {
                self.connect_attempts = 0;
                self.attach_upstream(ws);
                self.phase = Phase::Live;
                return self.release_held();
            }
            Internal::Connected(Err(e)) => {
                tracing::warn!("upstream connect for {}: {e:#}", self.m.id());
                if self.connect_attempts >= MAX_CONNECT_ATTEMPTS {
                    return Ok(Some("machine unreachable".into()));
                }
                // Asleep after all, or not ready yet: a wake sorts out both.
                self.phase = Phase::Asleep;
                self.wake();
                self.drain_background_held().await?;
            }
            Internal::Up(Some(text)) => return self.on_up(&text).await,
            Internal::Up(None) => return self.on_upstream_lost().await,
            Internal::UpstreamLost(power) => return self.after_upstream_lost(power).await,
            Internal::CloseNow => return Ok(Some("machine woke".into())),
        }
        Ok(None)
    }

    /// The machine sleeps: what was held meanwhile is handled like any request to it.
    async fn go_asleep(&mut self) -> Result<()> {
        self.phase = Phase::Asleep;
        for req in std::mem::take(&mut self.held) {
            self.on_asleep(req).await?;
        }
        Ok(())
    }

    fn release_held(&mut self) -> Step {
        let held = std::mem::take(&mut self.held);
        if self.cached.is_empty() {
            held.into_iter().for_each(|r| self.forward(r));
            return Ok(None);
        }
        // Streams answered from cache cannot turn live in place: finish the calls and finite
        // streams, then close so T3 Code resubscribes against the live server.
        held.into_iter()
            .filter(|r| !classify::is_subscription(r["tag"].as_str().unwrap_or_default()))
            .for_each(|r| self.forward(r));
        if !self.calls_in_flight() {
            return Ok(Some("machine woke".into()));
        }
        self.close_after_calls = true;
        let tx = self.tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(CLOSE_AFTER_WAKE_TIMEOUT).await;
            let _ = tx.send(Internal::CloseNow);
        });
        Ok(None)
    }

    fn attach_upstream(&mut self, ws: upstream::Upstream) {
        let (mut sink, mut stream) = ws.split();
        let (up_tx, mut up_rx) = mpsc::unbounded_channel::<UpMsg>();
        let tx = self.tx.clone();
        let task = tokio::spawn(async move {
            let mut ping = tokio::time::interval(upstream::PING);
            let mut deadline = tokio::time::Instant::now() + upstream::SILENCE;
            loop {
                tokio::select! {
                    out = up_rx.recv() => match out {
                        Some(m) => if sink.send(m).await.is_err() { break },
                        None => break,
                    },
                    _ = ping.tick() => if sink.send(UpMsg::Ping(Default::default())).await.is_err() { break },
                    _ = tokio::time::sleep_until(deadline) => break,
                    inbound = stream.next() => {
                        deadline = tokio::time::Instant::now() + upstream::SILENCE;
                        match inbound {
                            Some(Ok(UpMsg::Text(t))) => { let _ = tx.send(Internal::Up(Some(t.to_string()))); }
                            Some(Ok(UpMsg::Close(_))) | Some(Err(_)) | None => break,
                            Some(Ok(_)) => {}
                        }
                    }
                }
            }
            let _ = tx.send(Internal::Up(None));
        });
        self.up = Some(up_tx);
        self.up_task = Some(task);
    }

    fn drop_upstream(&mut self) {
        self.up = None;
        if let Some(t) = self.up_task.take() {
            t.abort();
        }
        for (id, f) in self.forwarded.drain() {
            if classify::is_subscription(&f.tag) {
                self.cached.insert(id);
            }
        }
    }

    async fn on_up(&mut self, text: &str) -> Step {
        for mut msg in messages(text)? {
            let id = msg.get("requestId").map(id_key).unwrap_or_default();
            match msg["_tag"].as_str().unwrap_or_default() {
                "Pong" => continue,
                "Chunk" => {
                    if let Some(f) = self.forwarded.get_mut(&id) {
                        if let Some(values) = msg.get_mut("values").and_then(Value::as_array_mut) {
                            if f.tag == "subscribeServerConfig" {
                                values.iter_mut().filter_map(|v| v.get_mut("config")).for_each(sanitize_server_config);
                            }
                            let first = f.chunks == 0;
                            f.chunks += 1;
                            self.m.cache.lock().unwrap().record_stream_items(&f.tag, &f.key, values, first);
                        }
                    }
                }
                "Exit" => {
                    let success = msg["exit"]["_tag"] == "Success";
                    if !success {
                        tracing::debug!("rpc failed: {}", msg["exit"]["cause"][0]["_tag"]);
                    }
                    let value = msg["exit"].get_mut("value");
                    if let (Some(f), true, Some(value)) = (self.forwarded.remove(&id), success, value) {
                        if f.tag == "server.getConfig" {
                            sanitize_server_config(value);
                        }
                        if f.record {
                            let mut cache = self.m.cache.lock().unwrap();
                            if f.tag == "server.refreshProviders" {
                                cache.fold_providers(&value["providers"]);
                            }
                            if f.tag == "assets.createUrl"
                                && let Some(earlier) = cache.unary.get(&f.key)
                            {
                                assets::carry(self.m.dir(), &earlier.value, value);
                            }
                            cache.record_unary(&f.key, f.epoch, value);
                        }
                    }
                }
                _ => {}
            }
            self.send(&msg).await?;
            if self.close_after_calls && msg["_tag"] == "Exit" && !self.calls_in_flight() {
                return Ok(Some("machine woke".into()));
            }
        }
        Ok(None)
    }

    /// Calls and finite streams in flight upstream fail; subscriptions stay open on the client,
    /// now answered by nobody (their state is final if the machine went to sleep).
    async fn fail_upstream(&mut self) -> Result<()> {
        let failed: Vec<Value> =
            self.forwarded.values().filter(|f| !classify::is_subscription(&f.tag)).map(|f| f.id.clone()).collect();
        self.drop_upstream();
        for id in failed {
            self.send(&exit_die(&id, "The machine went to sleep")).await?;
        }
        Ok(())
    }

    /// Fails the old upstream, then checks why it went, off the loop.
    async fn on_upstream_lost(&mut self) -> Step {
        self.fail_upstream().await?;
        if self.phase != Phase::Live {
            // A wake of ours is under way and will reconnect.
            return Ok(None);
        }
        self.phase = Phase::Settling;
        let m = self.m.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let power = m.refresh_power().await.unwrap_or(Power::Unknown);
            let power = if matches!(power, Power::Stopping | Power::Stopped) { m.settled_power().await } else { power };
            let _ = tx.send(Internal::UpstreamLost(power));
        });
        Ok(None)
    }

    async fn after_upstream_lost(&mut self, power: Power) -> Step {
        // A network blip, or a sleep the client may have missed the end of (the laptop slept
        // too): let T3 Code reconnect and resync.
        if power != Power::Stopped || self.m.fresh_capture().is_none() {
            return Ok(Some("upstream lost".into()));
        }
        // The machine went to sleep under an open socket, the way the proxy saw it: the
        // client's view stays true; keep the socket and answer locally from here.
        tracing::info!("{} went to sleep with a client attached", self.m.id());
        self.go_asleep().await?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boat::Boat;
    use crate::machine::Shared;
    use crate::store::{Machine, Settings};
    use crate::t3desktop::T3Desktop;
    use axum::Router;
    use axum::extract::WebSocketUpgrade;
    use axum::routing::get;
    use std::path::PathBuf;
    use std::sync::RwLock;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("t3boat-session-{:016x}", rand::random::<u64>()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_machine(dir: &std::path::Path, upstream_url: &str, power: Power) -> Arc<MachineRuntime> {
        let (events, _rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            boat: Boat::stub(),
            t3: T3Desktop::stub(),
            settings: RwLock::new(Settings::default()),
            events,
            http: reqwest::Client::new(),
        });
        let record = Machine {
            id: "bx_test".into(),
            sandbox_id: "bx_test".into(),
            name: "dinghy".into(),
            size: "default".into(),
            upstream_url: upstream_url.into(),
            upstream_token: "upstream-tok".into(),
            watchdog_url: "http://127.0.0.1:1".into(),
            watchdog_secret: "wd-sec".into(),
            local_port: 0,
            t3_version: "0.1.11".into(),
            provision_revision: "rev".into(),
            environment_id: "env-1".into(),
            client_tokens: vec![],
            device_tokens: vec![],
            link_tokens: vec![],
            created_at: 0,
            next_due_at: None,
            connect: false,
            cliproxy: false,
            cliproxy_accounts: vec![],
        };
        let m = Arc::new(MachineRuntime::new(shared, record, dir.to_path_buf()));
        m.set_power_for_test(power);
        m
    }

    async fn spawn_session(m: Arc<MachineRuntime>) -> (upstream::Upstream, JoinHandle<()>) {
        let app = Router::new().route(
            "/ws",
            get(move |ws: WebSocketUpgrade| {
                let m = m.clone();
                async move { ws.on_upgrade(move |socket| run(m, socket, String::new())) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await.unwrap();
        (ws, server)
    }

    async fn send_req(ws: &mut upstream::Upstream, id: u64, tag: &str, payload: Value) {
        let frame = json!({"_tag": "Request", "id": id, "tag": tag, "payload": payload, "headers": []});
        ws.send(UpMsg::text(frame.to_string())).await.unwrap();
    }

    async fn recv_json(ws: &mut upstream::Upstream) -> Value {
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next()).await.unwrap().unwrap().unwrap();
        let UpMsg::Text(text) = msg else { panic!("expected text frame, got {msg:?}") };
        serde_json::from_str(&text).unwrap()
    }

    #[tokio::test]
    async fn usage_summary_while_asleep_answers_from_cache_or_fails_without_waking() {
        let dir = TempDir::new();
        let m = test_machine(&dir.0, "http://127.0.0.1:1", Power::Stopped);
        let day_a = json!({"resolution": "day", "sinceDay": "2026-10-25", "untilDay": "2026-11-23"});
        let day_b = json!({"resolution": "day", "sinceDay": "2026-10-26", "untilDay": "2026-11-24"});
        {
            let mut cache = m.cache.lock().unwrap();
            cache.record_unary(&request_key("server.getUsageSummary", &day_a), 0, &json!({"buckets": [1]}));
            cache.bump_epoch();
        }
        let (mut ws, server) = spawn_session(m.clone()).await;

        send_req(&mut ws, 1, "server.getUsageSummary", day_a).await;
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["requestId"], 1);
        assert_eq!(reply["exit"]["_tag"], "Success");
        assert_eq!(reply["exit"]["value"], json!({"buckets": [1]}));

        send_req(&mut ws, 2, "server.getUsageSummary", day_b).await;
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["requestId"], 2);
        assert_eq!(reply["exit"]["_tag"], "Failure");
        assert_eq!(reply["exit"]["cause"][0]["defect"], "machine is asleep");

        // Neither call woke the machine.
        assert_eq!(m.power(), Power::Stopped);
        assert!(m.waking.try_lock().is_ok());

        server.abort();
    }

    /// Opening a project's settings lists its images for the icon picker: never a wake, nor a
    /// request left waiting into T3 Code's slow-request warning.
    #[tokio::test]
    async fn project_icon_candidates_while_asleep_answer_from_cache_or_fail_without_waking() {
        let dir = TempDir::new();
        let m = test_machine(&dir.0, "http://127.0.0.1:1", Power::Stopped);
        let icons = |cwd: &str| json!({"cwd": cwd, "query": "", "limit": 200, "kind": "file", "imageOnly": true});
        let seen = json!({"entries": [{"path": "public/logo.png", "kind": "file"}], "truncated": false});
        {
            let mut cache = m.cache.lock().unwrap();
            cache.record_unary(&request_key("projects.searchEntries", &icons("/a")), 0, &seen);
            cache.bump_epoch();
        }
        let (mut ws, server) = spawn_session(m.clone()).await;

        send_req(&mut ws, 1, "projects.searchEntries", icons("/a")).await;
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["requestId"], 1);
        assert_eq!(reply["exit"]["value"], seen);

        send_req(&mut ws, 2, "projects.searchEntries", icons("/b")).await;
        let reply = recv_json(&mut ws).await;
        assert_eq!(reply["requestId"], 2);
        assert_eq!(reply["exit"]["cause"][0]["defect"], "machine is asleep");

        assert_eq!(m.power(), Power::Stopped);
        assert!(m.waking.try_lock().is_ok());

        server.abort();
    }

    #[tokio::test]
    async fn background_and_void_calls_answer_immediately_during_wake() {
        let dir = TempDir::new();
        let m = test_machine(&dir.0, "http://127.0.0.1:1", Power::Stopped);

        let asset_kept_req = json!({"resource": {"_tag": "attachment", "attachmentId": "kept"}});
        let asset_kept_ans = json!({"relativeUrl": "/api/assets/t1/kept.png"});
        let asset_missing_req = json!({"resource": {"_tag": "attachment", "attachmentId": "missing"}});
        let asset_missing_ans = json!({"relativeUrl": "/api/assets/t2/missing.png"});
        let refs_req = json!({"cwd": "/w", "limit": 100});
        let refs_ans = json!({"refs": ["main"]});
        {
            let mut cache = m.cache.lock().unwrap();
            cache.record_stream_items(
                "subscribeServerConfig",
                &request_key("subscribeServerConfig", &json!({})),
                &[json!({"type": "snapshot", "config": {}})],
                true,
            );
            cache.record_unary(&request_key("assets.createUrl", &asset_kept_req), 0, &asset_kept_ans);
            cache.record_unary(&request_key("assets.createUrl", &asset_missing_req), 0, &asset_missing_ans);
            cache.record_unary(&request_key("vcs.listRefs", &refs_req), 0, &refs_ans);
            cache.bump_epoch();
        }
        let kept_file = assets::answer_path(&dir.0, &asset_kept_ans).unwrap();
        crate::store::write_private(&kept_file, b"[]\npng").unwrap();

        // Hold the wake lock so `Phase::Waking` stays in flight throughout the test.
        let _waking = m.waking.lock().await;
        let (mut ws, server) = spawn_session(m.clone()).await;

        send_req(&mut ws, 1, "subscribeServerConfig", json!({})).await;
        assert_eq!(recv_json(&mut ws).await["_tag"], "Chunk");

        // No fresh capture: `orchestration.subscribeShell` transitions the session to `Phase::Waking`.
        send_req(&mut ws, 2, "orchestration.subscribeShell", json!({})).await;
        // Let the session process `subscribeShell` before sending the next batch.
        send_req(&mut ws, 3, "server.probe", json!({})).await;
        assert_eq!(recv_json(&mut ws).await, exit_success(&json!(3), json!({})));

        // Void signals answer immediately while waking.
        send_req(&mut ws, 4, "preview.reportProfiles", json!({"profiles": []})).await;
        assert_eq!(recv_json(&mut ws).await, exit_success(&json!(4), Value::Null));

        send_req(&mut ws, 5, "server.reportClientActivity", json!({"focused": true})).await;
        assert_eq!(recv_json(&mut ws).await, exit_success(&json!(5), Value::Null));

        // Background probes answer from cache (with file check for assets) or fail fast while waking.
        send_req(&mut ws, 6, "assets.createUrl", asset_kept_req).await;
        assert_eq!(recv_json(&mut ws).await, exit_success(&json!(6), asset_kept_ans));

        send_req(&mut ws, 7, "assets.createUrl", asset_missing_req).await;
        assert_eq!(recv_json(&mut ws).await, exit_die(&json!(7), "machine is waking"));

        send_req(&mut ws, 8, "assets.createUrl", json!({"resource": {"_tag": "attachment", "attachmentId": "new"}}))
            .await;
        assert_eq!(recv_json(&mut ws).await, exit_die(&json!(8), "machine is waking"));

        send_req(&mut ws, 9, "server.refreshProviders", json!({"usageLimitsCommand": true})).await;
        assert_eq!(recv_json(&mut ws).await, exit_die(&json!(9), "machine is waking"));

        send_req(&mut ws, 10, "server.getUsageSummary", json!({"resolution": "day"})).await;
        assert_eq!(recv_json(&mut ws).await, exit_die(&json!(10), "machine is waking"));

        // Recorded side-info unary reads answer from cache while waking.
        send_req(&mut ws, 11, "vcs.listRefs", refs_req).await;
        assert_eq!(recv_json(&mut ws).await, exit_success(&json!(11), refs_ans));

        // User-initiated calls stay held for the live machine rather than failing fast.
        send_req(&mut ws, 12, "server.refreshProviders", json!({"reloadSecrets": true})).await;
        send_req(&mut ws, 13, "projects.readFile", json!({"cwd": "/w", "relativePath": "a.rs"})).await;
        assert!(tokio::time::timeout(Duration::from_millis(80), ws.next()).await.is_err());

        server.abort();
    }

    #[tokio::test]
    async fn fresh_connect_to_running_machine_forwards_void_and_background_calls_upstream() {
        let dir = TempDir::new();
        let upstream_app = Router::new().route(
            "/ws",
            get(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|mut socket| async move {
                    while let Some(Ok(DownMsg::Text(text))) = socket.next().await {
                        for msg in messages(text.as_str()).unwrap() {
                            if msg["_tag"] == "Request" {
                                let reply = exit_success(&msg["id"], json!({"upstream": msg["tag"]}));
                                let _ = socket.send(DownMsg::text(reply.to_string())).await;
                            }
                        }
                    }
                })
            }),
        );
        let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up_listener.local_addr().unwrap();
        let up_server = tokio::spawn(async move {
            let _ = axum::serve(up_listener, upstream_app).await;
        });

        let m = test_machine(&dir.0, &format!("http://{up_addr}"), Power::Running);
        let (mut ws, server) = spawn_session(m).await;

        // Sent immediately on a fresh socket (during Settling/Connecting with `cached` empty):
        // must be held briefly and forwarded to upstream rather than swallowed locally.
        send_req(&mut ws, 1, "preview.reportProfiles", json!({"profiles": ["default"]})).await;
        send_req(&mut ws, 2, "assets.createUrl", json!({"resource": {"_tag": "attachment", "attachmentId": "x"}}))
            .await;

        let r1 = recv_json(&mut ws).await;
        let r2 = recv_json(&mut ws).await;
        assert_eq!(r1, exit_success(&json!(1), json!({"upstream": "preview.reportProfiles"})));
        assert_eq!(r2, exit_success(&json!(2), json!({"upstream": "assets.createUrl"})));

        server.abort();
        up_server.abort();
    }

    #[tokio::test]
    async fn failed_connect_entering_wake_drains_held_background_calls() {
        let dir = TempDir::new();
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed.local_addr().unwrap();
        drop(closed);

        let m = test_machine(&dir.0, &format!("http://{closed_addr}"), Power::Running);
        let _waking = m.waking.lock().await;
        let (mut ws, server) = spawn_session(m.clone()).await;

        send_req(&mut ws, 1, "subscribeServerConfig", json!({})).await;
        send_req(&mut ws, 2, "preview.reportProfiles", json!({"profiles": []})).await;
        send_req(&mut ws, 3, "assets.createUrl", json!({"resource": {"_tag": "attachment", "attachmentId": "x"}}))
            .await;

        // Once the connect fails and enters `Phase::Waking`, held background calls drain at once,
        // while `subscribeServerConfig` stays held for the wake.
        let r2 = recv_json(&mut ws).await;
        let r3 = recv_json(&mut ws).await;
        assert_eq!(r2, exit_success(&json!(2), Value::Null));
        assert_eq!(r3, exit_die(&json!(3), "machine is waking"));
        assert!(tokio::time::timeout(Duration::from_millis(80), ws.next()).await.is_err());

        server.abort();
    }
}
