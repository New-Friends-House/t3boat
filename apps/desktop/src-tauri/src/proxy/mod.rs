//! The localhost server T3 Code knows the machine by. One per machine, on a fixed port.

pub mod assets;
pub mod auth;
pub mod cache;
pub mod classify;
pub mod link;
pub mod media;
pub mod session;
pub mod threads;
pub mod upstream;

use crate::machine::{MachineRuntime, Power};
use crate::tailnet;
use anyhow::Result;
use axum::body::Body;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, Path, Query, RawQuery, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Form, Json, Router};
use auth::TicketUse;
use cache::Shell;
use threads::ThreadFlags;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

type M = State<Arc<MachineRuntime>>;

/// Ten years: the proxy's own tokens never make T3 Code re-pair.
const CLIENT_TOKEN_TTL_SECS: i64 = 10 * 365 * 24 * 3600;
/// A T3 server linking to the machine gives its descriptor 3 s on loopback. The refresh from a
/// running machine gets half of that; the last one seen answers after it.
const DESCRIPTOR_REFRESH: std::time::Duration = std::time::Duration::from_millis(1500);
/// T3's largest request: a 100 MB file into the preview browser.
const MAX_BODY: usize = 128 * 1024 * 1024;

/// Serves the machine on loopback, for T3 Code here, and on this computer's tailnet address
/// while Tailscale runs, for the user's other devices. Only the loopback listener failing ends it.
pub async fn serve(machine: Arc<MachineRuntime>) -> Result<()> {
    let port = machine.record().local_port;
    let local = router(machine.clone(), false).layer(middleware::from_fn(local_host_only));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tokio::select! {
        served = axum::serve(listener, local) => served?,
        () = serve_tailnet(machine) => {}
    }
    Ok(())
}

fn router(machine: Arc<MachineRuntime>, remote: bool) -> Router {
    let mut app = Router::new()
        .route("/.well-known/t3/environment", get(descriptor))
        .route("/oauth/token", post(oauth_token))
        .route("/api/auth/session", get(auth_session))
        .route("/api/auth/websocket-ticket/{opens}", post(ticket))
        .route("/ws", get(ws))
        .route("/api/device-hub/{*path}", any(media::stream))
        .route("/api/preview-stream/{*path}", any(media::stream))
        .route("/api/orchestration/shell", get(shell_snapshot))
        .route("/api/orchestration/threads/{thread}/bounded", get(thread_snapshot))
        .route("/api/voice/status", get(voice_status))
        .route("/api/observability/v1/traces", post(traces));
    // Linking is between T3 servers on this computer; elsewhere these paths need a client token.
    if !remote {
        app = app
            .route("/oauth/mcp/register", post(link::register))
            .route("/oauth/mcp/decision", post(link::decision))
            .route("/oauth/mcp/token", post(link::token))
            .route("/mcp", any(link::mcp));
    }
    app.fallback(fallback)
        .layer(middleware::from_fn(cors))
        .layer(middleware::from_fn(plain_paths_only))
        .with_state(machine)
}

/// The proxy's tailnet address per local port, while it listens there.
static TAILNET: std::sync::Mutex<Vec<(u16, Ipv4Addr)>> = std::sync::Mutex::new(Vec::new());

/// Where the user's other devices reach the machine on `port`, while they can.
pub fn tailnet_address(port: u16) -> Option<Ipv4Addr> {
    TAILNET.lock().unwrap().iter().find(|(p, _)| *p == port).map(|(_, ip)| *ip)
}

/// The entry of a listener in `TAILNET`, for as long as it listens: dropped with it, also when
/// the machine's proxy is aborted.
struct Listening(u16);

impl Listening {
    fn new(port: u16, ip: Ipv4Addr) -> Self {
        let mut listening = TAILNET.lock().unwrap();
        listening.retain(|(p, _)| *p != port);
        listening.push((port, ip));
        Self(port)
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        TAILNET.lock().unwrap().retain(|(p, _)| *p != self.0);
    }
}

/// Follows Tailscale's tunnel: listens on its address, on the machine's port, while there is
/// one. Bound to that address and to the tunnel interface, so nothing else on the network
/// reaches the proxy, even through a Mac that forwards packets.
async fn serve_tailnet(machine: Arc<MachineRuntime>) {
    let port = machine.record().local_port;
    let mut tunnel = tailnet::tunnel();
    loop {
        let current = *tunnel.borrow_and_update();
        if let Some(t) = current {
            let ip = t.ip;
            match tailnet_listener(t, port) {
                Ok(listener) => {
                    tracing::info!("{} reachable over Tailscale at {ip}:{port}", machine.id());
                    let _listening = Listening::new(port, ip);
                    let app = router(machine.clone(), true)
                        .layer(middleware::from_fn_with_state(ip, tailnet_only))
                        .into_make_service_with_connect_info::<SocketAddr>();
                    tokio::select! {
                        served = axum::serve(listener, app) => {
                            tracing::warn!("{} stopped listening on {ip}:{port}: {served:?}", machine.id());
                        }
                        _ = tunnel.changed() => continue,
                    }
                }
                Err(e) => tracing::warn!("{} cannot listen on {ip}:{port}: {e:#}", machine.id()),
            }
        }
        // A new tunnel, or another try at this one.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(30), tunnel.changed()).await;
    }
}

/// A listener on the tunnel's address and interface. Reusing the address, so connections of
/// an earlier listener (open, or in TIME_WAIT) do not keep this one out.
#[cfg(target_os = "macos")]
fn tailnet_listener(tunnel: tailnet::Tunnel, port: u16) -> Result<tokio::net::TcpListener> {
    use std::os::fd::AsRawFd;
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    // SAFETY: a valid socket, and an option value of the size the option takes.
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            (&tunnel.interface as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if set != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    socket.bind(SocketAddr::from((tunnel.ip, port)))?;
    Ok(socket.listen(1024)?)
}

#[cfg(not(target_os = "macos"))]
fn tailnet_listener(_tunnel: tailnet::Tunnel, _port: u16) -> Result<tokio::net::TcpListener> {
    anyhow::bail!("other devices reach machines only from macOS")
}

/// A path with dot segments names one place to the router and another upstream, where they
/// are resolved: T3 Code never sends one.
async fn plain_paths_only(req: Request, next: Next) -> Response {
    if has_dot_segments(req.uri().path()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    next.run(req).await
}

fn has_dot_segments(path: &str) -> bool {
    path.contains('\\')
        || path.split('/').any(|segment| {
            let segment = segment.to_ascii_lowercase().replace("%2e", ".");
            segment == "." || segment == ".."
        })
}

/// Web pages can reach 127.0.0.1 too, through DNS rebinding; only requests addressed to this
/// computer by name are T3 Code's.
async fn local_host_only(req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or_default();
    let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    if !matches!(name, "localhost" | "127.0.0.1" | "[::1]") {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(req).await
}

/// The user's other devices: tailnet peers, addressing this computer by its tailnet address.
/// A web page DNS-rebound to that address names a host of its own.
async fn tailnet_only(
    State(ip): State<Ipv4Addr>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or_default();
    if !tailnet_client(ip, peer.ip(), host) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Before any route: the fallback would relay them, waking the machine.
    if is_linking(&canonical_path(req.uri())) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut req = req;
    req.extensions_mut().insert(OverTailnet);
    next.run(req).await
}

/// Marks a request that came in over the tailnet: from another of the user's devices.
#[derive(Clone, Copy)]
struct OverTailnet;

/// Linking between T3 servers stays on this computer. Compared as T3's router matches paths:
/// up to a `;`, percent-decoded, regardless of case, and with repeated slashes as one. A path
/// that does not decode is refused too.
fn is_linking(path: &str) -> bool {
    let path = path.split(';').next().unwrap_or_default();
    let Ok(path) = urlencoding::decode(path) else { return true };
    let path = path.to_ascii_lowercase();
    let path = path.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>();
    matches!(path.as_slice(), ["mcp", ..] | ["oauth", "mcp", ..])
}

fn tailnet_client(own: Ipv4Addr, peer: IpAddr, host: &str) -> bool {
    tailnet::is_tailnet(peer)
        && url::Url::parse(&format!("http://{host}/")).is_ok_and(|u| u.host() == Some(url::Host::Ipv4(own)))
}

/// The renderer runs at `t3code://app`; the real server allows any origin, so does the proxy.
async fn cors(req: Request, next: Next) -> Response {
    let mut res = if req.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let h = res.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(HeaderName::from_static(k), HeaderValue::from_static(v));
    };
    set(h, "access-control-allow-origin", "*");
    set(h, "access-control-allow-methods", "GET, POST, OPTIONS");
    set(
        h,
        "access-control-allow-headers",
        "authorization, b3, traceparent, content-type, dpop, x-t3-orchestration-protocol",
    );
    set(h, "access-control-max-age", "600");
    res
}

fn client_authorized(m: &MachineRuntime, headers: &HeaderMap) -> bool {
    let record = m.record();
    auth::access_token(headers)
        .is_some_and(|t| record.client_tokens.iter().chain(&record.device_tokens).any(|c| c == t))
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
}

fn iso_in(secs: i64) -> String {
    (chrono::Utc::now() + chrono::TimeDelta::seconds(secs)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

async fn descriptor(State(m): M) -> Response {
    if m.power() == Power::Running {
        let _ = tokio::time::timeout(DESCRIPTOR_REFRESH, m.fetch_descriptor()).await;
    }
    let cached = m.cache.lock().unwrap().descriptor.clone();
    match cached {
        Some(mut d) => {
            // The sidebar shows the machine's name, not the sandbox hostname.
            d["label"] = Value::String(m.record().name);
            Json(d).into_response()
        }
        // Transient, so T3 Code keeps retrying instead of blocking the connection.
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn oauth_token(
    State(m): M,
    over_tailnet: Option<axum::Extension<OverTailnet>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let code = form.get("subject_token").map(String::as_str).unwrap_or_default();
    // A code pairs only the device it was made for, by where it comes in.
    let who = if over_tailnet.is_some() { auth::Pairing::OtherDevice } else { auth::Pairing::Desktop };
    if !m.auth.redeem_pairing_code(code, who) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"}))).into_response();
    }
    let token = auth::random_token();
    // Kept apart: only the desktop's say whether T3 Code here has the machine.
    m.update_record(|r| match who {
        auth::Pairing::Desktop => r.client_tokens.push(token.clone()),
        auth::Pairing::OtherDevice => r.device_tokens.push(token.clone()),
    });
    let session = m.cache.lock().unwrap().auth_session.clone().unwrap_or_default();
    let scope = session
        .get("scopes")
        .and_then(Value::as_array)
        .map(|s| s.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let mut body = json!({
        "access_token": token,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": CLIENT_TOKEN_TTL_SECS,
        "scope": scope,
    });
    if let Some(p) = session.get("permissions") {
        body["permissions"] = p.clone();
    }
    tracing::info!("T3 Code paired with {}", m.id());
    Json(body).into_response()
}

async fn auth_session(State(m): M, headers: HeaderMap) -> Response {
    if !client_authorized(&m, &headers) {
        return unauthorized();
    }
    let cached = m.cache.lock().unwrap().auth_session.clone();
    match cached {
        Some(mut s) => {
            s.insert("expiresAt".into(), Value::String(iso_in(CLIENT_TOKEN_TTL_SECS)));
            Json(s).into_response()
        }
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// The proxy's own tickets, for the RPC socket and for media streams alike: asking for one
/// never reaches the machine.
async fn ticket(State(m): M, Path(opens): Path<TicketUse>, headers: HeaderMap) -> Response {
    if !client_authorized(&m, &headers) {
        return unauthorized();
    }
    let (ticket, ttl) = m.auth.issue_ticket(opens);
    Json(json!({"ticket": ticket, "expiresAt": iso_in(ttl.as_secs() as i64)})).into_response()
}

async fn ws(State(m): M, RawQuery(query): RawQuery, headers: HeaderMap, upgrade: WebSocketUpgrade) -> Response {
    let query = query.unwrap_or_default();
    let ticket = query_param(&query, "wsTicket");
    let ok = ticket.is_some_and(|t| m.auth.check_ticket(&t, TicketUse::Rpc)) || client_authorized(&m, &headers);
    if !ok {
        return unauthorized();
    }
    upgrade.on_upgrade(move |socket| session::run(m, socket, query))
}

/// The HTTP shell snapshot T3 Code loads on start: answered from the capture while asleep.
async fn shell_snapshot(State(m): M, Query(q): Query<HashMap<String, String>>, req: Request) -> Response {
    if !client_authorized(&m, req.headers()) {
        return unauthorized();
    }
    // Right after the app starts the power is not known yet: the capture would look stale, and
    // the machine be woken for what it holds.
    m.settled_power().await;
    if let Some(capture) = m.fresh_capture() {
        let resume_from = q.get("resumeFrom").and_then(|v| v.parse().ok());
        match capture.shell(resume_from) {
            Some(Shell::UpToDate) => return Json(json!({"resumable": true})).into_response(),
            Some(Shell::Snapshot(snapshot)) => return Json(snapshot).into_response(),
            None => {}
        }
    }
    forward(State(m), req).await
}

/// The HTTP snapshot T3 Code opens a chat with: answered from the thread store while asleep.
async fn thread_snapshot(
    State(m): M,
    Path(thread): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    if !client_authorized(&m, req.headers()) {
        return unauthorized();
    }
    let flags = ThreadFlags::from_query(&q);
    m.note_thread_encoding(flags);
    // As for the shell: the capture counts once the power is known.
    m.settled_power().await;
    if let Some(body) = m.fresh_capture().and_then(|c| m.stored_thread(&c, &thread, flags)) {
        return ([(header::CONTENT_TYPE, "application/json")], body).into_response();
    }
    forward(State(m), req).await
}

/// The voice status T3 Code reads on its own as it starts, when this machine takes its
/// dictation. A mic click reads the same, so it is answered as last seen while asleep and wakes
/// the machine only when never seen.
async fn voice_status(State(m): M, mut req: Request) -> Response {
    if !client_authorized(&m, req.headers()) {
        return unauthorized();
    }
    if m.settled_power().await != Power::Running
        && let Some(status) = m.cache.lock().unwrap().voice_status.clone()
    {
        return Json(status).into_response();
    }
    // The answer is read here, so it must come uncompressed.
    req.headers_mut().remove(header::ACCEPT_ENCODING);
    let answer = forward(State(m.clone()), req).await;
    if answer.status() != StatusCode::OK {
        return answer;
    }
    let (head, body) = answer.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if let Ok(status) = serde_json::from_slice(&body) {
        m.cache.lock().unwrap().voice_status = Some(status);
        m.save_cache();
    }
    Response::from_parts(head, Body::from(body))
}

/// Renderer traces: periodic, so forwarding them would keep the machine from sleeping.
async fn traces() -> Response {
    StatusCode::OK.into_response()
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
];

/// Routes whose URL carries its own one-time token instead of a bearer header.
const URL_TOKEN_ROUTES: &[&str] = &[assets::ROUTE, "/api/attachments/upload/"];

fn query_param(query: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

/// `query` without the parameters named in `drop`, the rest byte for byte.
fn query_without(query: &str, drop: &[&str]) -> String {
    query
        .split('&')
        .filter(|pair| !pair.is_empty() && !drop.contains(&pair.split('=').next().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("&")
}

/// The path a request names with its dot segments resolved, as the HTTP client resolves them on
/// the way to the machine: every check on a path sees the path that goes there.
fn canonical_path(uri: &Uri) -> String {
    url::Url::parse(&format!("http://proxy{}", uri.path())).map_or_else(|_| "/".to_owned(), |u| u.path().to_owned())
}

/// Path and query on the machine.
fn target(uri: &Uri) -> String {
    let path = canonical_path(uri);
    match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    }
}

/// The proxy's own credential on the machine's server.
fn upstream_bearer(m: &MachineRuntime) -> Option<HeaderValue> {
    HeaderValue::from_str(&format!("Bearer {}", m.upstream_token())).ok()
}

/// How a request goes on to the T3 server on the machine.
struct Relay {
    /// Path and query there.
    target: String,
    /// The credential it is sent with, if any: never the caller's own for the proxy.
    authorization: Option<HeaderValue>,
    /// Whether it may wake a sleeping machine. If not, a sleeping machine answers 503.
    wake: bool,
}

/// Everything without a route of its own. Its sockets (dictation, and whatever T3 adds) are
/// opened by a person, so they wake the machine.
async fn fallback(State(m): M, upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>, req: Request) -> Response {
    match upgrade {
        Ok(upgrade) => media::socket(m, upgrade, &req.into_parts().0, true).await,
        Err(_) => forward(State(m), req).await,
    }
}

/// Plain requests without a route of their own need the live machine: wake it if needed, swap in
/// the upstream token. URL-token requests without a bearer may come from any web page: they reach a
/// running machine but never wake it or keep it awake. The assets a recorded answer points to
/// are kept as they pass, and answered from what was kept while the machine does not run.
async fn forward(State(m): M, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let path = canonical_path(&parts.uri);
    let url_token = URL_TOKEN_ROUTES.iter().any(|r| path.starts_with(r));
    let bearer = parts.headers.contains_key(header::AUTHORIZATION);
    let authorized = client_authorized(&m, &parts.headers);
    if (bearer || !url_token) && !authorized {
        return unauthorized();
    }
    if authorized && parts.method == Method::POST {
        m.user_action();
    }
    let asset = (parts.method == Method::GET && path.starts_with(assets::ROUTE)).then(|| assets::path(m.dir(), &path));
    if m.power() != Power::Running && let Some(kept) = asset.as_deref().and_then(assets::read) {
        return kept;
    }
    let route = Relay {
        target: target(&parts.uri),
        authorization: if bearer { upstream_bearer(&m) } else { None },
        wake: authorized,
    };
    let answer = relay(&m, parts, body, route).await;
    // A range of it (206) is not the asset.
    let keep = asset.filter(|file| {
        answer.status() == StatusCode::OK && assets::recorded(m.dir(), &m.cache.lock().unwrap()).contains(file)
    });
    match keep {
        Some(file) => assets::keep(file, answer),
        None => answer,
    }
}

/// Sends the request to the machine's server and streams its answer back, unbuffered.
async fn relay(m: &MachineRuntime, parts: Parts, body: Body, route: Relay) -> Response {
    if m.power() != Power::Running {
        if let Err(res) = wake(m, route.wake).await {
            return res;
        }
    }
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let send = || {
        let url = format!("{}{}", m.upstream_url(), route.target);
        let mut rb = m.shared.http.request(parts.method.clone(), url).body(body.clone());
        for (k, v) in &parts.headers {
            // The credential is the route's, and the body's length is what is sent here. A DPoP
            // proof is bound to this proxy's URL, so the machine could only refuse it.
            let replaced = k == header::AUTHORIZATION || k == header::CONTENT_LENGTH || k == "dpop";
            if !replaced && !HOP_BY_HOP.contains(&k.as_str()) {
                rb = rb.header(k, v);
            }
        }
        if let Some(authorization) = &route.authorization {
            rb = rb.header(header::AUTHORIZATION, authorization);
        }
        rb.send()
    };
    let first = send().await;
    // Maybe never reached the machine: Boat answers for a sandbox that does not run itself (a
    // redirect to its fallback page, a gateway error). If it fell asleep since the last poll,
    // wake it and send once more.
    let unreached = match &first {
        Ok(r) => {
            let s = r.status();
            (s.is_redirection() && s != StatusCode::NOT_MODIFIED)
                || matches!(s, StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT)
        }
        Err(e) => e.is_connect(),
    };
    let res = if unreached && !matches!(m.refresh_power().await, Ok(Power::Running)) {
        if let Err(res) = wake(m, route.wake).await {
            return res;
        }
        send().await
    } else {
        first
    };
    let res = match res {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    };
    let mut out = Response::builder().status(res.status());
    for (k, v) in res.headers() {
        if !HOP_BY_HOP.contains(&k.as_str()) {
            out = out.header(k, v);
        }
    }
    out.body(Body::from_stream(res.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

/// Wakes the machine for a request that may, and answers 503 for one that may not.
async fn wake(m: &MachineRuntime, allowed: bool) -> Result<(), Response> {
    if !allowed {
        return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    m.ensure_awake()
        .await
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response())
}

#[cfg(test)]
mod tests {
    use super::{canonical_path, has_dot_segments, is_linking, tailnet_client, target, tailnet_address, Listening};
    use axum::http::Uri;
    use std::net::Ipv4Addr;

    #[test]
    fn checks_see_the_path_that_goes_upstream() {
        let path = |s: &str| canonical_path(&s.parse::<Uri>().unwrap());
        assert_eq!(path("/api/assets/../../mcp"), "/mcp");
        assert_eq!(path("/api/assets/%2e%2e/oauth/mcp/register"), "/api/oauth/mcp/register");
        assert_eq!(path("/api/assets/tok/img.png"), "/api/assets/tok/img.png");
        assert_eq!(target(&"/a/./b/../c?x=1&y=%2F".parse::<Uri>().unwrap()), "/a/c?x=1&y=%2F");
        for linking in [
            "/mcp", "/mcp/x", "/oauth/mcp/register", "/oauth/mcp/token", "/MCP", "//oauth//MCP/register", "/mcp/",
            "/%6dcp", "/oauth/%4D%43%50/register", "/mcp;x", "/oauth/mcp;/register", "/%ff%fe",
        ] {
            assert!(is_linking(linking), "{linking}");
        }
        for other in ["/mcpx", "/oauth/token", "/api/mcp"] {
            assert!(!is_linking(other), "{other}");
        }
        for dotted in ["/api/device-hub/../mcp", "/a/./b", "/a/%2E%2e/b", "/a/.%2e", "/a\\..\\b"] {
            assert!(has_dot_segments(dotted), "{dotted}");
        }
        for plain in ["/api/assets/tok/img.v2.png", "/a/...", "/.well-known/t3/environment", "/"] {
            assert!(!has_dot_segments(plain), "{plain}");
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_listener_stays_on_its_interface_and_leaves_no_entry() {
        let ip = Ipv4Addr::LOCALHOST;
        // SAFETY: a NUL-terminated name.
        let interface = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
        let tunnel = crate::tailnet::Tunnel { ip, interface };
        let listener = super::tailnet_listener(tunnel, 0).unwrap();
        let port = listener.local_addr().unwrap().port();
        // Rebinding while the first still listens is refused by the OS anyway; once it is gone,
        // the address is reused at once.
        drop(listener);
        let again = super::tailnet_listener(tunnel, port).unwrap();
        assert_eq!(again.local_addr().unwrap().port(), port);
        {
            let _listening = Listening::new(port, ip);
            assert_eq!(tailnet_address(port), Some(ip));
        }
        assert_eq!(tailnet_address(port), None);
    }

    #[test]
    fn the_tailnet_listener_serves_tailnet_peers_that_name_it() {
        let own = Ipv4Addr::new(100, 121, 195, 78);
        let phone = "100.123.19.65".parse().unwrap();
        assert!(tailnet_client(own, phone, "100.121.195.78:47734"));
        assert!(tailnet_client(own, phone, "100.121.195.78"));
        // Someone on another network that shares 100.64.0.0/10 is no tailnet peer to Tailscale,
        // but cannot be told apart by address: the listener is bound to Tailscale's own address.
        assert!(!tailnet_client(own, "192.168.0.20".parse().unwrap(), "100.121.195.78:47734"));
        assert!(!tailnet_client(own, "127.0.0.1".parse().unwrap(), "100.121.195.78:47734"));
        // A web page DNS-rebound to the address names a host of its own.
        for host in ["evil.example:47734", "100.121.195.78.evil.example", "localhost:47734", "100.121.195.79:47734", ""] {
            assert!(!tailnet_client(own, phone, host), "{host}");
        }
    }
}
