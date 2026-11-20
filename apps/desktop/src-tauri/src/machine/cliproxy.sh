#!/usr/bin/env bash
# Runs on a Boat sandbox, as `user`. Idempotent; provision.sh runs it on every upgrade too.
#   cliproxy.sh on|off
# On: installs the pinned CLIProxyAPI, runs it as a systemd user service on 127.0.0.1:8317 and
# points Claude Code (~/.claude/settings.json env) and Codex (~/.codex/config.toml) at it, so the
# machine's agents keep working with this computer off. The key they use is made here and never
# leaves the machine. Accounts are signed in on the machine itself (t3boat runs the proxy's own
# login), never copied from elsewhere: Claude's and Codex's OAuth refresh tokens are single-use,
# so two holders of one would take turns invalidating each other.
# Off: stops the service and takes exactly those settings back out. The binary and the signed-in
# accounts stay, so turning it on again needs no new sign-in.
set -euo pipefail

mode="$1"
version=8.0.79
port=8317
base_url="http://127.0.0.1:$port"
dir="$HOME/.t3boat/cliproxy"
bin="$dir/bin/cli-proxy-api"
units="$HOME/.config/systemd/user"
unit=t3boat-cliproxy.service
claude_settings="$HOME/.claude/settings.json"
codex_config="$HOME/.codex/config.toml"

# Points the agents at the proxy, or takes back what an earlier "on" put there and nothing else.
#   agents <on|off>, with KEY in the environment for "on"
agents() {
  KEY="${KEY:-}" node -e '
    const fs = require("fs"), path = require("path");
    const [on, url, claudeFile, codexFile] = [process.argv[1] === "on", ...process.argv.slice(2)];
    const key = process.env.KEY;
    const write = (f, text) => {
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f + ".t3boat-tmp", text, { mode: 0o600 });
      fs.renameSync(f + ".t3boat-tmp", f);
    };
    const read = (f) => {
      try {
        return fs.readFileSync(f, "utf8");
      } catch (e) {
        if (e.code === "ENOENT") return null;
        throw e;
      }
    };

    // Claude Code: its settings env. T3 reads the same env and then counts Claude as signed in.
    const claudeText = read(claudeFile);
    const s = claudeText === null ? {} : JSON.parse(claudeText);
    const before = JSON.stringify(s);
    s.env = s.env ?? {};
    if (on) {
      s.env.ANTHROPIC_BASE_URL = url;
      s.env.ANTHROPIC_AUTH_TOKEN = key;
    } else if (s.env.ANTHROPIC_BASE_URL === url) {
      delete s.env.ANTHROPIC_BASE_URL;
      delete s.env.ANTHROPIC_AUTH_TOKEN;
    }
    if (Object.keys(s.env).length === 0) delete s.env;
    if (JSON.stringify(s) !== before) write(claudeFile, JSON.stringify(s, null, 2) + "\n");

    // Codex: a model provider of its own, chosen at the top of config.toml. A model_provider the
    // user had there is set aside, and put back by "off".
    const MARK = " # t3boat: CLIProxyAPI", ASIDE = "#t3boat-aside# ";
    const BEGIN = "# >>> t3boat cliproxy", END = "# <<< t3boat cliproxy";
    const codexText = read(codexFile);
    // Left alone, byte for byte, unless "on" or an earlier "on" edited it.
    if (!on && !(codexText ?? "").includes("t3boat")) process.exit(0);
    const kept = [];
    let inBlock = false;
    for (const line of (codexText ?? "").split("\n")) {
      if (line.trim() === BEGIN) inBlock = true;
      else if (inBlock) inBlock = line.trim() !== END;
      else if (line.endsWith(MARK)) continue;
      else kept.push(line.startsWith(ASIDE) ? line.slice(ASIDE.length) : line);
    }
    while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
    let lines = kept;
    if (on) {
      const firstTable = lines.findIndex((l) => /^\s*\[/.test(l));
      const top = firstTable === -1 ? lines.length : firstTable;
      lines = lines.map((l, i) => (i < top && /^\s*model_provider\s*=/.test(l) ? ASIDE + l : l));
      lines.unshift(`model_provider = "t3boat_cliproxy"${MARK}`);
      lines.push(
        "",
        BEGIN,
        "[model_providers.t3boat_cliproxy]",
        `name = "CLIProxyAPI (t3boat)"`,
        `base_url = ${JSON.stringify(url + "/v1")}`,
        `wire_api = "responses"`,
        "requires_openai_auth = false",
        "supports_websockets = true",
        `experimental_bearer_token = ${JSON.stringify(key)}`,
        END,
      );
    }
    const codexNext = lines.length ? lines.join("\n") + "\n" : "";
    if (codexNext !== (codexText ?? "")) {
      if (codexText !== null || codexNext !== "") write(codexFile, codexNext);
    }
  ' "$1" "$base_url" "$claude_settings" "$codex_config"
}

if [ "$mode" = off ]; then
  if [ -f "$units/$unit" ]; then
    systemctl --user disable --now "$unit" >/dev/null 2>&1 || true
    rm -f "$units/$unit"
    systemctl --user daemon-reload
  fi
  agents off
  echo '{"cliproxy":"off"}'
  exit 0
fi
[ "$mode" = on ] || { echo "usage: cliproxy.sh on|off" >&2; exit 2; }

case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 sha=7cbb9709ed939ff3684e10592a45cc538ee82d5da759daa7e18c7e1dc3b32acd ;;
  aarch64 | arm64) arch=aarch64 sha=9cfd3f300662fbf5a0bb15239e5c4d22a478535a68b39e7f236d46c03fba42c5 ;;
  *) echo "CLIProxyAPI has no build for $(uname -m)" >&2; exit 1 ;;
esac
mkdir -p "$dir/bin" "$dir/auths" "$units"
chmod 700 "$dir" "$dir/auths"

# Pinned, and checked against the release's checksum.
restart=0
if [ "$(cat "$dir/bin/version" 2>/dev/null || true)" != "$version" ] || [ ! -x "$bin" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  tarball="CLIProxyAPI_${version}_linux_${arch}.tar.gz"
  curl -fsSL --retry 3 -o "$tmp/$tarball" \
    "https://github.com/router-for-me/CLIProxyAPI/releases/download/v$version/$tarball"
  echo "$sha  $tmp/$tarball" | sha256sum -c --quiet -
  tar -xzf "$tmp/$tarball" -C "$tmp" cli-proxy-api
  install -m 755 "$tmp/cli-proxy-api" "$bin.new"
  mv -f "$bin.new" "$bin"
  echo "$version" >"$dir/bin/version"
  restart=1
fi

# The one key the agents present; made once, kept across upgrades.
key_file="$dir/api-key"
if [ ! -s "$key_file" ]; then
  (umask 077 && node -e 'process.stdout.write("sk-t3boat-" + require("crypto").randomBytes(24).toString("hex"))' >"$key_file")
fi
key="$(cat "$key_file")"

# The proxy watches this file and its auth dir: a change or a new sign-in needs no restart.
config="$dir/config.yaml"
next="$(cat <<YAML
# Written by t3boat (cliproxy.sh); rewritten on upgrades.
config-version: 8
server:
  host: "127.0.0.1"
  port: $port
management:
  allow-remote: false
  disable-control-panel: true
access:
  api-keys:
    - "$key"
oauth:
  auth-dir: "$dir/auths"
routing:
  strategy: "round-robin"
  session-affinity: true
observability:
  logs:
    logging-to-file: false
  usage:
    usage-statistics-enabled: false
YAML
)"
if [ "$(cat "$config" 2>/dev/null || true)" != "$next" ]; then
  (umask 077 && printf '%s\n' "$next" >"$config.tmp")
  mv -f "$config.tmp" "$config"
fi

unit_text='[Unit]
Description=t3boat: CLIProxyAPI, the model proxy for this machine'"'"'s agents
After=network-online.target

[Service]
ExecStart=%h/.t3boat/cliproxy/bin/cli-proxy-api -config %h/.t3boat/cliproxy/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=default.target'
if [ "$(cat "$units/$unit" 2>/dev/null || true)" != "$unit_text" ]; then
  printf '%s\n' "$unit_text" >"$units/$unit"
  restart=1
fi
systemctl --user daemon-reload
systemctl --user enable "$unit" >/dev/null 2>&1
systemctl --user is-active --quiet "$unit" || restart=1
[ "$restart" = 0 ] || systemctl --user restart "$unit"

# Up once it refuses a request without the key.
ready=0
for _ in $(seq 1 60); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "$base_url/v1/models" || true)" = 401 ]; then ready=1; break; fi
  sleep 0.5
done
if [ "$ready" != 1 ]; then
  echo "CLIProxyAPI did not start" >&2
  journalctl --user -u "$unit" -n 30 --no-pager >&2 || true
  exit 1
fi

KEY="$key" agents on
echo '{"cliproxy":"on"}'
