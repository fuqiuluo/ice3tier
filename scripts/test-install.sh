#!/bin/sh
# Runs deploy/install.sh for real on a throwaway machine (CI): installs the node from DIR as a system service (systemd
# on Linux, launchd on macOS), joins it to a controller started here on loopback with `sudo i3t join`, checks that it
# comes online, that `sudo i3t run` points at the service and that asking for help does not restart it, installs over
# it, then uninstalls and checks nothing is left. Needs passwordless sudo and changes the machine: do not run it on
# yours.
#
# Usage: scripts/test-install.sh <dir with i3t, i3t-controller and i3tctl>
set -eu

dir=$(cd "${1:?usage: test-install.sh <dir with i3t, i3t-controller and i3tctl>}" && pwd)
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
os=$(uname -s)
ctl_pid=""
https_pid=""
label="com.github.fuqiuluo.ice3tier"

finish() {
    status=$?
    if [ "$status" -ne 0 ]; then
        printf '\n--- failed; the node says:\n'
        if [ "$os" = "Linux" ]; then
            sudo journalctl -u i3t --no-pager -n 80 || true
        else
            sudo tail -n 80 /var/log/i3t.log || true
        fi
        printf -- '--- the controller says:\n'
        if [ -n "$ctl_pid" ] || [ "$os" != "Linux" ]; then
            tail -n 40 "$work/ctl.err" || true
        else
            sudo journalctl -u i3t-controller --no-pager -n 40 || true
        fi
    fi
    if [ -n "$https_pid" ]; then
        kill "$https_pid" 2>/dev/null || true
    fi
    if [ -n "$ctl_pid" ]; then
        kill "$ctl_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
    exit "$status"
}
trap finish EXIT

step() {
    printf '\n=== %s\n' "$*"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

ctl() {
    "$dir/i3tctl" --json "$@"
}

all_online() {
    ctl node list | python3 -I -c 'import json, sys; nodes = json.load(sys.stdin); sys.exit(0 if nodes and all(n["online"] for n in nodes) else 1)'
}

service_running() {
    if [ "$os" = "Linux" ]; then
        systemctl is-active -q i3t
    else
        sudo launchctl print "system/$label" 2>/dev/null | grep -q 'state = running'
    fi
}

wait_online() {
    i=0
    until service_running && all_online; do
        i=$((i + 1))
        [ "$i" -lt 60 ] || fail "the node did not come online within 60 s"
        sleep 1
    done
}

# Wait for the node to report a working virtual adapter (and firewall / resolved on Linux) to the controller.
wait_vnet() {
    require_resolved=0
    if [ "$os" = "Linux" ] \
        && systemctl is-active -q systemd-resolved 2>/dev/null \
        && systemctl is-active -q polkit 2>/dev/null \
        && [ -f /etc/polkit-1/rules.d/50-i3t-resolved.rules ]; then
        require_resolved=1
    fi
    i=0
    while [ "$i" -lt 45 ]; do
        node_id=$(ctl node list | python3 -I -c 'import json, sys; nodes = json.load(sys.stdin); print(nodes[0]["id"] if nodes else "")' 2>/dev/null || true)
        if [ -n "$node_id" ] && ctl node show "$node_id" >"$work/node.json" 2>/dev/null; then
            if python3 -I - "$work/node.json" "$os" "$require_resolved" <<'PY'
import json, sys
path, os_name, req_resolved = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
try:
    with open(path, encoding="utf-8") as fh:
        detail = json.load(fh)
except Exception:
    sys.exit(1)
vnet = detail.get("vnet") or {}
if vnet.get("state") != "installed":
    sys.exit(1)
fw = vnet.get("firewall") or {}
accept = (fw.get("accept") or {}).get("state")
guard = (fw.get("guard") or {}).get("state")
names = (vnet.get("names") or {}).get("state")
if os_name == "Linux":
    if accept not in ("on", "not_needed") or guard != "on":
        sys.exit(1)
    if req_resolved and names != "resolved":
        sys.exit(1)
print(f"vnet ok: device={vnet.get('device')} mtu={vnet.get('mtu')} accept={accept} guard={guard} names={names}")
PY
            then
                return 0
            fi
        fi
        i=$((i + 1))
        sleep 1
    done
    fail "virtual adapter did not report ready within 45 s; last node detail: $(cat "$work/node.json" 2>/dev/null || true)"
}

# `sudo ARGS` must point at the service instead of starting a node.
points_at_service() {
    if sudo "$@" 2>"$work/run.err"; then fail "sudo $* started a node"; fi
    grep -q "system service" "$work/run.err" || fail "sudo $*: unexpected answer: $(cat "$work/run.err")"
}

step "controller on loopback"
"$dir/i3t-controller" --data-dir "$work/ctl" --public-addr 127.0.0.1:20331 --listen 127.0.0.1:20331 >"$work/ctl.out" 2>"$work/ctl.err" &
ctl_pid=$!
i=0
until grep -q '^    [^ ]' "$work/ctl.out" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || fail "the controller printed no admin token"
    sleep 1
done
I3T_ADMIN_TOKEN=$(sed -n 's/^    \([^ ]*\)$/\1/p' "$work/ctl.out" | head -n 1)
I3T_ADMIN_URL="http://127.0.0.1:20332"
export I3T_ADMIN_TOKEN I3T_ADMIN_URL
ctl network create ci >/dev/null
token=$(ctl token create --expires 30m | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["token"])')

step "install without a token"
sudo sh "$repo/deploy/install.sh" --from "$dir"
if [ "$os" = "Linux" ]; then
    [ "$(systemctl is-enabled i3t)" = "enabled" ] || fail "i3t.service is not enabled"
    if systemctl is-active -q i3t; then fail "i3t.service runs before joining"; fi
else
    [ -f "/Library/LaunchDaemons/$label.plist" ] || fail "no launchd plist"
fi

step "sudo i3t run points at the service"
points_at_service i3t run
points_at_service i3t --state-dir /var/lib/i3t/ run
points_at_service env I3T_STATE_DIR="$work/elsewhere" i3t --state-dir /var/lib/i3t run

step "sudo i3t join joins and starts the service"
printf '%s\n' "$token" | sudo i3t join --can-relay
wait_online
wait_vnet
sudo i3t status
if [ "$os" = "Linux" ]; then
    pid=$(systemctl show -p MainPID --value i3t)
    [ "$(ps -o user= -p "$pid" | tr -d ' ')" = "i3t" ] || fail "the node does not run as user i3t"
fi

step "asking for help leaves the service alone"
before=$(pgrep -x i3t) || fail "no node process"
sudo i3t join --help >/dev/null
sudo i3t --help join >/dev/null
sudo i3t run --help >/dev/null
[ "$(pgrep -x i3t)" = "$before" ] || fail "asking for help restarted the service"

step "install over the joined node"
sudo sh "$repo/deploy/install.sh" --from "$dir"
sleep 3
wait_online
wait_vnet
if [ "$os" = "Darwin" ]; then
    step "install over the joined node with a changed launchd plist"
    printf '<!-- old -->\n' | sudo tee -a "/Library/LaunchDaemons/$label.plist" >/dev/null
    sudo sh "$repo/deploy/install.sh" --from "$dir"
    if grep -q '<!-- old -->' "/Library/LaunchDaemons/$label.plist"; then fail "launchd plist was not replaced"; fi
    sleep 3
    wait_online
    wait_vnet
fi

step "uninstall without --purge keeps state, and reinstall brings the node back"
if [ "$os" = "Linux" ]; then
    step "verify Linux privilege boundary: i3t-writable binary is NEVER executed as root"
    [ -f /usr/local/libexec/i3t/i3t ] || fail "root-owned /usr/local/libexec/i3t/i3t is missing"
    if sudo -u i3t test -w /usr/local/libexec/i3t/i3t; then
        fail "user i3t must not be able to write /usr/local/libexec/i3t/i3t"
    fi
    sudo systemctl stop i3t
    canary_log="$work/canary.uid"
    chmod 0755 "$work"
    : > "$canary_log"
    chmod 0666 "$canary_log"
    canary_src="$work/canary-i3t.sh"
    cat <<EOF > "$canary_src"
#!/bin/sh
uid=\$(id -u)
printf '%s %s\n' "\$uid" "\$*" >> "$canary_log"
if [ "\$uid" -eq 0 ]; then
    exit 99
fi
exit 0
EOF
    chmod 0755 "$canary_src"
    sudo -u i3t cp "$canary_src" /var/lib/i3t/bin/i3t
    sudo -u i3t chmod 0755 /var/lib/i3t/bin/i3t

    sudo i3t --version >/dev/null 2>&1 || true
    sudo i3t --help >/dev/null 2>&1 || true
    sudo i3t >/dev/null 2>&1 || true
    sudo i3t hosts >/dev/null 2>&1 || true
    sudo i3t tune >/dev/null 2>&1 || true
    sudo i3t network status >/dev/null 2>&1 || true
    sudo i3t --state-dir "$work/custom-state" --version >/dev/null 2>&1 || true
    sudo sh "$repo/deploy/install.sh" --uninstall

    if grep -q '^0 ' "$canary_log"; then
        fail "i3t-writable binary was executed as root (uid=0): $(cat "$canary_log")"
    fi
    if ! grep -q ' --version$' "$canary_log"; then
        fail "expected sudo i3t --version to invoke the node binary as non-root user i3t"
    fi
else
    sudo sh "$repo/deploy/install.sh" --uninstall
fi
for path in /usr/local/bin/i3t /usr/local/libexec/i3t /etc/systemd/system/i3t.service "/Library/LaunchDaemons/$label.plist"; do
    [ ! -e "$path" ] || fail "$path is still there after --uninstall"
done
if pgrep -x i3t >/dev/null; then fail "an i3t process is still running after --uninstall"; fi
sudo test -f /var/lib/i3t/controller.json || fail "state was deleted without --purge"

if [ -x "$dir/i3t-release" ]; then
    step "reinstall from a local signed HTTPS release and verify tamper/HTTP rejections"
    case "$os" in
        Linux) rel_os="linux" ;;
        Darwin) rel_os="macos" ;;
        *) fail "unsupported os for release test: $os" ;;
    esac
    case "$(uname -m)" in
        x86_64 | amd64) rel_arch="x86_64" ;;
        aarch64 | arm64) rel_arch="aarch64" ;;
        *) fail "unsupported arch for release test: $(uname -m)" ;;
    esac
    rel_platform="${rel_os}-${rel_arch}"
    rel_root="$work/releases"
    rel_ver="0.9.9"
    rel_ver_dir="$rel_root/download/v${rel_ver}"
    rel_latest_dir="$rel_root/latest/download"
    mkdir -p "$rel_ver_dir" "$rel_latest_dir"
    cp "$dir/i3t" "$rel_ver_dir/i3t-${rel_platform}"
    cp "$dir/i3t-controller" "$rel_ver_dir/i3t-controller-${rel_platform}"
    cp "$dir/i3tctl" "$rel_ver_dir/i3tctl-${rel_platform}"
    rel_key="$work/release.key"
    rel_pub=$("$dir/i3t-release" keygen --out "$rel_key")
    "$dir/i3t-release" manifest --version "$rel_ver" --dir "$rel_ver_dir" --key "$rel_key" --min-controller 0.1.0 >/dev/null
    cp "$rel_ver_dir/manifest.json" "$rel_latest_dir/manifest.json"
    cp "$rel_ver_dir/manifest.json.sig" "$rel_latest_dir/manifest.json.sig"

    cat <<'EOF' > "$work/openssl.cnf"
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = 127.0.0.1
[v3_req]
subjectAltName = IP:127.0.0.1
basicConstraints = CA:TRUE
EOF
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/server.key" -out "$work/server.crt" \
        -days 1 -config "$work/openssl.cnf" >/dev/null 2>&1
    https_port=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
    cat <<'PY' > "$work/https_server.py"
import http.server, ssl, sys
port, directory, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=directory, **kw)
    def do_GET(self):
        if self.path.startswith("/redirect-http/"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/manifest.json")
            self.end_headers()
            return
        super().do_GET()
    def log_message(self, *a):
        pass
httpd = http.server.HTTPServer(("127.0.0.1", port), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert, keyfile=key)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
    python3 -I "$work/https_server.py" "$https_port" "$rel_root" "$work/server.crt" "$work/server.key" >"$work/https.out" 2>"$work/https.err" &
    https_pid=$!
    i=0
    until python3 -I -c "import socket; s=socket.create_connection(('127.0.0.1', ${https_port}), 0.5); s.close()" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -lt 15 ] || fail "local HTTPS release server did not start"
        sleep 1
    done

    if sudo sh "$repo/deploy/install.sh" --release-base "http://127.0.0.1:${https_port}" --release-key "$rel_pub" >/dev/null 2>&1; then
        fail "install.sh accepted plain http:// release URL"
    fi
    if sudo env CURL_CA_BUNDLE="$work/server.crt" sh "$repo/deploy/install.sh" --release-base "https://127.0.0.1:${https_port}/redirect-http" --release-key "$rel_pub" >/dev/null 2>&1; then
        fail "install.sh followed HTTPS -> HTTP redirect"
    fi
    if sudo env CURL_CA_BUNDLE="$work/server.crt" sh "$repo/deploy/install.sh" --release-base "https://127.0.0.1:${https_port}" >/dev/null 2>&1; then
        fail "install.sh accepted manifest signed with untrusted key"
    fi

    # Tampered binary must fail SHA-256 check
    cp "$rel_ver_dir/i3t-${rel_platform}" "$work/i3t.good"
    printf 'tampered' >> "$rel_ver_dir/i3t-${rel_platform}"
    if sudo env CURL_CA_BUNDLE="$work/server.crt" sh "$repo/deploy/install.sh" --release-base "https://127.0.0.1:${https_port}" --release-key "$rel_pub" >/dev/null 2>&1; then
        fail "install.sh accepted tampered binary"
    fi
    mv "$work/i3t.good" "$rel_ver_dir/i3t-${rel_platform}"

    # Valid signed HTTPS release succeeds and brings the node back online
    sudo env CURL_CA_BUNDLE="$work/server.crt" sh "$repo/deploy/install.sh" --release-base "https://127.0.0.1:${https_port}" --release-key "$rel_pub"
else
    sudo sh "$repo/deploy/install.sh" --from "$dir"
fi
sleep 3
wait_online
wait_vnet

step "uninstall --purge"
sudo sh "$repo/deploy/install.sh" --uninstall --purge
for path in /usr/local/bin/i3t /var/lib/i3t /etc/systemd/system/i3t.service "/Library/LaunchDaemons/$label.plist"; do
    [ ! -e "$path" ] || fail "$path is still there"
done
if pgrep -x i3t >/dev/null; then fail "an i3t process is still running"; fi
if [ "$os" = "Linux" ] && ip link show i3t0 >/dev/null 2>&1; then
    fail "i3t0 virtual adapter is still present after uninstall"
fi

if [ "$os" = "Linux" ]; then
    step "install controller and print its first-start admin token across TZ"
    kill "$ctl_pid" 2>/dev/null || true
    wait "$ctl_pid" 2>/dev/null || true
    ctl_pid=""
    PATH=/usr/local/bin:/usr/bin:/bin TZ=Asia/Shanghai sh "$repo/deploy/install.sh" --from "$dir" --controller --public-addr 127.0.0.1:20331 >"$work/ctl-install.out"
    cat "$work/ctl-install.out"
    ctl_token=$(sed -n 's/^    \([^ ]*\)$/\1/p' "$work/ctl-install.out" | head -n 1)
    [ -n "$ctl_token" ] || fail "controller install did not print the initial admin token"
    systemctl is-active -q i3t-controller || fail "i3t-controller.service is not active"

    step "upgrade installed controller in place without losing state"
    i=0
    until I3T_ADMIN_TOKEN="$ctl_token" "$dir/i3tctl" --json status >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 30 ] || fail "installed controller admin API did not respond within 30 s"
        sleep 1
    done
    I3T_ADMIN_TOKEN="$ctl_token" "$dir/i3tctl" --json network create upgrade-check >/dev/null
    if [ -n "$https_pid" ]; then
        sudo env CURL_CA_BUNDLE="$work/server.crt" sh "$repo/deploy/install.sh" --controller \
            --release-base "https://127.0.0.1:${https_port}" --release-key "$rel_pub"
    else
        sudo sh "$repo/deploy/install.sh" --from "$dir" --controller
    fi
    systemctl is-active -q i3t-controller || fail "i3t-controller.service is not active after upgrade"
    i=0
    until I3T_ADMIN_TOKEN="$ctl_token" "$dir/i3tctl" --json network list 2>/dev/null \
        | python3 -I -c 'import json, sys; sys.exit(0 if any(n["name"] == "upgrade-check" for n in json.load(sys.stdin)) else 1)'; do
        i=$((i + 1))
        [ "$i" -lt 30 ] || fail "installed controller lost state or failed to restart after upgrade"
        sleep 1
    done

    step "uninstall controller --purge"
    sudo sh "$repo/deploy/install.sh" --uninstall --controller --purge
    for path in /usr/local/bin/i3t-controller /usr/local/bin/i3tctl /var/lib/i3t-controller /etc/i3t /etc/systemd/system/i3t-controller.service; do
        [ ! -e "$path" ] || fail "$path is still there"
    done
fi

step "ok"
