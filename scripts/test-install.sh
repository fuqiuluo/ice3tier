#!/bin/sh
# Runs deploy/install.sh for real on a throwaway machine (CI): installs the node from DIR as a system service (systemd
# on Linux, launchd on macOS), joins it to a controller started here on loopback with `sudo i3t join`, checks that it
# comes online, that `sudo i3t run` points at the service and that asking for help does not restart it, installs over
# it, then uninstalls and checks nothing is left. Needs passwordless sudo and changes the machine: do not run it on
# yours.
#
# The controllers need a PostgreSQL: start the test one first (scripts/test-postgres.sh start) and export what it prints.
#
# Usage: scripts/test-install.sh <dir with i3t, i3t-controller and i3tctl>
set -eu

dir=$(cd "${1:?usage: test-install.sh <dir with i3t, i3t-controller and i3tctl>}" && pwd)
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
os=$(uname -s)
ctl_pid=""
https_pid=""
# A temporary directory mounted noexec for one step: unmounted there, or on the way out when that step fails.
noexec=""
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
    if [ -n "$noexec" ]; then
        sudo umount "$noexec" 2>/dev/null || true
        sudo rmdir "$noexec" 2>/dev/null || true
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

# A new empty database on the test PostgreSQL. Over TCP: the installed controller service is sandboxed away from
# /tmp and /home, where that server keeps its socket.
new_database() {
    I3T_TEST_DATABASE_URL="${I3T_TEST_DATABASE_TCP_URL:?start the test PostgreSQL first: export \$(scripts/test-postgres.sh start)}" \
        sh "$repo/scripts/test-postgres.sh" database "$1"
}

step "controller on loopback"
I3T_DATABASE_URL=$(new_database install_test) "$dir/i3t-controller" --data-dir "$work/ctl" --public-addr 127.0.0.1:20331 \
    --listen 127.0.0.1:20331 >"$work/ctl.out" 2>"$work/ctl.err" &
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
    if sh "$repo/deploy/install.sh" --from "$dir" --controller --public-addr 127.0.0.1:20331 >"$work/ctl-refused.out" 2>&1; then
        fail "controller install without a database went through"
    fi
    grep -q -- '--database-url' "$work/ctl-refused.out" || fail "the refusal does not name --database-url: $(cat "$work/ctl-refused.out")"
    [ ! -e /usr/local/bin/i3t-controller ] || fail "a refused controller install left the program behind"

    ctl_database=$(new_database install_service)
    PATH=/usr/local/bin:/usr/bin:/bin TZ=Asia/Shanghai sh "$repo/deploy/install.sh" --from "$dir" --controller --public-addr 127.0.0.1:20331 \
        --database-url "$ctl_database" >"$work/ctl-install.out"
    cat "$work/ctl-install.out"
    ctl_token=$(sed -n 's/^    \([^ ]*\)$/\1/p' "$work/ctl-install.out" | head -n 1)
    [ -n "$ctl_token" ] || fail "controller install did not print the initial admin token"
    systemctl is-active -q i3t-controller || fail "i3t-controller.service is not active"
    # The connection string holds the database password: only the service reads it.
    [ "$(sudo stat -c '%a %U' /var/lib/i3t-controller/database.url)" = "600 i3t-controller" ] \
        || fail "/var/lib/i3t-controller/database.url is readable by others"
    [ "$(sudo cat /var/lib/i3t-controller/database.url)" = "$ctl_database" ] || fail "the connection string is not in database.url"

    step "a new admin token with only the data directory, as the WebUI and the docs say"
    sudo systemctl stop i3t-controller
    new_token=$(sudo -u i3t-controller /usr/local/bin/i3t-controller --data-dir /var/lib/i3t-controller --reset-admin-token \
        | sed -n 's/^    \([^ ]*\)$/\1/p' | head -n 1)
    [ -n "$new_token" ] && [ "$new_token" != "$ctl_token" ] || fail "no new admin token was printed"
    ctl_token=$new_token
    sudo systemctl start i3t-controller

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

    step "back up and restore with the commands of the deployment guide"
    mkdir "$work/backup"
    # Left over from an older backup and readable by everyone: the new files must not inherit that.
    : > "$work/backup/controller.dump"
    : > "$work/backup/controller.key"
    chmod 644 "$work/backup/controller.dump" "$work/backup/controller.key"
    (
        cd "$work/backup"
        sudo sh -c 'set -e; umask 077; rm -f controller.dump; pg_dump --format custom --file controller.dump "$(cat /var/lib/i3t-controller/database.url)"'
        sudo install -m 600 /var/lib/i3t-controller/controller.key controller.key
    )
    for file in controller.dump controller.key; do
        [ "$(sudo stat -c '%a %U' "$work/backup/$file")" = "600 root" ] || fail "the backup's $file is not root's and private"
    done
    # Into another empty database on this server. The dump is root's, so root reads it.
    restored_database=$(new_database install_restored)
    sudo pg_restore --no-owner --dbname "$restored_database" "$work/backup/controller.dump" \
        || fail "the backup could not be restored with the documented command"
    sudo systemctl stop i3t-controller
    sudo install -o i3t-controller -g i3t-controller -m 600 "$work/backup/controller.key" /var/lib/i3t-controller/controller.key
    sudo sh "$repo/deploy/install.sh" --from "$dir" --controller --public-addr 127.0.0.1:20331 --database-url "$restored_database" >/dev/null
    ctl_database=$restored_database
    i=0
    until I3T_ADMIN_TOKEN="$ctl_token" "$dir/i3tctl" --json network list 2>/dev/null \
        | python3 -I -c 'import json, sys; sys.exit(0 if any(n["name"] == "upgrade-check" for n in json.load(sys.stdin)) else 1)'; do
        i=$((i + 1))
        [ "$i" -lt 30 ] || fail "the restored controller does not answer with the old admin token, or lost its networks"
        sleep 1
    done

    step "/etc/i3t/controller.env stays root's and private when the address is set again"
    # What an admin puts there by hand may be a secret; an older install left the file readable by everyone.
    [ "$(sudo stat -c '%a %U' /etc/i3t/controller.env)" = "600 root" ] || fail "controller.env is not root's and private after install"
    sudo chmod 644 /etc/i3t/controller.env
    sudo sh "$repo/deploy/install.sh" --from "$dir" --controller --public-addr 127.0.0.1:20331 >/dev/null
    [ "$(sudo stat -c '%a %U' /etc/i3t/controller.env)" = "600 root" ] || fail "setting the address again left controller.env readable by others"
    sudo chmod 644 /etc/i3t/controller.env
    sudo sh "$repo/deploy/install.sh" --from "$dir" --controller >/dev/null
    [ "$(sudo stat -c '%a %U' /etc/i3t/controller.env)" = "600 root" ] || fail "a plain upgrade left controller.env readable by others"

    step "one place says which database: a second one is refused"
    echo "I3T_DATABASE_URL=$ctl_database" | sudo tee -a /etc/i3t/controller.env >/dev/null
    # The runs whose output is kept go without sudo, like the first install above: the script asks for it itself, and
    # the output is this user's file.
    if sh "$repo/deploy/install.sh" --from "$dir" --controller --database-url "$(new_database install_other)" >"$work/ctl-two.out" 2>&1; then
        fail "a second place for the database was accepted"
    fi
    grep -q '/etc/i3t/controller.env' "$work/ctl-two.out" || fail "the refusal does not name controller.env: $(cat "$work/ctl-two.out")"
    [ "$(sudo cat /var/lib/i3t-controller/database.url)" = "$ctl_database" ] || fail "database.url was rewritten by a refused run"
    sudo sed -i '/^I3T_DATABASE_URL=/d' /etc/i3t/controller.env

    step "a controller that was set up here is not replaced by one that cannot start"
    # Stopped by hand, and its database setting gone or empty: the script still knows a controller lives here.
    # Nothing but a line end in the file, and an empty value in controller.env: the controller reads both as "no
    # database", so the script must too.
    sudo systemctl stop i3t-controller
    sudo sh -c 'echo > /var/lib/i3t-controller/database.url'
    echo 'I3T_DATABASE_URL=""' | sudo tee -a /etc/i3t/controller.env >/dev/null
    if sh "$repo/deploy/install.sh" --from "$dir" --controller >"$work/ctl-stopped.out" 2>&1; then
        fail "a stopped controller without a database was upgraded anyway"
    fi
    grep -q -- '--database-url' "$work/ctl-stopped.out" || fail "the refusal does not name --database-url: $(cat "$work/ctl-stopped.out")"

    step "uninstall controller --purge"
    sudo sh "$repo/deploy/install.sh" --uninstall --controller --purge
    for path in /usr/local/bin/i3t-controller /usr/local/bin/i3tctl /var/lib/i3t-controller /etc/i3t /etc/systemd/system/i3t-controller.service; do
        [ ! -e "$path" ] || fail "$path is still there"
    done

    step "a first start that cannot reach its database, then one that can: the token is shown on the second"
    # Nothing listens on port 1. The controller connects before it creates its key, so the retry is a first start.
    # systemd starts the failing service again and again: here ten times a second instead of every two seconds, so
    # that one of those starts is sure to fall into the middle of the retry if the script lets it. That start would
    # get the new database and print the token, and the start the script watches would have none to show.
    sudo mkdir -p /etc/systemd/system/i3t-controller.service.d
    printf '[Unit]\nStartLimitIntervalSec=0\n[Service]\nRestartSec=100ms\n' \
        | sudo tee /etc/systemd/system/i3t-controller.service.d/restart-fast.conf >/dev/null
    sh "$repo/deploy/install.sh" --from "$dir" --controller --public-addr 127.0.0.1:20331 \
        --database-url postgres://i3t@127.0.0.1:1/i3t >"$work/ctl-nodb.out" 2>&1 || true
    [ -z "$(sed -n 's/^    \([A-Za-z0-9_-]\{43\}\)$/\1/p' "$work/ctl-nodb.out")" ] || fail "a token without a database?"
    sudo test ! -e /var/lib/i3t-controller/controller.key || fail "a key was created although the database could not be reached"
    retry_database=$(new_database install_retry)
    sh "$repo/deploy/install.sh" --from "$dir" --controller --database-url "$retry_database" >"$work/ctl-retry.out" 2>&1 \
        || fail "the retry failed: $(cat "$work/ctl-retry.out")"
    [ -n "$(sed -n 's/^    \([A-Za-z0-9_-]\{43\}\)$/\1/p' "$work/ctl-retry.out")" ] \
        || fail "the retry did not show the admin token: $(cat "$work/ctl-retry.out")"
    sudo rm -r /etc/systemd/system/i3t-controller.service.d
    sudo sh "$repo/deploy/install.sh" --uninstall --controller --purge >/dev/null

    step "a controller whose log level hides the line that says it is up is not reported as down"
    # Installed without starting, then the log level set by hand, then started for the first time.
    quiet_database=$(new_database install_quiet)
    sudo sh "$repo/deploy/install.sh" --from "$dir" --controller --database-url "$quiet_database" >/dev/null
    echo 'I3T_LOG=warn' | sudo tee -a /etc/i3t/controller.env >/dev/null
    sh "$repo/deploy/install.sh" --from "$dir" --controller --public-addr 127.0.0.1:20331 >"$work/ctl-quiet.out" 2>&1 \
        || fail "the install failed: $(cat "$work/ctl-quiet.out")"
    systemctl is-active -q i3t-controller || fail "i3t-controller.service is not active"
    if sudo journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value i3t-controller)" --no-pager -o cat \
        | grep -q 'controller 已启动'; then
        fail "the log was not quiet: this step proves nothing"
    fi
    if grep -q 'did not come up' "$work/ctl-quiet.out"; then
        fail "a running controller was reported as down: $(cat "$work/ctl-quiet.out")"
    fi
    [ -n "$(sed -n 's/^    \([A-Za-z0-9_-]\{43\}\)$/\1/p' "$work/ctl-quiet.out")" ] \
        || fail "the first start with a quiet log did not show the admin token: $(cat "$work/ctl-quiet.out")"
    sudo sh "$repo/deploy/install.sh" --uninstall --controller --purge >/dev/null

    step "this script installs release 0.1.34, which takes no database, even from a noexec temporary directory"
    # The script may be newer than the programs it is given. 0.1.34 keeps its data in a file: it is installed as it
    # always was. With the temporary directory mounted noexec the copy there cannot be asked whether it takes a
    # database, so the one it was copied from is.
    case "$(uname -m)" in
        x86_64) old_arch=x86_64 old_sums="7e867bdec23e05f86d200209ed43927c9758eb74d50b8371ac9ea0ebf181f9b5 7730ef4421faa46051d3fc5782311cb315678583a5edd348189e1244682243a6" ;;
        aarch64 | arm64) old_arch=aarch64 old_sums="0db2ae42e4367d928d0124cf8e5e7bdc109ee5e9b4154148e6690e4e5ef8e24b e7a60a0708120392ab1ed3baaddeea806c01f41f9e309fce09ead1c413a42d67" ;;
        *) fail "no 0.1.34 release for $(uname -m)" ;;
    esac
    mkdir "$work/old"
    for program in i3t-controller i3tctl; do
        curl -fsSL --retry 3 -o "$work/old/$program" \
            "https://github.com/fuqiuluo/ice3tier/releases/download/v0.1.34/${program}-linux-${old_arch}" \
            || fail "could not download ${program} 0.1.34"
        chmod 755 "$work/old/$program"
    done
    [ "$(sha256sum "$work/old/i3t-controller" "$work/old/i3tctl" | cut -d' ' -f1 | tr '\n' ' ')" = "$old_sums " ] \
        || fail "the downloaded 0.1.34 programs are not the released ones"
    noexec=$(sudo mktemp -d)
    sudo mount -t tmpfs -o noexec,mode=1777 tmpfs "$noexec"
    old_database=$(new_database install_old)
    TMPDIR="$noexec" sh "$repo/deploy/install.sh" --from "$work/old" --controller --public-addr 127.0.0.1:20331 \
        --database-url "$old_database" >"$work/ctl-old.out" 2>&1 || fail "installing 0.1.34 failed: $(cat "$work/ctl-old.out")"
    sudo umount "$noexec"
    sudo rmdir "$noexec"
    noexec=""
    [ "$(/usr/local/bin/i3t-controller --version)" = "i3t-controller 0.1.34" ] || fail "not 0.1.34: $(/usr/local/bin/i3t-controller --version)"
    # The connection string was given, so the install goes through either way: what shows that the script found out
    # that this release takes no database is that it said so.
    grep -q 'does not use PostgreSQL' "$work/ctl-old.out" \
        || fail "the script did not see that 0.1.34 takes no database: $(cat "$work/ctl-old.out")"
    old_token=$(sed -n 's/^    \([A-Za-z0-9_-]\{43\}\)$/\1/p' "$work/ctl-old.out" | head -n 1)
    [ -n "$old_token" ] || fail "0.1.34 did not print its admin token: $(cat "$work/ctl-old.out")"
    sudo test -f /var/lib/i3t-controller/controller.db || fail "0.1.34 did not create its database file"
    [ "$(sudo cat /var/lib/i3t-controller/database.url)" = "$old_database" ] || fail "the connection string was not kept for later"

    step "upgrading it to this build: the database was given earlier, and the new admin token is shown"
    sh "$repo/deploy/install.sh" --from "$dir" --controller >"$work/ctl-new.out" 2>&1 || fail "the upgrade failed: $(cat "$work/ctl-new.out")"
    new_token=$(sed -n 's/^    \([A-Za-z0-9_-]\{43\}\)$/\1/p' "$work/ctl-new.out" | head -n 1)
    [ -n "$new_token" ] && [ "$new_token" != "$old_token" ] || fail "the new admin token was not shown: $(cat "$work/ctl-new.out")"
    i=0
    until I3T_ADMIN_TOKEN="$new_token" "$dir/i3tctl" --json status >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 30 ] || fail "the upgraded controller does not answer with its new token"
        sleep 1
    done
    sudo sh "$repo/deploy/install.sh" --uninstall --controller --purge >/dev/null
fi

step "ok"
