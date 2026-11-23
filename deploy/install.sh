#!/bin/sh
# One-line installer for ice3tier (node or controller) on Linux and macOS.
#
# Install node (default; a systemd service on Linux, a launchd daemon on macOS):
#   curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh
#
# Install, join, and start node in one command:
#   curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --token <TOKEN> [--can-relay] [--can-exit]
#
# Install and start controller (+ i3tctl). The controller stores its data in a PostgreSQL database you provide;
# to get both with one command use deploy/docker/compose.yaml instead:
#   curl -fsSL https://raw.githubusercontent.com/fuqiuluo/ice3tier/main/deploy/install.sh | sh -s -- --controller --public-addr <HOST:PORT> --database-url <URL>
#
# Options:
#   --controller              Install i3t-controller + i3tctl instead of the node
#   --public-addr HOST:PORT   Controller public address (writes /etc/i3t/controller.env and starts service)
#   --database-url URL        Controller database, postgres://USER:PASSWORD@HOST/DBNAME (or set I3T_DATABASE_URL);
#                             written to /var/lib/i3t-controller/database.url
#   --token TOKEN             Enrollment token (or set I3T_TOKEN); joins and starts the node immediately
#   --can-relay               Declare relay capability during join
#   --can-exit                Declare exit capability during join
#   --no-polkit               Do not install the systemd-resolved polkit rule
#   --no-vnet                 Disable the virtual network adapter and drop its Linux capabilities
#   --version TAG             Install a specific release tag (e.g. v0.1.31) instead of latest
#   --release-base URL        Release base URL (or set I3T_RELEASE_BASE; must use https://; default: GitHub Releases)
#   --release-key PUBKEY      Additional/custom Ed25519 release signing public key (or set I3T_RELEASE_KEY)
#   --from DIR                Install binaries from a local directory instead of downloading
#   --uninstall               Stop and remove installed service, wrapper, and unit files
#   --purge                   With --uninstall, also delete /var/lib/i3t (or /var/lib/i3t-controller) and /etc/i3t
#   -h, --help                Show this help
set -eu

# Debian and some other distros omit sbin from a non-root user's PATH; append it so `command -v` finds useradd,
# groupadd, runuser, semanage, and ip before invoking them through sudo.
PATH="${PATH:+${PATH}:}/usr/local/sbin:/usr/sbin:/sbin"
export PATH

REPO="fuqiuluo/ice3tier"
RELEASE_BASE="${I3T_RELEASE_BASE:-https://github.com/${REPO}/releases}"
# Pinned release signing public key (must match PROJECT_KEYS in crates/i3t-update/src/trust.rs).
RELEASE_PUBLIC_KEY="kWB8NBoJtLGX7mZwXgMSZ1C8RkUDpkdOphusy_JhEk0"
RELEASE_KEY="${I3T_RELEASE_KEY:-}"
VERSION="${I3T_VERSION:-}"
TOKEN="${I3T_TOKEN:-}"
MODE="node"
PUBLIC_ADDR=""
DATABASE_URL="${I3T_DATABASE_URL:-}"
CAN_RELAY=0
CAN_EXIT=0
INSTALL_POLKIT=1
NO_VNET=0
FROM_DIR=""
UNINSTALL=0
PURGE=0
SUDO=""
# Scratch directory for downloads. Not called TMPDIR: that one is exported on macOS and read by mktemp and others.
WORK=""
MANIFEST_VERIFIED=0
MANIFEST_VERSION=""

STATE_DIR="/var/lib/i3t"
NODE_BIN_DIR="${STATE_DIR}/bin"
ROOT_BIN_DIR="/usr/local/libexec/i3t"
ROOT_BIN="${ROOT_BIN_DIR}/i3t"
LAUNCHD_LABEL="com.github.fuqiuluo.ice3tier"
LAUNCHD_PLIST="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"
LAUNCHD_LOG="/var/log/i3t.log"
NEWSYSLOG_CONF="/etc/newsyslog.d/i3t.conf"

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Install the ice3tier node (default) as a systemd service on Linux or a launchd daemon on macOS,
or the controller as a systemd service on Linux.

Node options:
  --token TOKEN             Join the network and start the service (or set I3T_TOKEN)
  --can-relay               Pass --can-relay to `i3t join`
  --can-exit                Pass --can-exit to `i3t join`
  --no-polkit               Skip installing /etc/polkit-1/rules.d/50-i3t-resolved.rules
  --no-vnet                 Disable the virtual network adapter and drop service capabilities

Controller options:
  --controller              Install i3t-controller and i3tctl (systemd service on Linux)
  --public-addr HOST:PORT   Set I3T_PUBLIC_ADDR in /etc/i3t/controller.env and start the service
  --database-url URL        PostgreSQL database the controller stores its data in, e.g.
                            postgres://USER:PASSWORD@HOST/DBNAME (or set I3T_DATABASE_URL).
                            Written to /var/lib/i3t-controller/database.url, readable by the
                            service only. This script does not install PostgreSQL

Common options:
  --version TAG             Install a specific release tag (e.g. v0.1.31; default: latest)
  --release-base URL        Override release base URL (https:// required; or set I3T_RELEASE_BASE)
  --release-key PUBKEY      Trust an extra/custom Ed25519 release public key (or set I3T_RELEASE_KEY)
  --from DIR                Install binaries from a local directory (e.g. target/release)
  --uninstall               Remove the installed service, binaries, and polkit rule
  --purge                   With --uninstall, also delete state and config directories
  -h, --help                Show this help
EOF
}

log() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

cleanup_work() {
    if [ -n "$WORK" ] && [ -d "$WORK" ]; then
        rm -rf "$WORK"
    fi
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --controller)
                MODE="controller"
                ;;
            --public-addr)
                [ "$#" -ge 2 ] || die "--public-addr requires an argument"
                PUBLIC_ADDR="$2"
                shift
                ;;
            --public-addr=*)
                PUBLIC_ADDR="${1#*=}"
                ;;
            --database-url)
                [ "$#" -ge 2 ] || die "--database-url requires an argument"
                DATABASE_URL="$2"
                shift
                ;;
            --database-url=*)
                DATABASE_URL="${1#*=}"
                ;;
            --token)
                [ "$#" -ge 2 ] || die "--token requires an argument"
                TOKEN="$2"
                shift
                ;;
            --token=*)
                TOKEN="${1#*=}"
                ;;
            --can-relay)
                CAN_RELAY=1
                ;;
            --can-exit)
                CAN_EXIT=1
                ;;
            --no-polkit)
                INSTALL_POLKIT=0
                ;;
            --no-vnet)
                NO_VNET=1
                ;;
            --version)
                [ "$#" -ge 2 ] || die "--version requires an argument"
                VERSION="$2"
                shift
                ;;
            --version=*)
                VERSION="${1#*=}"
                ;;
            --release-base)
                [ "$#" -ge 2 ] || die "--release-base requires an argument"
                RELEASE_BASE="$2"
                shift
                ;;
            --release-base=*)
                RELEASE_BASE="${1#*=}"
                ;;
            --release-key)
                [ "$#" -ge 2 ] || die "--release-key requires an argument"
                RELEASE_KEY="$2"
                shift
                ;;
            --release-key=*)
                RELEASE_KEY="${1#*=}"
                ;;
            --from)
                [ "$#" -ge 2 ] || die "--from requires a directory"
                FROM_DIR="$2"
                shift
                ;;
            --from=*)
                FROM_DIR="${1#*=}"
                ;;
            --uninstall)
                UNINSTALL=1
                ;;
            --purge)
                PURGE=1
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "unknown option: $1 (try --help)"
                ;;
        esac
        shift
    done
    RELEASE_BASE="${RELEASE_BASE%/}"
    if [ -n "$VERSION" ]; then
        case "$VERSION" in
            v*) ;;
            *) VERSION="v$VERSION" ;;
        esac
        case "${VERSION#v}" in
            *[!0-9A-Za-z.-]* | *..* | .* | *. | *- | -* | "")
                die "invalid --version value: ${VERSION}"
                ;;
        esac
    fi
    if [ -n "$RELEASE_KEY" ]; then
        case "$RELEASE_KEY" in
            *[!0-9A-Za-z_-]*)
                die "invalid --release-key value (must be 43-character base64url)"
                ;;
        esac
        if [ "${#RELEASE_KEY}" -ne 43 ]; then
            die "invalid --release-key length (must be 43-character base64url)"
        fi
    fi
    if [ "$PURGE" -eq 1 ] && [ "$UNINSTALL" -ne 1 ]; then
        die "--purge can only be used with --uninstall"
    fi
}

detect_platform() {
    os_raw=$(uname -s)
    arch_raw=$(uname -m)
    case "$os_raw" in
        Linux) OS="linux" ;;
        Darwin) OS="macos" ;;
        *) die "unsupported OS: $os_raw (Linux and macOS are supported by this script)" ;;
    esac
    case "$arch_raw" in
        x86_64 | amd64) ARCH="x86_64" ;;
        aarch64 | arm64) ARCH="aarch64" ;;
        *) die "unsupported architecture: $arch_raw (supported: x86_64, aarch64)" ;;
    esac
    # A shell running under Rosetta reports x86_64 on Apple silicon: take the native program.
    if [ "$OS" = "macos" ] && [ "$ARCH" = "x86_64" ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = "1" ]; then
        ARCH="aarch64"
    fi
    PLATFORM="${OS}-${ARCH}"
}

detect_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        $SUDO true
    elif command -v doas >/dev/null 2>&1; then
        SUDO="doas"
        $SUDO true
    else
        die "root privileges are required (run as root, or install sudo/doas)"
    fi
}

has_systemd() {
    [ "$OS" = "linux" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

validate_https_url() {
    case "$1" in
        https://?*) ;;
        *) die "release URL must use https:// (got: $1)" ;;
    esac
    case "$1" in
        *[[:space:]]*) die "release URL must not contain whitespace: $1" ;;
    esac
}

download() {
    _d_url="$1"
    _d_dest="$2"
    validate_https_url "$_d_url"
    if command -v curl >/dev/null 2>&1; then
        curl -fLsS --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout 15 --max-time 300 --retry 3 -o "$_d_dest" "$_d_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only --secure-protocol=TLSv1_2 --timeout=30 --tries=3 -O "$_d_dest" "$_d_url"
    else
        die "neither curl nor wget is installed"
    fi
}

file_size() {
    wc -c < "$1" | tr -d ' \t\r\n'
}

file_sha256() {
    _h_path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$_h_path" | awk '{print tolower($1)}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$_h_path" | awk '{print tolower($1)}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -r "$_h_path" | awk '{print tolower($1)}'
    elif command -v python3 >/dev/null 2>&1; then
        python3 -I - "$_h_path" <<'PY'
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as fh:
    for chunk in iter(lambda: fh.read(65536), b""):
        h.update(chunk)
print(h.hexdigest())
PY
    else
        die "cannot compute SHA-256: install sha256sum, shasum, openssl, or python3"
    fi
}

# Verifies manifest.json against manifest.json.sig with one 43-char base64url Ed25519 public key.
# Returns 0 if valid, 1 if invalid signature, 2 if OpenSSL lacks Ed25519 -rawin support.
verify_sig_openssl() {
    _o_manifest="$1"
    _o_sig="$2"
    _o_pub="$3"
    command -v openssl >/dev/null 2>&1 || return 2
    _o_pub_pem="${WORK}/release.pub.pem"
    _o_sig_bin="${WORK}/manifest.sig.bin"
    _o_payload="${WORK}/manifest.payload"
    _o_pub_std=$(printf '%s' "$_o_pub" | tr -- '-_' '+/')
    printf -- '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA%s=\n-----END PUBLIC KEY-----\n' "$_o_pub_std" > "$_o_pub_pem"
    if ! openssl pkey -pubin -in "$_o_pub_pem" -noout >/dev/null 2>&1; then
        return 2
    fi
    if ! openssl pkeyutl -help 2>&1 | grep -q -- '-rawin'; then
        return 2
    fi
    _o_sig_clean=$(tr -d ' \t\r\n' < "$_o_sig")
    case "$_o_sig_clean" in
        *[!0-9A-Za-z_-]*) return 1 ;;
    esac
    [ "${#_o_sig_clean}" -eq 86 ] || return 1
    _o_sig_std=$(printf '%s' "$_o_sig_clean" | tr -- '-_' '+/')
    printf '%s==' "$_o_sig_std" | openssl base64 -d -A > "$_o_sig_bin" 2>/dev/null || return 1
    [ "$(file_size "$_o_sig_bin")" -eq 64 ] || return 1
    printf 'i3t-signature-v1\020release-manifest' > "$_o_payload"
    cat "$_o_manifest" >> "$_o_payload"
    openssl pkeyutl -verify -pubin -inkey "$_o_pub_pem" -rawin -in "$_o_payload" -sigfile "$_o_sig_bin" >/dev/null 2>&1
}

# Pure-stdlib Python 3 RFC 8032 Ed25519 verifier (fallback for macOS LibreSSL and systems without OpenSSL 1.1.1+).
verify_sig_python() {
    _p_manifest="$1"
    _p_sig="$2"
    _p_pub="$3"
    command -v python3 >/dev/null 2>&1 || return 2
    python3 -I - "$_p_manifest" "$_p_sig" "$_p_pub" <<'PY'
import base64, hashlib, sys

manifest_path, sig_path, pub_b64 = sys.argv[1:4]

def b64url_decode_exact(text, expected_len):
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in text):
        return None
    pad = "=" * ((4 - len(text) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(text + pad)
    except Exception:
        return None
    return raw if len(raw) == expected_len else None

pub_bytes = b64url_decode_exact(pub_b64.strip(), 32)
try:
    with open(sig_path, "rb") as fh:
        sig_text = fh.read().decode("ascii").strip()
except UnicodeDecodeError:
    sys.exit(1)
sig_bytes = b64url_decode_exact(sig_text, 64)
if pub_bytes is None or sig_bytes is None:
    sys.exit(1)

with open(manifest_path, "rb") as fh:
    msg = b"i3t-signature-v1\x10release-manifest" + fh.read()

P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
D2 = (2 * D) % P
I = pow(2, (P - 1) // 4, P)
BY = (4 * pow(5, P - 2, P)) % P
BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
B = (BX, BY, 1, (BX * BY) % P)

def decode_point(buf):
    sign = buf[31] >> 7
    y_bytes = bytearray(buf)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")
    if y >= P:
        return None
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    v3 = pow(v, 3, P)
    v7 = (v3 * v3 % P) * v % P
    x = (u * v3 % P) * pow((u * v7) % P, (P - 5) // 8, P) % P
    vx2 = (v * x * x) % P
    if vx2 == (-u) % P:
        x = (x * I) % P
    elif vx2 != u:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)

def point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (t1 * D2 * t2) % P
    d = (z1 * 2 * z2) % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)

def scalar_mult(pt, s):
    res = (0, 1, 1, 0)
    addend = pt
    while s > 0:
        if s & 1:
            res = point_add(res, addend)
        addend = point_add(addend, addend)
        s >>= 1
    return res

R_bytes = sig_bytes[:32]
S = int.from_bytes(sig_bytes[32:], "little")
if S >= L:
    sys.exit(1)
A = decode_point(pub_bytes)
R = decode_point(R_bytes)
if A is None or R is None:
    sys.exit(1)

k = int.from_bytes(hashlib.sha512(R_bytes + pub_bytes + msg).digest(), "little") % L
lhs = scalar_mult(B, S)
rhs = point_add(R, scalar_mult(A, k))
if (lhs[0] * rhs[2] - rhs[0] * lhs[2]) % P == 0 and (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % P == 0:
    sys.exit(0)
sys.exit(1)
PY
}

verify_manifest_with_key() {
    _k_manifest="$1"
    _k_sig="$2"
    _k_pub="$3"
    _k_rc=0
    verify_sig_openssl "$_k_manifest" "$_k_sig" "$_k_pub" || _k_rc=$?
    if [ "$_k_rc" -eq 0 ]; then
        return 0
    fi
    if [ "$_k_rc" -eq 2 ]; then
        _k_rc=0
        verify_sig_python "$_k_manifest" "$_k_sig" "$_k_pub" || _k_rc=$?
        if [ "$_k_rc" -eq 0 ]; then
            return 0
        fi
        if [ "$_k_rc" -eq 2 ]; then
            die "cannot verify release manifest signature: install openssl (1.1.1+) or python3"
        fi
    fi
    return 1
}

verify_manifest_signature() {
    _v_manifest="$1"
    _v_sig="$2"
    if verify_manifest_with_key "$_v_manifest" "$_v_sig" "$RELEASE_PUBLIC_KEY"; then
        return 0
    fi
    if [ -n "$RELEASE_KEY" ] && verify_manifest_with_key "$_v_manifest" "$_v_sig" "$RELEASE_KEY"; then
        return 0
    fi
    die "release manifest signature verification failed"
}

manifest_url() {
    _m_file="$1"
    if [ -n "$VERSION" ]; then
        printf '%s/download/%s/%s\n' "$RELEASE_BASE" "$VERSION" "$_m_file"
    else
        printf '%s/latest/download/%s\n' "$RELEASE_BASE" "$_m_file"
    fi
}

# Reads version, size, and sha256 for an exact asset filename from an already signature-verified manifest.json.
manifest_lookup() {
    _l_manifest="$1"
    _l_asset="$2"
    _l_want_ver="${VERSION#v}"
    if command -v python3 >/dev/null 2>&1; then
        python3 -I - "$_l_manifest" "$_l_asset" "$_l_want_ver" <<'PY'
import json, re, sys

manifest_path, asset, want_ver = sys.argv[1:4]
with open(manifest_path, "r", encoding="utf-8") as fh:
    m = json.load(fh)
ver = m.get("version")
if not isinstance(ver, str) or not re.fullmatch(r"[0-9A-Za-z.-]+", ver) or ".." in ver:
    sys.exit("invalid version in manifest")
if want_ver and ver != want_ver:
    sys.exit(f"manifest version mismatch: expected {want_ver}, got {ver}")
found = None
for section in ("artifacts", "files"):
    table = m.get(section)
    if not isinstance(table, dict):
        continue
    for entry in table.values():
        if isinstance(entry, dict) and entry.get("file") == asset:
            found = entry
            break
    if found is not None:
        break
if found is None:
    sys.exit(f"asset {asset} is not covered by the signed manifest")
size = found.get("size")
sha = found.get("sha256")
if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
    sys.exit(f"invalid size for {asset} in manifest")
if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
    sys.exit(f"invalid sha256 for {asset} in manifest")
print(f"{ver} {size} {sha.lower()}")
PY
    elif command -v jq >/dev/null 2>&1; then
        _l_out=$(jq -r --arg asset "$_l_asset" --arg want "$_l_want_ver" '
            (.version // "") as $ver |
            if ($ver | test("^[0-9A-Za-z.-]+$") | not) or ($ver | contains("..")) then error("invalid version in manifest")
            elif ($want != "" and $ver != $want) then error("manifest version mismatch")
            else
                ([(.artifacts // {} | .[]), (.files // {} | .[])] | map(select(.file == $asset)) | .[0]) as $a |
                if $a == null then error("asset not covered by manifest")
                elif (($a.size | type) != "number" or $a.size <= 0) then error("invalid size in manifest")
                elif (($a.sha256 | type) != "string" or ($a.sha256 | test("^[0-9a-fA-F]{64}$") | not)) then error("invalid sha256 in manifest")
                else "\($ver) \($a.size) \($a.sha256 | ascii_downcase)"
                end
            end
        ' "$_l_manifest") || die "failed to parse asset ${_l_asset} from manifest"
        printf '%s\n' "$_l_out"
    else
        awk -v asset="$_l_asset" -v want="$_l_want_ver" '
            /"version"[[:space:]]*:/ && ver == "" {
                v = $0; sub(/.*"version"[[:space:]]*:[[:space:]]*"/, "", v); sub(/".*/, "", v); ver = v
            }
            /"file"[[:space:]]*:/ {
                f = $0; sub(/.*"file"[[:space:]]*:[[:space:]]*"/, "", f); sub(/".*/, "", f)
                in_target = (f == asset)
                if (in_target) { size = ""; sha = "" }
            }
            in_target && /"size"[[:space:]]*:/ {
                s = $0; sub(/.*"size"[[:space:]]*:[[:space:]]*/, "", s); sub(/[^0-9].*/, "", s); size = s
            }
            in_target && /"sha256"[[:space:]]*:/ {
                h = $0; sub(/.*"sha256"[[:space:]]*:[[:space:]]*"/, "", h); sub(/".*/, "", h); sha = tolower(h)
                in_target = 0
            }
            END {
                if (ver == "" || (want != "" && ver != want)) exit 1
                if (size == "" || size + 0 <= 0 || length(sha) != 64) exit 1
                printf "%s %s %s\n", ver, size, sha
            }
        ' "$_l_manifest" || die "asset ${_l_asset} not found or invalid in signed manifest"
    fi
}

ensure_verified_manifest() {
    if [ "$MANIFEST_VERIFIED" -eq 1 ]; then
        return 0
    fi
    validate_https_url "$RELEASE_BASE"
    _m_path="${WORK}/manifest.json"
    _s_path="${WORK}/manifest.json.sig"
    _m_url=$(manifest_url "manifest.json")
    _s_url=$(manifest_url "manifest.json.sig")
    log "Downloading and verifying release manifest"
    download "$_m_url" "$_m_path" || die "failed to download ${_m_url}"
    download "$_s_url" "$_s_path" || die "failed to download ${_s_url}"
    _m_len=$(file_size "$_m_path")
    _s_len=$(file_size "$_s_path")
    if [ "$_m_len" -le 0 ] || [ "$_m_len" -gt 1048576 ]; then
        die "release manifest has unexpected size (${_m_len} bytes)"
    fi
    if [ "$_s_len" -le 0 ] || [ "$_s_len" -gt 4096 ]; then
        die "release manifest signature has unexpected size (${_s_len} bytes)"
    fi
    verify_manifest_signature "$_m_path" "$_s_path"
    MANIFEST_VERIFIED=1
}

fetch_binary() {
    name="$1"
    dest="$2"
    asset="${name}-${PLATFORM}"
    if [ -n "$FROM_DIR" ]; then
        if [ -f "${FROM_DIR}/${name}" ]; then
            cp "${FROM_DIR}/${name}" "$dest"
        elif [ -f "${FROM_DIR}/${asset}" ]; then
            cp "${FROM_DIR}/${asset}" "$dest"
        else
            die "binary not found in ${FROM_DIR} (looked for ${name} and ${asset})"
        fi
    else
        ensure_verified_manifest
        _f_meta=$(manifest_lookup "${WORK}/manifest.json" "$asset") || die "failed to resolve ${asset} in signed manifest"
        IFS=' ' read -r MANIFEST_VERSION _f_exp_size _f_exp_sha <<EOF
${_f_meta}
EOF
        url="${RELEASE_BASE}/download/v${MANIFEST_VERSION}/${asset}"
        log "Downloading ${asset} (v${MANIFEST_VERSION})"
        download "$url" "$dest" || die "failed to download ${url}"
        _f_act_size=$(file_size "$dest")
        if [ "$_f_act_size" -ne "$_f_exp_size" ]; then
            rm -f "$dest"
            die "size mismatch for ${asset}: expected ${_f_exp_size} bytes, got ${_f_act_size}"
        fi
        _f_act_sha=$(file_sha256 "$dest")
        if [ "$_f_act_sha" != "$_f_exp_sha" ]; then
            rm -f "$dest"
            die "SHA-256 mismatch for ${asset}: expected ${_f_exp_sha}, got ${_f_act_sha}"
        fi
        log "Verified ${asset} (SHA-256 matches signed manifest)"
    fi
    chmod 0755 "$dest"
}

# Atomically install an executable without triggering ETXTBSY on a running binary.
install_binary_atomic() {
    src="$1"
    dest="$2"
    owner="$3"
    group="$4"
    dir=$(dirname "$dest")
    base=$(basename "$dest")
    if $SUDO test -L "$dir" || $SUDO test -L "$dest"; then
        die "refusing to install through symbolic link: ${dest}"
    fi
    stage=$($SUDO mktemp "${dir}/.${base}.install.XXXXXX")
    if ! $SUDO install -o "$owner" -g "$group" -m 0755 "$src" "$stage" || ! $SUDO mv -f "$stage" "$dest"; then
        $SUDO rm -f "$stage" 2>/dev/null || true
        die "failed to install ${dest}"
    fi
}

# Install the self-updating binary into the i3t-owned bin directory AS user i3t, so root never writes into an
# unprivileged-owned directory (preventing symlink-following hazards during upgrades).
install_binary_as_i3t() {
    _ia_src="$1"
    _ia_dest="$2"
    _ia_dir=$(dirname "$_ia_dest")
    _ia_base=$(basename "$_ia_dest")
    if $SUDO test -L "$_ia_dir" || $SUDO test -L "$_ia_dest"; then
        die "refusing to install through symbolic link: ${_ia_dest}"
    fi
    # shellcheck disable=SC2016
    _ia_script='dir=$1; base=$2; src=$3; dest=$4; stage=$(mktemp "$dir/.$base.install.XXXXXX") || exit 1; if cp "$src" "$stage" && chmod 0755 "$stage" && mv -f "$stage" "$dest"; then exit 0; else rm -f "$stage"; exit 1; fi'
    if command -v runuser >/dev/null 2>&1; then
        $SUDO runuser -u i3t -- /bin/sh -c "$_ia_script" sh "$_ia_dir" "$_ia_base" "$_ia_src" "$_ia_dest"
    elif command -v sudo >/dev/null 2>&1; then
        $SUDO sudo -u i3t -- /bin/sh -c "$_ia_script" sh "$_ia_dir" "$_ia_base" "$_ia_src" "$_ia_dest"
    else
        $SUDO su -s /bin/sh -c "$_ia_script" -- i3t sh "$_ia_dir" "$_ia_base" "$_ia_src" "$_ia_dest"
    fi
}

nologin_shell() {
    for s in /usr/sbin/nologin /sbin/nologin /bin/false; do
        if [ -x "$s" ]; then
            printf '%s\n' "$s"
            return
        fi
    done
    printf '%s\n' /bin/false
}

ensure_system_user() {
    user="$1"
    home="$2"
    shell=$(nologin_shell)
    if ! getent group "$user" >/dev/null 2>&1; then
        if command -v groupadd >/dev/null 2>&1; then
            $SUDO groupadd --system "$user"
        elif command -v addgroup >/dev/null 2>&1; then
            $SUDO addgroup --system "$user"
        fi
    fi
    if ! id "$user" >/dev/null 2>&1; then
        if command -v useradd >/dev/null 2>&1; then
            $SUDO useradd --system --no-create-home --home-dir "$home" --shell "$shell" -g "$user" "$user"
        elif command -v adduser >/dev/null 2>&1; then
            $SUDO adduser --system --no-create-home --home "$home" --shell "$shell" --ingroup "$user" "$user"
        else
            die "cannot create system user ${user}: neither useradd nor adduser found"
        fi
    fi
}

is_mount_noexec() {
    target="$1"
    if command -v findmnt >/dev/null 2>&1; then
        opts=$(findmnt -n -o OPTIONS --target "$target" 2>/dev/null || true)
        case ",${opts}," in
            *,noexec,*) return 0 ;;
        esac
    fi
    return 1
}

relabel_selinux_bin() {
    dir="$1"
    if $SUDO test -L "$dir"; then
        die "refusing to relabel symbolic link: ${dir}"
    fi
    if command -v getenforce >/dev/null 2>&1; then
        state=$(getenforce 2>/dev/null || true)
        if [ "$state" = "Enforcing" ] || [ "$state" = "Permissive" ]; then
            if command -v semanage >/dev/null 2>&1 && command -v restorecon >/dev/null 2>&1; then
                $SUDO semanage fcontext -a -t bin_t "${dir}(/.*)?" 2>/dev/null ||
                    $SUDO semanage fcontext -m -t bin_t "${dir}(/.*)?" 2>/dev/null || true
                $SUDO restorecon -RF "$dir" 2>/dev/null || true
            elif command -v chcon >/dev/null 2>&1; then
                $SUDO chcon -hR -t bin_t "$dir" 2>/dev/null || true
            else
                warn "SELinux is ${state} and semanage/chcon were not found; label ${dir} as bin_t if systemd fails with 203/EXEC"
            fi
        fi
    fi
}

write_node_service() {
    cat <<'EOF' > "$1"
[Unit]
Description=ice3tier node
# 更新失败回退时会连续重启几次，不能被 systemd 默认的启动次数限制（10 秒内 5 次）拦住。
StartLimitIntervalSec=0
Documentation=https://github.com/fuqiuluo/ice3tier
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
# 程序放在状态目录里，服务账号对它可写，节点自己更新时不需要提权。
# 一键部署（建用户、装程序与命令行包装脚本、polkit 规则、SELinux）见 deploy/install.sh。
ExecStart=/var/lib/i3t/bin/i3t run
# 进程被 SIGKILL 或 OOM 杀掉时，内核会收回 TUN 网卡，但防火墙规则还在；在这里立刻拆掉孤儿规则，不留到下次启动。
# 加上 "-" 前缀：即使去掉了下面的能力或者程序是旧版本，也不影响服务正常停止和重启。
ExecStopPost=-/var/lib/i3t/bin/i3t network cleanup
Environment=I3T_STATE_DIR=/var/lib/i3t
User=i3t
Group=i3t
StateDirectory=i3t
StateDirectoryMode=0700
Restart=always
RestartSec=2
# 节点自己更新：换好程序文件之后以 75 退出，意思是"请重启我"。它不是出错，所以不算失败；
# 就算以后有人把上面的 Restart= 改成 on-failure，这个退出码也照样重启，更新才不会停在半路。
SuccessExitStatus=75
RestartForceExitStatus=75
# 配置文件有错、还没有加入网络，或者被 controller 吊销、拒绝时以 78（EX_CONFIG）退出：重启也救不了，直接停下。
RestartPreventExitStatus=78
LimitNOFILE=1048576

# 虚拟网卡（默认打开）要的能力，以 i3t 用户运行时由 systemd 给：CAP_NET_ADMIN 建网卡、配地址和路由、
# 加两条防火墙规则（执行的 iptables、nft 带着它）；CAP_NET_RAW 是老的 xtables 后端的 iptables 要的；CAP_NET_BIND_SERVICE
# 是名字服务的 53 端口（本节点虚拟 IP 上）。NoNewPrivileges=yes 不影响 ambient 的能力。
# 让 systemd-resolved 接受非 root 进程的 DNS 设置，还要安装 deploy/polkit/50-i3t-resolved.rules。
# 不要虚拟网卡的机器：i3t set network off，删掉 AmbientCapabilities=，并把 CapabilityBoundingSet= 留空。
# 只有这几项能力：节点进程不是 root，碰不了别的。
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
# 老的 xtables 后端的 iptables 要一个锁文件，默认在 /run 下，ProtectSystem=strict 时 /run 不能写：放到服务自己的运行目录里。
RuntimeDirectory=i3t
Environment=XTABLES_LOCKFILE=/run/i3t/xtables.lock

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
}

write_controller_service() {
    cat <<'EOF' > "$1"
[Unit]
Description=ice3tier controller
Documentation=https://github.com/fuqiuluo/ice3tier
# 数据库在本机时等它先起来；不在本机、或者叫别的名字时这一项没有作用，连不上会隔两秒再试。
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
# 数据目录默认和 StateDirectory= 一致，由 ProtectSystem=strict 放行写入；若改用别的目录，需另加 ReadWritePaths=。
# 里面是 controller 的密钥、更新包的缓存，和 database.url：数据库的连接串（有密码，只有这个服务的用户可读）。
Environment=I3T_DATA_DIR=/var/lib/i3t-controller
# 对外地址和额外选项写在 /etc/i3t/controller.env 里，比如：
#   I3T_PUBLIC_ADDR=ctl.example.com:20331
#   I3T_CONTROLLER_ARGS=--listen 0.0.0.0:20331
# 也兼容直接把 --data-dir / --public-addr 写在 I3T_CONTROLLER_ARGS 里。别的选项见 i3t-controller --help。
EnvironmentFile=/etc/i3t/controller.env
ExecStart=/usr/local/bin/i3t-controller $I3T_CONTROLLER_ARGS
User=i3t-controller
Group=i3t-controller
StateDirectory=i3t-controller
StateDirectoryMode=0700
Restart=always
RestartSec=2
LimitNOFILE=1048576

CapabilityBoundingSet=
NoNewPrivileges=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOF
}

write_polkit_rule() {
    cat <<'EOF' > "$1"
// 虚拟网卡的名字：让以 i3t 用户跑的节点（deploy/systemd/i3t.service）设置 systemd-resolved。
// systemd-resolved 按 polkit 决定一个不是 root 的进程能不能改网卡的 DNS，不认 CAP_NET_ADMIN；没有这条规则时，
// 名字服务的状态是 failed（resolvectl 说 Access denied 或 Interactive authentication required），按虚拟 IP 照常可用。
// 装上（要有 polkit，立刻生效，不用重启）：
//
//   sudo install -D -m 0644 50-i3t-resolved.rules /etc/polkit-1/rules.d/50-i3t-resolved.rules
//   sudo systemctl restart i3t
//
// 代价：这四个动作不分网卡，i3t 用户因此能改这台机器上任何一块网卡的 DNS 设置，不只是它自己的虚拟网卡 i3t0。
// 不想给的话不装，名字用 sudo i3t hosts --apply 写进 /etc/hosts。
polkit.addRule(function(action, subject) {
    var allowed = [
        "org.freedesktop.resolve1.set-dns-servers",
        "org.freedesktop.resolve1.set-domains",
        "org.freedesktop.resolve1.set-default-route",
        "org.freedesktop.resolve1.revert"
    ];
    if (subject.user == "i3t" && allowed.indexOf(action.id) >= 0) {
        return polkit.Result.YES;
    }
});
EOF
}

# The node on macOS: a launchd daemon running as root (the adapter needs it). launchd cannot be told to leave one exit
# status alone the way systemd's RestartPreventExitStatus=78 does, so a node that cannot start retries every 10 s.
write_launchd_plist() {
    cat <<EOF > "$1"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${NODE_BIN_DIR}/i3t</string>
        <string>run</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>I3T_STATE_DIR</key>
        <string>${STATE_DIR}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>${LAUNCHD_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${LAUNCHD_LOG}</string>
</dict>
</plist>
EOF
}

# The `i3t` command for service installs (systemd or launchd): runs the self-updating program in the state directory
# as the unprivileged service user, while privileged / custom-state-dir commands run the root-owned immutable binary.
write_cli_wrapper() {
    dest="$1"
    service="$2"
    bin_dir="$3"
    root_bin="$4"
    cat <<EOF > "$dest"
#!/bin/sh
# Installed by ice3tier's deploy/install.sh. Runs the self-updating program at ${bin_dir}/i3t as the service user.
# On systemd installs, root NEVER executes the i3t-writable binary: privileged subcommands (hosts/tune/network) and
# custom --state-dir invocations run the root-owned immutable binary at ${root_bin}.
set -eu

BIN="${bin_dir}/i3t"
ROOT_BIN="${root_bin}"
STATE="${STATE_DIR}"
SERVICE="${service}"
LABEL="${LAUNCHD_LABEL}"
PLIST="${LAUNCHD_PLIST}"
EOF
    cat <<'EOF' >> "$dest"

PATH="${PATH:+${PATH}:}/usr/sbin:/sbin"
export PATH

sub=""
info=0
# --state-dir wins over I3T_STATE_DIR, as it does in the program.
dir="${I3T_STATE_DIR:-}"
skip_next=0
for arg in "$@"; do
    if [ "$skip_next" -eq 1 ]; then
        dir="$arg"
        skip_next=0
        continue
    fi
    case "$arg" in
        --state-dir)
            skip_next=1
            ;;
        --state-dir=*)
            dir="${arg#*=}"
            ;;
        -h | --help | -V | --version)
            info=1
            ;;
        -*)
            ;;
        *)
            if [ -z "$sub" ]; then
                sub="$arg"
            fi
            ;;
    esac
done

# The directory a path names, with links and trailing slashes resolved; the path itself when it cannot be entered.
real_dir() {
    (CDPATH='' cd -- "$1" 2>/dev/null && pwd -P) || printf '%s\n' "$1"
}

custom_dir=0
if [ -n "$dir" ] && [ "$(real_dir "$dir")" != "$(real_dir "$STATE")" ]; then
    custom_dir=1
fi

exec_root_bin() {
    if [ -L "$ROOT_BIN" ] || [ ! -f "$ROOT_BIN" ] || [ ! -x "$ROOT_BIN" ]; then
        printf 'i3t: program not found at %s\n' "$ROOT_BIN" >&2
        exit 1
    fi
    exec "$ROOT_BIN" "$@"
}

if [ "$SERVICE" = "systemd" ]; then
    # Never execute the i3t-writable binary as root: privileged subcommands and custom --state-dir invocations
    # always run the root-owned immutable binary.
    case "$sub" in
        hosts | tune | network)
            exec_root_bin "$@"
            ;;
    esac
    if [ "$custom_dir" -eq 1 ]; then
        exec_root_bin "$@"
    fi
    if [ "$(id -u)" -ne 0 ] && [ ! -x "$BIN" ]; then
        if [ -z "$sub" ]; then
            exec_root_bin "$@"
        fi
        printf 'i3t: cannot run %s as this user (try: sudo i3t ...)\n' "$BIN" >&2
        exit 1
    fi
    if [ ! -x "$BIN" ]; then
        printf 'i3t: program not found at %s\n' "$BIN" >&2
        exit 1
    fi
else
    if [ ! -x "$BIN" ]; then
        if [ "$(id -u)" -ne 0 ]; then
            printf 'i3t: cannot run %s as this user (try: sudo i3t ...)\n' "$BIN" >&2
            exit 1
        fi
        printf 'i3t: program not found at %s\n' "$BIN" >&2
        exit 1
    fi
    case "$sub" in
        hosts | tune | network | "")
            exec "$BIN" "$@"
            ;;
    esac
fi

# Runs the program; the first argument is "exec" or "". On systemd installs root ALWAYS drops to user i3t.
as_node() {
    how="$1"
    shift
    if [ "$SERVICE" = "systemd" ] && [ "$(id -u)" -eq 0 ]; then
        if ! id i3t >/dev/null 2>&1; then
            printf 'i3t: system user i3t does not exist; refusing to execute %s as root\n' "$BIN" >&2
            exit 1
        fi
        if command -v runuser >/dev/null 2>&1; then
            $how runuser -u i3t -- env I3T_STATE_DIR="$STATE" ${I3T_LANG:+"I3T_LANG=$I3T_LANG"} ${I3T_LOG:+"I3T_LOG=$I3T_LOG"} ${I3T_SERVICE:+"I3T_SERVICE=$I3T_SERVICE"} "$BIN" "$@"
        elif command -v sudo >/dev/null 2>&1; then
            $how sudo -u i3t -- env I3T_STATE_DIR="$STATE" ${I3T_LANG:+"I3T_LANG=$I3T_LANG"} ${I3T_LOG:+"I3T_LOG=$I3T_LOG"} ${I3T_SERVICE:+"I3T_SERVICE=$I3T_SERVICE"} "$BIN" "$@"
        else
            $how su -s /bin/sh -c 'state=$1; service=$2; bin=$3; shift 3; exec env I3T_STATE_DIR="$state" I3T_SERVICE="$service" "$bin" "$@"' -- i3t sh "$STATE" "${I3T_SERVICE:-}" "$BIN" "$@"
        fi
    else
        $how "$BIN" "$@"
    fi
}

start_command() {
    if [ "$SERVICE" = "systemd" ]; then
        printf 'sudo systemctl restart i3t'
    else
        printf 'sudo launchctl kickstart -k system/%s' "$LABEL"
    fi
}

restart_service() {
    if [ "$SERVICE" = "systemd" ]; then
        systemctl restart i3t
        sleep 2
        systemctl is-active -q i3t && return 0
        printf 'i3t: the service is not running; see: journalctl -u i3t\n' >&2
    else
        if launchctl print "system/$LABEL" >/dev/null 2>&1; then
            launchctl kickstart -k "system/$LABEL"
        else
            launchctl enable "system/$LABEL" 2>/dev/null || true
            launchctl bootstrap system "$PLIST"
        fi
        sleep 2
        launchctl print "system/$LABEL" 2>/dev/null | grep -q 'state = running' && return 0
        printf 'i3t: the service is not running; see /var/log/i3t.log\n' >&2
    fi
    exit 1
}

# Asking for help or the version neither joins nor runs.
if [ "$(id -u)" -eq 0 ] && [ "$custom_dir" -eq 0 ] && [ "$info" -eq 0 ]; then
    case "$sub" in
        run)
            printf 'i3t: the node runs as a system service on this machine; start it with: %s\n' "$(start_command)" >&2
            exit 1
            ;;
        join)
            I3T_SERVICE=i3t
            export I3T_SERVICE
            as_node "" "$@"
            restart_service
            exit 0
            ;;
    esac
fi

as_node exec "$@"
EOF
}

run_as_i3t() {
    node_bin="$1"
    shift
    if command -v runuser >/dev/null 2>&1; then
        $SUDO runuser -u i3t -- env I3T_STATE_DIR="$STATE_DIR" ${I3T_LANG:+"I3T_LANG=$I3T_LANG"} ${I3T_SERVICE:+"I3T_SERVICE=$I3T_SERVICE"} "$node_bin" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        $SUDO sudo -u i3t -- env I3T_STATE_DIR="$STATE_DIR" ${I3T_LANG:+"I3T_LANG=$I3T_LANG"} ${I3T_SERVICE:+"I3T_SERVICE=$I3T_SERVICE"} "$node_bin" "$@"
    else
        $SUDO su -s /bin/sh -c 'state=$1; service=$2; bin=$3; shift 3; exec env I3T_STATE_DIR="$state" I3T_SERVICE="$service" "$bin" "$@"' -- i3t sh "$STATE_DIR" "${I3T_SERVICE:-}" "$node_bin" "$@"
    fi
}

# Runs the node program as root (macOS and Linux without systemd: the adapter needs root there).
run_as_root() {
    node_bin="$1"
    shift
    $SUDO env I3T_STATE_DIR="$STATE_DIR" ${I3T_LANG:+"I3T_LANG=$I3T_LANG"} ${I3T_SERVICE:+"I3T_SERVICE=$I3T_SERVICE"} "$node_bin" "$@"
}

join_node() {
    runner="$1"
    node_bin="$2"
    set -- join
    [ "$CAN_RELAY" -eq 1 ] && set -- "$@" --can-relay
    [ "$CAN_EXIT" -eq 1 ] && set -- "$@" --can-exit
    printf '%s\n' "$TOKEN" | "$runner" "$node_bin" "$@"
}

# The name of the node's adapter for messages: the one present, else the first the node would take.
adapter_name() {
    name=$(ip -o link show 2>/dev/null | sed -n 's/^[0-9]*: \(i3t[0-9]*\)[:@].*/\1/p' | head -n 1)
    printf '%s\n' "${name:-i3t0}"
}

# Linux without systemd: the program in /usr/local/bin, run by hand as root. The state directory is created here so
# that `sudo i3t join` and `sudo i3t run` agree on it whatever HOME sudo passes on.
install_node_plain() {
    log "Installing i3t to /usr/local/bin/i3t (systemd not detected)"
    $SUDO install -d -m 0755 /usr/local/bin
    install_binary_atomic "${WORK}/i3t" /usr/local/bin/i3t 0 0
    $SUDO install -d -m 0700 "$STATE_DIR"
    [ "$NO_VNET" -eq 1 ] && run_as_root /usr/local/bin/i3t set network off
    if [ -n "$TOKEN" ]; then
        join_node run_as_root /usr/local/bin/i3t
    fi
    log "Installed /usr/local/bin/i3t (state in ${STATE_DIR})"
    printf '\nNext steps:\n'
    [ -z "$TOKEN" ] && printf '  echo <enrollment-token> | sudo i3t join\n'
    printf '  sudo i3t run   # keep it running with your init system\n'
}

launchd_wait_stopped() {
    # bootout returns while the node is still shutting down (it removes its adapter first): wait for both the process
    # and the launchd job record to clear before bootstrapping again or deleting its program, as `systemctl disable
    # --now` does on Linux.
    i=0
    while pgrep -f "${NODE_BIN_DIR}/i3t run" >/dev/null 2>&1 ||
        $SUDO launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -gt 30 ]; then
            warn "the node is still running 30 s after it was told to stop"
            break
        fi
        sleep 1
    done
}

launchd_start() {
    reload="${1:-0}"
    if $SUDO launchctl print "system/${LAUNCHD_LABEL}" >/dev/null 2>&1; then
        if [ "$reload" -eq 1 ]; then
            $SUDO launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null || true
            launchd_wait_stopped
            $SUDO launchctl enable "system/${LAUNCHD_LABEL}" 2>/dev/null || true
            $SUDO launchctl bootstrap system "$LAUNCHD_PLIST"
        else
            $SUDO launchctl kickstart -k "system/${LAUNCHD_LABEL}"
        fi
    else
        $SUDO launchctl enable "system/${LAUNCHD_LABEL}" 2>/dev/null || true
        $SUDO launchctl bootstrap system "$LAUNCHD_PLIST"
    fi
}

install_node_launchd() {
    log "Installing i3t to ${NODE_BIN_DIR}/i3t (root, self-updating)"
    $SUDO install -d -o 0 -g 0 -m 0700 "$STATE_DIR" "$NODE_BIN_DIR"
    install_binary_atomic "${WORK}/i3t" "${NODE_BIN_DIR}/i3t" 0 0

    write_cli_wrapper "${WORK}/i3t-wrapper" launchd "$NODE_BIN_DIR" "${NODE_BIN_DIR}/i3t"
    $SUDO install -d -m 0755 /usr/local/bin
    install_binary_atomic "${WORK}/i3t-wrapper" /usr/local/bin/i3t 0 0

    log "Installing ${LAUNCHD_PLIST}"
    write_launchd_plist "${WORK}/i3t.plist"
    plutil -lint "${WORK}/i3t.plist" >/dev/null || die "the generated launchd plist is invalid"
    plist_changed=1
    if $SUDO cmp -s "${WORK}/i3t.plist" "$LAUNCHD_PLIST" 2>/dev/null; then
        plist_changed=0
    fi
    $SUDO install -o 0 -g 0 -m 0644 "${WORK}/i3t.plist" "$LAUNCHD_PLIST"
    # Flag N: do not signal syslogd on rotation. Because launchd holds the log file open as stdout/stderr, a running
    # node keeps writing to the old file descriptor until it restarts (or self-updates).
    printf '%s\t644\t5\t10240\t*\tJN\n' "$LAUNCHD_LOG" > "${WORK}/newsyslog.conf"
    $SUDO install -d -m 0755 "$(dirname "$NEWSYSLOG_CONF")"
    $SUDO install -o 0 -g 0 -m 0644 "${WORK}/newsyslog.conf" "$NEWSYSLOG_CONF"

    [ "$NO_VNET" -eq 1 ] && run_as_root "${NODE_BIN_DIR}/i3t" set network off

    if [ -n "$TOKEN" ]; then
        log "Joining network"
        I3T_SERVICE=i3t
        join_node run_as_root "${NODE_BIN_DIR}/i3t"
        log "Starting ${LAUNCHD_LABEL}"
        launchd_start "$plist_changed"
        log "i3t is running (check with: sudo i3t status)"
    elif $SUDO test -f "${STATE_DIR}/controller.json"; then
        log "Existing enrollment found; restarting ${LAUNCHD_LABEL}"
        launchd_start "$plist_changed"
        log "i3t upgraded and running (check with: sudo i3t status)"
    else
        # Keep launchd from loading an unjoined daemon at boot (and retrying every 10 s); `i3t join` re-enables it.
        $SUDO launchctl disable "system/${LAUNCHD_LABEL}" 2>/dev/null || true
        log "Installation complete!"
        printf '\nNext step (joins and starts the daemon):\n'
        printf '  echo <enrollment-token> | sudo i3t join   # add --can-relay or --can-exit if needed\n'
    fi
}

install_node_systemd() {
    log "Setting up system user i3t and ${STATE_DIR}"
    ensure_system_user "i3t" "$STATE_DIR"
    if $SUDO test -L "$STATE_DIR"; then
        die "refusing to use symbolic link as state directory: ${STATE_DIR}"
    fi
    if $SUDO test -e "$STATE_DIR" && ! $SUDO test -d "$STATE_DIR"; then
        die "state path exists and is not a directory: ${STATE_DIR}"
    fi
    $SUDO install -d -o i3t -g i3t -m 0700 "$STATE_DIR"

    # /var mounted noexec cannot execute /var/lib/i3t/bin/i3t; relocate to /opt/i3t/bin with a systemd drop-in.
    node_bin_dir="$NODE_BIN_DIR"
    custom_bin_dir=0
    if is_mount_noexec "$STATE_DIR"; then
        warn "/var is mounted noexec; installing i3t binary to /opt/i3t/bin instead"
        node_bin_dir="/opt/i3t/bin"
        custom_bin_dir=1
    fi
    if $SUDO test -L "$node_bin_dir"; then
        die "refusing to use symbolic link as node binary directory: ${node_bin_dir}"
    fi
    if $SUDO test -e "$node_bin_dir" && ! $SUDO test -d "$node_bin_dir"; then
        die "node binary path exists and is not a directory: ${node_bin_dir}"
    fi
    node_bin="${node_bin_dir}/i3t"
    if [ "$custom_bin_dir" -eq 0 ]; then
        if command -v runuser >/dev/null 2>&1; then
            $SUDO runuser -u i3t -- mkdir -p -m 0700 "$node_bin_dir"
        elif command -v sudo >/dev/null 2>&1; then
            $SUDO sudo -u i3t -- mkdir -p -m 0700 "$node_bin_dir"
        else
            $SUDO su -s /bin/sh -c 'mkdir -p -m 0700 "$1"' -- i3t sh "$node_bin_dir"
        fi
    else
        $SUDO install -d -o 0 -g 0 -m 0755 "$(dirname "$node_bin_dir")"
        $SUDO install -d -o i3t -g i3t -m 0700 "$node_bin_dir"
    fi

    log "Installing root-owned admin binary to ${ROOT_BIN}"
    $SUDO install -d -o 0 -g 0 -m 0755 "$ROOT_BIN_DIR"
    install_binary_atomic "${WORK}/i3t" "$ROOT_BIN" 0 0

    log "Installing i3t binary to ${node_bin} (writable by user i3t for self-updates)"
    install_binary_as_i3t "$ROOT_BIN" "$node_bin"
    relabel_selinux_bin "$node_bin_dir"

    write_cli_wrapper "${WORK}/i3t-wrapper" systemd "$node_bin_dir" "$ROOT_BIN"
    $SUDO install -d -m 0755 /usr/local/bin
    install_binary_atomic "${WORK}/i3t-wrapper" /usr/local/bin/i3t 0 0

    log "Installing /etc/systemd/system/i3t.service"
    write_node_service "${WORK}/i3t.service"
    $SUDO install -D -m 0644 "${WORK}/i3t.service" /etc/systemd/system/i3t.service

    if [ "$custom_bin_dir" -eq 1 ]; then
        cat <<EOF > "${WORK}/bin-dir.conf"
[Service]
ExecStart=
ExecStart=${node_bin} run
ExecStopPost=
ExecStopPost=-${node_bin} network cleanup
ReadWritePaths=${node_bin_dir}
EOF
        $SUDO install -D -m 0644 "${WORK}/bin-dir.conf" /etc/systemd/system/i3t.service.d/bin-dir.conf
    fi

    vnet_disabled="$NO_VNET"
    if [ "$NO_VNET" -eq 1 ]; then
        cat <<'EOF' > "${WORK}/no-vnet.conf"
[Service]
AmbientCapabilities=
CapabilityBoundingSet=
EOF
        $SUDO install -D -m 0644 "${WORK}/no-vnet.conf" /etc/systemd/system/i3t.service.d/no-vnet.conf
        run_as_i3t "$node_bin" set network off
    elif $SUDO test -f /etc/systemd/system/i3t.service.d/no-vnet.conf; then
        vnet_disabled=1
    fi

    if [ "$INSTALL_POLKIT" -eq 1 ] && [ "$vnet_disabled" -eq 0 ]; then
        if [ -d /etc/polkit-1/rules.d ]; then
            log "Installing /etc/polkit-1/rules.d/50-i3t-resolved.rules"
            write_polkit_rule "${WORK}/50-i3t-resolved.rules"
            $SUDO install -m 0644 "${WORK}/50-i3t-resolved.rules" /etc/polkit-1/rules.d/50-i3t-resolved.rules
        elif systemctl is-active -q systemd-resolved 2>/dev/null; then
            warn "systemd-resolved is active but /etc/polkit-1/rules.d was not found; install polkit or use 'sudo i3t hosts --apply' for DNS names"
        fi
    fi

    $SUDO systemctl daemon-reload

    if [ -n "$TOKEN" ]; then
        log "Joining network as user i3t"
        I3T_SERVICE=i3t
        join_node run_as_i3t "$node_bin"
        log "Enabling and starting i3t.service"
        $SUDO systemctl enable i3t >/dev/null
        $SUDO systemctl restart i3t
        log "i3t is running (check with: sudo i3t status)"
    elif $SUDO test -f "${STATE_DIR}/controller.json"; then
        log "Existing enrollment found; restarting i3t.service"
        $SUDO systemctl enable i3t >/dev/null
        $SUDO systemctl restart i3t
        log "i3t upgraded and running (check with: sudo i3t status)"
    else
        $SUDO systemctl enable i3t >/dev/null
        log "Installation complete!"
        printf '\nNext step (joins and starts the service):\n'
        printf '  echo <enrollment-token> | sudo i3t join   # add --can-relay or --can-exit if needed\n'
    fi

    if [ "$vnet_disabled" -eq 0 ] && systemctl is-active -q firewalld 2>/dev/null; then
        adapter=$(adapter_name)
        warn "firewalld is active; if peers cannot reach services on this node over ${adapter}, run:"
        printf '  sudo firewall-cmd --permanent --zone=trusted --add-interface=%s && sudo firewall-cmd --reload\n' "$adapter" >&2
    fi
}

install_node() {
    fetch_binary "i3t" "${WORK}/i3t"
    if [ "$OS" = "macos" ]; then
        install_node_launchd
    elif has_systemd; then
        install_node_systemd
    else
        install_node_plain
    fi
}

# Prints the controller's log for this start once the one-time admin token is in it (a line indented by four spaces),
# the service has failed, or 30 seconds have passed. Uses the invocation ID when available, falling back to a UTC
# timestamp so a caller's TZ cannot drift from the system journal's timezone.
show_first_start() {
    invocation="$1"
    since="$2"
    out=""
    i=0
    while [ "$i" -lt 30 ]; do
        if [ -n "$invocation" ]; then
            out=$($SUDO journalctl _SYSTEMD_INVOCATION_ID="$invocation" --no-pager -o cat 2>/dev/null || true)
        else
            out=$($SUDO journalctl -u i3t-controller --since "$since" --no-pager -o cat 2>/dev/null || true)
        fi
        if printf '%s\n' "$out" | grep -q '^    [^ ]'; then
            log "First start output (contains the one-time admin token):"
            printf '%s\n' "$out"
            return
        fi
        if $SUDO systemctl is-failed -q i3t-controller 2>/dev/null; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done
    printf '%s\n' "$out"
    warn "the admin token did not show up; check: sudo journalctl -u i3t-controller --no-pager"
}

# Restarts the controller service. `$1` is 1 when this start is the first one on an empty database: its output has
# the one-time admin token in it, so it is shown.
restart_controller() {
    since=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
    $SUDO systemctl restart i3t-controller
    if [ "$1" -eq 1 ]; then
        invocation=$($SUDO systemctl show -p InvocationID --value i3t-controller 2>/dev/null || true)
        show_first_start "$invocation" "$since"
    else
        log "i3t-controller upgraded and running"
    fi
}

# Whether the installed controller already knows which database to use: the file this script writes, or a setting
# someone put into /etc/i3t/controller.env by hand.
controller_has_database() {
    if $SUDO test -f /var/lib/i3t-controller/database.url; then
        return 0
    fi
    $SUDO test -f /etc/i3t/controller.env \
        && $SUDO grep -q -e '^[[:space:]]*I3T_DATABASE_URL=' -e '^[[:space:]]*I3T_CONTROLLER_ARGS=.*--database-url' /etc/i3t/controller.env
}

install_controller() {
    case "$DATABASE_URL" in
        *"
"*) die "invalid --database-url value (it must be a single line)" ;;
    esac

    fetch_binary "i3t-controller" "${WORK}/i3t-controller"
    fetch_binary "i3tctl" "${WORK}/i3tctl"

    # Releases up to 0.1.34 keep their data in a file and take no database. This script may be newer than the release
    # it installs, so ask the program that is about to be installed. When it cannot be asked (a temporary directory
    # mounted noexec), assume it needs one, as every later release does.
    needs_database=1
    chmod 0755 "${WORK}/i3t-controller"
    if controller_help=$("${WORK}/i3t-controller" --help 2>/dev/null) \
        && ! printf '%s\n' "$controller_help" | grep -q -- '--database-url'; then
        needs_database=0
    fi

    # Stop before installing anything when the controller is going to be (re)started without a database:
    # it cannot start without one, and an older install has none configured.
    if [ "$needs_database" -eq 1 ] && has_systemd && [ -z "$DATABASE_URL" ] && ! controller_has_database; then
        if [ -n "$PUBLIC_ADDR" ] || $SUDO systemctl is-active -q i3t-controller 2>/dev/null; then
            die "the controller stores its data in PostgreSQL: pass --database-url postgres://USER:PASSWORD@HOST/DBNAME (or set I3T_DATABASE_URL). This script does not install PostgreSQL; deploy/docker/compose.yaml starts the controller together with one. Data of an older install (/var/lib/i3t-controller/controller.db) is not carried over."
        fi
    fi
    if [ "$needs_database" -eq 0 ] && [ -n "$DATABASE_URL" ]; then
        warn "this release of the controller keeps its data in a file and does not use PostgreSQL; the connection string is saved for the release that does"
    fi

    $SUDO install -d -m 0755 /usr/local/bin
    log "Installing i3t-controller and i3tctl to /usr/local/bin"
    install_binary_atomic "${WORK}/i3t-controller" /usr/local/bin/i3t-controller 0 0
    install_binary_atomic "${WORK}/i3tctl" /usr/local/bin/i3tctl 0 0

    if ! has_systemd; then
        log "Installed /usr/local/bin/i3t-controller and /usr/local/bin/i3tctl (systemd not detected)"
        printf '\nNext steps:\n'
        if [ "$needs_database" -eq 1 ]; then
            printf '  export I3T_DATABASE_URL=postgres://USER:PASSWORD@HOST/DBNAME\n'
        fi
        printf '  i3t-controller --data-dir /var/lib/i3t-controller --public-addr <public-address>:20331\n'
        return
    fi

    log "Setting up system user i3t-controller and systemd service"
    ensure_system_user "i3t-controller" "/var/lib/i3t-controller"
    write_controller_service "${WORK}/i3t-controller.service"
    $SUDO install -D -m 0644 "${WORK}/i3t-controller.service" /etc/systemd/system/i3t-controller.service

    # The admin token is printed when the controller first starts on an empty database: on a new install (no key
    # yet), and when an install that kept its data in a file gets its database.
    first_start=0
    if ! $SUDO test -f /var/lib/i3t-controller/controller.key; then
        first_start=1
    elif [ "$needs_database" -eq 1 ] && [ -n "$DATABASE_URL" ] && ! controller_has_database; then
        first_start=1
    fi

    if [ -n "$DATABASE_URL" ]; then
        # The connection string holds the database password: it goes into the data directory, readable by the service
        # user only, where the controller looks for it when it is not given on the command line.
        log "Writing the database connection string to /var/lib/i3t-controller/database.url"
        printf '%s\n' "$DATABASE_URL" > "${WORK}/database.url"
        $SUDO install -d -o i3t-controller -g i3t-controller -m 0700 /var/lib/i3t-controller
        $SUDO install -o i3t-controller -g i3t-controller -m 0600 "${WORK}/database.url" /var/lib/i3t-controller/database.url
    fi

    if [ -n "$PUBLIC_ADDR" ]; then
        if $SUDO test -f /etc/i3t/controller.env; then
            {
                printf 'I3T_PUBLIC_ADDR=%s\n' "$PUBLIC_ADDR"
                $SUDO grep -v '^[[:space:]]*I3T_PUBLIC_ADDR=' /etc/i3t/controller.env || true
            } > "${WORK}/controller.env"
        else
            cat <<EOF > "${WORK}/controller.env"
I3T_PUBLIC_ADDR=${PUBLIC_ADDR}
# Optional extra flags, see \`i3t-controller --help\`:
# I3T_CONTROLLER_ARGS=--listen 0.0.0.0:20331
EOF
        fi
        $SUDO install -D -m 0644 "${WORK}/controller.env" /etc/i3t/controller.env
    elif ! $SUDO test -f /etc/i3t/controller.env; then
        cat <<'EOF' > "${WORK}/controller.env"
# Set the public address reachable by all nodes before starting i3t-controller:
# I3T_PUBLIC_ADDR=ctl.example.com:20331
# I3T_CONTROLLER_ARGS=--listen 0.0.0.0:20331
EOF
        $SUDO install -D -m 0644 "${WORK}/controller.env" /etc/i3t/controller.env
    fi

    $SUDO systemctl daemon-reload

    if [ -n "$PUBLIC_ADDR" ]; then
        log "Enabling and starting i3t-controller.service"
        $SUDO systemctl enable i3t-controller >/dev/null
        restart_controller "$first_start"
    elif $SUDO systemctl is-active -q i3t-controller 2>/dev/null; then
        log "Restarting i3t-controller.service"
        restart_controller "$first_start"
    else
        log "Installation complete!"
        printf '\nNext steps:\n'
        printf '  Edit /etc/i3t/controller.env and set I3T_PUBLIC_ADDR=<public-address>:20331\n'
        if [ "$needs_database" -eq 1 ] && ! controller_has_database; then
            printf '  Run this script again with --controller --database-url postgres://USER:PASSWORD@HOST/DBNAME\n'
        fi
        printf '  sudo systemctl enable --now i3t-controller\n'
        printf '  sudo journalctl -u i3t-controller -n 30 --no-pager   # get the initial admin token\n'
    fi
}

uninstall_node() {
    if [ "$OS" = "macos" ]; then
        log "Stopping and removing the launchd daemon"
        $SUDO launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null || true
        launchd_wait_stopped
        $SUDO rm -f "$LAUNCHD_PLIST" "$NEWSYSLOG_CONF"
    elif has_systemd; then
        log "Stopping and disabling i3t.service"
        $SUDO systemctl disable --now i3t 2>/dev/null || true
        $SUDO rm -f /etc/systemd/system/i3t.service
        $SUDO rm -rf /etc/systemd/system/i3t.service.d
        $SUDO rm -f /etc/polkit-1/rules.d/50-i3t-resolved.rules
        $SUDO systemctl daemon-reload
    fi
    if [ "$OS" = "linux" ] && has_systemd; then
        # On systemd installs, `systemctl disable --now i3t` above already ran ExecStopPost as user i3t.
        # Only run the root-owned immutable binary for fallback cleanup — never the i3t-writable binary.
        if ! $SUDO test -L "$ROOT_BIN_DIR" && ! $SUDO test -L "$ROOT_BIN" && $SUDO test -f "$ROOT_BIN" && $SUDO test -x "$ROOT_BIN"; then
            $SUDO "$ROOT_BIN" network cleanup >/dev/null 2>&1 || true
        fi
    elif [ -x /usr/local/bin/i3t ]; then
        $SUDO /usr/local/bin/i3t network cleanup >/dev/null 2>&1 || true
    fi
    $SUDO rm -f /usr/local/bin/i3t
    $SUDO rm -rf "$ROOT_BIN_DIR" "$NODE_BIN_DIR" /opt/i3t/bin
    if [ "$PURGE" -eq 1 ]; then
        log "Purging ${STATE_DIR}"
        $SUDO rm -rf "$STATE_DIR" /opt/i3t
        if [ "$OS" = "macos" ]; then
            $SUDO rm -f "$LAUNCHD_LOG" "$LAUNCHD_LOG".*
        fi
    else
        log "Removed the i3t service and program (state kept in ${STATE_DIR}; pass --purge to remove)"
    fi
}

uninstall_controller() {
    if has_systemd; then
        log "Stopping and disabling i3t-controller.service"
        $SUDO systemctl disable --now i3t-controller 2>/dev/null || true
        $SUDO rm -f /etc/systemd/system/i3t-controller.service
        $SUDO rm -rf /etc/systemd/system/i3t-controller.service.d
        $SUDO systemctl daemon-reload
    fi
    $SUDO rm -f /usr/local/bin/i3t-controller /usr/local/bin/i3tctl
    if [ "$PURGE" -eq 1 ]; then
        log "Purging /var/lib/i3t-controller and /etc/i3t (the PostgreSQL database is left as it is)"
        $SUDO rm -rf /var/lib/i3t-controller /etc/i3t
    else
        log "Removed i3t-controller service and binaries (the key and settings are kept in /var/lib/i3t-controller and /etc/i3t; pass --purge to remove. The PostgreSQL database is left as it is)"
    fi
}

main() {
    parse_args "$@"
    detect_platform
    detect_sudo

    if [ "$UNINSTALL" -eq 1 ]; then
        if [ "$MODE" = "controller" ]; then
            uninstall_controller
        else
            uninstall_node
        fi
        return
    fi

    WORK=$(mktemp -d)
    trap cleanup_work EXIT HUP INT TERM

    if [ "$MODE" = "controller" ]; then
        install_controller
    else
        install_node
    fi
}

main "$@"
