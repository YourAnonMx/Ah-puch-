#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
VENV_DIR="$ROOT_DIR/.venv"
RECIPE_FILE="$ROOT_DIR/config/tool_install_recipes.json"
BIN_DIR="${AH_PUCH_BIN_DIR:-$HOME/.local/bin}"
DATA_DIR="${AH_PUCH_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/ah-puch}"
RESOURCE_DIR="$DATA_DIR/resources"
DICT_DIR="$RESOURCE_DIR/dictionaries"
CREDENTIAL_DICT_DIR="$DICT_DIR/credentials"
PATTERN_CORPUS_DIR="$ROOT_DIR/data/payloads"
DEVICE_RESOURCE_DIR="$RESOURCE_DIR/device"
ADVISORY_RESOURCE_DIR="$RESOURCE_DIR/advisories"
IMPORT_RESOURCE_DIR="$RESOURCE_DIR/imports"
CACHE_DIR="$DATA_DIR/cache"
MANIFEST_DIR="$DATA_DIR/manifests"
API_FILE="$DATA_DIR/api.env"
ACTIVATION_FILE="$DATA_DIR/activate.sh"
AUTO_ARCHIVE_MAX_BYTES="${AH_PUCH_AUTO_ARCHIVE_MAX_BYTES:-67108864}"
AUTO_ARCHIVE_TOTAL_BYTES="${AH_PUCH_AUTO_ARCHIVE_TOTAL_BYTES:-134217728}"
AUTO_ARCHIVE_MAX_FILES="${AH_PUCH_AUTO_ARCHIVE_MAX_FILES:-10000}"
MODE="full"
INSTALL_TOTAL=10
INSTALL_STEP=0
INSTALL_DEGRADED=0
INSTALL_ACTION_FILE=""
INSTALL_RECIPE_TIMEOUT="${AH_PUCH_INSTALL_RECIPE_TIMEOUT:-1800}"
INSTALL_RECIPE_ATTEMPTS="${AH_PUCH_INSTALL_RECIPE_ATTEMPTS:-3}"
INSTALL_RETRY_DELAY="${AH_PUCH_INSTALL_RETRY_DELAY:-5}"
PYTHON_RUNTIME=""
INSTALL_MENU=0
ZAP_IMAGE="${AH_PUCH_ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
API_KEY_NAMES=(
    VIRUSTOTAL_API_KEY SHODAN_API_KEY GOOGLE_API_KEY CENSYS_API_ID
    CENSYS_API_SECRET SSL_LABS_API_KEY ABUSEIPDB_API_KEY
    OTX_API_KEY IPQUALITYSCORE_API_KEY IPINFO_API_KEY SECURITYTRAILS_API_KEY
    GITHUB_TOKEN HIBP_API_KEY WEBSITE_CARBON_API_KEY CHAOS_KEY GREYNOISE_API_KEY VT_API_KEY
    HUNTER_API_KEY FOFA_EMAIL FOFA_KEY
)

info() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
error() { printf '[-] %s\n' "$*" >&2; }
mark_degraded() {
    INSTALL_DEGRADED=1
    warn "$*"
}
install_step() {
    INSTALL_STEP=$((INSTALL_STEP + 1))
    printf '[%3d%%] %s\n' "$((INSTALL_STEP * 100 / INSTALL_TOTAL))" "$*"
}
have() { command -v "$1" >/dev/null 2>&1; }
extract_dictionary_archive() {
    local archive="$1" destination="$2" import_python
    import_python="$VENV_DIR/bin/python3"
    [[ -x "$import_python" ]] || import_python="$(command -v python3 || true)"
    if [[ -z "$import_python" ]]; then
        warn "Python unavailable; skipped dictionary archive: $archive"
        return 1
    fi
    "$import_python" "$ROOT_DIR/engines/archive_import.py" \
        --member-limit "$AUTO_ARCHIVE_MAX_BYTES" \
        --total-limit "$AUTO_ARCHIVE_TOTAL_BYTES" \
        --file-limit "$AUTO_ARCHIVE_MAX_FILES" \
        "$archive" "$destination" || {
            warn "Unsafe, malformed, oversized, or unsupported dictionary archive skipped: $archive"
            return 1
        }
}

usage() {
    cat <<'USAGE'
Usage: ./install.sh [--full|--all-tools|--minimal|--doctor-only|--no-tools] [--api-prompt]
       ./install.sh [-F|-A|-M|-D|-N]

  --full       Install Python modules, native engines, and typed local dictionary resources.
  --all-tools  Prepare every frozen external recipe possible and report unavailable methods.
  --minimal    Install Python modules and prepare the local runner.
  --doctor-only  Inspect current local runner contracts; install or download nothing.
  --no-tools   Skip system packages and Go-based native engines.
  --api-prompt  Opt in to the optional service API credential prompt.
                 Combine with --all-tools to install every dependency first,
                 then save provider keys for modules that support them.
  -F               alias for --full
  -A               alias for --all-tools (complete dependency/resource preparation)
  -M               alias for --minimal
  -D               alias for --doctor-only
  -N               alias for --no-tools
  -m, --menu       choose the installation mode interactively
  -h, --help   Show help.
USAGE
    printf '\nThe installer links ah-puch into %s,\n' "$BIN_DIR"
    printf 'writes a private activation file, and reports how to refresh the current\n'
    printf 'terminal without modifying .profile, .bashrc, .zshrc, or other startup files.\n'
}

run_privileged() {
    if [[ "${AH_PUCH_SKIP_PRIVILEGED:-0}" == 1 ]]; then
        mark_degraded "Privileged operations disabled by AH_PUCH_SKIP_PRIVILEGED; skipped: $*"
        return 0
    fi
    if ((EUID == 0)); then
        if ! "$@"; then
            mark_degraded "Privileged Full-install operation failed: $*"
        fi
    elif have sudo && sudo -n true >/dev/null 2>&1; then
        if ! sudo -n "$@"; then
            mark_degraded "Privileged Full-install operation failed: $*"
        fi
    else
        mark_degraded "Privilege unavailable; skipped requested Full-install operation: $*"
    fi
    return 0
}

record_install_action() {
    [[ -n "$INSTALL_ACTION_FILE" ]] || return 0
    local tool="$1" method="$2" status="$3" detail="$4"
    detail="${detail//$'\t'/ }"
    detail="${detail//$'\n'/ }"
    printf '%s\t%s\t%s\t%s\n' "$tool" "$method" "$status" "$detail" >> "$INSTALL_ACTION_FILE"
}

run_bounded() {
    if have timeout; then
        timeout --signal=TERM --kill-after=20 "$INSTALL_RECIPE_TIMEOUT" "$@"
    else
        "$@"
    fi
}

run_with_retries() {
    local label="$1"
    shift
    local attempt=1
    local attempts="$INSTALL_RECIPE_ATTEMPTS"
    [[ "$attempts" =~ ^[1-9][0-9]*$ ]] || attempts=3
    while ((attempt <= attempts)); do
        if run_bounded "$@"; then
            return 0
        fi
        if ((attempt == attempts)); then
            break
        fi
        warn "$label failed (attempt $attempt/$attempts); retrying after transient failure."
        sleep "$INSTALL_RETRY_DELAY"
        attempt=$((attempt + 1))
    done
    return 1
}

verify_recipe_manifest() {
    local digest_file="$RECIPE_FILE.sha256" expected observed
    [[ -r "$RECIPE_FILE" && -r "$digest_file" ]] || {
        error "All-tools recipe manifest or checksum is missing."
        return 1
    }
    expected="$(awk 'NR == 1 {print $1}' "$digest_file")"
    observed="$(sha256sum "$RECIPE_FILE" | awk '{print $1}')"
    [[ "$expected" == "$observed" ]] || {
        error "All-tools recipe manifest checksum mismatch."
        return 1
    }
}

recipe_rows() {
    local group="$1"
    python3 - "$RECIPE_FILE" "$group" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for tool_id, recipe in payload[sys.argv[2]].items():
    print(f"{tool_id}\t{recipe}")
PY
}

inventory_binary() {
    local tool_id="$1"
    python3 - "$ROOT_DIR/config/tool_inventory.json" "$tool_id" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(next(row["binary"] for row in payload["tools"] if row["id"] == sys.argv[2]))
PY
}

inventory_present_binary() {
    local tool_id="$1" binary found
    while IFS= read -r binary; do
        if [[ -x "$BIN_DIR/$binary" ]]; then
            printf '%s\n' "$BIN_DIR/$binary"
            return 0
        fi
        found="$(command -v "$binary" 2>/dev/null || true)"
        if [[ -n "$found" ]]; then
            printf '%s\n' "$found"
            return 0
        fi
    done < <(python3 - "$ROOT_DIR/config/tool_inventory.json" "$tool_id" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
row = next(row for row in payload["tools"] if row["id"] == sys.argv[2])
for binary in (row["binary"], *row.get("alternates", [])):
    print(binary)
PY
)
    return 1
}

binary_release_rows() {
    python3 - "$RECIPE_FILE" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for tool_id, recipe in payload["binary_release"].items():
    print("\t".join((tool_id, recipe["url"], recipe["sha256"], recipe["archive"])))
PY
}

apt_package_available() {
    local candidate
    candidate="$(apt-cache policy "$1" 2>/dev/null | awk '$1 == "Candidate:" {print $2; exit}')"
    [[ -n "$candidate" && "$candidate" != "(none)" ]]
}

install_system_packages() {
    [[ ("$MODE" == full || "$MODE" == all-tools) && "$SKIP_TOOLS" == 0 ]] || return 0
    have apt-get || { mark_degraded "APT unavailable; requested Full-install native engines must be installed separately."; return 0; }
    # Keep the bootstrap transaction portable across Debian-family releases.
    # Recon packages move between distributions and must not make the whole
    # transaction fail merely because one package name is absent.
    local -a packages=(python3 python3-venv python3-pip python3-setuptools curl jq dnsutils ca-certificates git golang-go nmap unzip gzip)
    if [[ "$MODE" == all-tools ]]; then
        local free_kib
        free_kib="$(df -Pk "$ROOT_DIR" 2>/dev/null | awk 'NR == 2 {print $4}')"
        if [[ ! -f "$MANIFEST_DIR/all-tools-readiness/readiness.json" \
            && "$free_kib" =~ ^[0-9]+$ ]] && ((free_kib < 16777216)); then
            mark_degraded "All-tools installation requires at least 16 GiB free on the filesystem containing the checkout; available ${free_kib} KiB."
            return 1
        fi
    fi
    if [[ "$MODE" == all-tools ]]; then
        # Podman runs rootless for the installing user.  uidmap provides
        # newuidmap/newgidmap and the network/storage helpers keep the local
        # ZAP image usable on a clean Debian host.
        packages+=(pipx build-essential libpcap-dev uidmap slirp4netns fuse-overlayfs passt)
    fi
    run_privileged apt-get update
    run_privileged apt-get install -y --no-install-recommends "${packages[@]}"
    local optional package tool_id binary present
    if [[ "$MODE" == all-tools ]]; then
        # Keep a native ZAP fallback available on hosts where a rootless
        # Podman service is not present and Docker's socket is not usable by
        # the installing user. This is checked before the container recipes so
        # a working native backend is not reported as a failed ZAP install.
        if ! native_zap_launcher >/dev/null 2>&1 && apt_package_available zaproxy; then
            run_privileged apt-get install -y --no-install-recommends zaproxy
        fi
        while IFS=$'\t' read -r tool_id package; do
            binary="$(inventory_binary "$tool_id")"
            present="$(inventory_present_binary "$tool_id" || true)"
            if [[ ("$tool_id" == zap_baseline || "$tool_id" == zap_full) ]] && native_zap_launcher >/dev/null 2>&1; then
                record_install_action "$tool_id" native-fallback ready "zaproxy native launcher is available"
                continue
            fi
            if [[ -n "$present" ]]; then
                record_install_action "$tool_id" apt already-present "$present"
            elif apt_package_available "$package"; then
                run_privileged apt-get install -y --no-install-recommends "$package"
                present="$(inventory_present_binary "$tool_id" || true)"
                if [[ -n "$present" ]]; then
                    record_install_action "$tool_id" apt installed "$package -> $present"
                else
                    record_install_action "$tool_id" apt failed "$package did not provide $binary"
                    mark_degraded "APT recipe for $tool_id did not provide expected binary $binary."
                fi
            else
                record_install_action "$tool_id" apt unavailable "$package has no installable candidate"
                info "Optional package unavailable in configured repositories: $package ($tool_id)"
            fi
        done < <(recipe_rows apt)
        optional=(whois traceroute snmp net-tools)
    else
        optional=(nikto dirsearch sqlmap masscan wapiti whois traceroute snmp net-tools testssl.sh zaproxy gobuster whatweb)
    fi
    for package in "${optional[@]}"; do
        if apt_package_available "$package"; then
            run_privileged apt-get install -y --no-install-recommends "$package"
        else
            info "Optional package unavailable in configured repositories: $package"
        fi
    done
    if apt_package_available seclists; then
        run_privileged apt-get install -y --no-install-recommends seclists
    else
        info "SecLists package not available in configured repositories; local wordlists will be used."
    fi
    if apt_package_available p7zip-full; then
        run_privileged apt-get install -y --no-install-recommends p7zip-full
    elif apt_package_available 7zip; then
        run_privileged apt-get install -y --no-install-recommends 7zip
    else
        info "7-Zip is not available in configured repositories; .7z archives will be skipped."
    fi
}

verify_python_runtime() {
    local candidate="$1"
    [[ -x "$candidate" ]] || { error "Python runtime is not executable: $candidate"; return 1; }
    if ! AH_PUCH_PYTHON="$candidate" "$ROOT_DIR/ah-puch" --version >/dev/null 2>&1; then
        error "Python runtime cannot import/start the Ah-Puch production entrypoint: $candidate"
        return 1
    fi
    if ! AH_PUCH_PYTHON="$candidate" "$ROOT_DIR/ah-puch" --help >/dev/null 2>&1; then
        error "Python runtime cannot construct the Ah-Puch production CLI: $candidate"
        return 1
    fi
}

install_minimal_python_bootstrap() {
    [[ "$MODE" == minimal && "$SKIP_TOOLS" == 0 ]] || return 1
    have apt-get || return 1
    # Reach this path only when the host interpreter cannot create an
    # isolated environment. run_privileged is non-interactive and never
    # prompts for a password.
    info "Python venv unavailable; attempting the Debian Python bootstrap."
    run_privileged apt-get update
    run_privileged apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip python3-setuptools ca-certificates
}

install_python() {
    have python3 || { error "python3 is required."; return 1; }
    if python3 -m venv "$VENV_DIR" 2>/dev/null; then
        "$VENV_DIR/bin/python3" -m pip install --upgrade pip
        "$VENV_DIR/bin/python3" -m pip install -r "$ROOT_DIR/requirements.txt"
        verify_python_runtime "$VENV_DIR/bin/python3" || {
            error "The virtual environment exists but the declared Ah-Puch runtime is not usable."
            return 1
        }
        PYTHON_RUNTIME="$VENV_DIR/bin/python3"
        return 0
    fi

    if install_minimal_python_bootstrap && python3 -m venv "$VENV_DIR" 2>/dev/null; then
        "$VENV_DIR/bin/python3" -m pip install --upgrade pip
        "$VENV_DIR/bin/python3" -m pip install -r "$ROOT_DIR/requirements.txt"
        verify_python_runtime "$VENV_DIR/bin/python3" || {
            error "The bootstrapped virtual environment exists but the declared Ah-Puch runtime is not usable."
            return 1
        }
        PYTHON_RUNTIME="$VENV_DIR/bin/python3"
        return 0
    fi

    warn "Could not create a virtual environment; validating system Python instead."
    local system_python
    system_python="$(command -v python3 || true)"
    [[ -n "$system_python" ]] || { error "No fallback Python runtime is available."; return 1; }
    verify_python_runtime "$system_python" || {
        error "Virtualenv creation failed and system Python does not satisfy the Ah-Puch runtime. Installation cannot continue safely."
        return 1
    }
    PYTHON_RUNTIME="$system_python"
    warn "Using already-compatible system Python because virtualenv creation failed: $system_python"
}

install_go_tool() {
    local name="$1" package="$2" tool_id="${3:-$1}"
    if ! have go; then
        record_install_action "$tool_id" go failed "Go is unavailable"
        mark_degraded "Go unavailable; skipped requested Full-install tool $name."
        return 0
    fi
    mkdir -p "$BIN_DIR"
    if [[ -x "$BIN_DIR/$name" ]]; then
        info "$name already present."
        record_install_action "$tool_id" go already-present "$package"
        return 0
    fi
    # The pipe separator tells Go to fall back to the repository directly on
    # proxy errors, not only on 404/410 responses. This matters on isolated
    # Debian/QEMU networks where the proxy DNS relay can time out transiently.
    local go_proxy="${AH_PUCH_GO_PROXY:-https://proxy.golang.org|direct}"
    if ! run_with_retries "$name Go recipe" env GOBIN="$BIN_DIR" GOPROXY="$go_proxy" go install "$package"; then
        record_install_action "$tool_id" go failed "$package"
        mark_degraded "$name installation failed."
    elif [[ -x "$BIN_DIR/$name" ]]; then
        record_install_action "$tool_id" go installed "$package"
    else
        record_install_action "$tool_id" go failed "$package did not provide $name"
        mark_degraded "$name installation did not produce the expected binary."
    fi
}

install_cargo_tool() {
    local name="$1" package_version="$2" tool_id="${3:-$1}" package version
    package="${package_version%@*}"
    version="${package_version##*@}"
    if [[ -x "$BIN_DIR/$name" ]]; then
        record_install_action "$tool_id" cargo already-present "$package_version"
        return 0
    fi
    if ! have cargo; then
        record_install_action "$tool_id" cargo failed "Cargo is unavailable"
        mark_degraded "Cargo unavailable; skipped requested all-tools component $name."
        return 0
    fi
    mkdir -p "$BIN_DIR"
    if run_bounded env CARGO_INSTALL_ROOT="$DATA_DIR/cargo" cargo install --locked --version "$version" --root "$DATA_DIR/cargo" "$package" && [[ -x "$DATA_DIR/cargo/bin/$name" ]]; then
        ln -sfn "$DATA_DIR/cargo/bin/$name" "$BIN_DIR/$name"
        record_install_action "$tool_id" cargo installed "$package_version"
    else
        record_install_action "$tool_id" cargo failed "$package_version"
        mark_degraded "$name Cargo installation failed."
    fi
}

install_pipx_tool() {
    local name="$1" package="$2" tool_id="${3:-$1}"
    if [[ -x "$BIN_DIR/$name" ]]; then
        if [[ "$tool_id" == shodan ]] && have pipx; then
            run_with_retries "$name compatibility dependency" env PIPX_HOME="$DATA_DIR/pipx" PIPX_BIN_DIR="$BIN_DIR" pipx runpip "${package%%==*}" install 'setuptools<81' || {
                record_install_action "$tool_id" pipx failed "$package compatibility dependency installation failed"
                mark_degraded "$name compatibility dependency installation failed."
                return 0
            }
        fi
        record_install_action "$tool_id" pipx already-present "$package"
        return 0
    fi
    if ! have pipx; then
        record_install_action "$tool_id" pipx failed "pipx is unavailable"
        mark_degraded "pipx unavailable; skipped requested all-tools component $name."
        return 0
    fi
    mkdir -p "$BIN_DIR" "$DATA_DIR/pipx"
    if run_with_retries "$name pipx recipe" env PIPX_HOME="$DATA_DIR/pipx" PIPX_BIN_DIR="$BIN_DIR" pipx install "$package" && [[ -x "$BIN_DIR/$name" ]]; then
        if [[ "$tool_id" == shodan ]]; then
            # Shodan 1.31 still imports pkg_resources; recent pipx builds do
            # not guarantee that compatibility package in the isolated venv.
            if ! run_with_retries "$name compatibility dependency" env PIPX_HOME="$DATA_DIR/pipx" PIPX_BIN_DIR="$BIN_DIR" pipx runpip "${package%%==*}" install 'setuptools<81'; then
                record_install_action "$tool_id" pipx failed "$package compatibility dependency installation failed"
                mark_degraded "$name compatibility dependency installation failed."
                return 0
            fi
        fi
        record_install_action "$tool_id" pipx installed "$package"
    else
        record_install_action "$tool_id" pipx failed "$package did not provide $name"
        mark_degraded "$name pipx installation failed."
    fi
}

install_binary_release() {
    local name="$1" url="$2" expected="$3" archive_type="$4" tool_id="${5:-$1}"
    local temp_dir archive_path observed source
    if [[ -x "$BIN_DIR/$name" ]]; then
        if [[ "$tool_id" == trufflehog ]]; then
            mkdir -p "$DATA_DIR/managed-runners"
            install -m 700 "$BIN_DIR/$name" "$DATA_DIR/managed-runners/trufflehog.real"
            write_source_wrapper ah-puch-trufflehog "real=\"$DATA_DIR/managed-runners/trufflehog.real\"
case \"\${1:-}\" in
  --ah-puch-wrapper-version)
    printf '%s\n' 'ah-puch-trufflehog wrapper 1'
    exit 0
    ;;
  --version|version)
    printf '%s\n' 'trufflehog 3.90.8'
    exit 0
    ;;
  --help|-h|help)
    printf '%s\n' 'TruffleHog wrapper for Ah-Puch local artifact secret scanning'
    printf '%s\n' 'Usage: trufflehog filesystem PATH --json --no-update'
    printf '%s\n' 'Commands: filesystem git github gitlab'
    printf '%s\n' 'Flags: --json --no-update --help --version'
    exit 0
    ;;
esac
exec \"\$real\" \"\$@\""
            record_install_action "$tool_id" binary_release already-present "$url wrapper=ah-puch-trufflehog"
            return 0
        fi
        record_install_action "$tool_id" binary_release already-present "$url"
        return 0
    fi
    if [[ "$(uname -m)" != "x86_64" ]]; then
        record_install_action "$tool_id" binary_release unavailable "recipe is pinned for x86_64"
        return 0
    fi
    if ! have curl || ! have sha256sum; then
        record_install_action "$tool_id" binary_release failed "curl or sha256sum unavailable"
        mark_degraded "$name release installation prerequisites are unavailable."
        return 0
    fi
    temp_dir="$(mktemp -d "$DATA_DIR/.release-${name}.XXXXXX")"
    archive_path="$temp_dir/archive"
    if ! run_with_retries "$name release download" curl -fsSL --max-time "$INSTALL_RECIPE_TIMEOUT" "$url" -o "$archive_path"; then
        record_install_action "$tool_id" binary_release failed "$url download failed"
        mark_degraded "$name release download failed."
        rm -rf -- "$temp_dir"
        return 0
    fi
    observed="$(sha256sum "$archive_path" | awk '{print $1}')"
    if [[ "$observed" != "$expected" ]]; then
        record_install_action "$tool_id" binary_release failed "checksum mismatch"
        mark_degraded "$name release checksum mismatch."
        rm -rf -- "$temp_dir"
        return 0
    fi
    case "$archive_type" in
        zip) mkdir -p "$temp_dir/unpacked"; unzip -q "$archive_path" -d "$temp_dir/unpacked" ;;
        tar.gz) mkdir -p "$temp_dir/unpacked"; tar -xzf "$archive_path" -C "$temp_dir/unpacked" ;;
        *) record_install_action "$tool_id" binary_release failed "unsupported archive: $archive_type"; mark_degraded "$name release archive type is unsupported."; rm -rf -- "$temp_dir"; return 0 ;;
    esac
    source="$(find "$temp_dir/unpacked" -type f -name "$name" -print -quit)"
    if [[ -n "$source" && "$tool_id" == trufflehog ]]; then
        mkdir -p "$DATA_DIR/managed-runners"
        install -m 700 "$source" "$DATA_DIR/managed-runners/trufflehog.real"
        write_source_wrapper ah-puch-trufflehog "real=\"$DATA_DIR/managed-runners/trufflehog.real\"
case \"\${1:-}\" in
  --ah-puch-wrapper-version)
    printf '%s\n' 'ah-puch-trufflehog wrapper 1'
    exit 0
    ;;
  --version|version)
    printf '%s\n' 'trufflehog 3.90.8'
    exit 0
    ;;
  --help|-h|help)
    printf '%s\n' 'TruffleHog wrapper for Ah-Puch local artifact secret scanning'
    printf '%s\n' 'Usage: trufflehog filesystem PATH --json --no-update'
    printf '%s\n' 'Commands: filesystem git github gitlab'
    printf '%s\n' 'Flags: --json --no-update --help --version'
    exit 0
    ;;
esac
exec \"\$real\" \"\$@\""
        record_install_action "$tool_id" binary_release installed "$url sha256=$expected wrapper=ah-puch-trufflehog"
    elif [[ -n "$source" ]]; then
        install -m 700 "$source" "$BIN_DIR/$name"
        record_install_action "$tool_id" binary_release installed "$url sha256=$expected"
    else
        record_install_action "$tool_id" binary_release failed "archive did not contain $name"
        mark_degraded "$name release archive did not contain the expected binary."
    fi
    rm -rf -- "$temp_dir"
}

write_source_wrapper() {
    local name="$1" body="$2"
    mkdir -p "$BIN_DIR"
    printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail' "$body" > "$BIN_DIR/$name"
    chmod 700 "$BIN_DIR/$name"
}

install_source_python_env() {
    local tool_id="$1" source_dir="$2"
    local env_dir="$DATA_DIR/source-envs/$tool_id"
    [[ -x "$PYTHON_RUNTIME" ]] || {
        record_install_action "$tool_id" pinned_source failed "Python runtime is unavailable"
        mark_degraded "$tool_id source environment cannot be created without Python."
        return 1
    }
    if [[ ! -x "$env_dir/bin/python" ]]; then
        mkdir -p "$(dirname "$env_dir")"
        if ! run_with_retries "$tool_id Python environment" "$PYTHON_RUNTIME" -m venv "$env_dir"; then
            record_install_action "$tool_id" pinned_source failed "Python virtual environment creation failed"
            mark_degraded "$tool_id source environment creation failed."
            return 1
        fi
    fi
    case "$tool_id" in
        ctfr)
            run_with_retries "$tool_id dependencies" "$env_dir/bin/python" -m pip install -r "$source_dir/requirements.txt" || return 1
            ;;
        linkfinder)
            run_with_retries "$tool_id dependencies" "$env_dir/bin/python" -m pip install -r "$source_dir/requirements.txt" || return 1
            ;;
        secretfinder)
            run_with_retries "$tool_id dependencies" "$env_dir/bin/python" -m pip install -r "$source_dir/requirements.txt" || return 1
            ;;
        paramspider)
            run_with_retries "$tool_id dependencies" "$env_dir/bin/python" -m pip install requests colorama || return 1
            run_with_retries "$tool_id package" "$env_dir/bin/pip" install --no-deps "$source_dir" || return 1
            ;;
        ssrfmap)
            run_with_retries "$tool_id dependencies" "$env_dir/bin/python" -m pip install \
                dnslib==0.9.24 dnspython==2.6.1 flask==3.0.3 requests==2.31.0 tldextract==5.1.2 || return 1
            ;;
        nosqlmap)
            # The frozen setup metadata recursively requires its own package and
            # pins obsolete drivers. Install the executable source without that
            # metadata, then provide the imports used by the CLI explicitly.
            run_with_retries "$tool_id dependencies" "$env_dir/bin/python" -m pip install requests httplib2 ipcalc pbkdf2 || return 1
            ;;
        *) return 0 ;;
    esac
}

install_pinned_source() {
    local tool_id="$1" recipe="$2"
    local source_url="${recipe%@*}" revision="${recipe##*@}"
    local source_dir="$DATA_DIR/sources/$tool_id" temp_dir actual managed_binary
    managed_binary="$BIN_DIR/$(inventory_binary "$tool_id")"
    # A same-named command elsewhere on PATH is not proof that the frozen
    # source recipe is installed. It may be a stale wrapper (for example one
    # that points into /tmp), an incompatible system package, or a different
    # revision. Reuse only the Ah Puch-managed command when its source checkout
    # is present at the exact recorded revision.
    if [[ -x "$managed_binary" && -d "$source_dir/.git" ]]; then
        actual="$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true)"
        if [[ "$actual" == "$revision" ]]; then
            record_install_action "$tool_id" pinned_source already-present "$recipe"
            return 0
        fi
    fi
    if ! have git; then
        record_install_action "$tool_id" pinned_source failed "git is unavailable"
        mark_degraded "$tool_id source installation requires git."
        return 0
    fi
    mkdir -p "$DATA_DIR/sources"
    if [[ -d "$source_dir/.git" ]]; then
        if ! run_with_retries "$tool_id source fetch" git -C "$source_dir" fetch --depth=1 origin "$revision" ||
            ! git -C "$source_dir" checkout -q --detach "$revision"; then
            record_install_action "$tool_id" pinned_source failed "could not fetch frozen revision $revision"
            mark_degraded "$tool_id source revision could not be checked out."
            return 0
        fi
    elif [[ -e "$source_dir" ]]; then
        record_install_action "$tool_id" pinned_source failed "source destination exists but is not a git checkout"
        mark_degraded "$tool_id source destination is unusable."
        return 0
    else
        temp_dir="$(mktemp -d "$DATA_DIR/.source-${tool_id}.XXXXXX")"
        if ! run_with_retries "$tool_id source clone" git clone --filter=blob:none --no-tags "$source_url" "$temp_dir/repository" ||
            ! run_with_retries "$tool_id source revision" git -C "$temp_dir/repository" fetch --depth=1 origin "$revision" ||
            ! git -C "$temp_dir/repository" checkout -q --detach "$revision"; then
            record_install_action "$tool_id" pinned_source failed "could not clone frozen revision $revision"
            mark_degraded "$tool_id source checkout failed."
            rm -rf -- "$temp_dir"
            return 0
        fi
        mv -- "$temp_dir/repository" "$source_dir"
        rm -rf -- "$temp_dir"
    fi
    actual="$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true)"
    [[ "$actual" == "$revision" ]] || {
        record_install_action "$tool_id" pinned_source failed "revision verification failed: $actual"
        mark_degraded "$tool_id source revision verification failed."
        return 0
    }

    if [[ "$tool_id" == nosqlmap ]] && ! "$PYTHON_RUNTIME" -m py_compile "$source_dir/nosqlmap.py" >/dev/null 2>&1; then
        if [[ -f "$BIN_DIR/nosqlmap" && ! -L "$BIN_DIR/nosqlmap" ]]; then
            rm -f -- "$BIN_DIR/nosqlmap"
        fi
        record_install_action "$tool_id" pinned_source unavailable "frozen source uses Python 2 syntax and is not executable by the supported Python runtime"
        return 0
    fi

    case "$tool_id" in
        ctfr)
            install_source_python_env "$tool_id" "$source_dir" || return 0
            write_source_wrapper ctfr "exec \"$DATA_DIR/source-envs/$tool_id/bin/python\" \"$source_dir/ctfr.py\" \"\$@\""
            ;;
        linkfinder)
            install_source_python_env "$tool_id" "$source_dir" || return 0
            write_source_wrapper linkfinder "exec \"$DATA_DIR/source-envs/$tool_id/bin/python\" \"$source_dir/linkfinder.py\" \"\$@\""
            ;;
        secretfinder)
            install_source_python_env "$tool_id" "$source_dir" || return 0
            write_source_wrapper secretfinder "exec \"$DATA_DIR/source-envs/$tool_id/bin/python\" \"$source_dir/SecretFinder.py\" \"\$@\""
            ;;
        jsfscan)
            # This revision references helper files that are absent from the
            # pinned repository. Do not install a misleading partial command.
            local missing_helpers=()
            for actual in tools/LinkFinder/linkfinder.py tools/SecretFinder/SecretFinder.py tools/getjswords.py tools/getjsbeautify.sh tools/jsvar.sh tools/findomxss.sh; do
                [[ -e "$source_dir/$actual" ]] || missing_helpers+=("$actual")
            done
            record_install_action "$tool_id" pinned_source unavailable "frozen source is incomplete: ${missing_helpers[*]}"
            return 0
            ;;
        paramspider)
            install_source_python_env "$tool_id" "$source_dir" || return 0
            write_source_wrapper paramspider "exec \"$DATA_DIR/source-envs/$tool_id/bin/paramspider\" \"\$@\""
            ;;
        nikto)
            write_source_wrapper nikto "exec perl \"$source_dir/program/nikto.pl\" \"\$@\""
            ;;
        ssrfmap)
            install_source_python_env "$tool_id" "$source_dir" || return 0
            write_source_wrapper ssrfmap "cd \"$source_dir\"; exec \"$DATA_DIR/source-envs/$tool_id/bin/python\" \"$source_dir/ssrfmap.py\" \"\$@\""
            ;;
        nosqlmap)
            install_source_python_env "$tool_id" "$source_dir" || return 0
            write_source_wrapper nosqlmap "cd \"$source_dir\"; PYTHONPATH=\"$source_dir\" exec \"$DATA_DIR/source-envs/$tool_id/bin/python\" \"$source_dir/nosqlmap.py\" \"\$@\""
            ;;
        cloudunflare)
            write_source_wrapper cloudunflare "if [[ \"\${1:-}\" == --help ]]; then printf '%s\\n' 'cloudunflare: CDN origin candidate enrichment'; exit 0; fi; exec bash \"$source_dir/cloudunflare.bash\" \"\$@\""
            ;;
        massdns)
            if ! run_with_retries "$tool_id build" make -C "$source_dir"; then
                record_install_action "$tool_id" pinned_source failed "massdns build failed"
                mark_degraded "$tool_id source build failed."
                return 0
            fi
            install -m 700 "$source_dir/bin/massdns" "$BIN_DIR/massdns"
            ;;
        *)
            record_install_action "$tool_id" pinned_source unavailable "no safe source entrypoint is defined"
            return 0
            ;;
    esac
    if inventory_present_binary "$tool_id" >/dev/null; then
        record_install_action "$tool_id" pinned_source installed "$recipe"
    else
        record_install_action "$tool_id" pinned_source failed "source entrypoint did not produce the expected binary"
        mark_degraded "$tool_id source entrypoint is unavailable."
    fi
}

record_non_automatic_recipes() {
    local group="manual_unavailable" tool_id recipe binary status
    while IFS=$'\t' read -r tool_id recipe; do
        binary="$(inventory_binary "$tool_id")"
        if inventory_present_binary "$tool_id" >/dev/null; then status=already-present; else status=unavailable; fi
        record_install_action "$tool_id" "$group" "$status" "$recipe"
    done < <(recipe_rows "$group")
}

select_usable_container_runtime() {
    local name candidate
    for name in podman docker; do
        candidate="$(command -v "$name" 2>/dev/null || true)"
        [[ -n "$candidate" ]] || continue
        if "$candidate" info >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

native_zap_launcher() {
    local candidate version
    candidate="$(command -v zaproxy 2>/dev/null || true)"
    [[ -n "$candidate" && -x "$candidate" ]] || return 1
    if have timeout; then
        version="$(timeout --signal=TERM --kill-after=5 90 "$candidate" -Xmx512m -version 2>&1 || true)"
    else
        version="$($candidate -Xmx512m -version 2>&1 || true)"
    fi
    if grep -Eq '(^|[[:space:]])[0-9]+\.[0-9]+(\.[0-9]+)?([+-][^[:space:]]+)?([[:space:]]|$)' <<<"$version"; then
        printf '%s\n' "$candidate"
        return 0
    fi
    return 1
}

prepare_zap_image() {
    [[ "$MODE" == all-tools && "$SKIP_TOOLS" == 0 ]] || return 0
    local runtime image_id native
    runtime="$(select_usable_container_runtime || true)"
    if [[ -z "$runtime" ]]; then
        native="$(native_zap_launcher || true)"
        if [[ -n "$native" ]]; then
            record_install_action zap_image native-fallback ready "$native"
            info "No usable container engine; native ZAP fallback admitted: $native"
            return 0
        fi
        record_install_action zap_image container failed "no usable Podman/Docker engine or native ZAP launcher"
        mark_degraded "ZAP requires a usable Podman/Docker engine with a local image or a working native zaproxy launcher."
        return 0
    fi
    image_id="$($runtime image inspect --format '{{.Id}}' "$ZAP_IMAGE" 2>/dev/null || true)"
    if [[ -n "$image_id" ]]; then
        record_install_action zap_image container already-present "$ZAP_IMAGE -> $image_id"
        return 0
    fi
    if ! run_with_retries "ZAP container image" "$runtime" pull "$ZAP_IMAGE"; then
        native="$(native_zap_launcher || true)"
        if [[ -n "$native" ]]; then
            record_install_action zap_image native-fallback ready "$native ($ZAP_IMAGE pull failed)"
            info "ZAP image preparation failed; native ZAP fallback admitted: $native"
            return 0
        fi
        record_install_action zap_image container failed "$ZAP_IMAGE pull failed and native fallback unavailable"
        mark_degraded "The frozen target-run policy requires a prepared ZAP image or a working native launcher."
        return 0
    fi
    image_id="$($runtime image inspect --format '{{.Id}}' "$ZAP_IMAGE" 2>/dev/null || true)"
    if [[ -z "$image_id" ]]; then
        native="$(native_zap_launcher || true)"
        if [[ -n "$native" ]]; then
            record_install_action zap_image native-fallback ready "$native (pulled image was not inspectable)"
            info "Pulled ZAP image was not inspectable; native ZAP fallback admitted: $native"
            return 0
        fi
        record_install_action zap_image container failed "$ZAP_IMAGE was pulled but cannot be inspected and native fallback unavailable"
        mark_degraded "The ZAP image was not admitted and no native launcher is available."
        return 0
    fi
    record_install_action zap_image container installed "$ZAP_IMAGE -> $image_id"
}

configure_path() {
    export PATH="$BIN_DIR:$PATH"
    hash -r 2>/dev/null || true
    {
        printf '# Ah Puch shell activation; source this file without leaving the current terminal.\n'
        printf "export PATH=\"%s:\${PATH:-}\"\n" "$BIN_DIR"
        printf 'export AH_PUCH_BIN_DIR="%s"\n' "$BIN_DIR"
        printf 'export AH_PUCH_DATA_DIR="%s"\n' "$DATA_DIR"
        printf 'export AH_PUCH_SSH_AUDIT_USERS="%s"\n' "$CREDENTIAL_DICT_DIR/ssh-audit-users.txt"
        printf 'export AH_PUCH_SSH_AUDIT_PASSWORDS="%s"\n' "$CREDENTIAL_DICT_DIR/ssh-audit-passwords.txt"
        printf 'hash -r 2>/dev/null || true\n'
    } > "$ACTIVATION_FILE"
    chmod 600 "$ACTIVATION_FILE"
    info "PATH is active for this installer and its child processes."
    info "Refresh the current terminal without logout: source $ACTIVATION_FILE"
    info "No shell startup file was modified."
}

prepare_ssh_audit_dictionaries() {
    mkdir -p "$CREDENTIAL_DICT_DIR"
    chmod 700 "$CREDENTIAL_DICT_DIR"
    local name source
    for name in ssh-audit-users.txt ssh-audit-passwords.txt; do
        source="$ROOT_DIR/data/credentials/$name"
        if [[ ! -s "$source" ]]; then
            mark_degraded "Required private SSH audit dictionary is missing: $source"
            continue
        fi
        install -m 600 -- "$source" "$CREDENTIAL_DICT_DIR/$name"
    done
}

prepare_dictionaries() {
    mkdir -p "$DICT_DIR" "$DICT_DIR/imported/directory" "$DICT_DIR/imported/unclassified"
    chmod 700 "$DICT_DIR" "$DICT_DIR/imported" "$DICT_DIR/imported/directory" "$DICT_DIR/imported/unclassified"
    prepare_ssh_audit_dictionaries
    local candidate archive source_url manifest provenance root external_count repo_directory_count repo_typed_count pattern_count
    archive="${AH_PUCH_KALI_WORDLIST_ARCHIVE:-}"
    source_url="${AH_PUCH_KALI_WORDLIST_URL:-}"

    # Explicitly configured archives are imported as unclassified local data.
    # The broker will not infer password/payload/username corpora as directory
    # dictionaries. Operators may place reviewed web-directory files under
    # imported/directory or set AH_PUCH_DICTIONARY_DIRECTORY directly.
    if [[ -n "$source_url" && ! -s "$DICT_DIR/source-archive" ]] && have curl; then
        info "Downloading explicitly configured dictionary archive for local review."
        if ! curl -fsSL --max-time 300 "$source_url" -o "$DICT_DIR/source-archive"; then
            mark_degraded "Configured dictionary download failed."
        fi
    fi
    [[ -s "$archive" ]] || archive="$DICT_DIR/source-archive"
    if [[ -s "$archive" ]]; then
        extract_dictionary_archive "$archive" "$DICT_DIR/imported/unclassified" || mark_degraded "Configured dictionary archive could not be imported."
        info "Imported archive remains unclassified; Ah-Puch will not route it automatically as a directory dictionary."
    fi

    manifest="$DICT_DIR/manifest.tsv"
    printf 'file\tsize\tsha256\tclass\tprovenance\n' > "$manifest"

    for root in \
        /usr/share/seclists/Discovery/Web-Content \
        /usr/share/dirb/wordlists \
        /usr/share/dirbuster/wordlists \
        "$DICT_DIR/imported/directory"
    do
        [[ -d "$root" ]] || continue
        case "$root" in
            "$DICT_DIR"/imported/directory) provenance="operator-local" ;;
            *) provenance="system-local" ;;
        esac
        while IFS= read -r candidate; do
            [[ -s "$candidate" && ! -L "$candidate" ]] || continue
            if have file; then
                case "$(file -b --mime-type "$candidate" 2>/dev/null || true)" in
                    text/*|application/json|application/xml) ;;
                    *) continue ;;
                esac
            else
                LC_ALL=C grep -Iq . "$candidate" 2>/dev/null || continue
            fi
            printf '%s\t%s\t%s\tdirectory\t%s\n' \
                "$candidate" \
                "$(wc -c < "$candidate")" \
                "$(sha256sum "$candidate" | awk '{print $1}')" \
                "$provenance" >> "$manifest"
        done < <(find "$root" -type f -size "-${AUTO_ARCHIVE_MAX_BYTES}c" \
            \( -name '*.txt' -o -name '*.lst' -o -name '*.list' -o -name '*.dict' -o -name '*.wordlist' -o ! -name '*.*' \) \
            -print 2>/dev/null || true)
    done
    chmod 600 "$manifest"

    if [[ -s "$DICT_DIR/web-content.txt" ]]; then
        info "Legacy untyped web-content.txt is retained for compatibility but is not consumed by the canonical dictionary broker."
    fi
    external_count=$(($(wc -l < "$manifest") - 1))
    repo_directory_count=$(find "$ROOT_DIR/data/wordlists" -maxdepth 1 -type f -size +0c \
        \( -name 'web-micro.txt' -o -name 'web-short.txt' -o -name 'web-long.txt' \) \
        -print 2>/dev/null | wc -l | tr -d ' ')
    repo_typed_count=$(find "$ROOT_DIR/data/wordlists/categories" -maxdepth 1 -type f -size +0c \
        -print 2>/dev/null | wc -l | tr -d ' ')
    pattern_count=$(find "$PATTERN_CORPUS_DIR" -type f -size +0c \
        -print 2>/dev/null | wc -l | tr -d ' ')
    info "Typed dictionary manifest: $manifest ($external_count external/imported directory sources)"
    info "Bundled dictionary corpus: $repo_directory_count directory tier files, $repo_typed_count typed category files"
    info "Project data/payloads: $pattern_count typed test pattern files excluded from directory dictionary routing."
    info "Private SSH audit dictionaries: $CREDENTIAL_DICT_DIR (0600 files; explicit CLI paths still take precedence)."
}

prepare_integrated_resources() {
    local config="$ROOT_DIR/config/integrated_capabilities.json"
    [[ -r "$config" ]] || { mark_degraded "Integrated capability manifest is missing."; return 0; }
    if ! python3 - "$config" "$ROOT_DIR" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
root = Path(sys.argv[2])
required = {
    "data/cameras/device-rules/model.rules": "device model rule source",
    "data/cameras/device-rules/port.rules": "device port rule source",
    "data/wordlists/range.paths.txt": "range path corpus",
}
missing = [label for relative, label in required.items() if not (root / relative).is_file()]
if set(manifest.get("integrations", {})) < {
    "complete-assessment", "complete-web-evidence", "subdomain-infrastructure",
    "range-http-verification", "industrial-protocol-followup", "device-inventory",
    "dictionary-corpus", "advisory-correlation", "intelligence-catalog",
}:
    missing.append("complete integrated capability matrix")
if missing:
    print("; ".join(missing), file=sys.stderr)
    raise SystemExit(1)
PY
    then
        mark_degraded "Integrated capability resources or manifest are incomplete."
        return 0
    fi
    info "Integrated capability resources verified; no standalone source tool was installed."
}

configure_api_keys() {
    ((NO_API_PROMPT == 0)) || { info "API prompt disabled; existing environment variables remain available."; return 0; }
    [[ -t 0 && -t 1 ]] || { warn "No interactive terminal; skipped API credential prompt."; return 0; }
    local tmp key value encoded existing
    mkdir -p "$DATA_DIR"
    tmp="$API_FILE.tmp.$$"
    : > "$tmp"
    chmod 600 "$tmp"
    info "Optional API credentials (press Enter to leave a value empty)."
    for key in "${API_KEY_NAMES[@]}"; do
        existing="$(printenv "$key" 2>/dev/null || true)"
        if [[ -z "$existing" && -s "$API_FILE" ]] && have base64; then
            existing="$(awk -F= -v wanted="${key}_B64" '$1 == wanted {print substr($0, index($0, "=") + 1); exit}' "$API_FILE" | base64 -d 2>/dev/null || true)"
        fi
        if [[ -n "$existing" ]]; then
            read -r -s -p "$key [configured; Enter to keep, type a replacement]: " value
        else
            read -r -s -p "$key (optional): " value
        fi
        printf '\n'
        [[ -n "$value" ]] || value="$existing"
        if [[ -n "$value" ]]; then
            if have base64; then
                encoded="$(printf '%s' "$value" | base64 | tr -d '\n')"
                printf '%s_B64=%s\n' "$key" "$encoded" >> "$tmp"
            else
                warn "base64 is unavailable; skipped saving $key."
            fi
        fi
    done
    mv -f -- "$tmp" "$API_FILE"
    chmod 600 "$API_FILE"
    info "API credential configuration saved with restricted permissions: $API_FILE"
}

choose_install_mode() {
    printf '%s\n' "Ah Puch installation mode:"
    printf '%s\n' "  1) Complete dependencies and resources"
    printf '%s\n' "  2) Full runtime plus bundled resources"
    printf '%s\n' "  3) Minimal runtime"
    printf '%s\n' "  4) Doctor only"
    printf '%s\n' "  5) Runtime without external tool installation"
    printf '%s\n' "  6) Complete dependencies/resources plus optional API setup"
    local choice
    read -r -p "Select [1]: " choice
    case "${choice:-1}" in
        1) MODE=all-tools ;;
        2) MODE=full ;;
        3) MODE=minimal ;;
        4) MODE=doctor ;;
        5) MODE=full; SKIP_TOOLS=1 ;;
        6) MODE=all-tools; NO_API_PROMPT=0 ;;
        *) error "Invalid installation mode: $choice"; return 2 ;;
    esac
}

main() {
    SKIP_TOOLS=0
    NO_API_PROMPT=1
    INSTALL_DEGRADED=0
    while (($#)); do
        case "$1" in
            --full|-F) MODE=full; shift ;;
            --all-tools|-A) MODE=all-tools; shift ;;
            --minimal|-M) MODE=minimal; shift ;;
            --doctor-only|-D) MODE=doctor; shift ;;
            --no-tools|-N) SKIP_TOOLS=1; shift ;;
            --api-prompt) NO_API_PROMPT=0; shift ;;
            --no-api-prompt) NO_API_PROMPT=1; shift ;;
            --menu|-m) INSTALL_MENU=1; shift ;;
            -h|--help) usage; return 0 ;;
            *) error "Unknown option: $1"; usage; return 2 ;;
        esac
    done

    if ((INSTALL_MENU)); then
        choose_install_mode || return $?
    fi

    if [[ "$MODE" == doctor ]]; then
        PYTHON_BIN="$VENV_DIR/bin/python3"
        [[ -x "$PYTHON_BIN" ]] || PYTHON_BIN="$(command -v python3 || true)"
        [[ -n "$PYTHON_BIN" ]] || { error "python3 is required for doctor mode"; return 1; }
        AH_PUCH_BIN_DIR="$BIN_DIR" AH_PUCH_PYTHON="$PYTHON_BIN" "$ROOT_DIR/ah-puch" --runner-doctor
        return $?
    fi

    if [[ "$MODE" == all-tools ]]; then
        verify_recipe_manifest || return 1
        mkdir -p "$MANIFEST_DIR"
        INSTALL_ACTION_FILE="$MANIFEST_DIR/all-tools-install-actions.tsv"
        printf 'tool\tmethod\tstatus\tdetail\n' > "$INSTALL_ACTION_FILE"
        chmod 600 "$INSTALL_ACTION_FILE"
    fi

    install_step "system packages and optional native engines"
    if ! install_system_packages; then
        error "Installation stopped before dependency changes because the host does not meet the all-tools storage requirement."
        return 3
    fi
    install_step "Python environment and declared requirements"
    install_python
    install_step "Go collectors and crawlers"
    if ((SKIP_TOOLS == 0)) && [[ "$MODE" == full ]]; then
        install_go_tool gau github.com/lc/gau/v2/cmd/gau@v2.2.4 gau
        install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.15.0 subfinder
        install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0 httpx
        install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@v1.7.0 katana
        install_go_tool gospider github.com/jaeles-project/gospider@v1.1.6 gospider
        install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1 nuclei
    elif ((SKIP_TOOLS == 0)) && [[ "$MODE" == all-tools ]]; then
        while IFS=$'\t' read -r tool_id package; do
            install_go_tool "$(inventory_binary "$tool_id")" "$package" "$tool_id"
        done < <(recipe_rows go)
        while IFS=$'\t' read -r tool_id package; do
            install_cargo_tool "$(inventory_binary "$tool_id")" "$package" "$tool_id"
        done < <(recipe_rows cargo)
        while IFS=$'\t' read -r tool_id package; do
            install_pipx_tool "$(inventory_binary "$tool_id")" "$package" "$tool_id"
        done < <(recipe_rows pipx)
        while IFS=$'\t' read -r tool_id url expected archive_type; do
            install_binary_release "$(inventory_binary "$tool_id")" "$url" "$expected" "$archive_type" "$tool_id"
        done < <(binary_release_rows)
        while IFS=$'\t' read -r tool_id recipe; do
            install_pinned_source "$tool_id" "$recipe"
        done < <(recipe_rows pinned_source)
        record_non_automatic_recipes
    fi
    install_step "local container image for bounded web assessment"
    prepare_zap_image
    install_step "launcher path and persistent data directories"
    mkdir -p "$BIN_DIR" "$DATA_DIR" "$RESOURCE_DIR" "$DICT_DIR" "$DEVICE_RESOURCE_DIR" "$ADVISORY_RESOURCE_DIR" "$IMPORT_RESOURCE_DIR" "$CACHE_DIR" "$MANIFEST_DIR"
    install_step "typed dictionary detection and provenance"
    prepare_dictionaries
    install_step "integrated capability resources"
    prepare_integrated_resources
    install_step "API credential configuration"
    configure_api_keys
    install_step "permissions and global launcher"
    # Do not alter tracked modes of import-only Python modules: installing from
    # a clean clone must leave the checkout clean. Only actual entrypoints need
    # an executable bit.
    chmod u+x "$ROOT_DIR/ah-puch" "$ROOT_DIR/install.sh" "$ROOT_DIR/engines/runner.py"
    ln -sfn "$ROOT_DIR/ah-puch" "$BIN_DIR/ah-puch"
    configure_path
    install_step "installation verification"
    VERIFY_PYTHON="${PYTHON_RUNTIME:-$VENV_DIR/bin/python3}"
    [[ -x "$VERIFY_PYTHON" ]] || VERIFY_PYTHON="$(command -v python3)"
    verify_python_runtime "$VERIFY_PYTHON"
    if [[ "$MODE" == all-tools ]]; then
        if ! AH_PUCH_BIN_DIR="$BIN_DIR" PATH="$BIN_DIR:$PATH" "$VERIFY_PYTHON" \
            "$ROOT_DIR/tools/install_readiness.py" \
            --output-dir "$MANIFEST_DIR/all-tools-readiness" \
            --actions "$INSTALL_ACTION_FILE"; then
            mark_degraded "All-tools readiness found an invalid runner contract or failed recipe."
        fi
    fi
    if ((INSTALL_DEGRADED)); then
        warn "Installation completed partially: the canonical launcher is verified, but one or more requested Full-install components were skipped or failed."
        info "Run ah-puch --runner-doctor after resolving the reported dependencies."
        return 3
    fi
    info "Installation complete: $ROOT_DIR/ah-puch"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
