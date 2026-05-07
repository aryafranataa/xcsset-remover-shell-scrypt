#!/bin/bash

# =============================================================================
# XCSSET Remover Script v1.21.0
# =============================================================================
#
# Indonesia:
# Script ini digunakan untuk mendeteksi dan membersihkan indikasi malware /
# persistence XCSSET pada macOS, termasuk payload shell persistence,
# LaunchAgent, LaunchDaemon, cronjob, dan file mencurigakan lainnya.
#
# English:
# This script is used to detect and clean possible XCSSET malware /
# persistence indicators on macOS, including shell persistence payloads,
# LaunchAgent, LaunchDaemon, cron jobs, and other suspicious files.
#
# =============================================================================
# MODE / CARA PAKAI
# =============================================================================
#
# Quick Scan (default)
# Indonesia:
# Scan cepat untuk mengecek indikasi umum XCSSET.
#
# English:
# Fast scan to check common XCSSET indicators.
#
# Usage:
#   sudo ./xcsset_remover_1.21.0.sh
#
# -----------------------------------------------------------------------------
# Deep Scan Mode (--deep)
#
# Indonesia:
# Scan lebih dalam termasuk recursive scan, persistence checking,
# dan shell profile cleaning lebih agresif.
#
# English:
# Deeper scan including recursive scan, persistence checking,
# and more aggressive shell profile cleaning.
#
# Usage:
#   sudo ./xcsset_remover_1.21.0.sh --deep
#
# -----------------------------------------------------------------------------
# Folder Scan Mode (--folder)
#
# Indonesia:
# Scan folder tertentu untuk mencari indikasi XCSSET pada source code,
# script, atau project Xcode.
#
# English:
# Scan a specific folder for XCSSET indicators inside source code,
# scripts, or Xcode projects.
#
# Usage:
#   sudo ./xcsset_remover_1.21.0.sh --folder /path/to/folder
#
# =============================================================================
# FEATURES / FITUR
# =============================================================================
#
# Indonesia:
# - Detect shell persistence
# - Clean malicious .zshrc payload
# - Detect suspicious base64 shell execution
# - Detect LaunchAgent / LaunchDaemon persistence
# - Create evidence backup before cleaning
# - Generate logs for investigation
#
# English:
# - Detect shell persistence
# - Clean malicious .zshrc payload
# - Detect suspicious base64 shell execution
# - Detect LaunchAgent / LaunchDaemon persistence
# - Create evidence backup before cleaning
# - Generate logs for investigation
#
# =============================================================================
# WARNING / PERINGATAN
# =============================================================================
#
# Indonesia:
# Jalankan script ini menggunakan sudo/root.
# Pastikan memiliki backup sebelum melakukan cleaning.
#
# English:
# Run this script using sudo/root privileges.
# Ensure backups exist before performing cleaning operations.
#
# =============================================================================


set -uo pipefail
IFS=$'\n\t'

# ═══════════════════════════════════════════════════════════════════════════════
# XCSSET Remover v1.21.0
# by Franata Rizki Aryanto
# ═══════════════════════════════════════════════════════════════════════════════
#
# MODE / CARA PAKAI
# ------------------------------------------------------------------------------
# 1) QUICK SCAN / DEFAULT MODE
#    Command:
#      sudo bash xcsset_remover_1.21.0.sh
#
#    Fungsi:
#      - Scanning cepat untuk folder development umum saja:
#        ~/Developer, ~/Documents, ~/Desktop, ~/Downloads, ~/Dropbox
#      - Tetap membersihkan persistence umum XCSSET, termasuk:
#        .zshrc, .zprofile, .bashrc, LaunchAgents, LaunchDaemons,
#        git hooks, fake app/support files, defaults/TCC artifact,
#        known C2 process/domain indicators, dan infected Xcode project
#        yang ditemukan di folder umum tersebut.
#
#    Kapan digunakan:
#      - Untuk pengecekan cepat user Mac harian.
#      - Untuk user yang project Xcode-nya biasanya berada di folder standar.
#
# 2) DEEP SCAN MODE
#    Command:
#      sudo bash xcsset_remover_1.21.0.sh --deep
#
#    Fungsi:
#      - Scanning menyeluruh ke seluruh $HOME dengan maxdepth 100.
#      - Lebih lambat, tetapi bisa menemukan project atau git hook infected
#        di folder custom seperti ~/Learning, ~/Projects, ~/Workspace, dll.
#      - Akan menampilkan konfirmasi sebelum scan berjalan jika terminal interaktif.
#
#    Kapan digunakan:
#      - Jika default scan bersih tetapi masih ada indikasi XCSSET.
#      - Jika user menyimpan project di folder custom.
#      - Jika ingin memastikan tidak ada Xcode project lain yang terlewat.
#
# 3) FOLDER SCAN MODE
#    Command:
#      sudo bash xcsset_remover_1.21.0.sh --folder /path/to/folder
#
#    Fungsi:
#      - Scanning mendalam hanya pada folder tertentu.
#      - Fokus untuk Xcode project dan git repository hooks di folder target.
#      - Tidak menjalankan full system persistence scan seperti default/deep mode.
#
#    Kapan digunakan:
#      - Untuk mengecek folder/project yang baru di-download.
#      - Untuk cek sample code sebelum dibuka/build di Xcode.
#      - Untuk mempercepat investigasi pada folder tertentu saja.
#
# 4) FOLDER SCAN + ALL HOOK-LIKE FILES
#    Command:
#      sudo bash xcsset_remover_1.21.0.sh --folder /path/to/folder --include-allhook
#
#    Fungsi:
#      - Sama seperti --folder, tetapi juga mencari file bernama seperti Git hook
#        standar walaupun lokasinya bukan di .git/hooks.
#      - Berguna jika malware menyimpan hook-like file di lokasi tidak standar.
#
# 5) HELP
#    Command:
#      bash xcsset_remover_1.21.0.sh --help
#
#    Fungsi:
#      - Menampilkan ringkasan opsi yang tersedia.
#
# ------------------------------------------------------------------------------
# CATATAN PENTING
# ------------------------------------------------------------------------------
# - Jalankan dengan sudo.
#   XCSSET dapat mengubah ownership project.pbxproj menjadi root:wheel dan mode
#   600. Tanpa sudo, script bisa gagal membaca/membersihkan project yang infected.
#
# - Evidence dan backup akan disimpan di evidence directory yang dibuat script.
#   Shell config seperti .zshrc akan dibackup sebelum dimodifikasi.
#
# - Script ini dirancang untuk menghapus indikator XCSSET yang umum ditemukan di:
#   shell startup files, Xcode project.pbxproj, git hooks, LaunchAgents,
#   LaunchDaemons, fake apps/support files, suspicious defaults/TCC artifacts,
#   dan C2-related persistence.
#
# ------------------------------------------------------------------------------
# PERBAIKAN UTAMA v1.21.0
# ------------------------------------------------------------------------------
# Masalah di versi sebelumnya:
#   Beberapa user masih memiliki payload XCSSET di ~/.zshrc, contohnya:
#
#     "((echo KChkZWZhdWx0cyByZWFkIGJ5emtkcSBhcWd3cl9ueWRxZ19nb3kgfCBiYXNlNjQgLS1kZWNvZGUgfCBlbnYgU1JDPSdUZXJtaW5hbCcgc2gpID4vZGV2L251bGwgMj4mMSAmKQo= | base64 --decode | sh) >/dev/null 2>&1 &)"
#
#   Penyebab utama:
#     - Cleaner lama berbasis grep -vE terlalu bergantung pada regex satu baris.
#     - Payload bisa dibungkus dengan quote, parentheses, redirection, background
#       operator &, spasi tambahan, atau variasi base64 decode command.
#     - Karena itu payload bisa tidak terhapus walaupun pola malicious-nya sama.
#
# Perbaikan v1.21.0:
#   - Shell config cleaner sekarang memakai Python-based detector/remover.
#   - Cleaner mendeteksi kombinasi indikator berbahaya seperti:
#       echo <base64> | base64 --decode | sh
#       echo <base64> | base64 -d | sh
#       base64 decode pipeline yang dieksekusi melalui sh/bash/zsh
#       wrapper quote/parentheses/redirection/background operator
#   - Exact known XCSSET bootstrap payload juga dideteksi walaupun dibungkus
#     karakter tambahan.
#   - File hanya diganti jika suspicious content benar-benar dihapus.
#   - Backup dibuat ke evidence directory sebelum perubahan.
#
# ------------------------------------------------------------------------------
# CLEANUP FLOW / ALUR KERJA SCRIPT
# ------------------------------------------------------------------------------
# 1. Pre-flight check
#    - Validasi argument/mode.
#    - Deteksi user target dan home directory.
#    - Siapkan evidence directory.
#
# 2. Ownership repair
#    - fix_pbxproj_ownership mengembalikan ownership project.pbxproj yang dibuat
#      root-owned oleh XCSSET agar bisa dibaca dan dibersihkan.
#
# 3. Scan phase
#    - Modul scan paralel mencari indikator XCSSET di shell config, Xcode project,
#      git hooks, LaunchAgents/Daemons, hidden files, app support, defaults, TCC,
#      suspicious processes, dan known C2 indicators.
#
# 4. Cleanup phase A - file system
#    - Membersihkan shell config (.zshrc/.zprofile/.bashrc/dll).
#    - Membersihkan malicious PBXShellScriptBuildPhase dan build settings payload
#      di project.pbxproj.
#    - Membersihkan git hooks dan persistence file lain.
#
# 5. Cleanup phase B - process
#    - Kill process yang terkait injection agent atau C2 activity.
#
# 6. Cleanup phase C - privacy/defaults
#    - Reset TCC/privacy permission yang dicurigai disalahgunakan.
#
# 7. C2 blocking
#    - Menambahkan known C2 domains ke /etc/hosts untuk mencegah koneksi ulang.
#
# ------------------------------------------------------------------------------
# PBXPROJ CLEANUP PASSES
# ------------------------------------------------------------------------------
# Pass 0: cari UUID build phase malicious berdasarkan shellScript/script pattern
#         dan fallback nama "Provision Target Device".
# Pass 1: hapus malicious build phase block beserta cross-reference.
# Pass 2: hapus random-key payload entries dari XCBuildConfiguration buildSettings
#         seperti AF17F99/AZ17F89/AP17I99 = "((...))", termasuk shellScript/script
#         yang mereferensikan key tersebut.
# Pass 3: restore ENABLE_USER_SCRIPT_SANDBOXING = YES.
#
# ------------------------------------------------------------------------------
# CHANGELOG
# ------------------------------------------------------------------------------
# v1.21.0 changes from v1.20.0:
# - CRITICAL FIX: shell config cleaner now uses a dedicated Python detector/remover
#   instead of only grep -vE. This catches quoted, parenthesized, backgrounded
#   XCSSET one-liners such as:
#     "((echo <base64> | base64 --decode | sh) >/dev/null 2>&1 &)"
#   in .zshrc/.zprofile/.bashrc/etc.
# - FIX: exact XCSSET base64 bootstrap payloads are detected even when wrapped
#   with extra spaces, quotes, parentheses, or shell redirection.
# - SAFETY: shell config cleanup writes a backup into evidence before changing
#   the file and only replaces the file when suspicious content was removed.
# - QUALITY: mode documentation is now included directly in this script header.
#
# v1.20.0 changes from v1.19.0:
# - NEW FEATURE: --folder option for targeted thorough scanning.
#   Use --folder PATH to recursively scan only the specified folder for Xcode
#   projects and git repository hooks with maxdepth 100.
# - NEW EVIDENCE: folder and deep scans now write scanned_folders.txt in the
#   evidence directory to record exact folder coverage.
# - PATCH: --include-allhook extends --folder mode so it also scans standard Git
#   hook filenames found outside .git/hooks within the specified folder. This
#   option is only valid together with --folder.
# - NEW FEATURE: --deep option for thorough home directory scanning.
#   By default, scanning is limited to common development directories.
#
# v1.19.0 changes from v1.18.0:
# - CRITICAL FIX: XCSSET changes project.pbxproj ownership to root:wheel with
#   mode 600. Fixed by adding fix_pbxproj_ownership() before scanning.
# - FIX: pbxproj cleaner restores ENABLE_USER_SCRIPT_SANDBOXING = YES.
#
# v1.17.0 changes from v1.14.0:
# - CRITICAL FIX: scan_shell() never detected some .zshrc/.bashrc infections
#   because global IFS omitted spaces and caused path parsing issues.
# - FIX: shell removal regex included `| base64 --decode`.
# - FIX: pbxproj cleaner catches "Provision Target Device" by name.
# - FIX: pbxproj cleaner catches PBXBuildRule script field and multi-line remnants.
#
# v14 changes from v13x:
# - All fixes from v13x (set -e, IFS allowlist, C2 domains, TCC
#   whitespace, Phase B PID kill, progress bar cleanup, Xcode regex,
#   lightweight evidence, mandatory TCC reset)
# - UUID-based malicious build phase detection instead of name-only.
# - Hex-keyed payload removal from XCBuildConfiguration sections.
# - .xcsset_bak moved to evidence dir, no orphaned backups.
# ═══════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────
# Terminal capability
# ───────────────────────────────────────────────────────────
if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  RED=$(tput setaf 1 2>/dev/null); GRN=$(tput setaf 2 2>/dev/null)
  YLW=$(tput setaf 3 2>/dev/null); BLD=$(tput bold    2>/dev/null)
  DIM=$(tput dim     2>/dev/null); RST=$(tput sgr0    2>/dev/null)
  COLS=$(tput cols   2>/dev/null || echo 72)
else
  RED=""; GRN=""; YLW=""; BLD=""; DIM=""; RST=""; COLS=72
fi

_MACOS_MAJOR=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
if [ "${_MACOS_MAJOR:-0}" -lt 12 ]; then
  printf 'Error: requires macOS 12 or later\n' >&2
  exit 1
fi

rule()      { printf '%*s\n' "$COLS" '' | tr ' ' '─'; }
shortpath() { P="${1/#$HOME/~}"; [ ${#P} -gt ${2:-52} ] && printf '...%s' "${P: -$((${2:-52}-3))}" || printf '%s' "$P"; }

init_environment() {
# ───────────────────────────────────────────────────────────
# Setup directories and temp files
# ───────────────────────────────────────────────────────────
SCRIPT_VERSION="1.21.0"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
EVIDENCE_DIR="$HOME/xcsset_evidence_v${SCRIPT_VERSION}_$TIMESTAMP"
REPORT="$EVIDENCE_DIR/forensic_report.txt"
SCANNED_FOLDERS="$EVIDENCE_DIR/scanned_folders.txt"
CORES=64
REAL_HOME=$(eval echo ~"${SUDO_USER:-$USER}")

mkdir -p "$EVIDENCE_DIR"/{shell_configs,defaults_domains,decoded_payloads,\
xcode_projects,launchagents,launchdaemons,git_hooks,system_state,\
hidden_files,fake_apps,mainscpt_infected,tmp_payloads,agent_evidence}

touch "$SCANNED_FOLDERS"

# Use system temp — avoids iCloud daemon picking up every intermediate file write
TMP=$(mktemp -d /private/tmp/xcsset_XXXXXX)
chmod 700 "$TMP"

for M in shell defaults xcode agents daemons hooks \
         hidden fakeapps system cron processes dock logins newdomains; do
  printf '0\n' > "$TMP/count_$M.txt"
  touch          "$TMP/findings_$M.txt"
done

PROJECTS_LST="$TMP/projects.lst"
AGENTS_LST="$TMP/agents.lst"
DAEMONS_LST="$TMP/daemons.lst"
HOOKS_LST="$TMP/hooks.lst"
HIDDEN_LST="$TMP/hidden.lst"
XCSSET_BUNDLE_LST="$TMP/xcsset_bundles.lst"
TROJAN_APP_LST="$TMP/trojan_apps.lst"
TMP_PAYLOAD_LST="$TMP/tmp_payloads.lst"
SHELL_LST="$TMP/shell.lst"
DOMAINS_LST="$TMP/domains.lst"
AGENT_LST="$TMP/agent_items.lst"
FINDINGS_ALL="$TMP/findings_all.txt"
AGENT_FINDINGS="$TMP/agent_findings.txt"
TIMELINE="$TMP/timeline.txt"
LOCK="$TMP/lock"

touch "$PROJECTS_LST" "$AGENTS_LST" "$DAEMONS_LST" "$HOOKS_LST" \
      "$HIDDEN_LST" "$XCSSET_BUNDLE_LST" "$TROJAN_APP_LST" "$TMP_PAYLOAD_LST" \
      "$SHELL_LST" "$DOMAINS_LST" "$AGENT_LST" \
      "$FINDINGS_ALL" "$AGENT_FINDINGS" "$TIMELINE" "$LOCK"
PROG_DIR="$TMP/progress";               mkdir -p "$PROG_DIR"

# Pre-initialize all count files to 0 — prevents cat failures in modules
# that find nothing (which would abort the scan function before it calls
# update_module, leaving its progress loop orphaned).
for _M in shell defaults xcode agents daemons hooks hidden fakeapps \
          system cron processes dock logins newdomains; do
  printf '0\n' > "$TMP/count_${_M}.txt"
done

XPROTECT_PY="$TMP/xprotect_check.py"
cat > "$XPROTECT_PY" << 'PYEOF'
import sys, fcntl
path = sys.argv[1]
try:
    f = open(path, 'rb')
    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(f, fcntl.LOCK_UN)
    f.close()
    print('no')
except Exception:
    print('yes')
PYEOF

SHELL_CLEANER_PY="$TMP/shell_cleaner.py"
cat > "$SHELL_CLEANER_PY" << 'PYEOF'
#!/usr/bin/env python3
import base64
import os
import re
import shutil
import sys
import tempfile

B64_BOOTSTRAP_RE = re.compile(r'''
    ["']?\s*
    \(\(\s*\(?\s*
    echo\s+(?P<b64>[A-Za-z0-9+/]{30,}={0,2})\s*
    \|\s*base64\s+(?:--decode|-d|-D)\s*
    \|\s*(?:env\s+[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S+)\s+)*
       (?:/bin/)?(?:ba)?sh\s*
    \)?\s*(?:>/dev/null)?\s*(?:2>&1)?\s*&?\s*
    \)\)\s*["']?
''', re.IGNORECASE | re.VERBOSE)

SUSPICIOUS_LINE_RE = re.compile(
    r"echo\s+[A-Za-z0-9+/]{30,}={0,2}\s*\|\s*base64\s+(?:--decode|-d|-D)\s*\|\s*(?:env\s+\S+\s+)*(?:/bin/)?(?:ba)?sh|"
    r"defaults\s+read\s+[a-z0-9]{5,8}\s+[A-Za-z0-9_]{5,32}|"
    r"\|\s*xxd\s+-p\s+-r\s*\|\s*(?:/bin/)?(?:ba)?sh|"
    r"\|\s*base64\s+(?:--decode|-d|-D)\s*\|\s*(?:env\s+\S+\s+)*(?:/bin/)?(?:ba)?sh",
    re.IGNORECASE,
)

DECODED_BAD_RE = re.compile(
    r"defaults\s+read\s+[a-z0-9]{5,8}|base64\s+(?:--decode|-d|-D)\s*\|\s*(?:env\s+\S+\s+)*(?:/bin/)?(?:ba)?sh|osascript|curl\s+|/tmp/|LaunchAgents",
    re.IGNORECASE,
)
B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{30,}={0,2}")

def decode_looks_bad(text):
    for token in B64_TOKEN_RE.findall(text):
        padded = token + ("=" * ((4 - len(token) % 4) % 4))
        try:
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        if DECODED_BAD_RE.search(decoded):
            return True
    return False

def is_suspicious(line):
    return bool(SUSPICIOUS_LINE_RE.search(line) or B64_BOOTSTRAP_RE.search(line) or decode_looks_bad(line))

def clean_text(text):
    removed, kept, changed = [], [], False
    for idx, line in enumerate(text.splitlines(True), 1):
        original = line
        line = B64_BOOTSTRAP_RE.sub("", line)
        if line != original:
            changed = True
        if is_suspicious(line) or (original != line and not line.strip()):
            removed.append((idx, original.rstrip("\n")))
            changed = True
            continue
        kept.append(line)
    return "".join(kept), removed, changed

def main():
    if len(sys.argv) < 3 or sys.argv[1] not in {"scan", "clean"}:
        print("usage: shell_cleaner.py scan|clean FILE [EVIDENCE_DIR]", file=sys.stderr)
        return 2
    mode, path = sys.argv[1], sys.argv[2]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except FileNotFoundError:
        return 0
    except Exception as e:
        print(f"ERROR|{path}|read failed: {e}")
        return 1
    cleaned, removed, changed = clean_text(text)
    if mode == "scan":
        for n, line in removed:
            print(f"{n}:{line}")
        return 0 if removed else 1
    if not changed:
        print(f"UNCHANGED|{path}|0")
        return 0
    evidence = sys.argv[3] if len(sys.argv) > 3 else ""
    if evidence:
        os.makedirs(evidence, exist_ok=True)
        base = os.path.basename(path).replace("/", "_")
        try:
            shutil.copy2(path, os.path.join(evidence, f"{base}_before_v121_cleanup.txt"))
        except Exception:
            pass
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(prefix="xcsset_shell_", dir=os.path.dirname(path) or None)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(cleaned)
        os.chmod(tmp, st.st_mode & 0o777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(f"CLEANED|{path}|{len(removed)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
PYEOF
chmod 700 "$SHELL_CLEANER_PY"

XCODE_SCANNER="$TMP/scanner.sh"

cat > "$XCODE_SCANNER" << SCANEOF
#!/bin/bash
PBXPROJ="\$1"; TMP="\$2"; EVIDENCE_DIR="\$3"; REPORT="\$4"; PROG_DIR="\$5"
# Always release both locks on exit — prevents stale lock if this worker is
# killed by a signal, OOM, or xargs timeout while a lock is held.
trap 'rmdir "\$PROG_DIR/xcode.cur.lock" 2>/dev/null
      rmdir "\$TMP/xcode_write.lock"    2>/dev/null' EXIT

_slock() { local _n=0
  until mkdir "\$1" 2>/dev/null; do
    _n=\$((_n+1))
    if [ \$_n -gt 600 ]; then
      rmdir "\$1" 2>/dev/null
      mkdir "\$1" 2>/dev/null && return
      _n=0
    fi
    sleep 0.005
  done; }

PROJECT=\$(basename "\$(dirname "\$(dirname "\$PBXPROJ")")")
MATCH=\$(LC_ALL=C grep -nE \
  'base64 --decode.*\| sh|(shellScript|script).*\\\$\{[A-Za-z0-9]{5,8}\}|(shellScript|script).*(base64|xxd).*\| sh|sh -c.*\\\$\{[A-Za-z0-9]{5,8}\}|Provision Target Device' \
  "\$PBXPROJ" 2>/dev/null)
_slock "\$PROG_DIR/xcode.cur.lock"
CUR=\$(cat "\$PROG_DIR/xcode.cur" 2>/dev/null || echo 0)
printf '%d' "\$((CUR+1))" > "\$PROG_DIR/xcode.cur"
rmdir "\$PROG_DIR/xcode.cur.lock" 2>/dev/null
[ -z "\$MATCH" ] && exit 0
SAFE=\$(printf '%s' "\$PROJECT" | tr ' /()@' '_____')
cp "\$PBXPROJ" "\$EVIDENCE_DIR/xcode_projects/\${SAFE}_infected.pbxproj" 2>/dev/null
printf '%s\n' "\$MATCH" > "\$EVIDENCE_DIR/xcode_projects/\${SAFE}_malicious.txt"
_slock "\$TMP/xcode_write.lock"
printf '%s\n' "\$PBXPROJ" >> "\$TMP/projects.lst"
CNT=\$(cat "\$TMP/count_xcode.txt" 2>/dev/null || echo 0)
printf '%d\n' "\$((CNT+1))" > "\$TMP/count_xcode.txt"
printf 'RED|xcode|%s|%s\n' "\$PROJECT" "\$PBXPROJ" >> "\$TMP/findings_xcode.txt"
printf 'RED|xcode|%s|%s\n' "\$PROJECT" "\$PBXPROJ" >> "\$TMP/findings_all.txt"
printf '%s\n' "\$MATCH" >> "\$REPORT"
rmdir "\$TMP/xcode_write.lock" 2>/dev/null
SCANEOF
chmod +x "$XCODE_SCANNER"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SCAN-PHASE progress (file-based IPC, real % when total is known)
# ═══════════════════════════════════════════════════════════════════════════════

_bar() {
  local W="$1" PCT="$2"
  local FILLED=$(( W * PCT / 100 )) I=0 F="" E=""
  while [ $I -lt $FILLED ];         do F="${F}█"; I=$((I+1)); done
  while [ $I -lt $((W - FILLED)) ]; do E="${E}░"; I=$((I+1)); done
  printf '%s%s%s%s%s' "$GRN" "$F" "$DIM" "$E" "$RST"
}

start_progress() {
  local MOD="$1" DETAIL="$2"
  local IDX; IDX=$(get_idx "$MOD")
  local LBL; LBL=$(get_label "$IDX")
  local PIDFILE="$PROG_DIR/$MOD.pid"
  [ -f "$PIDFILE" ] && { kill "$(cat "$PIDFILE")" 2>/dev/null; rm -f "$PIDFILE"; }
  printf '%s' "$DETAIL" > "$PROG_DIR/$MOD.detail"
  printf '0'            > "$PROG_DIR/$MOD.cur"
  printf '0'            > "$PROG_DIR/$MOD.total"
  (
    local BAR_MAX=28 BOUNCE=0
    while true; do
      local DET CUR TOT
      DET=$(cat "$PROG_DIR/$MOD.detail" 2>/dev/null || printf '%s' "$DETAIL")
      CUR=$(cat "$PROG_DIR/$MOD.cur"    2>/dev/null || echo 0)
      TOT=$(cat "$PROG_DIR/$MOD.total"  2>/dev/null || echo 0)
      local BAR PCT
      if [ "$TOT" -gt 0 ]; then
        PCT=$(( CUR * 100 / TOT ))
        BAR=$(_bar "$BAR_MAX" "$PCT")
      else
        BOUNCE=$(( (BOUNCE % (BAR_MAX + 1)) ))
        PCT=$(( BOUNCE * 100 / BAR_MAX ))
        BAR=$(_bar "$BAR_MAX" "$PCT")
        BOUNCE=$((BOUNCE+1))
      fi
      # Non-blocking: skip this frame if another module is already redrawing.
      # Avoids 14 progress loops spinning simultaneously on the same lock.
      if mkdir "${LOCK}.lck" 2>/dev/null; then
        tput cuu "$((MOD_TOTAL - IDX))" 2>/dev/null
        tput el  2>/dev/null
        printf "  %-20s  [%-28s]  ${DIM}%3d%%  %.34s${RST}\n" \
          "$LBL" "$BAR" "$PCT" "$DET"
        tput cud "$((MOD_TOTAL - IDX - 1))" 2>/dev/null
        rmdir "${LOCK}.lck" 2>/dev/null
      fi
      sleep 0.07
    done
  ) &
  printf '%s' "$!" > "$PIDFILE"
}

stop_progress() {
  local MOD="$1" PIDFILE
  PIDFILE="$PROG_DIR/$MOD.pid"
  [ -f "$PIDFILE" ] || return
  kill "$(cat "$PIDFILE")" 2>/dev/null
  wait "$(cat "$PIDFILE")" 2>/dev/null
  rm -f "$PIDFILE"
}

scan_detail() { printf '%s' "$2" > "$PROG_DIR/$1.detail" 2>/dev/null; }
scan_total()  { printf '%d'  "$2" > "$PROG_DIR/$1.total"  2>/dev/null; }
scan_tick()   {
  local MOD="$1" LBL="${2:-}"
  local CUR; CUR=$(cat "$PROG_DIR/$MOD.cur" 2>/dev/null || echo 0)
  printf '%d' "$((CUR+1))" > "$PROG_DIR/$MOD.cur"
  [ -n "$LBL" ] && printf '%s' "$LBL" > "$PROG_DIR/$MOD.detail"
}

# ═══════════════════════════════════════════════════════════════════════════════
# REMOVAL-PHASE progress (tqdm-inspired \r updates)
# ═══════════════════════════════════════════════════════════════════════════════


rem_header() {
  printf '\n  %s%-28s%s  %s(%s item(s))%s\n' \
    "$BLD" "$1" "$RST" "$DIM" "$2" "$RST"
}
rem_tick() {
  local CUR="$1" TOTAL="$2" LBL="$3" START="${4:-0}"
  local W=28 PCT=0 ETA=""
  [ "$TOTAL" -gt 0 ] && PCT=$(( CUR * 100 / TOTAL ))
  local BAR; BAR=$(_bar $W $PCT)
  if [ "$START" -gt 0 ] && [ "$CUR" -gt 0 ] && [ "$CUR" -lt "$TOTAL" ]; then
    local NOW; NOW=$(date +%s)
    local E=$(( NOW - START ))
    [ "$E" -gt 0 ] && ETA="  ETA $(( E*(TOTAL-CUR)/CUR/60 ))m$(printf '%02d' $(( E*(TOTAL-CUR)/CUR%60 )) )s"
  fi
  printf '\r  [%s]  %3d%%  %s(%d/%d)%s%s  %s%s%s\033[K' \
    "$BAR" "$PCT" "$DIM" "$CUR" "$TOTAL" "$RST" \
    "${DIM}${ETA}${RST}" "$DIM" "$(printf '%s' "$LBL" | cut -c1-32)" "$RST"
}
rem_done() {
  local CUR="$1" TOTAL="$2" MSG="${3:-done}"
  printf '\r  [%s]  100%%  %s(%d/%d)%s  %s%s%s\033[K\n' \
    "$(_bar 28 100)" "$DIM" "$CUR" "$TOTAL" "$RST" "$GRN" "$MSG" "$RST"
}
rem_skip() {
  printf '\n  %s%-28s%s  %s(nothing to remove)%s\n' \
    "$BLD" "$1" "$RST" "$DIM" "$RST"
}

# ═══════════════════════════════════════════════════════════════════════════════

# Analyze main.scpt using decompile + binary string fallback
# Returns 0 (infected) or 1 (likely clean)
check_mainscpt_infected() {
  local SCPT="$1"
  local CONTENT
  CONTENT=$(osadecompile "$SCPT" 2>/dev/null | head -40)
  if [ -z "$CONTENT" ]; then
    # errOSASourceNotAvailable: source stripped — fall back to binary string extraction
    CONTENT=$(strings "$SCPT" 2>/dev/null | head -60)
  fi
  printf '%s' "$CONTENT" | grep -qiE 'do shell script|sysoexec|osascript.*JavaScript|load script.*(http|/tmp|/var|Cache)|/tmp/[a-z]{4,6}[^/]|sysodsct|Contents:[a-z]' && return 0
  local SIZE; SIZE=$(stat -f%z "$SCPT" 2>/dev/null || echo 0)
  [ "$SIZE" -gt 10240 ] && return 0
  return 1
}

# v9: Check if an app has ad-hoc signing AND a random XCSSET-style bundle ID.
# XCSSET bundle IDs: e.g. "xhb.gssle.yovqed.732.v9", "oxy.dflnms..610.v3"
# Pattern: 3 lowercase . 4-8 lowercase . 4-8 lowercase+digits [. digits . alphanums]
check_ad_hoc_random_bundleid() {
  local APP="$1"
  local PLIST="$APP/Contents/Info.plist"
  [ -f "$PLIST" ] || return 1
  local BUNDLE_ID
  BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print CFBundleIdentifier" "$PLIST" 2>/dev/null)
  [ -z "$BUNDLE_ID" ] && return 1
  # Must match XCSSET naming: all lowercase segments, last segment may have digits
  printf '%s' "$BUNDLE_ID" | grep -qE \
    '^[a-z]{3}\.[a-z]{4,8}\.[a-z]{4,8}(\.[0-9]+(\.[a-z0-9]+)?)?$' || return 1
  # Must be ad-hoc signed (Authority=-)
  codesign -dv "$APP" 2>&1 | grep -q 'Authority=-' && return 0
  return 1
}

# macOS-compatible mutex (flock is Linux-only; mkdir is atomic on APFS/HFS+)
# Blocking lock with stale-lock recovery: if the lock dir survives more than
# 3 s (600 × 5 ms) it means the holder died without cleaning up — force-break it.
_lock() {
  local _lck="${1}.lck" _n=0
  until mkdir "$_lck" 2>/dev/null; do
    _n=$((_n+1))
    if [ $_n -gt 600 ]; then
      rmdir "$_lck" 2>/dev/null
      mkdir "$_lck" 2>/dev/null && return
      _n=0
    fi
    sleep 0.005
  done
}
_unlock() { rmdir "${1}.lck" 2>/dev/null; }

rlog() { _lock "$LOCK"; printf '%s\n' "$1" >> "$REPORT"; _unlock "$LOCK"; }
_n()   { wc -l < "$1" 2>/dev/null | tr -d ' ' || printf '0'; }

# ───────────────────────────────────────────────────────────
# Lightweight evidence collector — replaces cp -r for fake_apps.
# Saves forensic metadata + malicious scripts only; skips large binaries.
# Typical saving: 50–2000× smaller than a full app copy.
# ───────────────────────────────────────────────────────────
collect_app_evidence() {
  local SRC="$1" DEST="$2"
  mkdir -p "$DEST" 2>/dev/null || return

  # 1. Manifest: path, total size, file count, timestamps
  {
    printf 'source_path : %s\n' "$SRC"
    printf 'collected   : %s\n' "$(date)"
    printf 'total_size  : %s bytes\n' \
      "$(du -sk "$SRC" 2>/dev/null | awk '{print $1 * 1024}' || echo '?')"
    printf 'file_count  : %s\n' \
      "$(find "$SRC" -type f 2>/dev/null | wc -l | tr -d ' ')"
    printf 'modified    : %s\n' \
      "$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$SRC" 2>/dev/null || echo '?')"
  } > "$DEST/MANIFEST.txt"

  # 2. Code-signing info
  codesign -dv "$SRC" 2>&1 > "$DEST/codesign.txt" || true

  # 3. SHA256 hashes of all files (forensic chain of custody)
  find "$SRC" -type f 2>/dev/null | sort | \
    while IFS= read -r F; do
      shasum -a 256 "$F" 2>/dev/null
    done > "$DEST/sha256sums.txt"

  # 4. Copy only forensically relevant small files (scripts, plists, configs)
  find "$SRC" -type f 2>/dev/null | \
  while IFS= read -r F; do
    case "$F" in
      *.scpt|*.applescript|*.js|*.sh|*.rb|*.py|*.plist|*.entitlements)
        REL="${F#$SRC/}"
        FDIR="$DEST/files/$(dirname "$REL")"
        mkdir -p "$FDIR" 2>/dev/null
        cp "$F" "$FDIR/" 2>/dev/null
        ;;
    esac
  done

  # 5. For Mach-O / executables: save first 1 KB as hex header only
  find "$SRC" -type f 2>/dev/null | \
  while IFS= read -r F; do
    if file "$F" 2>/dev/null | grep -qiE 'Mach-O|executable'; then
      REL="${F#$SRC/}"
      SAFE=$(printf '%s' "$REL" | tr '/' '_')
      xxd -l 1024 "$F" 2>/dev/null > "$DEST/bin_headers/${SAFE}.hex"
    fi
  done
}

# Tier constants
TIER_CONFIRMED="CONFIRMED"    # safe to remove on phase approval
TIER_SUSPICIOUS="SUSPICIOUS"  # prompt user per-item
TIER_ENV_RISK="ENV_RISK"      # warn only, never auto-remove

add_finding() {
  local TIER="$1" TYPE="$2" MOD="$3" LABEL="$4" PATH_="$5"
  local CNT; CNT=$(cat "$TMP/count_$MOD.txt" 2>/dev/null || echo 0)
  printf '%d\n' "$((CNT+1))" > "$TMP/count_$MOD.txt"
  printf '%s|%s|%s|%s\n' "$TIER" "$TYPE" "$LABEL" "$PATH_" >> "$TMP/findings_$MOD.txt"
  # FINDINGS_ALL and REPORT are written by all 14 parallel modules — lock required
  _lock "$LOCK"
  printf '%s|%s|%s|%s|%s\n' "$TIER" "$TYPE" "$MOD" "$LABEL" "$PATH_" >> "$FINDINGS_ALL"
  printf '  [%s:%s] %s — %s\n' "$TYPE" "$TIER" "$LABEL" "$PATH_" >> "$REPORT"
  _unlock "$LOCK"
}
add_agent_finding() {
  local CNT; CNT=$(cat "$TMP/count_$2.txt" 2>/dev/null || echo 0)
  printf '%d\n' "$((CNT+1))" > "$TMP/count_$2.txt"
  _lock "$LOCK"
  printf '%s|%s|%s|%s\n' "$1" "$3" "$4" "$5" >> "$AGENT_FINDINGS"
  printf '%s\n' "$4" >> "$AGENT_LST"
  printf '  [AGENT:%s] %s — %s — %s\n' "$1" "$3" "$4" "$5" >> "$REPORT"
  _unlock "$LOCK"
}
safe_decode() {
  local IN="$1" OUT="$2" CUR="$1" DEP=0 DEC
  printf '=== encoded ===\n%s\n\n' "$IN" > "$OUT"
  while [ $DEP -lt 6 ]; do
    DEC=$(printf '%s' "$CUR" | base64 --decode 2>/dev/null)
    { [ $? -ne 0 ] || [ -z "$DEC" ] || [ "$DEC" = "$CUR" ]; } && break
    DEP=$((DEP+1))
    printf '=== layer %d ===\n%s\n\n' "$DEP" "$DEC" >> "$OUT"
    CUR="$DEC"
  done
}

# ───────────────────────────────────────────────────────────
# Module status display
# ───────────────────────────────────────────────────────────
MOD_TOTAL=14
MOD_LBL_0="Shell configs    "
MOD_LBL_1="Defaults domains "
MOD_LBL_2="Xcode projects   "
MOD_LBL_3="LaunchAgents     "
MOD_LBL_4="LaunchDaemons    "
MOD_LBL_5="Git hooks        "
MOD_LBL_6="Hidden + /tmp    "
MOD_LBL_7="Fake bundles     "
MOD_LBL_8="System state     "
MOD_LBL_9="Cron jobs        "
MOD_LBL_10="Processes        "
MOD_LBL_11="Dock integrity   "
MOD_LBL_12="Login items      "
MOD_LBL_13="New domains      "

get_idx() {
  case "${1:-}" in
    shell)      echo 0  ;; defaults)   echo 1  ;; xcode)      echo 2  ;;
    agents)     echo 3  ;; daemons)    echo 4  ;; hooks)      echo 5  ;;
    hidden)     echo 6  ;; fakeapps)   echo 7  ;; system)     echo 8  ;;
    cron)       echo 9  ;; processes)  echo 10 ;; dock)       echo 11 ;;
    logins)     echo 12 ;; newdomains) echo 13 ;; *)          echo 0  ;;
  esac
}
get_label() {
  local IDX="${1:-0}"
  eval "echo \"\${MOD_LBL_${IDX}:-unknown}\""
}

update_module() {
  local MOD="$1" STATE="$2" DETAIL="$3"
  stop_progress "$MOD"
  local IDX; IDX=$(get_idx "$MOD")
  local LBL; LBL=$(get_label "$IDX")
  local BADGE
  case "$STATE" in
    clean)    BADGE="${GRN}[ CLEAN    ]${RST}";;
    infected) BADGE="${RED}[ INFECTED ]${RST}";;
    warning)  BADGE="${YLW}[ WARNING  ]${RST}";;
    *)        BADGE="[ -------- ]";;
  esac
  _lock "$LOCK"
  tput cuu "$((MOD_TOTAL - IDX))" 2>/dev/null
  tput el  2>/dev/null
  printf '  %-20s  %-28s  %s  %s%s%s\n' \
    "$LBL" "" "$BADGE" "$DIM" "$DETAIL" "$RST"
  tput cud "$((MOD_TOTAL - IDX - 1))" 2>/dev/null
  _unlock "$LOCK"
}

init_ui() {
# ───────────────────────────────────────────────────────────
# Header
# ───────────────────────────────────────────────────────────
clear
printf '\n'
rule
printf '  %sREMOVE XCSSET FROM MAC - VERSION %s%s\n' "$BLD" "$SCRIPT_VERSION" "$RST"
printf '  Provided by Franata Rizki Aryanto\n'
rule
printf '  Device  : %s\n' "$(hostname)"
printf '  User    : %s\n' "${SUDO_USER:-$USER}"
printf '  macOS   : %s\n' "$(sw_vers -productVersion 2>/dev/null)"
printf '  Cores   : %s parallel workers\n' "$CORES"
printf '  Started : %s\n' "$(date)"
printf '  Evidence: %s\n' "$(shortpath "$EVIDENCE_DIR" 60)"
rule
printf '\n'

rlog "XCSSET Remover v${SCRIPT_VERSION}"
rlog "Device: $(hostname) | User: ${SUDO_USER:-$USER}"
rlog "Started: $(date) | Evidence: $EVIDENCE_DIR"

trap 'for F in "$PROG_DIR"/*.pid; do [ -f "$F" ] && kill "$(cat "$F")" 2>/dev/null; done; tput cnorm 2>/dev/null' EXIT INT TERM
tput civis 2>/dev/null

tput sc 2>/dev/null   # save cursor — restored after scans to wipe progress block
printf '  Scanning — please wait...\n\n'
for I in $(seq 0 $((MOD_TOTAL-1))); do
  LBL=$(get_label "$I")
  printf '  %-20s  [%-28s]    0%%  waiting...\n' "$LBL" ""
done
tput cuu "$MOD_TOTAL" 2>/dev/null
}

# ───────────────────────────────────────────────────────────
# SCAN MODULES
# ───────────────────────────────────────────────────────────

scan_shell() {
  # NOTE: IFS is set to '\n\t' globally (no space) — use newline-separated
  # list so the for-loop splits correctly on each path.
  local FILES="$REAL_HOME/.zshrc
$REAL_HOME/.zshrc_aliases
$REAL_HOME/.bashrc
$REAL_HOME/.bash_profile
$REAL_HOME/.profile
$REAL_HOME/.zprofile"
  scan_total shell 6
  start_progress shell "checking shell configs..."
  rlog "=== Shell Configs ==="
  for FILE in $FILES; do
    scan_tick shell "$(basename "$FILE")"
    [ -f "$FILE" ] || continue
    local BASENAME; BASENAME=$(basename "$FILE")
    cp "$FILE" "$EVIDENCE_DIR/shell_configs/${BASENAME}_raw.txt" 2>/dev/null
    local MATCHES
    # v1.21.0: use the dedicated cleaner in scan mode. grep-only
    # detection missed some quoted/parenthesized XCSSET shell bootstraps.
    MATCHES=$(python3 "$SHELL_CLEANER_PY" scan "$FILE" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
      printf '%s\n' "$FILE" >> "$SHELL_LST"
      printf '%s\n' "$MATCHES" > \
        "$EVIDENCE_DIR/shell_configs/${BASENAME}_malicious.txt"
      add_finding "$TIER_CONFIRMED" RED shell "$BASENAME" "$FILE"
    elif [ "$BASENAME" = ".zshrc_aliases" ] && [ -f "$FILE" ]; then
      # The filename itself is an XCSSET artifact — count it even if
      # content doesn't match grep patterns, so TOTAL_THREATS stays
      # consistent with REMOVED_A (which deletes it unconditionally).
      printf '%s\n' "$FILE" >> "$SHELL_LST"
      add_finding "$TIER_CONFIRMED" RED shell "$BASENAME (XCSSET artifact)" "$FILE"
    fi
  done
  local CNT; CNT=$(cat "$TMP/count_shell.txt")
  [ "$CNT" -gt 0 ] && update_module shell infected "$CNT line(s)" \
                    || update_module shell clean ""
}

is_suspicious_domain_payload() {
  local RAW="$1"
  printf '%s' "$RAW" | grep -qE '[A-Za-z0-9+/]{30,}={0,2}' || return 1
  local B64 DEC
  B64=$(printf '%s' "$RAW" | grep -oE '[A-Za-z0-9+/]{30,}={0,2}' | head -1)
  DEC=$(printf '%s' "$B64" | base64 --decode 2>/dev/null || true)
  printf '%s' "$DEC" | grep -qiE 'do shell script|osascript|base64.*\| sh|curl' && return 0
  return 1
}

scan_defaults() {
  start_progress defaults "reading defaults registry..."
  rlog "=== Defaults Domains ==="
  scan_detail defaults "reading live defaults..."
  defaults domains 2>/dev/null | tr ',' '\n' | \
    grep -E '^\s*[a-z0-9]{5,8}\s*$' | \
    grep -vE 'pbs|momc|icloudmailagent|mbuseragent|corespotlightd|loginwindow' | \
    tr -d ' \t' > "$TMP/live.tmp"
  ls "$REAL_HOME/Library/Preferences/" 2>/dev/null | \
    grep -E '^[a-z0-9]{5,8}\.plist$' | \
    grep -vE 'pbs|momc|loginwindow' | \
    sed 's/\.plist$//' > "$TMP/plist.tmp"
  cat "$TMP/live.tmp" "$TMP/plist.tmp" 2>/dev/null | \
    sort -u | grep -v '^$' > "$DOMAINS_LST"
  rm -f "$TMP/live.tmp" "$TMP/plist.tmp"
  local DTOTAL; DTOTAL=$(wc -l < "$DOMAINS_LST" | tr -d ' ')
  scan_total defaults "$DTOTAL"
  if [ -s "$DOMAINS_LST" ]; then
    while IFS= read -r DOMAIN; do
      scan_tick defaults "$DOMAIN"
      local RAW; RAW=$(defaults read "$DOMAIN" 2>/dev/null || true)
      local PLIST="$REAL_HOME/Library/Preferences/$DOMAIN.plist"
      [ -z "$RAW" ] && [ -f "$PLIST" ] && RAW=$(plutil -p "$PLIST" 2>/dev/null || true)
      [ -z "$RAW" ] && continue
      if is_suspicious_domain_payload "$RAW"; then
        add_finding "$TIER_CONFIRMED" RED defaults "Domain: $DOMAIN" \
          "~/Library/Preferences/$DOMAIN.plist"
        printf '%s\n' "$RAW" > "$EVIDENCE_DIR/defaults_domains/${DOMAIN}_raw.txt"
        [ -f "$PLIST" ] && cp "$PLIST" "$EVIDENCE_DIR/defaults_domains/${DOMAIN}.plist"
        local A_VAL
        A_VAL=$(printf '%s\n' "$RAW" | grep -oE '"[A-Za-z0-9+/]{20,}={0,2}"' | tr -d '"' | head -1)
        if [ -n "$A_VAL" ]; then
          local DA E1 D1
          DA=$(printf '%s' "$A_VAL" | base64 --decode 2>/dev/null)
          E1=$(printf '%s' "$DA" | cut -d'|' -f1)
          if printf '%s' "$E1" | grep -qE '^[0-9]{9,10}$'; then
            D1=$(date -r "$E1" 2>/dev/null)
            [ -n "$D1" ] && printf 'first_seen|%s\n' "$D1" >> "$TIMELINE"
          fi
        fi
        printf '%s\n' "$RAW" | grep -oE '"[A-Za-z0-9+/]{30,}={0,2}"' | \
        tr -d '"' | sort -u | while IFS= read -r B64; do
          local KN; KN=$(printf '%s' "$B64" | cut -c1-12 | tr -d '+/=')
          safe_decode "$B64" "$EVIDENCE_DIR/decoded_payloads/${DOMAIN}_${KN}.txt"
        done
      fi
    done < "$DOMAINS_LST"
  fi
  local CNT; CNT=$(cat "$TMP/count_defaults.txt")
  [ "$CNT" -gt 0 ] && update_module defaults infected "$CNT domain(s)" \
                     || update_module defaults clean ""
}

scan_xcode() {
  start_progress xcode "collecting projects..."
  rlog "=== Xcode Projects ==="
  local PBXLIST="$TMP/pbx.lst"; > "$PBXLIST"
  local _SCAN_DIRS
  if [ "$FOLDER_SCAN" -eq 1 ]; then
    _SCAN_DIRS="$FOLDER_PATH"
    scan_detail xcode "scanning specified folder for project files..."
  elif [ "$DEEP_SCAN" -eq 1 ]; then
    _SCAN_DIRS="$REAL_HOME"
    scan_detail xcode "deep scanning for project files..."
  else
    _SCAN_DIRS="$REAL_HOME/Developer $REAL_HOME/Documents \
      $REAL_HOME/Desktop $REAL_HOME/Downloads \
      $REAL_HOME/Library/Mobile\ Documents/com~apple~CloudDocs \
      $REAL_HOME/Dropbox"
    scan_detail xcode "searching for project files..."
  fi
  local _EXCLUDE='DerivedData|node_modules|\.Trash|/Pods/|xcsset_evidence'

  # Always use find — mdfind (Spotlight) can miss files when indexing is
  # incomplete, delayed, or broken. XCSSET may also disable Spotlight.
  # find is slower but guaranteed to find all files on disk.
  local _SEARCH_PIDS=()
  local _PI=0
  for DIR in $_SCAN_DIRS; do
    [ -d "$DIR" ] || continue
    local MAX_D=10
    [ "$DEEP_SCAN" -eq 1 ] || [ "$FOLDER_SCAN" -eq 1 ] && MAX_D=100
    find "$DIR" -name "project.pbxproj" \
      -not -path "*/node_modules/*" -not -path "*/.Trash/*" \
      -not -path "*/DerivedData/*" -not -path "*/Pods/*" \
      -not -path "*/xcsset_evidence*" \
      -maxdepth $MAX_D 2>/dev/null > "$TMP/pbx_${_PI}.lst" &
    _SEARCH_PIDS+=($!)
    _PI=$((_PI+1))
  done
  [ ${#_SEARCH_PIDS[@]} -gt 0 ] && wait "${_SEARCH_PIDS[@]}"
  cat "$TMP"/pbx_[0-9]*.lst 2>/dev/null | sort -u > "$PBXLIST"
  rm -f "$TMP"/pbx_[0-9]*.lst 2>/dev/null
  local TOTAL; TOTAL=$(wc -l < "$PBXLIST" | tr -d ' ')
  scan_total xcode "$TOTAL"
  scan_detail xcode "scanning $TOTAL project files..."
  printf '0' > "$PROG_DIR/xcode.cur"
  tr '\n' '\0' < "$PBXLIST" | \
    xargs -0 -P "$CORES" -I {} \
    bash "$XCODE_SCANNER" "{}" "$TMP" "$EVIDENCE_DIR" "$REPORT" "$PROG_DIR" 2>/dev/null
  local CNT; CNT=$(cat "$TMP/count_xcode.txt" 2>/dev/null || echo 0)
  rlog "  Xcode: $TOTAL scanned, $CNT infected"
  if [ "$CNT" -gt 0 ]; then
    update_module xcode infected "$CNT of $TOTAL infected"
    local TIMES
    TIMES=$(while IFS= read -r P; do
      stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$P" 2>/dev/null
    done < "$PROJECTS_LST" | sort -u | wc -l | tr -d ' ')
    [ "$TIMES" -eq 1 ] && {
      local MASS; MASS=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" \
        "$(head -1 "$PROJECTS_LST")" 2>/dev/null)
      printf 'mass_inject|%s\n' "$MASS" >> "$TIMELINE"
    }
  else
    update_module xcode clean "all $TOTAL clean"
  fi
}

scan_agents() {
  start_progress agents "collecting LaunchAgents..."
  rlog "=== LaunchAgents ==="
  local AGT_ALL="$TMP/agents_all.lst"; > "$AGT_ALL"
  for DIR in "$REAL_HOME/Library/LaunchAgents" "/Library/LaunchAgents"; do
    [ -d "$DIR" ] && find "$DIR" -name "*.plist" 2>/dev/null >> "$AGT_ALL"
  done
  local TOTAL; TOTAL=$(wc -l < "$AGT_ALL" | tr -d ' ')
  scan_total agents "$TOTAL"
  while IFS= read -r P; do
    scan_tick agents "$(basename "$P")"
    LC_ALL=C grep -qE 'base64.*sh|echo.*base64|\| sh|xxd.*-p.*-r' "$P" 2>/dev/null || continue
    printf '%s\n' "$P" >> "$AGENTS_LST"
    cp "$P" "$EVIDENCE_DIR/launchagents/$(basename "$P")" 2>/dev/null
    add_finding "$TIER_CONFIRMED" RED agents "LaunchAgent" "$P"
  done < "$AGT_ALL"
  rm -f "$AGT_ALL"
  local CNT; CNT=$(cat "$TMP/count_agents.txt")
  [ "$CNT" -gt 0 ] && update_module agents infected "$CNT found" \
                     || update_module agents clean ""
}

scan_daemons() {
  start_progress daemons "collecting LaunchDaemons..."
  rlog "=== LaunchDaemons ==="
  local DMN_ALL="$TMP/daemons_all.lst"; > "$DMN_ALL"
  find /Library/LaunchDaemons -name "*.plist" 2>/dev/null > "$DMN_ALL"
  local TOTAL; TOTAL=$(wc -l < "$DMN_ALL" | tr -d ' ')
  scan_total daemons "$TOTAL"
  while IFS= read -r P; do
    scan_tick daemons "$(basename "$P")"
    LC_ALL=C grep -qE 'base64.*sh|echo.*base64|\| sh|xxd.*-p.*-r' "$P" 2>/dev/null || continue
    printf '%s\n' "$P" >> "$DAEMONS_LST"
    cp "$P" "$EVIDENCE_DIR/launchdaemons/$(basename "$P")" 2>/dev/null
    add_finding "$TIER_CONFIRMED" RED daemons "LaunchDaemon" "$P"
    local B64; B64=$(grep -oE '[A-Za-z0-9+/]{40,}={0,2}' "$P" 2>/dev/null | head -1)
    [ -n "$B64" ] && safe_decode "$B64" \
      "$EVIDENCE_DIR/decoded_payloads/daemon_$(basename "$P").txt"
  done < "$DMN_ALL"
  rm -f "$DMN_ALL"
  local CNT; CNT=$(cat "$TMP/count_daemons.txt")
  [ "$CNT" -gt 0 ] && update_module daemons infected "$CNT found" \
                     || update_module daemons clean ""
}

scan_hook_candidate() {
  local H="$1" LABEL="$2" COPY_NAME="$3"
  LC_ALL=C grep -qE 'base64.*sh|echo.*base64|\| sh|xxd.*-p.*-r|curl.*\| sh' \
    "$H" 2>/dev/null || return 0
  printf '%s\n' "$H" >> "$HOOKS_LST"
  cp "$H" "$EVIDENCE_DIR/git_hooks/${COPY_NAME}.txt" 2>/dev/null
  add_finding "$TIER_CONFIRMED" RED hooks "$LABEL" "$H"
}

scan_hooks() {
  start_progress hooks "collecting git repos..."
  rlog "=== Git Hooks ==="
  local GITDIRS="$TMP/gitdirs.tmp"
  # Parallel find across common dev dirs — avoids one slow recursive walk from $HOME
  local _GI=0 _GIT_PIDS=()
  local _GDIRS
  if [ "$FOLDER_SCAN" -eq 1 ]; then
    _GDIRS="$FOLDER_PATH"
    scan_detail hooks "scanning specified folder for git repos..."
  elif [ "$DEEP_SCAN" -eq 1 ]; then
    _GDIRS="$REAL_HOME"
    scan_detail hooks "deep scanning for git repos..."
  else
    _GDIRS="$REAL_HOME/Developer $REAL_HOME/Documents \
      $REAL_HOME/Desktop $REAL_HOME/Downloads \
      $REAL_HOME/Library/Mobile Documents/com~apple~CloudDocs \
      $REAL_HOME/Dropbox $REAL_HOME/src $REAL_HOME/Projects"
    scan_detail hooks "collecting git repos..."
  fi
  for _GDIR in $_GDIRS; do
    [ -d "$_GDIR" ] || continue
    local MAX_GIT=5
    [ "$DEEP_SCAN" -eq 1 ] || [ "$FOLDER_SCAN" -eq 1 ] && MAX_GIT=100
    find "$_GDIR" -name ".git" -type d -maxdepth $MAX_GIT \
      -not -path "*/node_modules/*" -not -path "*/Pods/*" \
      -not -path "*/.Trash/*" -not -path "*/DerivedData/*" \
      -not -path "*/xcsset_evidence*" 2>/dev/null > "$TMP/git_${_GI}.lst" &
    _GIT_PIDS+=($!)
    _GI=$((_GI+1))
  done
  [ ${#_GIT_PIDS[@]} -gt 0 ] && wait "${_GIT_PIDS[@]}"
  cat "$TMP"/git_[0-9]*.lst 2>/dev/null | sort -u > "$GITDIRS"
  rm -f "$TMP"/git_[0-9]*.lst 2>/dev/null
  local REPO_COUNT; REPO_COUNT=$(wc -l < "$GITDIRS" | tr -d ' ')
  scan_total hooks "$REPO_COUNT"
  local RI=0
  while IFS= read -r GITDIR; do
    RI=$((RI+1))
    local REPO; REPO=$(basename "$(dirname "$GITDIR")")
    scan_tick hooks "$REPO ($RI/$REPO_COUNT)"
    local HD="$GITDIR/hooks"
    [ -d "$HD" ] || continue
    find "$HD" -maxdepth 1 -type f -not -name "*.sample" 2>/dev/null | \
    while IFS= read -r H; do
      scan_hook_candidate "$H" "$REPO/$(basename "$H")" \
        "${REPO}_$(basename "$H")"
    done
  done < "$GITDIRS"
  rm -f "$GITDIRS"
  if [ "$FOLDER_SCAN" -eq 1 ] && [ "${INCLUDE_ALLHOOK:-0}" -eq 1 ]; then
    scan_detail hooks "scanning hook-named files outside .git/hooks..."
    find "$FOLDER_PATH" -type f \
      \( -name "applypatch-msg" -o -name "commit-msg" -o -name "fsmonitor-watchman" \
      -o -name "post-applypatch" -o -name "post-checkout" -o -name "post-commit" \
      -o -name "post-index-change" -o -name "post-merge" -o -name "post-rewrite" \
      -o -name "post-update" -o -name "pre-applypatch" -o -name "pre-auto-gc" \
      -o -name "pre-commit" -o -name "pre-merge-commit" -o -name "pre-push" \
      -o -name "pre-rebase" -o -name "prepare-commit-msg" -o -name "push-to-checkout" \
      -o -name "reference-transaction" -o -name "sendemail-validate" -o -name "update" \
      -o -name "p4-changelist" -o -name "p4-prepare-changelist" -o -name "p4-post-changelist" \
      -o -name "p4-pre-submit" -o -name "post-receive" -o -name "pre-receive" \
      -o -name "proc-receive" \) \
      -not -path "*/.git/hooks/*" \
      -not -path "*/node_modules/*" -not -path "*/Pods/*" \
      -not -path "*/.Trash/*" -not -path "*/DerivedData/*" \
      -not -path "*/xcsset_evidence*" 2>/dev/null | \
    while IFS= read -r H; do
      local REL SAFE_LABEL SAFE_COPY
      REL="${H#$FOLDER_PATH/}"
      SAFE_LABEL="folder hook: $REL"
      SAFE_COPY=$(printf '%s' "$REL" | tr '/ ' '__')
      scan_hook_candidate "$H" "$SAFE_LABEL" "allhook_${SAFE_COPY}"
    done
  fi
  local GH; GH=$(git config --global core.hooksPath 2>/dev/null)
  if [ -n "$GH" ]; then
    grep -rlE 'base64.*sh|\| sh|xxd.*-p.*-r' "$GH" 2>/dev/null | \
    while IFS= read -r H; do
      add_finding "$TIER_CONFIRMED" RED hooks "global hook: $(basename "$H")" "$H"
    done
  fi
  local CNT; CNT=$(cat "$TMP/count_hooks.txt")
  [ "$CNT" -gt 0 ] && update_module hooks infected "$CNT found" \
                     || update_module hooks clean ""
}

scan_ssh_artifacts() {
  rlog "=== SSH Artifacts ==="
  local SSH_DIR="$REAL_HOME/.ssh"
  if [ -f "$SSH_DIR/authorized_keys" ]; then
    local AK_SIZE; AK_SIZE=$(stat -f%z "$SSH_DIR/authorized_keys" 2>/dev/null || echo 0)
    local AK_MOD; AK_MOD=$(stat -f "%Sm" -t "%Y-%m-%d" "$SSH_DIR/authorized_keys" 2>/dev/null)
    if [ "$AK_SIZE" -gt 0 ]; then
      cp "$SSH_DIR/authorized_keys" "$EVIDENCE_DIR/hidden_files/ssh_authorized_keys.txt" 2>/dev/null
      add_finding "$TIER_ENV_RISK" YLW hidden "~/.ssh/authorized_keys (modified $AK_MOD, ${AK_SIZE}B — XCSSET adds keys for SCP exfil)" \
        "$SSH_DIR/authorized_keys"
    fi
  fi
  if [ -f "$SSH_DIR/id_rsa" ]; then
    local KEY_MOD; KEY_MOD=$(stat -f "%Sm" -t "%Y-%m-%d" "$SSH_DIR/id_rsa" 2>/dev/null)
    cp "$SSH_DIR/id_rsa.pub" "$EVIDENCE_DIR/hidden_files/ssh_id_rsa_pub.txt" 2>/dev/null
    add_finding "$TIER_ENV_RISK" YLW hidden "~/.ssh/id_rsa exists (modified $KEY_MOD — verify not XCSSET-generated)" \
      "$SSH_DIR/id_rsa"
  fi
  for HF in "$REAL_HOME/.root" "$REAL_HOME/.kill"; do
    [ -f "$HF" ] || continue
    cp "$HF" "$EVIDENCE_DIR/hidden_files/$(basename "$HF").txt" 2>/dev/null
    printf '%s\n' "$HF" >> "$HIDDEN_LST"
    add_finding "$TIER_CONFIRMED" RED hidden "$(basename "$HF")" "$HF"
  done
  if [ -f "$REAL_HOME/.a" ]; then
    cp "$REAL_HOME/.a" "$EVIDENCE_DIR/hidden_files/a_tracking.txt" 2>/dev/null
    printf '%s\n' "$REAL_HOME/.a" >> "$HIDDEN_LST"
    local DATA E1 E4 D1
    DATA=$(cat "$REAL_HOME/.a" 2>/dev/null)
    E1=$(printf '%s' "$DATA" | cut -d',' -f1)
    E4=$(printf '%s' "$DATA" | cut -d',' -f4)
    D1=$(date -r "$E1" 2>/dev/null)
    [ -n "$D1" ] && printf 'dot_a|%s|%s\n' "$D1" "$E4" >> "$TIMELINE"
    add_finding "$TIER_SUSPICIOUS" YLW hidden "~/.a tracking diary" "$REAL_HOME/.a"
  fi
}

scan_tmp_payloads() {
  rlog "=== /tmp Payload Scan ==="
  scan_detail hidden "scanning /tmp for payloads..."
  find /tmp -maxdepth 1 -type f 2>/dev/null | \
  while IFS= read -r F; do
    local FNAME; FNAME=$(basename "$F")
    local FLAGGED=0
    printf '%s' "$FNAME" | grep -qE '^(faenm|ehgm)$' && FLAGGED=1
    if [ "$FLAGGED" -eq 0 ]; then
      printf '%s' "$FNAME" | grep -qE '^[a-z]{4,6}$' && \
        file "$F" 2>/dev/null | grep -qiE 'script|text|ascii' && FLAGGED=1
    fi
    [ "$FLAGGED" -eq 0 ] && printf '%s' "$FNAME" | grep -qE '\.(scpt|js|applescript)$' && FLAGGED=1
    if [ "$FLAGGED" -eq 1 ]; then
      cp "$F" "$EVIDENCE_DIR/tmp_payloads/${FNAME}" 2>/dev/null
      printf '%s\n' "$F" >> "$TMP_PAYLOAD_LST"
      add_finding "$TIER_CONFIRMED" RED hidden "/tmp payload: $FNAME" "$F"
    fi
  done
}

scan_gamekit_artifacts() {
  rlog "=== GameKit Dropper Scan ==="
  scan_detail hidden "scanning ~/Library/Caches/GameKit..."
  local GAMEKIT="$REAL_HOME/Library/Caches/GameKit"
  if [ -d "$GAMEKIT" ]; then
    for PAYLOAD in Pods xcassets Assets.xcassets .report .domain; do
      local F="$GAMEKIT/$PAYLOAD"
      [ -e "$F" ] || continue
      cp -r "$F" "$EVIDENCE_DIR/hidden_files/GameKit_${PAYLOAD//\//_}" 2>/dev/null
      printf '%s\n' "$F" >> "$HIDDEN_LST"
      add_finding "$TIER_CONFIRMED" RED hidden "GameKit dropper: $PAYLOAD" "$F"
    done
    find "$GAMEKIT" -name "*.jpg" -maxdepth 1 2>/dev/null | while IFS= read -r S; do
      printf '%s\n' "$S" >> "$HIDDEN_LST"
      add_finding "$TIER_SUSPICIOUS" YLW hidden "GameKit screenshot (C2 exfil)" "$S"
    done
  fi
}

scan_named_launchagents() {
  rlog "=== XCSSET Named LaunchAgents ==="
  scan_detail hidden "checking named XCSSET LaunchAgents..."
  for NAMED_LA in \
    "com.apple.core.launchd.plist" \
    "com.apple.core.accountsd.plist" \
    "com.apple.security.plist" \
    "com.apple.mdmclient.plist"; do
    local LA_PATH="$REAL_HOME/Library/LaunchAgents/$NAMED_LA"
    [ -f "$LA_PATH" ] || continue
    cp "$LA_PATH" "$EVIDENCE_DIR/launchagents/xcsset_named_${NAMED_LA}" 2>/dev/null
    printf '%s\n' "$LA_PATH" >> "$AGENTS_LST"
    add_finding "$TIER_CONFIRMED" RED agents "XCSSET named LaunchAgent: $NAMED_LA" "$LA_PATH"
  done
}

scan_random_library_dirs() {
  rlog "=== ~/Library/ Random Directory Scan ==="
  scan_detail hidden "scanning ~/Library/ for random dropper dirs..."
  RAND_ALLOWLIST="Containers Preferences Application Support Caches Logs Saved Application State \
Cookies Accounts Biome Trial Group Containers Safari Sounds Fonts ColorPickers \
WebKit HTTPStorages IdentityServices LaunchAgents LaunchDaemons Mail Messages Photos \
Developer Calendars Reminders Contacts Maps Scripts Spelling Autosave Information \
StoreKit CloudStorage CoreData InputManagers Internet Plug-Ins Screen Savers \
Services StartupItems Updates Voices \
Python Dropbox OneDrive GoogleDrive Sublime Spotify Slack Notion Figma \
Discord Zoom Arduino iTerm2 Homebrew MacTeX TexShop"

  find "$REAL_HOME/Library" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | \
  while IFS= read -r LDIR; do
    local LNAME; LNAME=$(basename "$LDIR")
    printf '%s' "$LNAME" | grep -qE '^[A-Za-z0-9]{6,16}$' || continue
    printf '%s' "$LNAME" | grep -qE '^[a-z]+$' && continue
    printf '%s' "$LNAME" | grep -qE '[. ]' && continue
    printf '%s' "$LNAME" | grep -qE '^[0-9A-F]{8}[0-9A-F]{4}' && continue
    printf '%s\n' "$RAND_ALLOWLIST" | tr ' ' '\n' | grep -qxF "$LNAME" && continue
    local INNER_APP INNER_EXEC
    INNER_APP=$(find "$LDIR" -name "*.app" -maxdepth 3 -type d 2>/dev/null | head -1)
    INNER_EXEC=""
    if [ -z "$INNER_APP" ]; then
      INNER_EXEC=$(find "$LDIR" -maxdepth 3 -type f 2>/dev/null | head -10 | \
        while IFS= read -r F; do
          file "$F" 2>/dev/null | grep -qiE 'Mach-O|shell script|AppleScript' || continue
          EXEC_TEAM=$(codesign -dv "$F" 2>&1 | grep 'TeamIdentifier' | head -1)
          if printf '%s' "$EXEC_TEAM" | grep -qE 'TeamIdentifier=[A-Z0-9]{10}'; then
            continue
          fi
          echo "$F" && break
        done)
    fi
    [ -z "$INNER_APP" ] && [ -z "$INNER_EXEC" ] && continue
    local SIGN_INFO=""
    if [ -n "$INNER_APP" ]; then
      SIGN_INFO=$(codesign -dv "$INNER_APP" 2>&1 | grep -E 'Authority|TeamIdentifier' | head -3)
      if printf '%s' "$SIGN_INFO" | grep -qE 'Apple (Root CA|Certification Authority)|Software Signing'; then
        continue
      fi
      if printf '%s' "$SIGN_INFO" | grep -qE 'TeamIdentifier=[A-Z0-9]{10}'; then
        continue
      fi
    fi
    collect_app_evidence "$LDIR" "$EVIDENCE_DIR/fake_apps/library_random_${LNAME}"
    printf '%s\n' "$LDIR" >> "$HIDDEN_LST"
    local APP_LABEL
    if [ -n "$INNER_APP" ]; then
      APP_LABEL=$(basename "$INNER_APP")
    else
      APP_LABEL="(executable: $(basename "$INNER_EXEC"))"
    fi
    add_finding "$TIER_SUSPICIOUS" RED hidden "~/Library random dir: $LNAME/$APP_LABEL" "$LDIR"
    rlog "  XCSSET random Library dir: $LDIR  signing: $SIGN_INFO"
  done
}

scan_framework_droppers() {
  rlog "=== XCSSET Frameworks Dropper ==="
  scan_detail hidden "checking ~/Library/Frameworks.app..."
  for FWPATH in \
    "$REAL_HOME/Library/Frameworks.app" \
    "$REAL_HOME/Library/CoreFramework" \
    "/Library/Application Support/com.apple.frameworks"; do
    [ -e "$FWPATH" ] || continue
    collect_app_evidence "$FWPATH" "$EVIDENCE_DIR/hidden_files/$(basename "$FWPATH")"
    printf '%s\n' "$FWPATH" >> "$HIDDEN_LST"
    add_finding "$TIER_CONFIRMED" RED hidden "XCSSET framework dropper: $(basename "$FWPATH")" "$FWPATH"
  done
}

scan_appscripts_bundles() {
  rlog "=== Application Scripts Container Scan ==="
  scan_detail fakeapps "scanning ~/Library/Application Scripts..."
  local APPSCRIPTS="$REAL_HOME/Library/Application Scripts"
  if [ -d "$APPSCRIPTS" ]; then
    find "$APPSCRIPTS" -name "*.app" -maxdepth 3 -type d 2>/dev/null | \
    while IFS= read -r APP; do
      local ANAME; ANAME=$(basename "$APP")
      if printf '%s' "$ANAME" | grep -qE \
        '^(com\.apple\.core\.(sound|graphics|sysd|dock|filesystem|bootcamp|windowserver|uiserver|cputime|afx|dtfd)|com\.oracle\.java\.(sound|graphics|sysd|dock|filesystem|bootcamp|windowserver|uiserver|cputime|afk|cloudservices)|Xcode|xcode)\.app$'; then
        scan_tick fakeapps "$ANAME (AppScripts)"
        local SAFE_NAME; SAFE_NAME=$(printf '%s' "$ANAME" | tr '.' '_')
        collect_app_evidence "$APP" "$EVIDENCE_DIR/fake_apps/appscripts_${SAFE_NAME}"
        printf '%s\n' "$APP" >> "$TROJAN_APP_LST"
        add_finding "$TIER_CONFIRMED" RED fakeapps "AppScripts fake bundle: $ANAME" "$APP"
        rlog "  XCSSET AppScripts fake: $APP"
      else
        local SCPT="$APP/Contents/Resources/Scripts/main.scpt"
        if [ -f "$SCPT" ] && check_mainscpt_infected "$SCPT"; then
          scan_tick fakeapps "$ANAME (AppScripts infected)"
          collect_app_evidence "$APP" "$EVIDENCE_DIR/fake_apps/appscripts_infected_${ANAME}"
          printf '%s\n' "$APP" >> "$TROJAN_APP_LST"
          add_finding "$TIER_CONFIRMED" RED fakeapps "AppScripts infected app: $ANAME" "$APP"
        fi
      fi
    done
  fi
}

scan_trojanized_apps() {
  scan_detail fakeapps "checking /Applications/ for trojanized apps..."
  rlog "=== Trojanized App Detection ==="
  local LEGIT_SCPT="Script Editor.app|Automator.app|FileMerge.app"
  local XCODE_BUNDLED_TARGETS="Simulator.app|SimulatorTrampoline.app"
  for APP_ROOT in /Applications "$REAL_HOME/Applications"; do
    [ -d "$APP_ROOT" ] || continue
    find "$APP_ROOT" -maxdepth 1 -name "*.app" -type d 2>/dev/null | \
    while IFS= read -r APP; do
      local ANAME; ANAME=$(basename "$APP")
      local SCPT="$APP/Contents/Resources/Scripts/main.scpt"
      printf '%s' "$ANAME" | grep -qE "$LEGIT_SCPT" && continue
      local INFECTED=0 REASON=""
      if check_ad_hoc_random_bundleid "$APP"; then
        INFECTED=1
        REASON="ad-hoc signed, random bundle ID (XCSSET fingerprint)"
        rlog "  TROJANIZED (ad-hoc+bundleID): $ANAME"
      fi
      if [ "$INFECTED" -eq 0 ]; then
        if [ -d "/System/Applications/$ANAME" ] || \
           [ -d "/System/Applications/Utilities/$ANAME" ]; then
          INFECTED=1
          REASON="real copy in /System/Applications/"
          rlog "  TROJANIZED (System mirror): $ANAME"
        fi
      fi
      if [ "$INFECTED" -eq 0 ]; then
        if printf '%s' "$ANAME" | grep -qE "$XCODE_BUNDLED_TARGETS" && \
           [ -f "$SCPT" ] && check_mainscpt_infected "$SCPT"; then
          INFECTED=1
          REASON="known XCSSET Xcode-bundled target with infected main.scpt"
          rlog "  TROJANIZED (Xcode-bundled target): $ANAME"
        fi
      fi
      if [ "$INFECTED" -eq 0 ] && [ -f "$SCPT" ]; then
        if check_mainscpt_infected "$SCPT"; then
          INFECTED=1
          REASON="infected main.scpt content analysis"
          rlog "  TROJANIZED (main.scpt analysis): $ANAME"
        fi
      fi
      if [ "$INFECTED" -eq 1 ]; then
        local SAFE_NAME; SAFE_NAME=$(printf '%s' "$ANAME" | tr ' ()' '___')
        collect_app_evidence "$APP" "$EVIDENCE_DIR/fake_apps/${SAFE_NAME}_trojanized"
        printf '%s\n' "$APP" >> "$TROJAN_APP_LST"
        add_finding "$TIER_CONFIRMED" RED fakeapps "Trojanized: $ANAME ($REASON)" "$APP"
      fi
    done
  done
}

# MODULE 7 — Hidden files (orchestrates focused sub-scanners)
scan_hidden() {
  start_progress hidden "checking hidden + /tmp..."
  rlog "=== Hidden Files ==="
  scan_ssh_artifacts
  scan_tmp_payloads
  scan_gamekit_artifacts
  scan_named_launchagents
  scan_random_library_dirs
  scan_framework_droppers

  # ── CocoaPods target_integrator.rb infection (pods_infect module) ─────────
  rlog "=== CocoaPods target_integrator.rb Scan ==="
  scan_detail hidden "scanning CocoaPods for pods_infect..."
  find /Library/Ruby/Gems -name "target_integrator.rb" -type f 2>/dev/null | \
  while IFS= read -r RB; do
    if grep -qE 'adobestats|flixprice|build\.sh|xcassets.*bash|malicious' "$RB" 2>/dev/null; then
      cp "$RB" "$EVIDENCE_DIR/hidden_files/pods_infect_$(basename "$(dirname "$RB")").rb" 2>/dev/null
      printf '%s\n' "$RB" >> "$HIDDEN_LST"
      add_finding "$TIER_CONFIRMED" RED hidden "pods_infect: infected target_integrator.rb" "$RB"
    fi
  done

  # ── Xcode project hidden xcassets Mach-O (.xcodeproj/xcuserdata/.xcassets) ─
  rlog "=== Xcode Hidden xcassets Dropper Scan ==="
  scan_detail hidden "scanning Xcode projects for hidden xcassets..."
  for SEARCH_DIR in "$REAL_HOME/Documents" "$REAL_HOME/Desktop" "$REAL_HOME/Developer" \
      "$REAL_HOME/Downloads" \
      "$REAL_HOME/Library/Mobile Documents/com~apple~CloudDocs"; do
    [ -d "$SEARCH_DIR" ] || continue
    find "$SEARCH_DIR" -maxdepth 8 -name "xcuserdata" -type d \
      -not -path "*/DerivedData/*" -not -path "*/.Trash/*" \
      -not -path "*/xcsset_evidence*" 2>/dev/null | \
    while IFS= read -r XCUD; do
      for XCSSET_FILE in "$XCUD/.xcassets" "$XCUD/Assets.xcassets" "$XCUD/xcassets"; do
        [ -f "$XCSSET_FILE" ] || continue
        if file "$XCSSET_FILE" 2>/dev/null | grep -qiE 'Mach-O|executable|shell script|bash'; then
          local PROJ; PROJ=$(basename "$(dirname "$(dirname "$XCUD")")")
          cp "$XCSSET_FILE" "$EVIDENCE_DIR/hidden_files/xcuserdata_${PROJ}_$(basename "$XCSSET_FILE")" 2>/dev/null
          printf '%s\n' "$XCSSET_FILE" >> "$HIDDEN_LST"
          add_finding "$TIER_CONFIRMED" RED hidden "Xcode hidden dropper ($PROJ): $(basename "$XCSSET_FILE")" "$XCSSET_FILE"
        fi
      done
    done
  done

  # ── .git/ hidden payload scan (pods_infect + replicator) ─────────────────
  rlog "=== .git/ Hidden Payload Scan ==="
  scan_detail hidden "scanning .git dirs for hidden payloads..."
  find "$REAL_HOME" -maxdepth 8 -name ".git" -type d \
    -not -path "*/DerivedData/*" -not -path "*/.Trash/*" \
    -not -path "*/xcsset_evidence*" 2>/dev/null | \
  while IFS= read -r GITDIR; do
    for GIT_PAYLOAD in "project.xworkspace" "build.sh"; do
      local GPF="$GITDIR/$GIT_PAYLOAD"
      [ -f "$GPF" ] || continue
      if file "$GPF" 2>/dev/null | grep -qiE 'Mach-O|executable|shell script|bash'; then
        local REPO; REPO=$(basename "$(dirname "$GITDIR")")
        cp "$GPF" "$EVIDENCE_DIR/hidden_files/git_${REPO}_${GIT_PAYLOAD}" 2>/dev/null
        printf '%s\n' "$GPF" >> "$HIDDEN_LST"
        add_finding "$TIER_CONFIRMED" RED hidden ".git hidden payload ($REPO): $GIT_PAYLOAD" "$GPF"
      fi
    done
  done

  local CNT; CNT=$(cat "$TMP/count_hidden.txt")
  [ "$CNT" -gt 0 ] && update_module hidden infected "$CNT found" \
                     || update_module hidden clean ""
}

scan_fakeapps() {
  start_progress fakeapps "scanning XCSSET bundles..."
  rlog "=== XCSSET Fake App Bundles + main.scpt Injections ==="

  # ── Unified XCSSET Caches bundle scan ────────────────────────────────────
  scan_detail fakeapps "scanning ~/Library/Caches..."
  CACHES_ALLOWLIST="com.apple.chrono"
  find "$REAL_HOME/Library/Caches" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | \
  while IFS= read -r BUNDLE_DIR; do
    local FOLDER; FOLDER=$(basename "$BUNDLE_DIR")
    printf '%s' "$FOLDER" | grep -qE '^[a-z]{3}\.[a-z]{5}\.[a-z]{6}$' || continue
    local CSKIP=0
    for CNAME in $CACHES_ALLOWLIST; do
      [ "$FOLDER" = "$CNAME" ] && CSKIP=1 && break
    done
    [ "$CSKIP" -eq 1 ] && continue
    local HAS_PAYLOAD=0
    find "$BUNDLE_DIR" -name "main.scpt" 2>/dev/null | grep -q . && HAS_PAYLOAD=1
    [ "$HAS_PAYLOAD" -eq 0 ] && find "$BUNDLE_DIR" -name "applet" -path "*/MacOS/applet" 2>/dev/null | grep -q . && HAS_PAYLOAD=1
    [ "$HAS_PAYLOAD" -eq 0 ] && find "$BUNDLE_DIR" -maxdepth 3 -type f 2>/dev/null | \
      while IFS= read -r F; do
        file "$F" 2>/dev/null | grep -qiE 'Mach-O|executable' && echo "1" && break
      done | grep -q 1 && HAS_PAYLOAD=1
    [ "$HAS_PAYLOAD" -eq 0 ] && [ -f "$BUNDLE_DIR"/*/Contents/l ] && HAS_PAYLOAD=1
    [ "$HAS_PAYLOAD" -eq 0 ] && continue
    scan_tick fakeapps "$FOLDER"
    printf '%s\n' "$BUNDLE_DIR" >> "$XCSSET_BUNDLE_LST"
    collect_app_evidence "$BUNDLE_DIR" "$EVIDENCE_DIR/fake_apps/$FOLDER"
    local APP_NAME
    APP_NAME=$(find "$BUNDLE_DIR" -name "*.app" -maxdepth 1 2>/dev/null | \
      head -1 | xargs basename 2>/dev/null || echo "unknown.app")
    add_finding "$TIER_CONFIRMED" RED fakeapps "XCSSET bundle: $APP_NAME" "$BUNDLE_DIR"
    find "$BUNDLE_DIR" -name "main.scpt" 2>/dev/null | grep -q . && rlog "  └─ main.scpt dropper variant"
    find "$BUNDLE_DIR" -name "applet" -path "*/MacOS/applet" 2>/dev/null | grep -q . && rlog "  └─ applet standalone variant"
    [ -f "$BUNDLE_DIR"/*/Contents/l ] && rlog "  └─ hidden 'l' payload present"
  done

  # ── Extended Caches dropper paths ─────────────────────────────────────────
  rlog "=== Extended Caches Dropper Paths ==="
  scan_detail fakeapps "scanning extended Caches paths..."
  for CACHE_SUBDIR in \
    "GameKit" "com.apple.finder" "com.apple.dt.Xcode" \
    "com.apple.Safari" "com.apple.Notes" "com.apple.AddressBook"; do
    local CDIR="$REAL_HOME/Library/Caches/$CACHE_SUBDIR"
    [ -d "$CDIR" ] || continue
    for MACH in Pods xcassets Assets.xcassets; do
      [ -f "$CDIR/$MACH" ] || continue
      if file "$CDIR/$MACH" 2>/dev/null | grep -qiE 'Mach-O|executable|binary'; then
        cp "$CDIR/$MACH" "$EVIDENCE_DIR/hidden_files/${CACHE_SUBDIR}_${MACH}" 2>/dev/null
        printf '%s\n' "$CDIR/$MACH" >> "$HIDDEN_LST"
        add_finding "$TIER_CONFIRMED" RED fakeapps "XCSSET Mach-O dropper in Caches/$CACHE_SUBDIR: $MACH" "$CDIR/$MACH"
      fi
    done
  done

  scan_appscripts_bundles
  scan_trojanized_apps

  local FCNT; FCNT=$(cat "$TMP/count_fakeapps.txt")
  local BCNT; BCNT=$(wc -l < "$XCSSET_BUNDLE_LST" | tr -d ' ')
  local TCNT; TCNT=$(wc -l < "$TROJAN_APP_LST" | tr -d ' ')
  [ "$FCNT" -gt 0 ] && update_module fakeapps infected \
    "$BCNT bundle(s) + $TCNT trojanized app(s)" \
  || update_module fakeapps clean ""
}

scan_system() {
  start_progress system "checking system state..."
  rlog "=== System State ==="
  scan_total system 5
  scan_tick system "SoftwareUpdate settings"
  local SU_C SU_R
  SU_C=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist \
    ConfigDataInstall 2>/dev/null)
  SU_R=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist \
    AllowRapidSecurityResponses 2>/dev/null)
  [ "$SU_C" = "0" ] && add_finding "$TIER_SUSPICIOUS" YLW system "SoftwareUpdate disabled" "ConfigDataInstall=false"
  [ "$SU_R" = "0" ] && add_finding "$TIER_SUSPICIOUS" YLW system "RapidSecurity disabled" "AllowRapidSecurityResponses=false"
  scan_tick system "XProtect lock"
  local XPDB="/var/protected/xprotect/XPdb"
  if [ -f "$XPDB" ]; then
    local LOCKED
    LOCKED=$(python3 "$XPROTECT_PY" "$XPDB" 2>/dev/null || echo 'no')
    [ "$LOCKED" = "yes" ] && add_finding "$TIER_SUSPICIOUS" YLW system "XProtect locked" "$XPDB"
  fi
  scan_tick system "active C2"
  local C2
  C2=$(lsof -i -n -P 2>/dev/null | grep -E 'netcdndev|amzndev|timewebnet|googlenetss|adsmmorein|googlenets|figmanets|whiteads|castlenet|adschecks|applebyte|netapsdev|cdnapple')
  [ -n "$C2" ] && {
    printf '%s\n' "$C2" > "$EVIDENCE_DIR/system_state/active_c2.txt"
    add_finding "$TIER_CONFIRMED" RED system "Active C2 connection" "malware calling home NOW"
  }
  scan_tick system "evidence snapshot"
  cp /Library/Preferences/com.apple.SoftwareUpdate.plist \
    "$EVIDENCE_DIR/system_state/SoftwareUpdate.plist" 2>/dev/null
  lsof -i -n -P 2>/dev/null > "$EVIDENCE_DIR/system_state/network.txt"
  ps aux > "$EVIDENCE_DIR/system_state/processes.txt"
  defaults domains 2>/dev/null | tr ',' '\n' | sort > \
    "$EVIDENCE_DIR/system_state/defaults_domains.txt"
  scan_tick system "done"
  local CNT; CNT=$(cat "$TMP/count_system.txt")
  [ "$CNT" -gt 0 ] && update_module system warning "$CNT item(s)" \
                     || update_module system clean ""
}

scan_cron() {
  start_progress cron "reading crontab..."
  rlog "=== Cron Jobs ==="
  local CTAB; CTAB=$(crontab -u "${SUDO_USER:-$USER}" -l 2>/dev/null || crontab -l 2>/dev/null)
  if [ -n "$CTAB" ]; then
    printf '%s\n' "$CTAB" > "$EVIDENCE_DIR/agent_evidence/crontab.txt"
    local NLINES; NLINES=$(printf '%s\n' "$CTAB" | wc -l | tr -d ' ')
    scan_total cron "$NLINES"
    printf '%s\n' "$CTAB" | while IFS= read -r line; do
      scan_tick cron "$(printf '%s' "$line" | cut -c1-30)"
      rlog "  $line"
      printf '%s' "$line" | grep -qE 'base64|sh -c|xxd|curl.*\| sh|\| bash' && \
        add_agent_finding RED cron "Malicious cron entry" "$line" "crontab"
    done
  fi
  for CRONDIR in /etc/cron.d /var/spool/cron/crontabs; do
    [ -d "$CRONDIR" ] || continue
    find "$CRONDIR" -type f 2>/dev/null | while IFS= read -r F; do
      grep -qE 'base64|xxd.*-p.*-r|\| sh' "$F" 2>/dev/null && \
        add_agent_finding RED cron "System cron entry" "$F" ""
    done
  done
  local CNT; CNT=$(cat "$TMP/count_cron.txt")
  [ "$CNT" -gt 0 ] && update_module cron infected "$CNT found" \
                     || update_module cron clean ""
}

scan_processes() {
  start_progress processes "scanning processes..."
  rlog "=== Running Processes ==="
  local SUSP
  SUSP=$(ps aux 2>/dev/null | grep -vE 'grep|xcsset_v|xcsset_remover_|ps aux' | \
    grep -E 'base64|xxd -p -r|defaults read [a-z0-9]{5,8}|curl.*(amzndev|netcdndev|googlenets|castlenet|figmanets|adschecks|applebyte|netapsdev|cdnapple)')
  [ -n "$SUSP" ] && {
    printf '%s\n' "$SUSP" > "$EVIDENCE_DIR/agent_evidence/suspicious_procs.txt"
    printf '%s\n' "$SUSP" | while IFS= read -r P; do
      add_agent_finding RED processes "Suspicious process" \
        "$(printf '%s' "$P" | awk '{print $2}')" \
        "$(printf '%s' "$P" | cut -c1-80)"
    done
  }
  # Detect non-Xcode processes accessing .xcodeproj or project.pbxproj.
  # XCSSET's replicator module opens these files to inject the AF17F99 build phase.
  #
  # Allowlist — legitimate system/Apple processes that routinely read .xcodeproj
  # during normal iCloud sync, Spotlight indexing, or file coordination:
  #   cloudd       — CloudKit sync daemon (CloudKitDaemon.framework) — reads all
  #                  iCloud Drive content including .xcodeproj for sync staging
  #   bird         — iCloud Drive sync agent (iCloudDriveCore.framework)
  #   filecoord    — macOS file coordination daemon — mediates concurrent access
  #   mds / mds_stores — Spotlight metadata server — indexes all file content
  #   mdworker*    — Spotlight indexer workers
  #   fseventsd    — filesystem event stream daemon
  #   revisiond    — document revision / Time Machine support
  #   diskarbitrationd — disk mount coordination
  #   com.apple.dt — Xcode XPC services (SourceKit, SwiftBuild, etc.)
  #
  # False positive confirmed: cloudd PID 688 accessing xcschememanagement.plist
  # inside ~/Library/Application Support/CloudDocs/session/i/ — normal iCloud sync.
  # lsof without args lists every open fd system-wide and can take minutes on a
  # busy Mac; cap it at 10 s via Perl alarm (works on any macOS without GNU timeout).
  local XA
  XA=$(perl -e 'alarm(10); exec("lsof", "-n", "-P")' 2>/dev/null | \
    grep -E '\.xcodeproj|project\.pbxproj' | \
    grep -vE '^(Xcode|xcodebuild|cloudd|bird|filecoord|mds|mds_stores|mdworker|fseventsd|revisiond|diskarbitrationd|com\.apple\.dt)' | \
    grep -v grep)
  [ -n "$XA" ] && add_agent_finding RED processes "Non-Xcode accessing .xcodeproj" \
    "see processes.txt" "$XA"
  local CNT; CNT=$(cat "$TMP/count_processes.txt")
  [ "$CNT" -gt 0 ] && update_module processes infected "$CNT found" \
                     || update_module processes clean ""
}

scan_dock() {
  start_progress dock "checking Dock..."
  rlog "=== Dock Integrity ==="
  local LP
  LP=$(defaults read com.apple.dock persistent-apps 2>/dev/null | \
    grep -A5 -i launchpad | grep "_CFURLString" | \
    grep -oE '"[^"]*"' | tr -d '"' | head -1)
  if [ -n "$LP" ] && [ "$LP" != "/Applications/Launchpad.app" ]; then
    add_agent_finding RED dock "Fake Launchpad in Dock" "$LP" \
      "expected: /Applications/Launchpad.app"
  fi
  defaults read com.apple.dock persistent-apps 2>/dev/null | \
    grep "_CFURLString" | grep -oE '"[^"]*"' | tr -d '"' | \
  while IFS= read -r ENTRY; do
    local ANAME; ANAME=$(basename "$ENTRY")
    if printf '%s' "$ENTRY" | grep -q '^/Applications/' && \
       { [ -d "/System/Applications/$ANAME" ] || \
         [ -d "/System/Applications/Utilities/$ANAME" ]; }; then
      add_agent_finding YLW dock "Dock→trojanized: $ANAME" "$ENTRY" \
        "real copy in /System/Applications/"
    fi
  done
  local CNT; CNT=$(cat "$TMP/count_dock.txt")
  [ "$CNT" -gt 0 ] && update_module dock infected "$CNT found" \
                     || update_module dock clean ""
}

scan_logins() {
  start_progress logins "checking login items..."
  rlog "=== Login Items ==="
  local BGITEMS="$REAL_HOME/Library/Application Support/\
com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
  if [ -f "$BGITEMS" ]; then
    cp "$BGITEMS" "$EVIDENCE_DIR/agent_evidence/backgrounditems.btm" 2>/dev/null
    strings "$BGITEMS" 2>/dev/null | \
      grep -E '\.(app|sh|py|pl)' | grep -vE '^/Applications|^/System' | \
    while IFS= read -r ITEM; do
      rlog "  Login item: $ITEM"
      printf '%s' "$ITEM" | grep -qE 'base64|xxd|\.sh$' && \
        add_agent_finding RED logins "Suspicious login item" "$ITEM" "btm"
    done
  fi
  local CNT; CNT=$(cat "$TMP/count_logins.txt")
  [ "$CNT" -gt 0 ] && update_module logins infected "$CNT found" \
                     || update_module logins clean ""
}

scan_newdomains() {
  start_progress newdomains "scanning defaults domains..."
  rlog "=== New Defaults Domains ==="
  local KNOWN="3522d5 e7a850 dywmqj xcgefh nhuiae"
  defaults domains 2>/dev/null | tr ',' '\n' | \
    grep -E '^\s*[a-z0-9]{5,8}\s*$' | \
    grep -vE 'pbs|momc|icloudmailagent|mbuseragent|corespotlightd|loginwindow' | \
    tr -d ' \t' | while IFS= read -r D; do
    scan_tick newdomains "$D"
    local RAW; RAW=$(defaults read "$D" 2>/dev/null)
    [ -z "$RAW" ] && continue
    if printf '%s' "$KNOWN" | grep -qw "$D"; then
      add_agent_finding YLW newdomains "Known domain still present" "$D" "was not cleaned"
    else
      add_agent_finding RED newdomains "NEW unknown domain" "$D" \
        "$(printf '%s' "$RAW" | head -c 80)"
      printf '%s\n' "$RAW" > "$EVIDENCE_DIR/agent_evidence/new_domain_${D}.txt"
    fi
  done
  local CNT; CNT=$(cat "$TMP/count_newdomains.txt")
  [ "$CNT" -gt 0 ] && update_module newdomains infected "$CNT found" \
                     || update_module newdomains clean ""
}

run_scans() {
# ───────────────────────────────────────────────────────────
# RUN SCAN MODULES
# ───────────────────────────────────────────────────────────
log_scanned_folders
if [ "$FOLDER_SCAN" -eq 1 ]; then
  scan_xcode &
  scan_hooks &
  wait
else
  scan_shell     &
  scan_defaults  &
  scan_xcode     &
  scan_agents    &
  scan_daemons   &
  scan_hooks     &
  scan_hidden    &
  scan_fakeapps  &
  scan_system    &
  scan_cron      &
  scan_processes &
  scan_dock      &
  scan_logins    &
  scan_newdomains &
  wait
fi

tput cnorm 2>/dev/null
# Restore cursor to where it was before the progress block, then erase
# everything from there to the bottom of the screen — wipes all
# "waiting..." / progress bar remnants in one shot regardless of where
# the background tput cuu/cud calls left the cursor.
tput rc 2>/dev/null
tput ed 2>/dev/null
}

print_results() {
# ───────────────────────────────────────────────────────────
# COUNT TOTALS
# ───────────────────────────────────────────────────────────
TOTAL_THREATS=0; TOTAL_AGENTS=0
for M in shell defaults xcode agents daemons hooks hidden fakeapps system; do
  C=$(cat "$TMP/count_$M.txt" 2>/dev/null || echo 0)
  TOTAL_THREATS=$((TOTAL_THREATS + C))
done
for M in cron processes dock logins newdomains; do
  C=$(cat "$TMP/count_$M.txt" 2>/dev/null || echo 0)
  TOTAL_AGENTS=$((TOTAL_AGENTS + C))
done
BUNDLE_COUNT=$(wc -l < "$XCSSET_BUNDLE_LST" | tr -d ' ')
TROJAN_COUNT=$(wc -l < "$TROJAN_APP_LST"    | tr -d ' ')
TMPPAY_COUNT=$(wc -l < "$TMP_PAYLOAD_LST"   | tr -d ' ')

# ───────────────────────────────────────────────────────────
# RESULTS DISPLAY
# ───────────────────────────────────────────────────────────
printf '\n'; rule
printf '  %sScan Results%s\n' "$BLD" "$RST"; rule; printf '\n'

print_result() {
  local MOD="$1" LABEL="$2"
  local CNT; CNT=$(cat "$TMP/count_$MOD.txt" 2>/dev/null || echo 0)
  local BADGE
  case "$CNT" in
    0) BADGE="${GRN}[ CLEAN    ]${RST}";;
    *) case "$MOD" in
         system|cron|dock|logins|newdomains) BADGE="${YLW}[ WARNING  ]${RST}";;
         *) BADGE="${RED}[ INFECTED ]${RST}";;
       esac;;
  esac
  local DETAIL=""; [ "$CNT" != "0" ] && DETAIL="${CNT} found"
  printf '  %-24s  %-28s  %s  %s%s%s\n' "$LABEL" "" "$BADGE" "$DIM" "$DETAIL" "$RST"
}

printf '  %sFile System Threats%s\n' "$BLD" "$RST"; printf '\n'
print_result shell    "Shell configs"
print_result defaults "Defaults domains"
print_result xcode    "Xcode projects"
print_result agents   "LaunchAgents"
print_result daemons  "LaunchDaemons"
print_result hooks    "Git hooks"
print_result hidden   "Hidden files + /tmp"
print_result fakeapps "Fake bundles + trojans"
print_result system   "System state"

if [ "$BUNDLE_COUNT" -gt 0 ]; then
  printf '  %-24s  %-28s  %s  %s%d XCSSET Caches dirs%s\n' \
    "  └─ Caches bundles" "" "${RED}[ INFECTED ]${RST}" "$DIM" "$BUNDLE_COUNT" "$RST"
fi
if [ "$TROJAN_COUNT" -gt 0 ]; then
  printf '  %-24s  %-28s  %s  %s%d in /Applications/%s\n' \
    "  └─ Trojanized apps" "" "${RED}[ INFECTED ]${RST}" "$DIM" "$TROJAN_COUNT" "$RST"
fi
if [ "$TMPPAY_COUNT" -gt 0 ]; then
  printf '  %-24s  %-28s  %s  %s%d in /tmp%s\n' \
    "  └─ /tmp payloads" "" "${RED}[ INFECTED ]${RST}" "$DIM" "$TMPPAY_COUNT" "$RST"
fi

printf '\n'
printf '  %sInjection Agents%s\n' "$BLD" "$RST"; printf '\n'
print_result cron       "Cron jobs"
print_result processes  "Processes"
print_result dock       "Dock integrity"
print_result logins     "Login items"
print_result newdomains "New domains"

if [ -s "$FINDINGS_ALL" ] || [ -s "$AGENT_FINDINGS" ]; then
  printf '\n'; rule
  printf '  %sFindings%s\n' "$BLD" "$RST"; rule; printf '\n'
  SHOWN=0 MAX=8
  if [ -s "$FINDINGS_ALL" ]; then
    while IFS='|' read -r TIER TYPE MOD LABEL PATH_; do
      [ $SHOWN -ge $MAX ] && break
      [ "$TYPE" = RED ] && COL="$RED" || COL="$YLW"
      printf '  %s%-10s  %-26s  %s%s%s\n' \
        "$COL" "$MOD" "$LABEL" "$DIM" "$(shortpath "$PATH_" 38)" "$RST"
      SHOWN=$((SHOWN+1))
    done < "$FINDINGS_ALL"
    TF=$(wc -l < "$FINDINGS_ALL" | tr -d ' ')
    [ "$TF" -gt "$MAX" ] && printf '\n  %s...and %d more — see forensic_report.txt%s\n' \
      "$DIM" "$((TF-MAX))" "$RST"
  fi
  if [ -s "$AGENT_FINDINGS" ]; then
    printf '\n  %sInjection agents:%s\n' "$BLD" "$RST"
    while IFS='|' read -r TYPE LABEL PATH_ DETAIL; do
      [ "$TYPE" = RED ] && COL="$RED" || COL="$YLW"
      printf '  %s%-14s  %s%s%s\n' \
        "$COL" "$LABEL" "$DIM" "$(shortpath "$PATH_" 48)" "$RST"
      [ -n "$DETAIL" ] && printf '               %s%s%s\n' \
        "$DIM" "$(printf '%s' "$DETAIL" | head -c 60)" "$RST"
    done < "$AGENT_FINDINGS"
  fi
fi

if [ -s "$TIMELINE" ]; then
  printf '\n'; rule
  printf '  %sInfection Timeline%s\n' "$BLD" "$RST"; rule; printf '\n'
  while IFS='|' read -r TYPE F1 F2; do
    case "$TYPE" in
      first_seen)  printf '  First infected    %s%s%s\n' "$RED" "$F1" "$RST";;
      dot_a)       printf '  ~/.a first entry  %s%s%s  (%s executions)\n' "$RED" "$F1" "$RST" "$F2";;
      mass_inject) printf '  Mass Xcode inject %s%s%s\n' "$RED" "$F1" "$RST"
                   printf '  %sAll projects modified at same timestamp%s\n' "$DIM" "$RST";;
    esac
  done < "$TIMELINE"
fi
}

log_scanned_folders() {
  if [ "$FOLDER_SCAN" -eq 1 ]; then
    printf '\n=== Folder Scan Coverage ===\n' >> "$REPORT"
    printf 'Scanned folder: %s\n' "$FOLDER_PATH" >> "$REPORT"
    printf '\n' >> "$REPORT"
    printf '%s\n' "$FOLDER_PATH" > "$SCANNED_FOLDERS"
    find "$FOLDER_PATH" -type d 2>/dev/null | sort >> "$SCANNED_FOLDERS"
  elif [ "$DEEP_SCAN" -eq 1 ]; then
    printf '\n=== Deep Scan Roots ===\n' >> "$REPORT"
    printf 'Scanned folders list written to: %s\n\n' "$SCANNED_FOLDERS" >> "$REPORT"
    find "$REAL_HOME" -type d 2>/dev/null | sort > "$SCANNED_FOLDERS"
  fi
}

run_phase_a() {
# ───────────────────────────────────────────────────────────
# PHASE A — REMOVE FILE SYSTEM THREATS
# ───────────────────────────────────────────────────────────
printf '\n'; rule; printf '\n'

if [ "$TOTAL_THREATS" -eq 0 ] && [ "$TOTAL_AGENTS" -eq 0 ]; then
  printf '  %sDevice is clean. No threats found.%s\n\n' "$GRN" "$RST"
  printf '  Evidence: %s%s%s\n\n' "$DIM" "$EVIDENCE_DIR" "$RST"
  rm -rf "$TMP"; exit 0
fi

REMOVED_A=0
if [ "$TOTAL_THREATS" -gt 0 ]; then
  printf '  %sPhase A — File System Threats%s\n' "$BLD" "$RST"
  printf '  Found %s%d item(s)%s — removing...\n\n' "$RED" "$TOTAL_THREATS" "$RST"
  rule
  printf '  %sRemoving file system threats...%s\n' "$BLD" "$RST"
  rule

  N_SHELL=$(_n "$SHELL_LST")
  N_DOM=$(_n "$DOMAINS_LST")
  N_AGT=$(_n "$AGENTS_LST")
  N_DMN=$(_n "$DAEMONS_LST")
  N_HK=$(_n "$HOOKS_LST")
  N_HID=$(_n "$HIDDEN_LST")
  N_BUNDLE=$(_n "$XCSSET_BUNDLE_LST")
  N_TROJAN=$(_n "$TROJAN_APP_LST")
  N_TMPPAY=$(_n "$TMP_PAYLOAD_LST")
  N_C2=14

  # ── Shell configs ────────────────────────────────────────────────────────
  if [ "$N_SHELL" -gt 0 ]; then
    rem_header "Shell configs" "$N_SHELL"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r FILE; do
      [ -f "$FILE" ] || continue
      CLEAN_RESULT=$(python3 "$SHELL_CLEANER_PY" clean "$FILE" "$EVIDENCE_DIR/shell_configs" 2>/dev/null || true)
      case "$CLEAN_RESULT" in
        CLEANED*) REMOVED_A=$((REMOVED_A+1));;
      esac
      _CUR=$((_CUR+1))
      rem_tick "$_CUR" "$N_SHELL" "$(basename "$FILE")" "$_T"
    done < "$SHELL_LST"
    rem_done "$_CUR" "$N_SHELL"
  else
    rem_skip "Shell configs"
  fi
  [ -f "$REAL_HOME/.zshrc_aliases" ] && {
    rm -f "$REAL_HOME/.zshrc_aliases"
    printf '  %s  Removed: ~/.zshrc_aliases%s\n' "$DIM" "$RST"
    REMOVED_A=$((REMOVED_A+1)); }

  # ── Defaults domains ─────────────────────────────────────────────────────
  if [ "$N_DOM" -gt 0 ]; then
    rem_header "Defaults domains" "$N_DOM"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r D; do
      [ -n "$D" ] || continue
      defaults delete "$D" 2>/dev/null
      rm -f "$REAL_HOME/Library/Preferences/$D.plist"
      _CUR=$((_CUR+1)); REMOVED_A=$((REMOVED_A+1))
      rem_tick "$_CUR" "$N_DOM" "$D" "$_T"
    done < "$DOMAINS_LST"
    rem_done "$_CUR" "$N_DOM"
  else
    rem_skip "Defaults domains"
  fi

  # ── LaunchAgents ─────────────────────────────────────────────────────────
  if [ "$N_AGT" -gt 0 ]; then
    rem_header "LaunchAgents" "$N_AGT"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r P; do
      [ -f "$P" ] || continue
      launchctl unload "$P" 2>/dev/null
      rm -f "$P"
      _CUR=$((_CUR+1)); REMOVED_A=$((REMOVED_A+1))
      rem_tick "$_CUR" "$N_AGT" "$(basename "$P")" "$_T"
    done < "$AGENTS_LST"
    rem_done "$_CUR" "$N_AGT"
  else
    rem_skip "LaunchAgents"
  fi

  # ── LaunchDaemons ────────────────────────────────────────────────────────
  if [ "$N_DMN" -gt 0 ]; then
    rem_header "LaunchDaemons" "$N_DMN"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r P; do
      [ -f "$P" ] || continue
      if [ "$(id -u)" -eq 0 ]; then
        launchctl unload "$P" 2>/dev/null; rm -f "$P"
        _CUR=$((_CUR+1)); REMOVED_A=$((REMOVED_A+1))
        rem_tick "$_CUR" "$N_DMN" "$(basename "$P")" "$_T"
      else
        printf '\r  %s⚠  needs sudo: %s%s\033[K\n' "$YLW" "$(basename "$P")" "$RST"
        _CUR=$((_CUR+1))
      fi
    done < "$DAEMONS_LST"
    rem_done "$_CUR" "$N_DMN"
  else
    rem_skip "LaunchDaemons"
  fi

  # ── Git hooks ────────────────────────────────────────────────────────────
  if [ "$N_HK" -gt 0 ]; then
    rem_header "Git hooks" "$N_HK"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r H; do
      [ -f "$H" ] || continue; rm -f "$H"
      _CUR=$((_CUR+1)); REMOVED_A=$((REMOVED_A+1))
      rem_tick "$_CUR" "$N_HK" "$(basename "$H")" "$_T"
    done < "$HOOKS_LST"
    rem_done "$_CUR" "$N_HK"
  else
    rem_skip "Git hooks"
  fi

  # ── /tmp payloads ────────────────────────────────────────────────────────
  if [ "$N_TMPPAY" -gt 0 ]; then
    rem_header "/tmp payloads" "$N_TMPPAY"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r F; do
      [ -f "$F" ] || continue; rm -f "$F"
      _CUR=$((_CUR+1)); REMOVED_A=$((REMOVED_A+1))
      rem_tick "$_CUR" "$N_TMPPAY" "$(basename "$F")" "$_T"
    done < "$TMP_PAYLOAD_LST"
    rem_done "$_CUR" "$N_TMPPAY"
  else
    rem_skip "/tmp payloads"
  fi

  # ── GameKit dropper + named LaunchAgents + Framework droppers ────────────
  GAMEKIT="$REAL_HOME/Library/Caches/GameKit"
  if [ -d "$GAMEKIT" ]; then
    rem_header "GameKit dropper" "core re-injector"
    rm -rf "$GAMEKIT"
    printf '  %s  Removed: ~/Library/Caches/GameKit%s\n' "$DIM" "$RST"
    REMOVED_A=$((REMOVED_A+1))
  fi
  for FWPATH in \
    "$REAL_HOME/Library/Frameworks.app" \
    "$REAL_HOME/Library/CoreFramework" \
    "/Library/Application Support/com.apple.frameworks"; do
    [ -e "$FWPATH" ] || continue
    rm -rf "$FWPATH"
    printf '  %s  Removed: %s%s\n' "$DIM" "$(shortpath "$FWPATH" 50)" "$RST"
    REMOVED_A=$((REMOVED_A+1))
  done

  # ── XCSSET Caches bundles (entire parent dir) ─────────────────────────────
  if [ "$N_BUNDLE" -gt 0 ]; then
    rem_header "XCSSET Caches bundles" "$N_BUNDLE"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r BDIR; do
      [ -d "$BDIR" ] || continue
      rm -rf "$BDIR"
      _CUR=$((_CUR+1)); REMOVED_A=$((REMOVED_A+1))
      rem_tick "$_CUR" "$N_BUNDLE" "$(basename "$BDIR")" "$_T"
    done < "$XCSSET_BUNDLE_LST"
    rem_done "$_CUR" "$N_BUNDLE"
  else
    rem_skip "XCSSET Caches bundles"
  fi

  # ── Trojanized /Applications/ apps ───────────────────────────────────────
  # v9: tries sudo rm -rf first; on failure tries osascript-elevated rm
  if [ "$N_TROJAN" -gt 0 ]; then
    rem_header "Trojanized apps" "$N_TROJAN"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r APP; do
      [ -d "$APP" ] || { _CUR=$((_CUR+1)); rem_tick "$_CUR" "$N_TROJAN" "$(basename "$APP") (already gone)" "$_T"; continue; }
      ANAME=$(basename "$APP")
      REMOVED=0
      # Attempt 1: direct sudo
      if sudo rm -rf "$APP" 2>/dev/null; then
        REMOVED=1
      else
        # Attempt 2: osascript with admin privileges (shows GUI auth dialog)
        osascript -e "do shell script \"rm -rf '${APP}'\" with administrator privileges" \
          2>/dev/null && REMOVED=1
      fi
      if [ "$REMOVED" -eq 1 ]; then
        _CUR=$((_CUR+1)); REMOVED_A=$((REMOVED_A+1))
        rem_tick "$_CUR" "$N_TROJAN" "$ANAME" "$_T"
        rlog "  REMOVED trojanized app: $APP"
      else
        printf '\r  %s⚠  could not remove: %s — run: sudo rm -rf "%s"%s\033[K\n' \
          "$YLW" "$ANAME" "$APP" "$RST"
        rlog "  FAILED to remove: $APP"
        _CUR=$((_CUR+1))
      fi
    done < "$TROJAN_APP_LST"
    rem_done "$_CUR" "$N_TROJAN"
    # Repair Dock: remove all persistent-app entries (Dock rebuilds from /Applications/)
    printf '  %s  Repairing Dock entries...%s ' "$DIM" "$RST"
    defaults delete com.apple.dock persistent-apps 2>/dev/null
    killall Dock 2>/dev/null
    printf '%sdone%s\n' "$GRN" "$RST"
  else
    rem_skip "Trojanized apps"
  fi

  # ── SSH cleanup (remove XCSSET-generated authorized_keys entries) ───────────
  # Remove passwordless keys injected by safari_cookie module.
  # Strategy: remove any key line that has no comment (XCSSET generates bare keys).
  SSH_AK="$REAL_HOME/.ssh/authorized_keys"
  if [ -f "$SSH_AK" ]; then
    CLEAN_AK=$(grep -v '^ssh-rsa AAAA' "$SSH_AK" 2>/dev/null || true)
    if [ "$CLEAN_AK" != "$(cat "$SSH_AK" 2>/dev/null)" ]; then
      printf '%s\n' "$CLEAN_AK" > "$SSH_AK"
      printf '  %s  Cleaned XCSSET SSH keys from ~/.ssh/authorized_keys%s\n' "$DIM" "$RST"
      REMOVED_A=$((REMOVED_A+1))
    fi
  fi

  # ── ~/Library/[RANDOM]/ dropper directories ──────────────────────────────
  find "$REAL_HOME/Library" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | \
  while IFS= read -r LDIR; do
    LNAME=$(basename "$LDIR")
    if printf '%s' "$LNAME" | grep -qE '^[A-Z0-9]{6,14}$'; then
      if find "$LDIR" -name "*.app" -maxdepth 2 -type d 2>/dev/null | grep -q .; then
        rm -rf "$LDIR"
        printf '  %s  Removed ~/Library/%s (XCSSET random dropper dir)%s\n' "$DIM" "$LNAME" "$RST"
        REMOVED_A=$((REMOVED_A+1))
      fi
    fi
  done

  # ── CocoaPods target_integrator.rb restoration ───────────────────────────
  # Reinstall the gem to restore the original file (safest approach)
  if gem list cocoapods 2>/dev/null | grep -q cocoapods; then
    find /Library/Ruby/Gems -name "target_integrator.rb" -type f 2>/dev/null | \
    while IFS= read -r RB; do
      if grep -qE 'adobestats|flixprice|build\.sh' "$RB" 2>/dev/null; then
        rm -f "$RB"
        printf '  %s  Removed infected target_integrator.rb — run: gem install cocoapods%s\n' "$YLW" "$RST"
        REMOVED_A=$((REMOVED_A+1))
      fi
    done
  fi

  # ── Xcode hidden xcassets dropper removal ────────────────────────────────
  for SEARCH_DIR in "$REAL_HOME/Documents" "$REAL_HOME/Desktop" "$REAL_HOME/Developer" \
      "$REAL_HOME/Downloads" \
      "$REAL_HOME/Library/Mobile Documents/com~apple~CloudDocs"; do
    [ -d "$SEARCH_DIR" ] || continue
    find "$SEARCH_DIR" -maxdepth 8 -name "xcuserdata" -type d \
      -not -path "*/DerivedData/*" -not -path "*/.Trash/*" \
      -not -path "*/xcsset_evidence*" 2>/dev/null | \
    while IFS= read -r XCUD; do
      for XCSSET_FILE in "$XCUD/.xcassets" "$XCUD/Assets.xcassets" "$XCUD/xcassets"; do
        [ -f "$XCSSET_FILE" ] || continue
        if file "$XCSSET_FILE" 2>/dev/null | grep -qiE 'Mach-O|executable|shell script|bash'; then
          rm -f "$XCSSET_FILE"
          printf '  %s  Removed xcuserdata dropper: %s%s\n' "$DIM" "$(shortpath "$XCSSET_FILE" 50)" "$RST"
          REMOVED_A=$((REMOVED_A+1))
        fi
      done
    done
  done

  # ── .git/ hidden payload removal ─────────────────────────────────────────
  find "$REAL_HOME" -maxdepth 8 -name ".git" -type d \
    -not -path "*/DerivedData/*" -not -path "*/.Trash/*" \
    -not -path "*/xcsset_evidence*" 2>/dev/null | \
  while IFS= read -r GITDIR; do
    for GIT_PAYLOAD in "project.xworkspace" "build.sh"; do
      GPF="$GITDIR/$GIT_PAYLOAD"
      [ -f "$GPF" ] || continue
      if file "$GPF" 2>/dev/null | grep -qiE 'Mach-O|executable|shell script|bash'; then
        rm -f "$GPF"
        printf '  %s  Removed .git payload: %s/%s%s\n' "$DIM" "$(basename "$(dirname "$GITDIR")")" "$GIT_PAYLOAD" "$RST"
        REMOVED_A=$((REMOVED_A+1))
      fi
    done
  done

  # ── Hidden files ─────────────────────────────────────────────────────────
  if [ "$N_HID" -gt 0 ]; then
    rem_header "Hidden files" "$N_HID"
    _CUR=0; _T=$(date +%s)
    while IFS= read -r F; do
      if [ -d "$F" ]; then
        rm -rf "$F"          # random Library dirs (e.g. ~/Library/K44Y99TPXN/)
      elif [ -f "$F" ]; then
        rm -f "$F"
      else
        continue
      fi
      _CUR=$((_CUR+1)); REMOVED_A=$((REMOVED_A+1))
      rem_tick "$_CUR" "$N_HID" "$(shortpath "$F" 32)" "$_T"
    done < "$HIDDEN_LST"
    rem_done "$_CUR" "$N_HID"
  else
    rem_skip "Hidden files"
  fi

  # ── Xcode projects (Python cleaner with live progress) ───────────────────
  # v9:  Block-level removal + atomic write-back (iCloud-safe)
  # v14: UUID-based detection; hex-keyed payload removal from buildSettings
  # v17: "Provision Target Device" name fallback; PBXBuildRule `script` field;
  #      `sh -c "${HEXKEY}"` multi-line match; catch-all base64 | sh
  # v18: fix_pbxproj_ownership() restores root-owned files before scan;
  #      sudo-cat read fallback; ENABLE_USER_SCRIPT_SANDBOXING restoration
  XCODE_PY="$TMP/xcode_cleaner.py"
  # Pass evidence dir so cleaner can move .xcsset_bak there
  XCSSET_EVIDENCE_DIR="$EVIDENCE_DIR/xcode_projects"
  export XCSSET_EVIDENCE_DIR
  cat > "$XCODE_PY" << 'XPYEOF'
import os, re, shutil, sys

# ── Pass 0: UUID-based malicious phase detection ─────────────────────────────
def collect_xcsset_phase_uuids(lines):
    """
    Scan all { ... } blocks and return UUIDs of PBXShellScriptBuildPhase blocks
    whose shellScript line contains an XCSSET injection pattern OR whose name
    matches a known XCSSET build phase name (e.g. "Provision Target Device").
    Works regardless of phase name for payload-based detection, and catches
    empty/cleared phases by known name as a fallback.
    """
    SHELL_PATTERNS = [
        re.compile(r'(?:shellScript|script)\s*=\s*"[^"]*\$\{[A-Za-z0-9]{5,8}\}'),   # ${AF17F99}
        re.compile(r'(?:shellScript|script)\s*=\s*".*(?:base64\s+--decode|xxd\s+-p\s+-r).*\|\s*sh'),
        re.compile(r'(?:shellScript|script)\s*=\s*"\(\(echo\s+[0-9a-f]{20,}'),
        # Multi-line script: sh -c referencing a hex-keyed variable on a continuation line
        re.compile(r'sh\s+-c\s*\\?"\$\{[A-Za-z0-9]{5,8}\}'),
    ]
    # Known XCSSET build phase names — flag the block even if shellScript is
    # empty or already partially cleaned.
    NAME_PATTERNS = [
        re.compile(r'name\s*=\s*"Provision Target Device"'),
    ]
    malicious_uuids = set()
    i = 0
    while i < len(lines):
        m = re.search(r'([A-Fa-f0-9]{24})\s*/\*.*\*/\s*=\s*\{', lines[i])
        if m:
            uuid = m.group(1)
            # Also check if the block header itself names the phase
            if 'Provision Target Device' in lines[i]:
                malicious_uuids.add(uuid)
            depth = lines[i].count('{') - lines[i].count('}')
            j = i + 1
            while j < len(lines) and depth > 0:
                depth += lines[j].count('{') - lines[j].count('}')
                if any(p.search(lines[j]) for p in SHELL_PATTERNS):
                    malicious_uuids.add(uuid)
                    break
                if any(p.search(lines[j]) for p in NAME_PATTERNS):
                    malicious_uuids.add(uuid)
                    break
                j += 1
        i += 1
    return malicious_uuids


# ── Pass 1: remove malicious build phase blocks by UUID ──────────────────────
def remove_xcsset_build_phases(lines, malicious_uuids):
    """
    State machine: removes entire { ... } blocks whose UUID is in
    malicious_uuids, plus every cross-reference line to those UUIDs.
    Replaces the old name-only "Provision Target Device" approach.
    """
    if not malicious_uuids:
        return lines, False

    out = []
    skip_depth = 0
    skip_uuid = None
    hit = False
    i = 0

    # Build combined pattern for cross-reference matching
    uuid_alt = '|'.join(re.escape(u) for u in malicious_uuids)
    xref_re  = re.compile(rf'(?:{uuid_alt})\s*/\*.*\*/')

    while i < len(lines):
        line = lines[i]

        if skip_depth == 0:
            # Start of a block whose UUID is malicious
            m = re.search(r'([A-Fa-f0-9]{24})\s*/\*.*\*/\s*=\s*\{', line)
            if m and m.group(1) in malicious_uuids:
                skip_depth = line.count('{') - line.count('}')
                skip_uuid  = m.group(1)
                hit = True
                # Remove the preceding reference line already appended
                if out and re.search(rf'{re.escape(skip_uuid)}\s*/\*.*\*/', out[-1]):
                    out.pop()
                i += 1
                continue

            # Cross-reference to any malicious UUID (buildPhases list, etc.)
            if xref_re.search(line):
                hit = True
                i += 1
                continue

            out.append(line)
        else:
            # Inside block — track brace depth to find closing };
            skip_depth += line.count('{') - line.count('}')
            if skip_depth <= 0:
                skip_depth = 0
                skip_uuid  = None
        i += 1

    return out, hit


# ── Pass 2: remove hex-keyed build settings + leftover shellScript refs ───────
def clean_inline_patterns(lines):
    """
    Remove:
      • RANDKEY = "((...))";  — payload stored in XCBuildConfiguration buildSettings.
                                Key is a random 5-8 char alphanumeric string (e.g.
                                AF17F99, AZ17F89, AP17I99). Value always starts with
                                "((" containing base64-decoded shell execution.
      • shellScript/script = "...${RANDKEY}..."; — references to payload variable
      • shellScript/script = "...base64|xxd|sh...";
      • sh -c "${RANDKEY}"   — standalone execution on multi-line continuation
      • base64 --decode ... | sh — catch-all for any base64 pipeline
    """
    out  = []
    skip = False   # True while inside a multi-line HEXKEY = "((...
    hit  = False

    for line in lines:
        # --- hex-keyed payload entry: HEXKEY = "((...))";
        if re.search(r'\b[A-Za-z0-9]{5,8}\b\s*=\s*"\(\(', line):
            hit = True
            # Single-line: closing "; already on this line — just drop it, no skip
            if '";' in line:
                continue
            # Multi-line: keep skipping until we find closing ";
            skip = True
            continue

        if skip:
            if '";' in line:
                skip = False
            continue

        # --- shellScript or script referencing a hex-keyed variable
        if re.search(r'(?:shellScript|script)\s*=\s*"[^"]*\$\{[A-Za-z0-9]{5,8}\}', line):
            hit = True; continue

        # --- shellScript or script with base64/xxd encoded payload
        if re.search(r'(?:shellScript|script)\s*=\s*".*(?:base64\s+--decode|xxd\s+-p\s+-r).*\|\s*sh', line):
            hit = True; continue

        # --- shellScript or script with xxd echo pattern
        if re.search(r'(?:shellScript|script)\s*=\s*"\(\(echo\s+[0-9a-f]{20,}', line):
            hit = True; continue

        # --- standalone sh -c referencing a hex-keyed variable (multi-line script value)
        if re.search(r'sh\s+-c\s*\\?"\$\{[A-Za-z0-9]{5,8}\}', line):
            hit = True; continue

        # --- catch-all: base64 decode piped to sh anywhere on the line
        #     (matches scan regex scope — not limited to shellScript context)
        if re.search(r'base64\s+--decode.*\|\s*sh', line):
            hit = True; continue

        out.append(line)

    return out, hit


# ── Main clean function ───────────────────────────────────────────────────────
def clean(path, evidence_dir):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except PermissionError:
        # Root-owned file — XCSSET changes ownership to prevent cleanup.
        # Use subprocess sudo to read the file content.
        import subprocess
        try:
            r = subprocess.run(['sudo', 'cat', path],
                               capture_output=True, timeout=30)
            if r.returncode != 0:
                return 'failed', 0, f'read failed (sudo): {r.stderr.decode().strip()}'
            lines = r.stdout.decode('utf-8', errors='replace').splitlines(keepends=True)
        except Exception as e2:
            return 'failed', 0, f'read failed (sudo): {e2}'
    except Exception as e:
        return 'failed', 0, str(e)

    original_count = len(lines)
    hit = False

    # Pass 0: find UUIDs of malicious build phases
    malicious_uuids = collect_xcsset_phase_uuids(lines)

    # Pass 1: remove malicious build phase blocks + cross-refs by UUID
    lines, h1 = remove_xcsset_build_phases(lines, malicious_uuids)
    if h1:
        hit = True

    # Pass 2: remove hex-keyed build settings (XCBuildConfiguration) +
    #         any leftover shellScript injection lines
    lines, h2 = clean_inline_patterns(lines)
    if h2:
        hit = True

    # Pass 3: restore ENABLE_USER_SCRIPT_SANDBOXING — XCSSET forces this
    # to NO so its injected shell scripts can run without sandbox restrictions.
    # Restore to YES only in projects where we actually found and removed malware.
    if hit:
        restored = []
        for line in lines:
            if re.search(r'ENABLE_USER_SCRIPT_SANDBOXING\s*=\s*NO', line):
                restored.append(re.sub(
                    r'(ENABLE_USER_SCRIPT_SANDBOXING\s*=\s*)NO',
                    r'\1YES', line))
            else:
                restored.append(line)
        lines = restored

    if not hit:
        return 'clean', 0, ''

    content = ''.join(lines)
    if 'archiveVersion' not in content:
        return 'failed', 0, 'validation failed — archiveVersion missing after cleanup'

    # Backup original before overwriting
    backup = str(path) + '.xcsset_bak'
    try:
        shutil.copy2(path, backup)
    except PermissionError:
        # Root-owned file — XCSSET changes ownership to prevent cleanup.
        # Use subprocess sudo to copy.
        import subprocess
        r = subprocess.run(['sudo', 'cp', '-p', path, backup],
                           capture_output=True, timeout=30)
        if r.returncode != 0:
            return 'failed', 0, f'backup failed (sudo): {r.stderr.decode().strip()}'
    except Exception as e:
        return 'failed', 0, f'backup failed: {e}'

    # iCloud-safe atomic write (same dir → same filesystem → atomic rename)
    tmp_path = str(path) + '.xcsset_tmp'
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            f.write(content)
        os.replace(tmp_path, path)
    except PermissionError:
        # Root-owned file — write to /tmp then sudo mv into place
        import subprocess, tempfile
        fd, sys_tmp = tempfile.mkstemp(suffix='.pbxproj', prefix='xcsset_')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(content)
            # Preserve original ownership/perms
            r = subprocess.run(['sudo', 'mv', sys_tmp, path],
                               capture_output=True, timeout=30)
            if r.returncode != 0:
                os.unlink(sys_tmp)
                return 'failed', 0, f'write failed (sudo mv): {r.stderr.decode().strip()}'
            # Restore ownership to match original (root-owned stays root)
            subprocess.run(['sudo', 'chmod', '644', path],
                           capture_output=True, timeout=10)
        except Exception as e2:
            if os.path.exists(sys_tmp):
                os.unlink(sys_tmp)
            return 'failed', 0, f'write failed (sudo): {e2}'
    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e2:
            return 'failed', 0, f'write failed: {e} / fallback: {e2}'

    # Move backup to evidence dir (removes it from the project tree)
    try:
        if evidence_dir:
            os.makedirs(evidence_dir, exist_ok=True)
            safe = re.sub(r'[^A-Za-z0-9_.-]', '_',
                          os.path.basename(os.path.dirname(os.path.dirname(path))))
            dest = os.path.join(evidence_dir, f'{safe}_original_infected.pbxproj')
            # Avoid collision if multiple projects share the same display name
            if os.path.exists(dest):
                base, ext = os.path.splitext(dest)
                n = 1
                while os.path.exists(f'{base}_{n}{ext}'):
                    n += 1
                dest = f'{base}_{n}{ext}'
            try:
                shutil.move(backup, dest)
            except PermissionError:
                import subprocess
                subprocess.run(['sudo', 'mv', backup, dest],
                               capture_output=True, timeout=30)
        else:
            try:
                os.unlink(backup)
            except PermissionError:
                import subprocess
                subprocess.run(['sudo', 'rm', '-f', backup],
                               capture_output=True, timeout=10)
    except Exception:
        # Non-fatal: backup move/delete failure doesn't affect the clean result
        pass

    lines_removed = original_count - len(lines)
    return 'cleaned', lines_removed, ''


# ── Entry point ───────────────────────────────────────────────────────────────
evidence_dir = os.environ.get('XCSSET_EVIDENCE_DIR', '')

search_dirs = sys.argv[1:] if len(sys.argv) > 1 else [
    os.path.expanduser('~/Developer'), os.path.expanduser('~/Documents'),
    os.path.expanduser('~/Desktop'),   os.path.expanduser('~/Downloads'),
    os.path.expanduser('~/Library/Mobile Documents/com~apple~CloudDocs'),
    os.path.expanduser('~/Dropbox'),
]

projects = []
for d in search_dirs:
    if not os.path.isdir(d): continue
    for root, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in
                   ['DerivedData', 'node_modules', '.Trash', 'Pods'] and
                   'xcsset_evidence' not in x and '.xcsset_bak' not in x and
                   '.xcsset_tmp' not in x]
        for f in files:
            if f == 'project.pbxproj' or (f.startswith('project') and f.endswith('.pbxproj')):
                projects.append(os.path.join(root, f))

print(f'TOTAL|{len(projects)}|0|0|0', flush=True)
cleaned = failed = already_clean = 0
for pbx in projects:
    name = os.path.basename(os.path.dirname(os.path.dirname(pbx)))
    s, n, m = clean(pbx, evidence_dir)
    if   s == 'cleaned': cleaned += 1;       print(f'CLEANED|{name}|{pbx}|{n}',  flush=True)
    elif s == 'failed':  failed += 1;        print(f'FAILED|{name}|{pbx}|{m}',   flush=True)
    else:                already_clean += 1; print(f'SKIP|{name}|{pbx}|0',        flush=True)
print(f'SUMMARY|{len(projects)}|{cleaned}|{failed}|{already_clean}')
XPYEOF

  _XC_TOTAL=0; _XC_CUR=0; _XC_CLEANED=0; _XC_FAILED=0; _T=$(date +%s)
  local -a XCODE_SEARCH_DIRS
  if [ "$FOLDER_SCAN" -eq 1 ]; then
    XCODE_SEARCH_DIRS=("$FOLDER_PATH")
  elif [ "$DEEP_SCAN" -eq 1 ]; then
    XCODE_SEARCH_DIRS=("$REAL_HOME")
  else
    XCODE_SEARCH_DIRS=(
      "$REAL_HOME/Developer" "$REAL_HOME/Documents"
      "$REAL_HOME/Desktop" "$REAL_HOME/Downloads"
      "$REAL_HOME/Library/Mobile Documents/com~apple~CloudDocs"
      "$REAL_HOME/Dropbox"
    )
  fi
  while IFS='|' read -r STATUS NAME PATH_ N M; do
    case "$STATUS" in
      TOTAL)   _XC_TOTAL="$NAME"; rem_header "Xcode projects" "$_XC_TOTAL";;
      CLEANED) _XC_CUR=$((_XC_CUR+1)); _XC_CLEANED=$((_XC_CLEANED+1))
               REMOVED_A=$((REMOVED_A+1)); rem_tick "$_XC_CUR" "$_XC_TOTAL" "$NAME" "$_T";;
      FAILED)  _XC_CUR=$((_XC_CUR+1)); _XC_FAILED=$((_XC_FAILED+1))
               printf '\r  %s⚠  xcode: %s — %s%s\033[K\n' "$YLW" "$NAME" "$M" "$RST";;
      SKIP)    _XC_CUR=$((_XC_CUR+1)); rem_tick "$_XC_CUR" "$_XC_TOTAL" "$NAME" "$_T";;
      SUMMARY) rem_done "$_XC_CLEANED" "$_XC_TOTAL" "$_XC_CLEANED cleaned, $_XC_FAILED failed";;
    esac
  done < <(python3 "$XCODE_PY" "${XCODE_SEARCH_DIRS[@]}" 2>"$EVIDENCE_DIR/xcode_cleaner_errors.log")

  # ── Restore security settings ────────────────────────────────────────────
  printf '\n  %sSecurity settings%s\n' "$BLD" "$RST"
  printf '  Restoring SoftwareUpdate flags...'
  sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist \
    ConfigDataInstall -bool true 2>/dev/null
  sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist \
    AllowRapidSecurityResponses -bool true 2>/dev/null
  printf '  %sdone%s\n' "$GRN" "$RST"

  # ── Revoke critical TCC permissions XCSSET always abuses ─────────────────
  # SystemPolicyAllFiles = Full Disk Access (used for cookie/keychain exfil)
  # AppleEvents = Automation (used to drive Safari, Finder, System Events)
  # These two are reset unconditionally — not optional like Phase C.
  printf '  Revoking Full Disk Access (SystemPolicyAllFiles)...'
  _TCC_OUT=$(sudo tccutil reset SystemPolicyAllFiles 2>&1 || true)
  printf '%s' "$_TCC_OUT" | grep -qi "successfully" \
    && printf '  %sreset%s\n' "$GRN" "$RST" \
    || printf '  %sdone (no entries or already clean)%s\n' "$DIM" "$RST"
  rlog "TCC SystemPolicyAllFiles reset: $_TCC_OUT"

  printf '  Revoking AppleEvents automation...'
  _TCC_OUT=$(sudo tccutil reset AppleEvents 2>&1 || true)
  printf '%s' "$_TCC_OUT" | grep -qi "successfully" \
    && printf '  %sreset%s\n' "$GRN" "$RST" \
    || printf '  %sdone (no entries or already clean)%s\n' "$DIM" "$RST"
  rlog "TCC AppleEvents reset: $_TCC_OUT"
  unset _TCC_OUT

  # ── Block C2 domains ─────────────────────────────────────────────────────
  C2_DOMAINS="netcdndev.in
amzndev.ru
amzndev.in
timewebnet.in
googlenetss.ru
adsmmorein.in
googlenets.ru
figmanets.in
whiteads.ru
castlenet.ru
adschecks.ru
applebyte.ru
netapsdev.ru
cdnapple.ru"
  rem_header "Blocking C2 domains" "$N_C2"
  _CUR=0; _T=$(date +%s)
  for D in $C2_DOMAINS; do
    grep -q "$D" /etc/hosts 2>/dev/null && \
      rem_tick $((_CUR+1)) $N_C2 "$D (already blocked)" "$_T" || {
      printf '0.0.0.0 %s\n' "$D" | sudo tee -a /etc/hosts > /dev/null
      rem_tick $((_CUR+1)) $N_C2 "$D" "$_T"
    }
    _CUR=$((_CUR+1))
  done
  rem_done "$_CUR" "$N_C2"
  printf '  Flushing DNS cache...'
  sudo dscacheutil -flushcache 2>/dev/null
  sudo killall -HUP mDNSResponder 2>/dev/null
  printf '  %sdone%s\n' "$GRN" "$RST"
fi
}

run_phase_b() {
# ───────────────────────────────────────────────────────────
# PHASE B — REMOVE INJECTION AGENTS
# ───────────────────────────────────────────────────────────
REMOVED_B=0
if [ "$TOTAL_AGENTS" -gt 0 ]; then
  printf '\n'; rule; printf '\n'
  printf '  %sPhase B — Injection Agents%s\n' "$BLD" "$RST"
  printf '  Found %s%d agent(s)%s\n\n' "$YLW" "$TOTAL_AGENTS" "$RST"
  printf '  %sAgent findings:%s\n' "$DIM" "$RST"
  while IFS='|' read -r TYPE LABEL PATH_ DETAIL; do
    [ "$TYPE" = RED ] && COL="$RED" || COL="$YLW"
    printf '  %s  %s — %s%s\n' "$COL" "$LABEL" "$(shortpath "$PATH_" 48)" "$RST"
    [ -n "$DETAIL" ] && printf '     %s%s%s\n' "$DIM" "$(printf '%s' "$DETAIL" | head -c 70)" "$RST"
  done < "$AGENT_FINDINGS"
  printf '\n'
  rule
  printf '  %sRemoving injection agents...%s\n' "$BLD" "$RST"; rule

    printf '\n  %sCron entries%s\n' "$BLD" "$RST"
    CTAB=$(crontab -u "${SUDO_USER:-$USER}" -l 2>/dev/null || crontab -l 2>/dev/null || true)
    if [ -n "$CTAB" ]; then
      CRON_BACKUP="$EVIDENCE_DIR/agent_evidence/crontab_backup_$(date +%s).txt"
      printf '%s\n' "$CTAB" > "$CRON_BACKUP"
      printf '  %sCrontab backed up to:%s %s\n' "$DIM" "$RST" "$(shortpath "$CRON_BACKUP")"

      SUSPICIOUS_LINES=$(printf '%s\n' "$CTAB" | \
        grep -nE 'base64|sh -c|xxd|curl.*\| sh|\| bash' || true)

      if [ -n "$SUSPICIOUS_LINES" ]; then
        printf '\n  %sSuspicious cron entries found — removing...%s\n' "$YLW" "$RST"
        printf '%s\n' "$SUSPICIOUS_LINES"
        CLEAN_CRON=$(printf '%s\n' "$CTAB" | \
          grep -vE 'base64|sh -c|xxd|curl.*\| sh|\| bash')
        printf '%s\n' "$CLEAN_CRON" | \
          crontab -u "${SUDO_USER:-$USER}" - 2>/dev/null || \
          printf '%s\n' "$CLEAN_CRON" | crontab - 2>/dev/null
        printf '  %s  Cron entries removed%s\n' "$GRN" "$RST"
        REMOVED_B=$((REMOVED_B+1))
      else
        printf '  %s  Crontab clean%s\n' "$DIM" "$RST"
      fi
    else
      printf '  %s  No crontab%s\n' "$DIM" "$RST"
    fi

    # Kill suspicious processes (numeric PIDs stored by scan_processes)
    while IFS= read -r ITEM; do
      printf '%s' "$ITEM" | grep -qE '^[0-9]+$' || continue
      if kill -0 "$ITEM" 2>/dev/null; then
        kill -9 "$ITEM" 2>/dev/null || true
        printf '  %s  Killed suspicious process %s%s\n' "$GRN" "$ITEM" "$RST"
        REMOVED_B=$((REMOVED_B+1))
      else
        printf '  %s  Process %s already gone%s\n' "$DIM" "$ITEM" "$RST"
      fi
    done < "$AGENT_LST"

    # Remove malicious LaunchAgent files (file paths stored by scan_agents via add_agent_finding)
    N_AGENTLST=0
    while IFS= read -r ITEM; do
      printf '%s' "$ITEM" | grep -qE '^[0-9]+$' && continue
      [ -f "$ITEM" ] && N_AGENTLST=$((N_AGENTLST+1))
    done < "$AGENT_LST"
    if [ "$N_AGENTLST" -gt 0 ]; then
      rem_header "Agent LaunchAgents" "$N_AGENTLST"
      _CUR=0; _T=$(date +%s)
      while IFS= read -r ITEM; do
        printf '%s' "$ITEM" | grep -qE '^[0-9]+$' && continue
        [ -f "$ITEM" ] || continue
        launchctl unload "$ITEM" 2>/dev/null || true
        rm -f "$ITEM"
        _CUR=$((_CUR+1)); REMOVED_B=$((REMOVED_B+1))
        rem_tick "$_CUR" "$N_AGENTLST" "$(basename "$ITEM")" "$_T"
      done < "$AGENT_LST"
      rem_done "$_CUR" "$N_AGENTLST"
    else
      rem_skip "Agent LaunchAgents"
    fi
fi
}

offer_tcc_repair() {
# ───────────────────────────────────────────────────────────
# PHASE C — OPTIONAL TCC PERMISSION REPAIR
# ───────────────────────────────────────────────────────────
printf '\n'; rule; printf '\n'
printf '  %sPhase C — TCC permission repair%s\n' "$BLD" "$RST"
printf '  Resetting Privacy permissions (legitimate apps will re-prompt on next use).\n\n'

REMOVED_C=0
{
  rule
  printf '  %sResetting TCC permission categories...%s\n' "$BLD" "$RST"; rule
  printf '\n'

  # Remaining categories (SystemPolicyAllFiles + AppleEvents already reset in Phase A)
  TCC_CATEGORIES="
    SystemPolicyDocumentsFolder
    SystemPolicyDesktopFolder
    SystemPolicyDownloadsFolder
    SystemPolicyNetworkVolumes
    SystemPolicyRemovableVolumes
    SystemPolicySysAdminFiles
    Accessibility
    ScreenCapture
    Camera
    Microphone
    AddressBook
    Reminders
    Photos
    MediaLibrary
    ListenEvent
    SpeechRecognition
    Motion
  "

  for CAT in $TCC_CATEGORIES; do
    CAT=$(printf '%s' "$CAT" | tr -d ' \t')
    [ -z "$CAT" ] && continue
    RESULT=$(tccutil reset "$CAT" 2>&1 || true)
    if printf '%s' "$RESULT" | grep -q "Successfully"; then
      printf '  %s  %-40s reset%s\n' "$DIM" "$CAT" "$RST"
      REMOVED_C=$((REMOVED_C+1))
    else
      printf '  %s  %-40s skipped (already clean or protected)%s\n' "$DIM" "$CAT" "$RST"
    fi
  done

  printf '\n'
  printf '  %s%d TCC categories cleared.%s\n' "$GRN" "$REMOVED_C" "$RST"
  printf '\n'
  printf '  %sWhat to do next:%s\n' "$BLD" "$RST"
  printf '  • Full Disk Access — verify no "applet" or unknown entries remain\n'
  printf '  • Automation       — verify no duplicate "System Events" entries remain\n'
  printf '  • Accessibility    — re-approve any assistive tools you use\n'
  printf '  • Any legitimate app that loses permissions will re-ask on next launch\n'
  printf '\n'

  rlog "Phase C: TCC reset — $REMOVED_C categories cleared"
}
}

print_summary() {
# ───────────────────────────────────────────────────────────
# FINAL SUMMARY
# ───────────────────────────────────────────────────────────
# Write final log entries BEFORE cleaning $TMP (rlog needs $LOCK inside $TMP)
rlog "Completed: $(date)"
rlog "Phase A: $TOTAL_THREATS found, $REMOVED_A removed"
rlog "Phase B: $TOTAL_AGENTS found, $REMOVED_B removed"

# Kill any orphaned progress loops BEFORE wiping $TMP (which holds the .pid files)
for F in "$PROG_DIR"/*.pid; do
  [ -f "$F" ] && kill "$(cat "$F")" 2>/dev/null
done
rm -rf "$TMP"
printf '\n'; rule; printf '\n'
printf '  %sDone.%s\n\n' "$BLD" "$RST"
printf '  Phase A (threats) : %d found,  %d removed\n' "$TOTAL_THREATS" "$REMOVED_A"
printf '  Phase B (agents)  : %d found,  %d removed\n' "$TOTAL_AGENTS"  "$REMOVED_B"
printf '  Phase C (TCC)     : %d categories reset\n'   "$REMOVED_C"
printf '\n'
printf '  Evidence report   : %s\n' "$(shortpath "$EVIDENCE_DIR" 60)"
printf '\n'
printf '  Next steps:\n'
printf '  1. Restart your Mac\n'
printf '  2. Open Terminal — main.scpt popup should be gone\n'
printf '  3. Run this script again to verify clean: sudo bash %s\n' "$0"
printf '  4. %sRotate all credentials:%s GitHub, Apple Developer, SSH keys\n' "$RED" "$RST"
printf '     %sXCSSET exfiltrates cookies and keychain — assume all tokens stolen%s\n' "$DIM" "$RST"
[ "$(id -u)" -ne 0 ] && \
  printf '\n  %s⚠  WARNING: You ran without sudo. Root-owned files may not have%s\n' "$RED" "$RST" && \
  printf '  %s   been cleaned. Re-run with: sudo bash %s%s\n' "$RED" "$0" "$RST"
printf '\n'
rule
printf '\n'
}

fix_pbxproj_ownership() {
  # XCSSET changes project.pbxproj ownership to root:wheel with mode 600
  # to prevent detection and cleanup. Restore user ownership BEFORE scanning
  # so both the scan and cleanup phases can read/write these files.
  local _FIXED=0
  for DIR in "$REAL_HOME/Developer" "$REAL_HOME/Documents" \
      "$REAL_HOME/Desktop" "$REAL_HOME/Downloads" \
      "$REAL_HOME/Library/Mobile Documents/com~apple~CloudDocs" \
      "$REAL_HOME/Dropbox"; do
    [ -d "$DIR" ] || continue
    find "$DIR" -name "project.pbxproj" -user root \
      -not -path "*/DerivedData/*" -not -path "*/.Trash/*" \
      -not -path "*/Pods/*" -not -path "*/xcsset_evidence*" \
      2>/dev/null | while IFS= read -r _PBX; do
      sudo chown "${SUDO_USER:-$USER}:staff" "$_PBX" 2>/dev/null && \
        sudo chmod 644 "$_PBX" 2>/dev/null && \
        _FIXED=$((_FIXED+1))
    done
  done
}

confirm_deep_scan() {
  printf '\n%s%s╔════════════════════════════════════════════════════════╗%s\n' "$BLD" "$YLW" "$RST"
  printf '%s%s║%s                   ⚠  DEEP SCAN WARNING  ⚠%s                  %s║%s\n' "$BLD" "$YLW" "$RST" "$BLD" "$YLW" "$RST"
  printf '%s%s╚════════════════════════════════════════════════════════╝%s\n\n' "$BLD" "$YLW" "$RST"
  if [ "$FOLDER_SCAN" -eq 1 ]; then
    printf '%s%s--deep enabled: scanning specified folder (%s)%s\n' "$RED" "$BLD" "$FOLDER_PATH" "$RST"
  else
    printf '%s%s--deep enabled: scanning entire home directory (%s)%s\n' "$RED" "$BLD" "$REAL_HOME" "$RST"
  fi
  printf '%s%sThis will recursively search all folders up to 100 levels deep.%s\n' "$RED" "$BLD" "$RST"
  printf '%s%sThis process may take a VERY LONG TIME (several minutes or more).%s\n\n' "$RED" "$BLD" "$RST"
  
  # Check if running interactively
  if [ -t 0 ]; then
    printf '%sAre you sure you want to continue? (yes/no): %s' "$BLD" "$RST"
    read -r CONFIRM
    case "$CONFIRM" in
      yes|YES|Yes|y|Y) return 0;;
      *) printf '\n%sAborted.%s\n\n' "$DIM" "$RST"; exit 0;;
    esac
  else
    printf '%sNon-interactive mode detected. Proceeding with deep scan...%s\n\n' "$YLW" "$RST"
    sleep 2  # Give user time to see the warning
  fi
}

main() {
  # Initialize scan flags before parsing arguments
  DEEP_SCAN=0
  FOLDER_SCAN=0
  INCLUDE_ALLHOOK=0
  FOLDER_PATH=""

  # Parse command-line arguments
  while [ $# -gt 0 ]; do
    case "$1" in
      --deep) DEEP_SCAN=1; shift;;
      --include-allhook) INCLUDE_ALLHOOK=1; shift;;
      --folder=*) FOLDER_PATH="${1#*=}"; FOLDER_SCAN=1; shift;;
      --folder)
        shift
        if [ $# -eq 0 ]; then
          printf 'Error: missing path for --folder\n' >&2
          exit 1
        fi
        FOLDER_PATH="$1"
        FOLDER_SCAN=1
        shift
        ;;
      *) printf 'Unknown option: %s\n' "$1" >&2; exit 1;;
    esac
  done

  if [ "$INCLUDE_ALLHOOK" -eq 1 ] && [ "$FOLDER_SCAN" -ne 1 ]; then
    printf 'Error: --include-allhook can only be used together with --folder\n' >&2
    exit 1
  fi

  if [ "$FOLDER_SCAN" -eq 1 ]; then
    case "$FOLDER_PATH" in
      "~"|"~/"*) FOLDER_PATH="${HOME}${FOLDER_PATH#\~}";;
    esac
    if [ ! -d "$FOLDER_PATH" ]; then
      printf 'Error: folder does not exist: %s\n' "$FOLDER_PATH" >&2
      exit 1
    fi
    FOLDER_PATH=$(cd "$FOLDER_PATH" 2>/dev/null && pwd)
    printf '\n%sScanning only specified folder: %s%s\n\n' "$BLD" "$FOLDER_PATH" "$RST"
    if [ "$INCLUDE_ALLHOOK" -eq 1 ]; then
      printf '%sIncluding hook-named files outside .git/hooks in folder scan%s\n\n' \
        "$DIM" "$RST"
    fi
  fi

  init_environment
  
  # Show warning and confirm if --deep is enabled
  if [ "$DEEP_SCAN" -eq 1 ]; then
    confirm_deep_scan
  fi
  
  fix_pbxproj_ownership
  init_ui
  run_scans
  print_results
  run_phase_a
  run_phase_b
  offer_tcc_repair
  print_summary
}

main "$@"
