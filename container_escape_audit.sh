#!/usr/bin/env bash
# =============================================================================
# container_escape_audit.sh  —  v4.7.3
# Copyright (c) 2026 Liam Romanis
#
# Licence: Creative Commons Attribution-NonCommercial 4.0 International
#          (CC BY-NC 4.0)
#          https://creativecommons.org/licenses/by-nc/4.0/
# SPDX-License-Identifier: CC-BY-NC-4.0
#
# You are free to use, share, and adapt this tool for non-commercial purposes,
# provided you give appropriate credit and indicate any changes made.
# Commercial use requires explicit written permission from the author.
#
# Detects potential container escape vectors from within a running container.
# Intended for AUTHORISED security assessments only.
#
# Usage:
#   chmod +x container_escape_audit.sh
#   ./container_escape_audit.sh [options]
#
# Options:
#   --report <file>      Write a detailed human-readable report to <file>,
#                         used EXACTLY as given — no timestamp is appended.
#                         (default: container_escape_report_<timestamp>.txt)
#   --report-name <name> Use <name> as the report file's base name, with the
#                         same "_<timestamp>.txt" suffix the default uses —
#                         e.g. --report-name prod-node-07 produces
#                         prod-node-07_20260714_153000.txt. If --report is
#                         ALSO given, --report is used verbatim and
#                         --report-name is ignored (a warning is printed).
#                         If neither is given, the original default name
#                         (container_escape_report_<timestamp>.txt) is used
#                         unchanged.
#   --json            Also emit a machine-readable JSON summary to stdout
#   --quiet           Suppress info lines; print only WARN/CRITICAL to terminal
#   --no-report       Skip writing the report file entirely
#   --cve-conf <file> Path to CVE check config file
#                     (default: same directory as this script / cve_checks.conf)
#   --check-updates   Check github.com/liamromanis101/K8s-container_escape_audit
#                     for a newer script release (release.txt) and a newer CVE
#                     database (cve_release.txt vs. this cve_checks.conf's own
#                     "Last updated" line). Completely opt-in — no network call
#                     is made at all unless this flag is given. Prints:
#                       ## Update Check:
#                       [Script]: Yes|No
#                       [CVEs]: Yes|No
#                     If GitHub can't be reached, prints that plainly and
#                     tells you to check the repo manually — never fails or
#                     blocks the rest of the audit.
#
# Each finding in the report includes:
#   - What it is
#   - Impact
#   - Exploitability
#   - Recommendation
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# CLI flags
# ---------------------------------------------------------------------------
OUTPUT_JSON=false
QUIET=false
NO_REPORT=false
DUMP_STATE=false
CHECK_UPDATES=false
SCRIPT_VERSION="4.7.3"
REPORT_NAME_BASE="container_escape_report"   # default base name; overridable via --report-name
REPORT_FILE=""                                 # left empty until after arg parsing unless --report is given explicitly
REPORT_FILE_EXPLICIT=false                     # true only if --report set the filename verbatim
CVE_CONF_ENV="${CVE_CONF:-}"                   # capture env var BEFORE the next line clears it
CVE_CONF=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)          OUTPUT_JSON=true ;;
    --quiet)         QUIET=true ;;
    --no-report)     NO_REPORT=true ;;
    --report)        shift; REPORT_FILE="$1"; REPORT_FILE_EXPLICIT=true ;;
    --report-name)   shift; REPORT_NAME_BASE="$1" ;;
    --cve-conf)      shift; CVE_CONF="$1" ;;
    --dump-state)    DUMP_STATE=true ;;
    --check-updates) CHECK_UPDATES=true ;;
    *) echo "Unknown option: $1" >&2 ;;
  esac
  shift
done

# Resolve the CVE conf path here (CLI flag > environment variable > script
# directory) rather than just before run_cve_checks — the update-check
# (below, if --check-updates is given) also needs to know which conf file's
# "Last updated" line to compare, so both need this resolved early.
if [[ -z "$CVE_CONF" ]]; then
  CVE_CONF="${CVE_CONF_ENV:-}"
fi
if [[ -z "$CVE_CONF" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  CVE_CONF="${SCRIPT_DIR}/cve_checks.conf"
fi

# --report always wins if both are given — it's a complete, verbatim filename
# and there's no sensible way to also honour a base name on top of it.
if [[ "$REPORT_FILE_EXPLICIT" == true && "$REPORT_NAME_BASE" != "container_escape_report" ]]; then
  echo "Note: --report was given a full filename; --report-name is ignored (using --report as-is)." >&2
fi

# Only compute the base-name + timestamp filename if --report did NOT already
# set one explicitly — this is what makes --report-name's "continue with the
# existing method if unset" behaviour work: an unset --report-name leaves
# REPORT_NAME_BASE at its original default, reproducing the exact filename
# the script always used, just via this variable instead of a literal.
if [[ "$REPORT_FILE_EXPLICIT" == false ]]; then
  REPORT_FILE="${REPORT_NAME_BASE}_$(date +%Y%m%d_%H%M%S).txt"
fi

# ---------------------------------------------------------------------------
# Colour helpers (disabled when JSON mode or non-TTY)
# ---------------------------------------------------------------------------
if [[ "$OUTPUT_JSON" == false && -t 1 ]]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

# ---------------------------------------------------------------------------
# Update check (opt-in via --check-updates only — this tool otherwise makes
# NO network calls at all; nothing here runs unless explicitly requested).
#
# Checks two independent things against two small files in the repo:
#   release.txt      - just the latest script version, e.g. "4.7"
#   cve_release.txt  - just the date cve_checks.conf was last updated,
#                      e.g. "2026-07-20", compared against the LOCAL conf
#                      file's own "# Last updated: YYYY-MM-DD" trailer line
#                      (so it reflects whatever cve_checks.conf is actually
#                      in use, not an assumption baked into the script).
#
# Self-contained on purpose (its own version comparator, no dependency on
# functions defined later in the file) so it can run immediately after the
# banner, before any checks, rather than waiting on the CVE engine to load.
# ---------------------------------------------------------------------------
_update_ver_lt() {
  local a="$1" b="$2"
  [[ "$a" == "$b" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)" == "$a" ]]
}

check_for_updates() {
  [[ "$CHECK_UPDATES" == false ]] && return
  [[ "$OUTPUT_JSON" == true ]] && return  # plain-text output would corrupt the JSON stream on stdout

  local repo_raw="https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/main"
  local have_fetch=true
  _uc_fetch() { :; }
  if command -v curl >/dev/null 2>&1; then
    _uc_fetch() { curl -fsSL --max-time 4 --connect-timeout 2 "$1" 2>/dev/null; }
  elif command -v wget >/dev/null 2>&1; then
    _uc_fetch() { wget -qO- --timeout=4 "$1" 2>/dev/null; }
  else
    have_fetch=false
  fi

  echo ""
  echo "## Update Check:"

  if [[ "$have_fetch" == false ]]; then
    echo "Could not check for updates: neither curl nor wget is available on this system."
    echo "Please check https://github.com/liamromanis101/K8s-container_escape_audit manually."
    echo ""
    return
  fi

  local remote_script_ver remote_cve_date
  remote_script_ver="$(_uc_fetch "${repo_raw}/release.txt" | tr -d '[:space:]')"
  remote_cve_date="$(_uc_fetch "${repo_raw}/cve_release.txt" | tr -d '[:space:]')"

  if [[ -z "$remote_script_ver" && -z "$remote_cve_date" ]]; then
    echo "Could not reach GitHub — no network access, blocked egress, or the"
    echo "repository was temporarily unreachable. Please check"
    echo "https://github.com/liamromanis101/K8s-container_escape_audit manually."
    echo ""
    return
  fi

  local script_status="Unknown"
  if [[ "$remote_script_ver" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
    if _update_ver_lt "$SCRIPT_VERSION" "$remote_script_ver"; then
      script_status="Yes"
    else
      script_status="No"
    fi
  fi

  local local_cve_date=""
  if [[ -f "$CVE_CONF" ]]; then
    local_cve_date="$(grep -oE '^# Last updated: [0-9]{4}-[0-9]{2}-[0-9]{2}' "$CVE_CONF" 2>/dev/null | head -1 | awk '{print $NF}')"
  fi
  local cve_status="Unknown"
  if [[ "$remote_cve_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    if [[ -n "$local_cve_date" ]]; then
      if [[ "$local_cve_date" < "$remote_cve_date" ]]; then
        cve_status="Yes"
      else
        cve_status="No"
      fi
    fi
  fi

  echo "[Script]: ${script_status}"
  echo "[CVEs]: ${cve_status}"
  if [[ "$script_status" == "Yes" || "$cve_status" == "Yes" ]]; then
    echo "See: https://github.com/liamromanis101/K8s-container_escape_audit/releases"
  fi
  [[ "$script_status" == "Unknown" || "$cve_status" == "Unknown" ]] && \
    echo "(An 'Unknown' result means the corresponding remote file was missing or unreadable — check the repo manually.)"
  echo ""
}

# ---------------------------------------------------------------------------
# Findings store
# ---------------------------------------------------------------------------
declare -A FINDINGS
FINDING_ORDER=()
SEP=$'\x1f'

add_finding() {
  local id="$1" severity="$2" title="$3"
  local what="${4:-}" impact="${5:-}" exploit="${6:-}" rec="${7:-}" evidence="${8:-}"
  FINDINGS["$id"]="${severity}${SEP}${title}${SEP}${what}${SEP}${impact}${SEP}${exploit}${SEP}${rec}${SEP}${evidence}"
  FINDING_ORDER+=("$id")
}

# ---------------------------------------------------------------------------
# Generic system-state registry
# ---------------------------------------------------------------------------
# Standard checks record generic, CVE-agnostic facts about the system here so
# that later composite CVE checks can reference them instead of re-deriving the
# same signal. Keys are stable identifiers (e.g. MAC_ENFORCING, USERNS_RESTRICTED);
# values are one of: true / false / unknown  (or a short token where a boolean
# is insufficient, e.g. MAC_MODE=enforcing|permissive|disabled|none).
#
# Rationale (see design notes): a fact like "is an enforcing LSM active" or
# "are unprivileged user namespaces restricted" is a property of the system,
# not of any one CVE. Computing it once and publishing it here avoids every
# CVE check re-implementing AppArmor/SELinux/userns probing, and means adding a
# new standard signal automatically benefits every CVE that consumes it.
declare -A SYS_STATE

# set_state KEY VALUE  — publish a generic system-state fact.
set_state() {
  SYS_STATE["$1"]="$2"
}

# get_state KEY [DEFAULT]  — read a fact; prints DEFAULT (or "unknown") if unset.
get_state() {
  local key="$1" default="${2:-unknown}"
  if [[ -n "${SYS_STATE[$key]+x}" ]]; then
    printf '%s' "${SYS_STATE[$key]}"
  else
    printf '%s' "$default"
  fi
}


# ---------------------------------------------------------------------------
# Terminal logging helpers
# ---------------------------------------------------------------------------
info()  { [[ "$QUIET" == false && "$OUTPUT_JSON" == false ]] && echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()  { [[ "$OUTPUT_JSON" == false ]] && echo -e "${YELLOW}[WARN]${RESET}  $*"; }
crit()  { [[ "$OUTPUT_JSON" == false ]] && echo -e "${RED}[CRIT]${RESET}  $*"; }
ok()    { [[ "$QUIET" == false && "$OUTPUT_JSON" == false ]] && echo -e "${GREEN}[ OK ]${RESET}  $*"; }
hdr()   { [[ "$OUTPUT_JSON" == false ]] && echo -e "\n${BOLD}${CYAN}--- $* ---${RESET}"; }

# ---------------------------------------------------------------------------
# CVE evidence trail
# ---------------------------------------------------------------------------
# Each CVE check records the individual sub-tests it performs — the concrete
# observation AND the raw value behind it — into CVE_EVIDENCE. The buffer is
# reset at the start of every CVE check via _ev_reset, accumulated by _ev as
# the helpers run, and rendered both to stdout (beneath the verdict line) and
# into the finding's 7th 'evidence' field for the report and JSON.
#
# Each entry has the form "<outcome>${US}<label>${US}<detail>" where outcome is
# one of PASS / FLAG / INFO / SKIP, used only to pick a glyph/colour on stdout.
CVE_EVIDENCE=()
EUS=$'\x1e'   # unit separator between outcome/label/detail within one entry
EROW=$'\x1d'  # row separator between evidence entries when packed into a field
KVER_VERDICT=""   # set by _kernel_in_affected_range: fixed|not-affected|vulnerable|defer|unknown

_ev_reset() { CVE_EVIDENCE=(); }

# _ev <outcome> <label> <detail>
#   outcome: PASS | FLAG | INFO | SKIP
#   label  : short name of the sub-test (e.g. "Kernel version range")
#   detail : the concrete result incl. raw values (e.g. "running=6017000 ...")
_ev() {
  local outcome="$1" label="$2" detail="${3:-}"
  CVE_EVIDENCE+=("${outcome}${EUS}${label}${EUS}${detail}")
}

# Glyph + colour for an evidence outcome (stdout only)
_ev_glyph() {
  case "$1" in
    PASS) echo -e "${GREEN}+${RESET}" ;;
    FLAG) echo -e "${YELLOW}!${RESET}" ;;
    SKIP) echo -e "${CYAN}~${RESET}" ;;
    *)    echo -e "${CYAN}.${RESET}" ;;
  esac
}

# Print the accumulated evidence to stdout as indented sub-bullets.
# Long detail lines are word-wrapped to the terminal width and continuation
# lines are hang-indented to align under the first line's text, so wrapped
# output stays in the indented column instead of falling back to column 0.
# Suppressed in --quiet and --json modes (the report/JSON still carry it).
_ev_print_stdout() {
  [[ "$OUTPUT_JSON" == true || "$QUIET" == true ]] && return
  local entry outcome label detail glyph

  # Visible prefix is: 9 spaces + 1 glyph char + 1 space = 11 columns.
  # Continuation lines are indented to that same column.
  local indent="           "   # 11 spaces

  # Determine wrap width from the terminal, default to 100, clamp to a sane min.
  local width="${COLUMNS:-0}"
  if [[ "$width" -le 0 ]]; then
    width=$(tput cols 2>/dev/null || echo 100)
  fi
  [[ "$width" -lt 40 ]] && width=100
  # Width available for the wrapped text after the 11-column indent.
  local textw=$(( width - 11 ))
  [[ "$textw" -lt 30 ]] && textw=30

  for entry in "${CVE_EVIDENCE[@]}"; do
    IFS="$EUS" read -r outcome label detail <<< "$entry"
    glyph=$(_ev_glyph "$outcome")

    local body
    if [[ -n "$detail" ]]; then
      body="${label}: ${detail}"
    else
      body="${label}"
    fi

    # Word-wrap the body, then attach the glyph prefix to the first line and
    # hang-indent every continuation line to the same column.
    local first_line=true
    while IFS= read -r wrapped; do
      if [[ "$first_line" == true ]]; then
        echo -e "         ${glyph} ${wrapped}"
        first_line=false
      else
        echo -e "${indent}${wrapped}"
      fi
    done < <(printf '%s\n' "$body" | fold -s -w "$textw")
  done
}

# Pack the current CVE_EVIDENCE buffer into a single field value (rows joined
# with EROW) for storage in the finding. Returns empty string if no evidence.
_ev_pack() {
  local out="" entry
  for entry in "${CVE_EVIDENCE[@]}"; do
    [[ -n "$out" ]] && out+="${EROW}"
    out+="${entry}"
  done
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------
write_report() {
  [[ "$NO_REPORT" == true ]] && return
  local f="$REPORT_FILE"

  {
    echo "============================================================"
    echo " CONTAINER ESCAPE AUDIT REPORT"
    echo " Generated  : $(date)"
    echo " Hostname   : $(hostname 2>/dev/null || echo 'unknown')"
    echo " Kernel     : $(uname -r 2>/dev/null || echo 'unknown')"
    echo " UID / GID  : $(id 2>/dev/null || echo 'unknown')"
    echo " CGroup     : $(cat /proc/1/cgroup 2>/dev/null | head -1 || echo 'unknown')"
    echo "============================================================"
    echo ""

    local n_crit=0 n_high=0 n_med=0 n_info=0
    for fid in "${FINDING_ORDER[@]}"; do
      IFS="$SEP" read -r sev _ _ _ _ _ _ <<< "${FINDINGS[$fid]}"
      case "$sev" in
        CRITICAL) (( n_crit++ )) ;;
        HIGH)     (( n_high++ )) ;;
        MEDIUM)   (( n_med++  )) ;;
        INFO)     (( n_info++ )) ;;
      esac
    done

    echo "EXECUTIVE SUMMARY"
    echo "------------------------------------------------------------"
    printf "  %-12s %d\n" "CRITICAL:"  "$n_crit"
    printf "  %-12s %d\n" "HIGH:"      "$n_high"
    printf "  %-12s %d\n" "MEDIUM:"    "$n_med"
    printf "  %-12s %d\n" "INFO:"      "$n_info"
    printf "  %-12s %d\n" "TOTAL:"     "$(( n_crit + n_high + n_med + n_info ))"
    echo ""

    for pass in CRITICAL HIGH MEDIUM INFO; do
      local printed_header=false
      for fid in "${FINDING_ORDER[@]}"; do
        IFS="$SEP" read -r sev title what impact exploit rec evidence <<< "${FINDINGS[$fid]}"
        [[ "$sev" != "$pass" ]] && continue

        if [[ "$printed_header" == false ]]; then
          echo "============================================================"
          echo " $pass FINDINGS"
          echo "============================================================"
          printed_header=true
        fi

        local border="  ------------------------------------------------------------"
        echo ""
        echo "  ID           : $fid"
        echo "  Severity     : $sev"
        echo "  Title        : $title"
        echo ""
        echo "  WHAT IT IS"
        echo "$what" | fold -s -w 70 | sed 's/^/    /'
        echo ""
        if [[ -n "$evidence" ]]; then
          echo "  CHECKS PERFORMED"
          local _row _o _l _d _mark
          while IFS= read -r _row; do
            [[ -z "$_row" ]] && continue
            IFS="$EUS" read -r _o _l _d <<< "$_row"
            case "$_o" in
              PASS) _mark="[pass]" ;;
              FLAG) _mark="[FLAG]" ;;
              SKIP) _mark="[skip]" ;;
              *)    _mark="[info]" ;;
            esac
            if [[ -n "$_d" ]]; then
              printf '    %s %s: %s\n' "$_mark" "$_l" "$_d" | fold -s -w 74 | sed '2,$s/^/        /'
            else
              printf '    %s %s\n' "$_mark" "$_l"
            fi
          done <<< "$(printf '%s' "$evidence" | tr "$EROW" '\n')"
          echo ""
        fi
        echo "  IMPACT"
        echo "$impact" | fold -s -w 70 | sed 's/^/    /'
        echo ""
        echo "  EXPLOITABILITY"
        echo "$exploit" | fold -s -w 70 | sed 's/^/    /'
        echo ""
        echo "  RECOMMENDATION"
        echo "$rec" | fold -s -w 70 | sed 's/^/    /'
        echo ""
        echo "$border"
      done
    done

    echo ""
    echo "END OF REPORT"
    echo "This report was generated for authorised security assessment purposes only."

  } > "$f"

  echo -e "\n${GREEN}[REPORT]${RESET} Written to: ${BOLD}$f${RESET}"
}

# ---------------------------------------------------------------------------
# JSON emitter
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# _json_escape — escape a string for safe inclusion in JSON.
# Handles backslash, double-quote, control chars (tab/newline/CR) and any
# literal backslash-escapes carried in field text (e.g. "\0", "\n"). Without
# this, descriptions containing a backslash or a raw control char produce
# invalid JSON. Prefer python3 when present (fully correct), else fall back to
# sed for the common cases.
# ---------------------------------------------------------------------------
_json_escape() {
  local s="$1"
  if command -v python3 &>/dev/null; then
    printf '%s' "$s" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])'
  else
    # Fallback: backslash first, then quotes, then collapse real control chars.
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"
    printf '%s' "$s"
  fi
}

emit_json() {
  local first=true
  echo "{"
  echo "  \"tool\": \"container_escape_audit\","
  echo "  \"version\": \"4.4\","
  echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"host\": \"$(hostname 2>/dev/null || echo 'unknown')\","
  echo "  \"kernel\": \"$(uname -r 2>/dev/null || echo 'unknown')\","
  echo "  \"findings\": ["
  for fid in "${FINDING_ORDER[@]}"; do
    IFS="$SEP" read -r sev title what impact exploit rec evidence <<< "${FINDINGS[$fid]}"
    [[ "$first" == false ]] && echo ","
    first=false
    printf '    {\n      "id": "%s",\n      "severity": "%s",\n      "title": "%s",\n      "what": "%s",\n      "impact": "%s",\n      "exploitability": "%s",\n      "recommendation": "%s",\n      "checks_performed": [' \
      "$(_json_escape "$fid")" "$(_json_escape "$sev")" \
      "$(_json_escape "$title")" \
      "$(_json_escape "$what")" \
      "$(_json_escape "$impact")" \
      "$(_json_escape "$exploit")" \
      "$(_json_escape "$rec")"
    if [[ -n "$evidence" ]]; then
      local _ev_first=true _row _o _l _d
      echo ""
      while IFS= read -r _row; do
        [[ -z "$_row" ]] && continue
        IFS="$EUS" read -r _o _l _d <<< "$_row"
        [[ "$_ev_first" == false ]] && echo ","
        _ev_first=false
        printf '        {"outcome": "%s", "check": "%s", "detail": "%s"}' \
          "$(_json_escape "$_o")" "$(_json_escape "$_l")" "$(_json_escape "$_d")"
      done <<< "$(printf '%s' "$evidence" | tr "$EROW" '\n')"
      printf '\n      ]'
    else
      printf ']'
    fi
    printf '\n    }'
  done
  echo ""
  echo "  ]"
  echo "}"
}

# ===========================================================================
# CHECK FUNCTIONS  —  Checks 1-23
# ===========================================================================

check_privileged() {
  hdr "1. Privileged container"
  local capeff
  capeff=$(grep CapEff /proc/self/status | awk '{print $2}')
  if [[ "$capeff" == "0000003fffffffff" || "$capeff" == "000001ffffffffff" || \
        "$capeff" == "0000001fffffffff" ]]; then
    crit "Container appears PRIVILEGED (CapEff=$capeff)"
    add_finding "privileged_container" "CRITICAL" \
      "Container is running in privileged mode" \
      "The container was started with --privileged (or equivalent), granting it every Linux capability. The effective capability bitmask is $capeff." \
      "Full host compromise is trivial. A privileged container can mount the host's raw block devices, load kernel modules, modify kernel parameters, and escape all namespace isolation. This is operationally equivalent to having a root shell on the host node with no restrictions." \
      "Trivial. No exploit required. 'mount /dev/sda1 /mnt && chroot /mnt' gives immediate host root access. Automated tools such as deepce and CDK detect this and perform the escape automatically." \
      "Never use --privileged in production. Grant only specific required capabilities via --cap-add. Enforce Pod Security Admission (PSA) at the 'restricted' or 'baseline' level to prevent privileged pods cluster-wide."
  else
    ok "Container does not appear fully privileged (CapEff=$capeff)"
  fi
}

check_capabilities() {
  hdr "2. Dangerous Linux capabilities"
  local capeff
  capeff=$(grep CapEff /proc/self/status | awk '{print $2}')

  if command -v capsh &>/dev/null; then
    info "Decoded capabilities: $(capsh --decode="$capeff" 2>/dev/null || echo 'decode failed')"
  fi

  local -A CAP_NAME CAP_WHAT CAP_IMPACT CAP_EXPLOIT CAP_REC

  CAP_NAME[21]="CAP_SYS_ADMIN"
  CAP_WHAT[21]="CAP_SYS_ADMIN grants a broad set of administrative kernel privileges: mounting filesystems, creating namespaces, loading eBPF programs, and manipulating cgroup hierarchies."
  CAP_IMPACT[21]="Near-equivalent to full host root. Enables cgroup release_agent escape, mount-based host filesystem access, namespace manipulation, and eBPF-based kernel memory writes."
  CAP_EXPLOIT[21]="High. CAP_SYS_ADMIN alone is sufficient for the cgroup release_agent escape. CDK and deepce automate this."
  CAP_REC[21]="Remove CAP_SYS_ADMIN entirely. Apply PSA restricted profile. Block mount(2) and clone(2) with namespace flags via seccomp."

  CAP_NAME[19]="CAP_SYS_PTRACE"
  CAP_WHAT[19]="CAP_SYS_PTRACE allows attaching a debugger to any visible process, reading and writing its memory, and intercepting its system calls via ptrace(2)."
  CAP_IMPACT[19]="If the host PID namespace is shared, an attacker can attach to host processes to extract secrets, inject shellcode, or take over host daemons entirely."
  CAP_EXPLOIT[19]="Medium. Requires a visible privileged target process. gdb/strace attachment is trivial once a target is identified."
  CAP_REC[19]="Remove CAP_SYS_PTRACE. Never share the host PID namespace with application workloads. Enforce ptrace_scope >= 1 via sysctl on the host."

  CAP_NAME[16]="CAP_SYS_MODULE"
  CAP_WHAT[16]="CAP_SYS_MODULE allows loading and unloading Linux kernel modules directly into the running kernel via init_module(2) and delete_module(2)."
  CAP_IMPACT[16]="Unrestricted kernel code execution. A malicious kernel module can open reverse shells from kernel space, patch LSM hooks to disable AppArmor/SELinux, or disable seccomp enforcement."
  CAP_EXPLOIT[16]="High if a compiler or pre-built module is available. A minimal reverse-shell kernel module is approximately 20 lines of C."
  CAP_REC[16]="Remove CAP_SYS_MODULE. Lock module loading with kernel.modules_disabled=1 after boot. Apply seccomp to block init_module(2) and finit_module(2) syscalls."

  CAP_NAME[17]="CAP_SYS_RAWIO"
  CAP_WHAT[17]="CAP_SYS_RAWIO allows direct read/write access to physical memory (/dev/mem, /dev/kmem) and raw block devices, bypassing all filesystem abstractions."
  CAP_IMPACT[17]="Reading /dev/mem exposes all physical RAM including kernel secrets. Writing enables kernel patching and arbitrary code execution at the physical memory level."
  CAP_EXPLOIT[17]="Medium-high. Standard tools (dd) assist. Most effective against kernels without CONFIG_STRICT_DEVMEM=y."
  CAP_REC[17]="Remove CAP_SYS_RAWIO. Ensure /dev/mem is not exposed. Build kernels with CONFIG_STRICT_DEVMEM=y."

  CAP_NAME[2]="CAP_DAC_READ_SEARCH"
  CAP_WHAT[2]="CAP_DAC_READ_SEARCH bypasses discretionary access control checks for reading files and searching directories regardless of permissions."
  CAP_IMPACT[2]="Enables the Shocker exploit: using open_by_handle_at(2) to open files on the host filesystem by inode, bypassing chroot jails. A container can read /etc/shadow, SSH private keys, or any other sensitive host file."
  CAP_EXPLOIT[2]="Medium. The Shocker PoC is publicly available. Requires brute-forcing inode numbers, feasible on ext4 filesystems."
  CAP_REC[2]="Remove CAP_DAC_READ_SEARCH. Apply a seccomp profile blocking open_by_handle_at(2)."

  CAP_NAME[12]="CAP_NET_ADMIN"
  CAP_WHAT[12]="CAP_NET_ADMIN grants control over the host's network stack: creating interfaces, modifying routing tables, adjusting iptables/nftables rules."
  CAP_IMPACT[12]="An attacker can redirect traffic, sniff packets between pods, modify firewall rules, or create tunnel interfaces for covert exfiltration."
  CAP_EXPLOIT[12]="Medium. Requires network tooling in the container. Primary risk is lateral movement and traffic interception."
  CAP_REC[12]="Remove CAP_NET_ADMIN unless the workload manages network interfaces. Use Kubernetes NetworkPolicy for traffic control."

  CAP_NAME[7]="CAP_SETUID"
  CAP_WHAT[7]="CAP_SETUID allows changing the process's user ID to any value, including UID 0 (root), via setuid(2)."
  CAP_IMPACT[7]="An attacker can call setuid(0) to become root within the container, enabling exploitation of any other misconfiguration that requires root."
  CAP_EXPLOIT[7]="Low-medium alone, High combined with other findings. setuid(0) is a single syscall."
  CAP_REC[7]="Remove CAP_SETUID. Set runAsNonRoot: true and allowPrivilegeEscalation: false in the pod security context."

  CAP_NAME[6]="CAP_SETGID"
  CAP_WHAT[6]="CAP_SETGID allows changing the process's group ID to any value, including joining privileged groups such as docker, disk, or shadow."
  CAP_IMPACT[6]="Joining the docker group allows controlling the Docker daemon. Joining the disk group gives read/write access to all block devices."
  CAP_EXPLOIT[6]="Low-medium. Impact depends on which privileged groups exist."
  CAP_REC[6]="Remove CAP_SETGID. Run as a specific non-root user and group. Set allowPrivilegeEscalation: false."

  CAP_NAME[0]="CAP_CHOWN"
  CAP_WHAT[0]="CAP_CHOWN allows changing the ownership of any file to any user/group, bypassing normal ownership restrictions."
  CAP_IMPACT[0]="An attacker can chown any file including SUID binaries, sensitive config files, or key material on host-mounted paths."
  CAP_EXPLOIT[0]="Low-medium. Most effective as a chaining capability alongside other misconfigurations."
  CAP_REC[0]="Remove CAP_CHOWN unless strictly required. Use readOnlyRootFilesystem: true."

  CAP_NAME[39]="CAP_BPF"
  CAP_WHAT[39]="CAP_BPF (split out of CAP_SYS_ADMIN in kernel 5.8) permits loading BPF programs and creating most BPF map types via bpf(2)."
  CAP_IMPACT[39]="Combined with CAP_PERFMON (or CAP_SYS_ADMIN), a container can load kernel-tracing BPF programs to read arbitrary kernel memory and, in documented cross-container attacks, escape to the host. On its own it substantially widens the kernel attack surface reachable from the container."
  CAP_EXPLOIT[39]="Medium-high. The CAP_BPF + CAP_PERFMON container-escape chain is publicly documented ('Bewildered eBPF on Clouds'). Requires the bpf(2) syscall to be reachable (see check 28)."
  CAP_REC[39]="Remove CAP_BPF unless the workload legitimately loads eBPF. Block bpf(2) via seccomp. Prefer RuntimeDefault seccomp, which denies bpf(2)."

  CAP_NAME[38]="CAP_PERFMON"
  CAP_WHAT[38]="CAP_PERFMON (split out of CAP_SYS_ADMIN in kernel 5.8) grants access to performance-monitoring and observability interfaces including perf_event_open(2) and certain BPF helpers."
  CAP_IMPACT[38]="Extends the BPF/tracing attack surface. In combination with CAP_BPF it enables kernel-memory reads used in cross-container escape research. perf subsystem bugs have historically yielded LPE."
  CAP_EXPLOIT[38]="Medium. Primarily dangerous chained with CAP_BPF or against a vulnerable perf subsystem (see check 46 perf_event hardening)."
  CAP_REC[38]="Remove CAP_PERFMON unless profiling is required. Restrict perf_event_open(2) via kernel.perf_event_paranoid and seccomp."

  CAP_NAME[1]="CAP_DAC_OVERRIDE"
  CAP_WHAT[1]="CAP_DAC_OVERRIDE bypasses all discretionary access control (read, write, and execute permission checks) on files and directories."
  CAP_IMPACT[1]="Full read/write to any file the container can see regardless of ownership or mode. On any host-mounted path this permits editing /etc/passwd, SSH keys, SUID binaries, or unit files to escalate or escape."
  CAP_EXPLOIT[1]="Low-medium alone; High when any sensitive host path is mounted (see check 4). No exploit needed — it is a direct permission bypass."
  CAP_REC[1]="Remove CAP_DAC_OVERRIDE unless strictly required. Use readOnlyRootFilesystem: true and avoid mounting host paths."

  CAP_NAME[27]="CAP_MKNOD"
  CAP_WHAT[27]="CAP_MKNOD allows creating special files (device nodes) with mknod(2), including block and character devices."
  CAP_IMPACT[27]="A container can create a device node for a host block device (e.g. the root disk) and then read/write it directly, bypassing the filesystem entirely — a classic path to host disk access and escape when device cgroup controls are permissive."
  CAP_EXPLOIT[27]="Medium. Requires that the device cgroup allow access to the created node; where it does, 'mknod' + 'dd' against the host disk is straightforward."
  CAP_REC[27]="Remove CAP_MKNOD (it is dropped by the runtime default set but often re-added). Ensure the device cgroup denies unlisted devices."

  CAP_NAME[18]="CAP_SYS_CHROOT"
  CAP_WHAT[18]="CAP_SYS_CHROOT permits calling chroot(2) to change the apparent filesystem root."
  CAP_IMPACT[18]="Enables chroot-based confinement-escape tricks (double-chroot / fchdir breakout) and assists other escapes that manipulate the root directory. Dangerous mainly in combination with host-path visibility or CAP_DAC_READ_SEARCH."
  CAP_EXPLOIT[18]="Low-medium. A chaining primitive rather than a standalone escape."
  CAP_REC[18]="Remove CAP_SYS_CHROOT unless the workload legitimately re-roots. Apply seccomp blocking chroot(2)."

  CAP_NAME[13]="CAP_NET_RAW"
  CAP_WHAT[13]="CAP_NET_RAW allows opening raw and packet sockets (AF_PACKET), enabling arbitrary packet crafting and sniffing on the container's network."
  CAP_IMPACT[13]="Permits sniffing traffic of co-located pods on a shared L2 segment, ARP/DNS spoofing, and lateral-movement traffic interception. Not a host escape but a strong pivot primitive."
  CAP_EXPLOIT[13]="Medium. Requires packet tooling in the container; ARP-spoofing co-tenants is well tooled."
  CAP_REC[13]="Drop CAP_NET_RAW (it is in the default set but rarely needed). Enforce with the PSA restricted profile and NetworkPolicy segmentation."

  CAP_NAME[34]="CAP_SYSLOG"
  CAP_WHAT[34]="CAP_SYSLOG permits privileged syslog(2) operations, including reading the kernel ring buffer and viewing kernel pointers even when kptr_restrict is set."
  CAP_IMPACT[34]="Leaks kernel addresses (defeating KASLR) via dmesg / kallsyms exposure, providing the information leak that most kernel LPE exploits require to be reliable."
  CAP_EXPLOIT[34]="Low direct impact, High as an enabler — it supplies the address leak that turns an unreliable kernel bug into a deterministic exploit (see checks 36/37 kptr/dmesg restrict)."
  CAP_REC[34]="Remove CAP_SYSLOG. Set kernel.kptr_restrict=2 and kernel.dmesg_restrict=1 on the host."

  # Optional per-capability severity override (defaults to HIGH when unset).
  local -A CAP_SEV
  CAP_SEV[13]="MEDIUM"   # CAP_NET_RAW  — lateral-movement pivot, not host escape
  CAP_SEV[18]="MEDIUM"   # CAP_SYS_CHROOT — chaining primitive
  CAP_SEV[34]="MEDIUM"   # CAP_SYSLOG   — info-leak enabler

  local cap_dec found_any=false
  cap_dec=$(printf "%d" "0x${capeff}")
  # Publish the CAP_SYS_ADMIN signal (bit 21) — a generic precondition consumed
  # by several composite CVE checks (unrestricted userns creation, /proc/sys).
  if (( (cap_dec & (1 << 21)) != 0 )); then
    set_state CAP_SYS_ADMIN "true"
  else
    set_state CAP_SYS_ADMIN "false"
  fi
  for bit in "${!CAP_NAME[@]}"; do
    local mask=$(( 1 << bit ))
    if (( (cap_dec & mask) != 0 )); then
      local cap_sev="${CAP_SEV[$bit]:-HIGH}"
      warn "Dangerous capability present: ${CAP_NAME[$bit]} (bit $bit)"
      add_finding "cap_${bit}" "$cap_sev" \
        "Dangerous capability present: ${CAP_NAME[$bit]}" \
        "${CAP_WHAT[$bit]}" "${CAP_IMPACT[$bit]}" "${CAP_EXPLOIT[$bit]}" "${CAP_REC[$bit]}"
      found_any=true
    fi
  done
  [[ "$found_any" == false ]] && ok "No individually dangerous capabilities detected"
}

check_namespaces() {
  hdr "3. Namespace isolation"

  local -A NS_WHAT NS_IMPACT NS_EXPLOIT NS_REC NS_SEV
  NS_SEV[pid]="HIGH"; NS_SEV[net]="HIGH"; NS_SEV[ipc]="MEDIUM"
  NS_SEV[uts]="MEDIUM"; NS_SEV[mnt]="HIGH"

  NS_WHAT[pid]="The container shares the host's PID namespace, meaning it can enumerate and interact with every process on the host node."
  NS_WHAT[net]="The container shares the host's network namespace and uses the host's actual network interfaces."
  NS_WHAT[ipc]="The container shares the host's IPC namespace, giving access to the host's shared memory segments, semaphores, and message queues."
  NS_WHAT[uts]="The container shares the host's UTS namespace; hostname and NIS domain changes affect the host system."
  NS_WHAT[mnt]="The container shares the host's mount namespace and can see the host's complete filesystem mount table."

  NS_IMPACT[pid]="An attacker can signal, inspect, and attach to any host process. /proc/<host_pid>/environ may expose secrets from host processes."
  NS_IMPACT[net]="The container can bind to any port on the host's IP addresses and access loopback-bound services unreachable from normal containers."
  NS_IMPACT[ipc]="Applications using POSIX shared memory or System V IPC can be read or corrupted from within the container."
  NS_IMPACT[uts]="Hostname changes may confuse monitoring, logging, and certificate validation."
  NS_IMPACT[mnt]="The container can enumerate all host mounts and interact with mount points that should be isolated."

  NS_EXPLOIT[pid]="Immediately exploitable for process enumeration and /proc-based secret extraction."
  NS_EXPLOIT[net]="Immediately exploitable for port binding and traffic interception given appropriate tooling."
  NS_EXPLOIT[ipc]="Depends on what IPC objects are present. 'ipcs' enumerates them trivially."
  NS_EXPLOIT[uts]="Low direct exploitability."
  NS_EXPLOIT[mnt]="Enumeration is trivial via /proc/mounts."

  NS_REC[pid]="Remove hostPID: true from pod specs. Audit: kubectl get pods -A -o json | jq '.items[] | select(.spec.hostPID==true)'."
  NS_REC[net]="Remove hostNetwork: true unless the workload is a node-level network daemon."
  NS_REC[ipc]="Remove hostIPC: true. Use a proper messaging or API layer for inter-process communication."
  NS_REC[uts]="Remove hostUTS: true. There are very few legitimate use cases."
  NS_REC[mnt]="Audit mount namespace configuration and ensure the container runtime is configured with correct isolation defaults."

  local self_pid=$$
  for ns in pid net ipc uts mnt; do
    if [[ -e "/proc/$self_pid/ns/$ns" && -e "/proc/1/ns/$ns" ]]; then
      local self_ns init_ns
      self_ns=$(readlink "/proc/$self_pid/ns/$ns" 2>/dev/null || echo "")
      init_ns=$(readlink "/proc/1/ns/$ns" 2>/dev/null || echo "")
      if [[ "$self_ns" == "$init_ns" && -n "$self_ns" ]]; then
        warn "Sharing host $ns namespace ($self_ns)"
        add_finding "host_ns_${ns}" "${NS_SEV[$ns]}" \
          "Host $ns namespace is shared" \
          "${NS_WHAT[$ns]}" "${NS_IMPACT[$ns]}" "${NS_EXPLOIT[$ns]}" "${NS_REC[$ns]}"
      else
        ok "$ns namespace is isolated"
      fi
    fi
  done
}

check_mounts() {
  hdr "4. Dangerous filesystem mounts"

  for sock in /var/run/docker.sock /run/docker.sock \
              /run/containerd/containerd.sock /var/run/containerd/containerd.sock \
              /run/crio/crio.sock /var/run/crio/crio.sock; do
    [[ -S "$sock" ]] || continue
    crit "Container runtime socket accessible: $sock"
    add_finding "runtime_socket_${sock//\//_}" "CRITICAL" \
      "Container runtime socket accessible: $sock" \
      "The container runtime's UNIX domain socket is bind-mounted into the container. This socket is the administrative API for the container daemon, which runs as root on the host." \
      "Full host node compromise. An attacker uses the Docker/containerd/CRI-O API to create a new privileged container with the host root filesystem mounted, exec into it, and obtain a root shell on the host." \
      "Trivial. 'docker run -v /:/host --privileged alpine chroot /host' is a single command. CDK and deepce perform this automatically on socket detection." \
      "Never mount the runtime socket into application containers. For CI/CD image building use rootless Docker, Kaniko, or Buildah."
  done

  local -A MOUNT_WHAT MOUNT_IMPACT MOUNT_EXPLOIT MOUNT_REC
  MOUNT_WHAT["/"]="The container's filesystem root is a bind-mount of the host root filesystem."
  MOUNT_IMPACT["/"]="Complete host filesystem read/write access. Add SSH keys, create SUID binaries, overwrite init scripts, install backdoors."
  MOUNT_EXPLOIT["/"]="Trivial. Standard filesystem commands are sufficient."
  MOUNT_REC["/"]="Never bind-mount the host root. Use minimal, specific volume mounts."
  MOUNT_WHAT["/etc"]="/etc contains authentication databases, network config, and service config. A bind-mount makes the host's /etc available."
  MOUNT_IMPACT["/etc"]="Writable access allows adding root accounts, granting passwordless sudo, poisoning DNS, or modifying service configs."
  MOUNT_EXPLOIT["/etc"]="'echo attacker::0:0::/root:/bin/bash >> /etc/passwd && su attacker' gives immediate root."
  MOUNT_REC["/etc"]="Use Kubernetes ConfigMaps for configuration. If bind-mount is unavoidable, use read-only mode."
  MOUNT_WHAT["/proc/sys"]="The kernel's /proc/sys filesystem is mounted, exposing kernel parameter controls."
  MOUNT_IMPACT["/proc/sys"]="Writable core_pattern allows executing arbitrary code as root. Writable sysrq-trigger allows immediate host reboot."
  MOUNT_EXPLOIT["/proc/sys"]="Writing a pipe handler to core_pattern then triggering a crash executes arbitrary code as root."
  MOUNT_REC["/proc/sys"]="Mount /proc/sys read-only. Apply seccomp to block sysctl(2)."
  MOUNT_WHAT["/sys"]="The host's sysfs is mounted, exposing kernel subsystem interfaces including cgroup controls."
  MOUNT_IMPACT["/sys"]="Writable sysfs enables the cgroup release_agent host escape and hardware state manipulation."
  MOUNT_EXPLOIT["/sys"]="The cgroup release_agent escape via /sys/fs/cgroup is extensively documented and automated."
  MOUNT_REC["/sys"]="Mount sysfs read-only or not at all for application containers."
  MOUNT_WHAT["/dev"]="The host's /dev directory is mounted, exposing raw device files including physical disks and memory."
  MOUNT_IMPACT["/dev"]="Access to /dev/sda* allows direct disk read/write bypassing filesystem permissions. /dev/mem exposes all physical RAM."
  MOUNT_EXPLOIT["/dev"]="'dd if=/dev/sda of=/tmp/disk.img' dumps the host disk. Direct disk writes modify any file on the host."
  MOUNT_REC["/dev"]="Never mount /dev. For GPU/hardware requirements use the Kubernetes device plugin framework."

  while IFS= read -r line; do
    local device mountpoint fstype options
    read -r device _ mountpoint fstype options _ <<< "$line"
    case "$fstype" in
      proc|sysfs|tmpfs|devpts|cgroup|cgroup2|mqueue|hugetlbfs|pstore|securityfs|debugfs|tracefs|bpf|overlay)
        continue ;;
    esac
    local rw_flag="read-only"
    echo "$options" | grep -q '\brw\b' && rw_flag="READ-WRITE"
    for prefix in "/" "/etc" "/proc/sys" "/sys" "/dev"; do
      if [[ "$mountpoint" == "$prefix" || "$mountpoint" == "$prefix/"* ]]; then
        local sev="HIGH"
        [[ "$rw_flag" == "READ-WRITE" ]] && sev="CRITICAL"
        warn "$rw_flag mount of sensitive path: $mountpoint ($fstype)"
        add_finding "mount_${prefix//\//_}_${rw_flag// /-}" "$sev" \
          "Sensitive host path mounted ($rw_flag): $mountpoint" \
          "${MOUNT_WHAT[$prefix]:-Sensitive path $prefix is mounted.} Mountpoint: $mountpoint, mode: $rw_flag." \
          "${MOUNT_IMPACT[$prefix]:-Sensitive host data may be accessible.}" \
          "${MOUNT_EXPLOIT[$prefix]:-Depends on path and permissions.}" \
          "${MOUNT_REC[$prefix]:-Review and restrict this mount.}"
      fi
    done
  done < /proc/mounts
}

check_proc() {
  hdr "5. /proc filesystem exposure"

  # Publish the generic "/proc/sys writable from here" signal for composite CVE
  # checks (privileged-container indicator; gates several page-cache and
  # core_pattern-based escapes). core_pattern is the canonical probe point.
  if [[ -w /proc/sys/kernel/core_pattern ]]; then
    set_state PROC_SYS_WRITABLE "true"
  else
    set_state PROC_SYS_WRITABLE "false"
  fi

  if [[ -w /proc/sys/kernel/core_pattern ]]; then
    crit "/proc/sys/kernel/core_pattern is writable"
    add_finding "proc_core_pattern_writable" "CRITICAL" \
      "Writable /proc/sys/kernel/core_pattern" \
      "This kernel parameter specifies how crash dump files are named. When the value begins with '|', the kernel executes the specified program as root when any process crashes." \
      "An attacker sets core_pattern to '|/tmp/escape.sh'. They trigger a crash. The kernel executes the script as root outside all container namespaces — a clean host escape." \
      "Widely tooled. Working PoCs exist for all major distributions. CDK implements this as an automated escape technique." \
      "Set core_pattern via sysctl on the host before launching containers. Mount /proc/sys read-only inside containers."
  fi

  if [[ -w /proc/sysrq-trigger ]]; then
    crit "/proc/sysrq-trigger is writable"
    add_finding "proc_sysrq_writable" "CRITICAL" \
      "Writable /proc/sysrq-trigger" \
      "The SysRq trigger file sends magic key commands directly to the kernel regardless of running processes." \
      "Writing 'b' causes immediate host reboot. Writing 'c' causes kernel panic. Writing 'f' invokes the OOM killer." \
      "Immediate: 'echo b > /proc/sysrq-trigger' reboots the host. No exploit required." \
      "Mount /proc read-only. Apply AppArmor profiles denying writes to this path."
  fi

  if [[ -r /proc/kcore ]]; then
    warn "/proc/kcore is readable"
    add_finding "proc_kcore_readable" "HIGH" \
      "Readable /proc/kcore (kernel memory exposure)" \
      "/proc/kcore exposes the entire host kernel virtual address space as an ELF core file, including all physical memory mapped by the kernel." \
      "An attacker can read all kernel memory to extract cryptographic keys, ASLR offsets, and sensitive data from adjacent pods' memory." \
      "Moderate. Requires tooling to parse ELF format. Volatility and custom scripts make this feasible." \
      "Ensure /proc is mounted without exposing kcore. Apply seccomp to block open(2) on /proc/kcore."
  fi

  if [[ -r /proc/kmem || -w /proc/kmem ]]; then
    crit "/proc/kmem is accessible"
    add_finding "proc_kmem_accessible" "CRITICAL" \
      "/proc/kmem accessible (direct kernel memory access)" \
      "/proc/kmem provides direct read/write access to kernel virtual memory." \
      "Writing to kernel memory enables overwriting kernel code, patching security hooks, disabling LSM enforcement, or injecting arbitrary kernel payloads." \
      "High. Overwriting a kernel function pointer gives unrestricted kernel code execution." \
      "Ensure /proc/kmem and /dev/kmem are not accessible in containers. Block with seccomp. Mount /proc read-only."
  fi

  if [[ -r /proc/1/environ ]]; then
    warn "/proc/1/environ is readable (host PID1 environment exposed)"
    add_finding "proc_1_environ_readable" "HIGH" \
      "Host PID 1 environment file readable (/proc/1/environ)" \
      "/proc/1/environ contains all environment variables set when the host init process started. This may be systemd, a container runtime, or a Kubernetes kubelet." \
      "The host init environment may contain API tokens, Kubernetes bootstrap tokens, TLS private key paths, or database connection strings." \
      "cat /proc/1/environ | tr '\\0' '\\n' displays all variables. No exploit required." \
      "Run containers as non-root (hidepid=2 on /proc mount prevents non-root from reading other processes' entries)."
  fi

  ok "/proc check complete"
}

check_k8s_serviceaccount() {
  hdr "6. Kubernetes service account"
  local sa_dir="/var/run/secrets/kubernetes.io/serviceaccount"
  [[ -d "$sa_dir" ]] || { ok "No Kubernetes service account directory found"; return; }

  local token_file="$sa_dir/token"
  [[ -r "$token_file" ]] || { ok "Token not readable"; return; }

  warn "Service account token readable"
  add_finding "sa_token_readable" "HIGH" \
    "Kubernetes service account token is readable" \
    "Kubernetes mounts a service account JWT token at $token_file in every pod unless automountServiceAccountToken: false is explicitly set." \
    "Depending on RBAC permissions, an attacker can enumerate cluster resources, read secrets, create privileged pods, modify workloads, or gain cluster-admin." \
    "Low to Critical depending on RBAC. Token is a regular file read. peirates and CDK automate Kubernetes escalation from stolen tokens." \
    "Set automountServiceAccountToken: false on pods that do not call the Kubernetes API. Follow least-privilege RBAC."

  if command -v kubectl &>/dev/null; then
    local rules
    rules=$(kubectl auth can-i --list 2>/dev/null || echo "FAILED")
    if [[ "$rules" != "FAILED" ]]; then
      if echo "$rules" | grep -qE '^\*\s+\*|cluster-admin'; then
        crit "Service account appears to have cluster-admin or wildcard permissions"
        add_finding "sa_cluster_admin" "CRITICAL" \
          "Service account has cluster-admin or wildcard RBAC permissions" \
          "The service account bound to this pod has been granted cluster-admin or wildcard (*) RBAC permissions." \
          "Full Kubernetes cluster compromise. Read all secrets across all namespaces, create privileged pods on any node, modify any workload." \
          "Trivial. 'kubectl --token=<token> get secrets -A' retrieves every secret in the cluster." \
          "Immediately revoke the cluster-admin binding. Conduct a full RBAC audit. Rotate all exposed secrets."
      fi
    fi
  fi
}

check_env_secrets() {
  hdr "7. Environment variable secret leakage"
  local patterns=(PASSWORD PASSWD SECRET TOKEN API_KEY APIKEY PRIVATE_KEY
                  ACCESS_KEY AUTH_TOKEN DATABASE_URL DB_PASS REDIS_PASS
                  AWS_SECRET GCP_KEY GITHUB_TOKEN SLACK_TOKEN STRIPE_KEY)
  local found=false
  for pat in "${patterns[@]}"; do
    while IFS= read -r envvar; do
      local varname="${envvar%%=*}"
      warn "Potentially sensitive env var: $varname"
      add_finding "env_${varname}" "MEDIUM" \
        "Sensitive environment variable present: $varname" \
        "The environment variable '$varname' matches patterns commonly associated with credentials, API keys, or secrets." \
        "Any process achieving code execution can read these values. Env vars are also visible in container inspect output, pod descriptions, and application logs." \
        "'cat /proc/self/environ | tr '\\0' '\\n'' lists all environment variables. No exploit required." \
        "Use a secrets management solution (Vault, AWS Secrets Manager) and mount secrets as files rather than environment variables."
      found=true
    done < <(env 2>/dev/null | grep -i "$pat" || true)
  done
  [[ "$found" == false ]] && ok "No obviously sensitive environment variable names found"
}

check_cron() {
  hdr "8. Cron writability"
  local paths=(/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily
               /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs)
  for p in "${paths[@]}"; do
    [[ -e "$p" && -w "$p" ]] || continue
    crit "Writable cron path: $p"
    add_finding "writable_cron_${p//\//_}" "HIGH" \
      "Writable cron directory or file: $p" \
      "The cron path at $p is writable by the current process. Cron jobs placed here are executed by the system cron daemon, typically as root." \
      "An attacker writes a cron job that executes a reverse shell or creates a backdoor account. If on a host-mounted volume, the cron job executes on the host node — a host escape with automatic persistence." \
      "Writing a cron job requires only standard file write access. Execution is automatic and requires no further interaction." \
      "Mount cron directories read-only or do not mount them. Run containers as non-root."
  done
  ok "Cron writability check complete"
}

check_auth_files() {
  hdr "9. Authentication file writability"

  local -A AUTH_WHAT AUTH_IMPACT AUTH_EXPLOIT AUTH_REC
  AUTH_WHAT["/etc/passwd"]="/etc/passwd maps usernames to UIDs and specifies default login shells."
  AUTH_IMPACT["/etc/passwd"]="Adding an entry with UID 0 creates a root account. If host-mounted, this creates a root account on the host OS itself."
  AUTH_EXPLOIT["/etc/passwd"]="'echo backdoor::0:0::/root:/bin/bash >> /etc/passwd && su backdoor' gives an immediate root shell."
  AUTH_REC["/etc/passwd"]="Apply readOnlyRootFilesystem: true. Run as non-root. Do not bind-mount /etc."
  AUTH_WHAT["/etc/shadow"]="/etc/shadow stores hashed passwords for system users."
  AUTH_IMPACT["/etc/shadow"]="Replacing root's password hash enables root login. Reading enables offline hash cracking."
  AUTH_EXPLOIT["/etc/shadow"]="Replace the root password field with a known hash then 'su root' with the known password."
  AUTH_REC["/etc/shadow"]="Apply readOnlyRootFilesystem: true. Never bind-mount /etc."
  AUTH_WHAT["/etc/sudoers"]="/etc/sudoers controls which users can execute commands as root via sudo."
  AUTH_IMPACT["/etc/sudoers"]="Adding 'ALL ALL=(ALL) NOPASSWD: ALL' grants every user passwordless root sudo. If host-mounted, this affects the host OS."
  AUTH_EXPLOIT["/etc/sudoers"]="'echo ALL ALL=(ALL) NOPASSWD: ALL >> /etc/sudoers && sudo bash' gives immediate root."
  AUTH_REC["/etc/sudoers"]="Apply readOnlyRootFilesystem: true. Do not bind-mount /etc."
  AUTH_WHAT["/etc/sudoers.d"]="/etc/sudoers.d holds additional policy files automatically included by sudo."
  AUTH_IMPACT["/etc/sudoers.d"]="Same as /etc/sudoers — allows granting passwordless root sudo to any user."
  AUTH_EXPLOIT["/etc/sudoers.d"]="Write a file containing permissive sudo rules. Instant root sudo."
  AUTH_REC["/etc/sudoers.d"]="Same as /etc/sudoers recommendations."

  for f in /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d; do
    [[ -e "$f" && -w "$f" ]] || continue
    crit "Writable auth file: $f"
    add_finding "writable_auth_${f//\//_}" "CRITICAL" \
      "Writable authentication file: $f" \
      "${AUTH_WHAT[$f]}" "${AUTH_IMPACT[$f]}" "${AUTH_EXPLOIT[$f]}" "${AUTH_REC[$f]}"
  done
  ok "Auth file writability check complete"
}

check_memory_access() {
  hdr "10. Process memory access"

  local ptrace_scope
  ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "unknown")
  if [[ "$ptrace_scope" == "0" ]]; then
    warn "ptrace_scope=0: permissive process tracing policy"
    add_finding "ptrace_scope_0" "MEDIUM" \
      "Kernel ptrace_scope is 0 (permissive)" \
      "ptrace_scope=0 means any process owned by the same UID can attach to any other owned process via ptrace(2)." \
      "Combined with a shared host PID namespace, an attacker can attach to host processes to read their memory or inject shellcode." \
      "Moderate. gdb/strace attachment is trivial once a target is identified." \
      "Set kernel.yama.ptrace_scope=1 or higher in /etc/sysctl.d/ on the host."
  else
    ok "ptrace_scope=$ptrace_scope"
  fi

  if [[ -r /dev/mem || -w /dev/mem ]]; then
    local access="readable"; [[ -w /dev/mem ]] && access="writable"
    crit "/dev/mem is $access"
    add_finding "dev_mem_${access}" "CRITICAL" \
      "/dev/mem is $access (physical memory device)" \
      "/dev/mem is a character device providing direct access to the host's physical memory address space." \
      "Reading exposes all physical RAM — kernel code, all processes' memory, encryption keys. Writing enables kernel code patching." \
      "High. 'dd if=/dev/mem | strings' extracts readable data from all physical memory." \
      "Ensure /dev/mem is not passed via --device. Build kernels with CONFIG_STRICT_DEVMEM=y."
  fi
}

check_security_profiles() {
  hdr "11. Security profiles (Seccomp / AppArmor / SELinux)"

  local seccomp_mode
  seccomp_mode=$(grep Seccomp /proc/self/status 2>/dev/null | awk '{print $2}')
  case "$seccomp_mode" in
    0)
      warn "Seccomp: DISABLED"
      add_finding "seccomp_disabled" "MEDIUM" \
        "Seccomp is disabled for this container" \
        "Seccomp restricts the set of system calls available to a process. When disabled, all Linux syscalls are available." \
        "Many escape techniques rely on syscalls that a seccomp profile would block: unshare(2), clone(2), mount(2), init_module(2), open_by_handle_at(2), keyctl(2), bpf(2), and perf_event_open(2)." \
        "Seccomp being disabled is not itself an escape vector, but removes a critical defence-in-depth layer." \
        "Apply seccompProfile.type: RuntimeDefault to all pods. For sensitive workloads, create a custom allowlist profile." ;;
    1) ok "Seccomp: strict mode (mode 1)" ;;
    2) ok "Seccomp: BPF filter active (mode 2)" ;;
  esac

  # --- no_new_privs bit -----------------------------------------------------
  # The kernel-level control behind allowPrivilegeEscalation: false. When 0, a
  # process can gain privileges via SUID binaries or file capabilities on exec;
  # when 1, the kernel refuses those transitions for the process and its
  # children. Readable directly from /proc/self/status (NoNewPrivs: 0|1).
  local nnp
  nnp=$(grep -i '^NoNewPrivs:' /proc/self/status 2>/dev/null | awk '{print $2}')
  if [[ "$nnp" == "0" ]]; then
    warn "no_new_privs is NOT set (NoNewPrivs: 0)"
    add_finding "no_new_privs_unset" "MEDIUM" \
      "no_new_privs bit is not set (privilege escalation via SUID/file caps possible)" \
      "The no_new_privs process attribute is 0, meaning the kernel will still honour set-user-ID/set-group-ID bits and file capabilities when this process or its children call execve(2). This is the kernel primitive behind the Kubernetes allowPrivilegeEscalation setting; a value of 0 indicates allowPrivilegeEscalation was not set to false (or was explicitly true)." \
      "If a SUID-root binary (e.g. a stray sudo, mount, or ping with the SUID bit) or a file with file capabilities exists in the container image, a non-root process can execute it to gain elevated privileges, which is often the first rung of an escape chain that other findings in this report can complete." \
      "Low on its own; a force-multiplier when combined with SUID binaries (check 13) or a writable-auth-file / mount finding. It removes a kernel-enforced barrier rather than being an exploit itself." \
      "Set securityContext.allowPrivilegeEscalation: false on the container (this sets no_new_privs=1). Pair with runAsNonRoot: true and a dropped capability set, and strip SUID/SGID bits from image binaries that do not need them."
  elif [[ "$nnp" == "1" ]]; then
    ok "no_new_privs is set (NoNewPrivs: 1) — SUID/file-cap privilege gain blocked"
  fi

  if [[ -f /proc/self/attr/current ]]; then
    local aa_label
    aa_label=$(cat /proc/self/attr/current 2>/dev/null || echo "")
    if [[ -z "$aa_label" || "$aa_label" == "unconfined" ]]; then
      warn "AppArmor: UNCONFINED"
      add_finding "apparmor_unconfined" "MEDIUM" \
        "AppArmor profile is not applied (unconfined)" \
        "AppArmor applies mandatory access control based on profiles restricting file access, capabilities, and network operations." \
        "The Docker default AppArmor profile blocks writes to /proc/sys and restricts mount operations. Without it, these path-based restrictions are absent." \
        "Not a direct escape, but removes protection against file-based attack paths." \
        "Ensure the runtime applies an AppArmor profile. Apply profiles via securityContext.appArmorProfile in Kubernetes."
    else
      ok "AppArmor profile applied: $aa_label"
    fi
  fi

  # --- AppArmor enforcement-artifact inspection -----------------------------
  # The gap analysis flagged "Multiple vulnerabilities in AppArmor" (oss-security
  # 2026-05-20) as an EXTEND of the LSM status check: knowing AppArmor is
  # "applied" is not the same as knowing the userspace stack (parser, profiles
  # directory) is present and enforcing. Inspect the observable artifacts so a
  # profile that is loaded-but-stale, or a missing parser, is visible.
  local aa_enabled_file="/sys/module/apparmor/parameters/enabled"
  local aa_present=false aa_enforcing="unknown"
  if [[ -r "$aa_enabled_file" ]]; then
    aa_present=true
    case "$(cat "$aa_enabled_file" 2>/dev/null)" in
      Y|1) aa_enforcing="enabled" ;;
      N|0) aa_enforcing="disabled" ;;
      *)   aa_enforcing="unknown" ;;
    esac
  fi

  local aa_profiles_count="unknown"
  if [[ -r /sys/kernel/security/apparmor/profiles ]]; then
    aa_profiles_count=$(wc -l < /sys/kernel/security/apparmor/profiles 2>/dev/null || echo "unknown")
  fi

  local aa_parser="absent"
  command -v apparmor_parser &>/dev/null && aa_parser="present"

  if [[ "$aa_present" == true && "$aa_enforcing" == "disabled" ]]; then
    warn "AppArmor LSM present but globally disabled (${aa_enabled_file}=N)"
    add_finding "apparmor_lsm_disabled" "MEDIUM" \
      "AppArmor LSM is present in the kernel but globally disabled" \
      "The AppArmor LSM is compiled into this kernel but is disabled (${aa_enabled_file} reports disabled). Loaded profiles: ${aa_profiles_count}. apparmor_parser binary: ${aa_parser}. Per-container confinement labels are therefore not enforced regardless of any per-pod appArmorProfile setting." \
      "With the LSM globally disabled, AppArmor-based mitigations for other findings in this report (for example, the cifs.upcall confinement that mitigates CIFSwitch, or the default Docker profile blocking /proc/sys writes) are NOT in effect. Recent AppArmor advisories (multiple vulnerabilities reported on oss-security, 2026-05) further underline that AppArmor cannot be relied upon as a sole control when its stack is incomplete." \
      "Low as a standalone item; HIGH as a force-multiplier because it removes a defence-in-depth layer assumed by other mitigations." \
      "Re-enable AppArmor at the host (kernel parameter apparmor=1 security=apparmor) and ensure apparmor_parser and the profile set are installed and loaded. Verify profiles are in enforce (not complain) mode. Keep the AppArmor userspace updated to pick up fixes for the 2026-05 advisory set."
  elif [[ "$aa_present" == true ]]; then
    info "AppArmor LSM enabled=${aa_enforcing}; loaded profiles=${aa_profiles_count}; parser=${aa_parser}"
  fi

  # --- SELinux enforcement --------------------------------------------------
  # Previously only named in this check's heading with no logic behind it.
  # SELinux is a generic system-state signal: multiple CVEs (e.g. CIFSwitch's
  # cifs.upcall path, the runc maskedPaths CVEs) are mitigated by an enforcing
  # policy, so the fact is computed once here and published to SYS_STATE for any
  # composite CVE check to consume.
  local se_mode="none" se_source=""
  if command -v getenforce &>/dev/null; then
    case "$(getenforce 2>/dev/null)" in
      Enforcing)  se_mode="enforcing" ;;
      Permissive) se_mode="permissive" ;;
      Disabled)   se_mode="disabled" ;;
    esac
    se_source="getenforce"
  fi
  # Fallback / corroboration via the SELinuxfs mount (works without the userspace tool).
  if [[ "$se_mode" == "none" && -r /sys/fs/selinux/enforce ]]; then
    case "$(cat /sys/fs/selinux/enforce 2>/dev/null)" in
      1) se_mode="enforcing" ;;
      0) se_mode="permissive" ;;
    esac
    se_source="/sys/fs/selinux/enforce"
  fi
  # /etc/selinux/config tells us the configured (boot) mode even if the tool is absent.
  local se_configured="unknown"
  if [[ -r /etc/selinux/config ]]; then
    se_configured=$(awk -F= '/^SELINUX=/{print $2; exit}' /etc/selinux/config 2>/dev/null | tr -d '[:space:]')
    [[ -z "$se_configured" ]] && se_configured="unknown"
  fi

  case "$se_mode" in
    enforcing)
      ok "SELinux: enforcing (${se_source})"
      ;;
    permissive)
      warn "SELinux: permissive — policy loaded but not blocking (${se_source})"
      add_finding "selinux_permissive" "MEDIUM" \
        "SELinux is in permissive mode (not enforcing)" \
        "SELinux is present and a policy is loaded, but the mode is permissive: violations are logged, not denied (observed via ${se_source}; /etc/selinux/config SELINUX=${se_configured}). The system therefore gains SELinux's audit visibility but none of its access-control protection." \
        "Any CVE mitigation that relies on an enforcing SELinux policy — for example confinement of rootful helpers such as cifs.upcall, or LSM-label enforcement that defeats the runc maskedPaths bypass (CVE-2025-52881) — is NOT in effect while SELinux is permissive." \
        "Low as a standalone item; a force-multiplier because it removes a defence-in-depth layer other findings assume." \
        "Set SELinux to enforcing: 'setenforce 1' for the running system and SELINUX=enforcing in /etc/selinux/config to persist across reboot, after confirming the policy does not break required workloads."
      ;;
    disabled)
      warn "SELinux: disabled"
      add_finding "selinux_disabled" "MEDIUM" \
        "SELinux is disabled" \
        "SELinux is disabled on this system (observed via ${se_source}; /etc/selinux/config SELINUX=${se_configured}). No SELinux mandatory access control is in effect." \
        "SELinux-based mitigations for other findings in this report are not available. On distributions whose default protection against CVEs like CIFSwitch depends on an enforcing SELinux policy, that protection is absent." \
        "Low standalone; a force-multiplier removing a defence-in-depth layer." \
        "If the platform expects SELinux (RHEL/Fedora/CentOS family), re-enable it: SELINUX=enforcing in /etc/selinux/config, ensure a policy package is installed, relabel if required (touch /.autorelabel), and reboot."
      ;;
    none)
      # Distinguish "SELinux tooling/fs absent" (common on Debian/Ubuntu) from a finding.
      info "SELinux: not present (no getenforce, no selinuxfs) — configured mode: ${se_configured}"
      ;;
  esac

  # --- Publish consolidated MAC state to the registry -----------------------
  # MAC_MODE captures the strongest enforcing LSM observed; MAC_ENFORCING is the
  # convenience boolean most CVE checks will consume.
  local mac_mode="none" mac_enforcing="false"
  if [[ "$se_mode" == "enforcing" ]]; then
    mac_mode="selinux-enforcing"; mac_enforcing="true"
  elif [[ "$aa_present" == true && "$aa_enforcing" == "enabled" ]]; then
    mac_mode="apparmor-enabled"; mac_enforcing="true"
  elif [[ "$se_mode" == "permissive" ]]; then
    mac_mode="selinux-permissive"; mac_enforcing="false"
  elif [[ "$se_mode" == "disabled" || "$aa_enforcing" == "disabled" ]]; then
    mac_mode="present-disabled"; mac_enforcing="false"
  fi
  set_state MAC_MODE "$mac_mode"
  set_state MAC_ENFORCING "$mac_enforcing"
  set_state SELINUX_MODE "$se_mode"
  set_state APPARMOR_STATE "$aa_enforcing"
}

check_cgroup_release_agent() {
  hdr "12. cgroup v1 release_agent"
  local found=false
  while IFS= read -r agent_path; do
    [[ -w "$agent_path" ]] || continue
    crit "Writable cgroup release_agent: $agent_path"
    add_finding "cgroup_release_agent_${agent_path//\//_}" "CRITICAL" \
      "Writable cgroup v1 release_agent: $agent_path" \
      "In cgroup v1, the release_agent file specifies a binary the kernel executes on the HOST outside all container namespaces when the last process in a cgroup exits." \
      "Full host code execution as root with no namespace restrictions. Write a payload script, set release_agent to that path, fork a process into a sub-cgroup and kill it. The kernel executes the payload on the host." \
      "Well-documented. Felix Wilhelm's PoC is ~15 shell commands. CDK and deepce implement this as a one-click automated escape." \
      "Migrate to cgroup v2 (no release_agent). Mount cgroupfs read-only. Remove CAP_SYS_ADMIN. Apply seccomp to block mount(2)."
    found=true
  done < <(find /sys/fs/cgroup -name "release_agent" 2>/dev/null || true)
  [[ "$found" == false ]] && ok "No writable cgroup release_agent found"
}

check_suid() {
  hdr "13. SUID/SGID binaries"
  info "Scanning for SUID/SGID binaries (may take a moment)..."
  local bins
  bins=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | head -50)
  if [[ -n "$bins" ]]; then
    while IFS= read -r bin; do
      warn "SUID/SGID: $bin"
      add_finding "suid_${bin//\//_}" "MEDIUM" \
        "SUID/SGID binary present: $bin" \
        "$bin has the setuid or setgid bit set and executes with the permissions of its owner regardless of who runs it." \
        "If exploitable via GTFOBins technique, command injection, or library loading flaw, an attacker gains a root shell." \
        "Check https://gtfobins.github.io/ for $bin. Many common binaries (find, vim, python, cp, bash) have documented one-liners." \
        "Remove unnecessary SUID/SGID bits. Set no-new-privileges: true. Use readOnlyRootFilesystem. Integrate SUID scanning into CI/CD."
    done <<< "$bins"
  else
    ok "No SUID/SGID binaries found"
  fi
}

check_kernel() {
  hdr "14. Kernel version"
  # NOTE: CVE version checks are handled by the config-driven CVE engine (run_cve_checks).
  # This check records the kernel version as an informational finding only.
  local kver
  kver=$(uname -r)
  info "Kernel version: $kver"
  add_finding "kernel_version" "INFO" \
    "Kernel version: $kver" \
    "The host kernel version is $kver. Detailed CVE version checks are performed by the config-driven CVE engine (see CVE check section below)." \
    "Outdated kernels may be vulnerable to container escape CVEs exploitable by unprivileged users inside containers." \
    "uname -r is available to any user. Version information is sufficient to identify applicable CVEs." \
    "Keep the host kernel patched. Use a container-optimised OS with automated security updates. See CVE check findings for specific vulnerabilities."
}

check_imds() {
  hdr "15. Cloud metadata service (IMDS)"
  command -v curl &>/dev/null || { info "curl not available; skipping IMDS check"; return; }

  local -A IMDS
  IMDS["http://169.254.169.254/latest/meta-data/"]="AWS EC2"
  IMDS["http://169.254.169.254/metadata/instance?api-version=2021-02-01"]="Azure IMDS"
  IMDS["http://metadata.google.internal/computeMetadata/v1/"]="GCP metadata"

  for url in "${!IMDS[@]}"; do
    local provider="${IMDS[$url]}"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]]; then
      crit "Cloud IMDS reachable: $provider ($url)"
      add_finding "imds_${provider//[^a-zA-Z0-9]/_}" "CRITICAL" \
        "Cloud instance metadata service reachable: $provider" \
        "The cloud provider's IMDS at $url is reachable from within the container and provides temporary IAM credentials." \
        "An attacker retrieves IAM credentials and calls cloud APIs. Depending on instance role permissions: read S3 secrets, access other cloud services, escalate IAM, provision infrastructure, or pivot to other accounts." \
        "Trivial. A single curl command retrieves credentials as JSON. Automated tools (Pacu, CloudFox) enumerate cloud permissions from IMDS credentials." \
        "Enable IMDSv2 (AWS) with hop-limit=1 blocking container access. Use IRSA/Workload Identity. Apply NetworkPolicy to block egress to 169.254.169.254."
    else
      ok "IMDS not reachable: $provider (HTTP $code)"
    fi
  done
}

check_kubelet_api() {
  hdr "16. Kubelet API exposure"
  command -v curl &>/dev/null || { info "curl not available; skipping kubelet check"; return; }

  local gw_ip
  gw_ip=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1 || echo "")

  for target in "127.0.0.1" "$gw_ip" "${KUBERNETES_SERVICE_HOST:-}"; do
    [[ -z "$target" ]] && continue

    local ro_code
    ro_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
      "http://${target}:10255/pods" 2>/dev/null || echo "000")
    if [[ "$ro_code" == "200" ]]; then
      crit "Kubelet read-only API accessible at ${target}:10255 (unauthenticated)"
      add_finding "kubelet_readonly_${target//./_}" "HIGH" \
        "Kubelet read-only API accessible without authentication: ${target}:10255" \
        "The kubelet exposes a read-only HTTP API on port 10255 listing all pods on the node with full specifications." \
        "An attacker enumerates all pods including environment variables (which may contain credentials), volume paths, and service account tokens." \
        "A single curl command returns the complete pod list in JSON. No authentication required." \
        "Set --read-only-port=0 in kubelet configuration. Apply NetworkPolicy to block pod access to port 10255."
    fi

    local auth_code
    auth_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
      "https://${target}:10250/pods" 2>/dev/null || echo "000")
    if [[ "$auth_code" == "200" ]]; then
      crit "Kubelet main API accessible anonymously at ${target}:10250"
      add_finding "kubelet_anon_${target//./_}" "CRITICAL" \
        "Kubelet main API accessible without authentication: ${target}:10250" \
        "The kubelet's main API on port 10250 is accessible without credentials and provides /exec, /run, and /pods endpoints." \
        "Full code execution in any pod on the node without authentication. Exploited in the Tesla cryptomining breach." \
        "Trivial. A single curl to /run/<ns>/<pod>/<container> executes commands. Automated in peirates and CDK." \
        "Set --anonymous-auth=false and --authorization-mode=Webhook in kubelet configuration. Restrict port 10250 with firewall rules."
    fi
  done
}

check_ld_preload() {
  hdr "17. Dynamic linker injection paths"
  for p in /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d; do
    [[ -e "$p" && -w "$p" ]] || continue
    crit "Writable linker config: $p"
    add_finding "writable_ld_${p//\//_}" "HIGH" \
      "Writable dynamic linker configuration: $p" \
      "/etc/ld.so.preload specifies shared libraries loaded into every process before any other library." \
      "An attacker writes a malicious shared library and adds its path to /etc/ld.so.preload. The library loads into every subsequent process including SUID binaries, executing as root." \
      "Moderate. Requires writing a shared library. Once ld.so.preload is written, any SUID binary execution triggers the payload automatically." \
      "Apply readOnlyRootFilesystem: true. Use minimal container images without compilers."
  done
  ok "Library injection path check complete"
}

check_escape_tools() {
  hdr "18. Namespace escape tooling present"
  local tools=(nsenter unshare runc ctr crictl chroot pivot_root)
  local found=false
  for t in "${tools[@]}"; do
    command -v "$t" &>/dev/null || continue
    local tpath
    tpath=$(command -v "$t")
    warn "Escape-relevant tool present: $t ($tpath)"
    add_finding "escape_tool_${t}" "MEDIUM" \
      "Namespace/runtime escape tool present: $t" \
      "$t is a Linux utility for namespace manipulation, container runtime interaction, or filesystem pivoting." \
      "'nsenter -t 1 -m -u -i -n -p -- /bin/bash' enters the host's namespaces directly when run with appropriate capabilities." \
      "Low standalone, High when combined with relevant capabilities." \
      "Use minimal base images (distroless, scratch). Remove all tools not required by the application."
    found=true
  done
  [[ "$found" == false ]] && ok "No namespace escape tooling found in PATH"
}

check_cgroupv2() {
  hdr "19. cgroup v2 writability"
  [[ -f /sys/fs/cgroup/cgroup.controllers ]] || { ok "cgroup v2 not detected"; return; }
  info "cgroup v2 unified hierarchy detected"

  if [[ -w /sys/fs/cgroup/cgroup.subtree_control ]]; then
    warn "cgroup v2 subtree_control is writable"
    add_finding "cgroupv2_subtree_writable" "MEDIUM" \
      "cgroup v2 cgroup.subtree_control is writable" \
      "cgroup.subtree_control determines which resource controllers are enabled in child cgroups." \
      "While cgroup v2 removes the release_agent escape, writable cgroup paths can be used to manipulate resource limits (DoS attacks) or in some kernel versions container escapes via devices controller or eBPF." \
      "Lower than cgroup v1. Resource manipulation attacks against co-located workloads are straightforward." \
      "Mount cgroupfs read-only. Remove CAP_SYS_ADMIN. Use cgroup v2 delegation through the container runtime."
  else
    ok "cgroup v2 subtree_control is not writable"
  fi
}

check_secret_mounts() {
  hdr "20. Secret mount directories"
  for d in /run/secrets /var/run/secrets /secrets /etc/secrets; do
    [[ -d "$d" ]] || continue
    local files
    files=$(find "$d" -type f 2>/dev/null | head -20)
    [[ -n "$files" ]] || continue
    warn "Secret mount directory found: $d"
    local flist
    flist=$(echo "$files" | tr '\n' ' ')
    add_finding "secret_mount_${d//\//_}" "HIGH" \
      "Secret mount directory accessible: $d" \
      "The directory $d contains files injected by Docker Swarm, Kubernetes, or a secrets management system (TLS certs, API tokens, passwords)." \
      "Secrets mounted as files are readable by any process in the container. Compromise may allow lateral movement to databases, APIs, or other services." \
      "ls and cat are sufficient. Files: $flist" \
      "Mount secrets with mode 0400 owned by the specific UID the application runs as. Use dynamic secrets management (Vault agent injector, External Secrets Operator)."
  done
  ok "Secret mount check complete"
}

check_ssh_keys() {
  hdr "21. SSH key exposure"
  local found=false
  for pattern in /root/.ssh /etc/ssh/ssh_host_*_key; do
    for f in $pattern; do
      [[ -e "$f" ]] || continue
      if [[ -f "$f" && -r "$f" ]]; then
        warn "Readable SSH key: $f"
        add_finding "ssh_key_${f//\//_}" "HIGH" \
          "SSH private key or host key readable: $f" \
          "An SSH private key at $f is readable from within the container." \
          "A readable host SSH private key allows direct SSH login to the host node or other nodes that trust this key, bypassing the container entirely." \
          "'ssh -i $f root@<host_ip>' — a single command. No exploit required." \
          "Never mount SSH key directories into containers. Scan images for accidentally included private keys. Rotate any exposed keys immediately."
        found=true
      fi
    done
  done
  [[ "$found" == false ]] && ok "No readable SSH private keys found"
}

check_module_loading() {
  hdr "22. Kernel module loading status"
  local md
  md=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo "unknown")
  case "$md" in
    0)
      info "Module loading is ENABLED (modules_disabled=0)"
      add_finding "modules_loading_enabled" "INFO" \
        "Kernel module loading is enabled (modules_disabled=0)" \
        "modules_disabled=0 means kernel modules can be loaded at runtime. Combined with CAP_SYS_MODULE, this permits loading arbitrary kernel code." \
        "If CAP_SYS_MODULE is also present, a malicious .ko module can be loaded to establish persistence, spawn reverse shells, or disable audit logging." \
        "High if CAP_SYS_MODULE is present; informational otherwise." \
        "Set kernel.modules_disabled=1 via sysctl after all necessary modules are loaded at boot." ;;
    1) ok "Kernel module loading is locked (modules_disabled=1)" ;;
    *) info "modules_disabled value unknown: $md" ;;
  esac
}

check_overlayfs() {
  hdr "23. OverlayFS container layer"
  local upper_dir
  upper_dir=$(grep overlay /proc/mounts 2>/dev/null | grep -oP 'upperdir=\K[^,]+' | head -1 || echo "")
  [[ -n "$upper_dir" ]] || { ok "OverlayFS upper directory not identifiable"; return; }

  info "OverlayFS upper directory: $upper_dir"
  if [[ -w "$upper_dir" ]]; then
    warn "OverlayFS upper directory is writable from within the container"
    add_finding "overlayfs_upper_writable" "MEDIUM" \
      "OverlayFS upper directory is writable: $upper_dir" \
      "Container filesystems use OverlayFS layering a writable upper directory over read-only image layers. If the upper path is accessible from within the container, filesystem isolation may be weaker than expected." \
      "Access to the overlay upper path may allow reading files across different image layers, including data 'deleted' in a later layer that still exists in a lower layer, potentially revealing secrets removed during image build." \
      "Low-moderate. More useful for forensic analysis and layer secret extraction than active exploitation." \
      "Ensure the container runtime correctly isolates overlay mount paths. Apply readOnlyRootFilesystem where possible."
  else
    ok "OverlayFS upper directory is not writable"
  fi
}

# ===========================================================================
# CHECK FUNCTIONS  —  Checks 24-35
# ===========================================================================

check_nvidiascape() {
  hdr "25. NVIDIAScape (CVE-2025-23266) — NVIDIA Container Toolkit"

  local nvidia_ctk_found=false nvidia_ctk_version="not found"
  local vulnerable_version=false nvidia_runtime=false
  local ld_preload_val="${LD_PRELOAD:-}" ld_preload_suspicious=false hooks_exposed=false

  if command -v nvidia-ctk &>/dev/null; then
    nvidia_ctk_found=true
    nvidia_ctk_version=$(nvidia-ctk --version 2>/dev/null | head -1 || echo "unknown")
    local ver_num
    ver_num=$(echo "$nvidia_ctk_version" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$ver_num" ]]; then
      local major minor patch
      IFS='.' read -r major minor patch <<< "$ver_num"
      if (( major < 1 )) || (( major == 1 && minor < 17 )) || \
         (( major == 1 && minor == 17 && patch < 8 )); then
        vulnerable_version=true
      fi
    fi
  fi

  env 2>/dev/null | grep -q "NVIDIA_VISIBLE_DEVICES\|NVIDIA_DRIVER_CAPABILITIES" && nvidia_runtime=true
  grep -q "NVIDIA_VISIBLE_DEVICES\|NVIDIA_DRIVER_CAPABILITIES" /proc/1/environ 2>/dev/null && nvidia_runtime=true

  if [[ -n "$ld_preload_val" ]]; then
    echo "$ld_preload_val" | grep -qE '^(/tmp|/dev/shm|/run|/var/tmp)' && ld_preload_suspicious=true
  fi

  { [[ -d /run/oci/hooks.d ]] || [[ -d /usr/share/containers/oci/hooks.d ]]; } && hooks_exposed=true

  if [[ "$nvidia_ctk_found" == true && "$vulnerable_version" == true ]]; then
    crit "VULNERABLE: NVIDIA Container Toolkit $nvidia_ctk_version (CVE-2025-23266 NVIDIAScape)"
    add_finding "cve_2025_23266_nvidiascape" "CRITICAL" \
      "NVIDIAScape (CVE-2025-23266) — vulnerable NVIDIA Container Toolkit $nvidia_ctk_version" \
      "NVIDIA Container Toolkit version $nvidia_ctk_version is present and is <= 1.17.7. The toolkit's createContainer OCI hook inherits environment variables from the container image without sanitisation. LD_PRELOAD currently set: '${ld_preload_val:-none}'. NVIDIA runtime env vars present: $nvidia_runtime. OCI hooks directory exposed: $hooks_exposed." \
      "Full root access on the host from a three-line Dockerfile. CVSS 9.0. Particularly acute in shared GPU multi-tenant cloud environments." \
      "Trivial. A three-line Dockerfile (FROM nvidia/cuda base, ENV LD_PRELOAD=./evil.so, COPY evil.so .) is sufficient. Working PoC published by Wiz Research (July 2025)." \
      "1) Upgrade NVIDIA Container Toolkit to >= 1.17.8 and GPU Operator to >= 25.3.1 immediately. 2) Interim: set 'disable-cuda-compat-lib-hook = true' in /etc/nvidia-container-toolkit/config.toml. 3) Scan running pods for images with LD_PRELOAD set to unusual library paths."
  elif [[ "$nvidia_ctk_found" == true && "$vulnerable_version" == false ]]; then
    ok "NVIDIA Container Toolkit $nvidia_ctk_version found — version appears patched (>= 1.17.8)"
    add_finding "cve_2025_23266_nvidiascape" "INFO" \
      "NVIDIAScape (CVE-2025-23266) — NVIDIA CTK present, version appears patched" \
      "NVIDIA Container Toolkit $nvidia_ctk_version is present and appears to be >= 1.17.8 (patched)." \
      "N/A — toolkit version appears patched." "N/A" \
      "Verify with 'nvidia-ctk --version'. Ensure GPU Operator is also updated to >= 25.3.1 if used."
  elif [[ "$nvidia_runtime" == true ]]; then
    warn "NVIDIA runtime environment detected but nvidia-ctk binary not found in PATH"
    add_finding "cve_2025_23266_nvidiascape" "MEDIUM" \
      "NVIDIAScape (CVE-2025-23266) — NVIDIA runtime detected, CTK not in PATH" \
      "NVIDIA runtime environment variables are present but nvidia-ctk was not found in PATH for version verification. LD_PRELOAD: '${ld_preload_val:-none}'." \
      "If the host's NVIDIA Container Toolkit is <= 1.17.7, this environment is vulnerable." \
      "Moderate. Cannot confirm without version check, but NVIDIA runtime presence warrants investigation." \
      "Verify the NVIDIA Container Toolkit version on the host node. Upgrade to >= 1.17.8 if not already patched."
  elif [[ "$ld_preload_suspicious" == true ]]; then
    warn "LD_PRELOAD points to suspicious path: $ld_preload_val"
    add_finding "ld_preload_suspicious" "HIGH" \
      "Suspicious LD_PRELOAD value pointing to writable path: $ld_preload_val" \
      "LD_PRELOAD is set to a path in a commonly writable directory ($ld_preload_val). May indicate active exploitation or preparation for library injection." \
      "LD_PRELOAD libraries are loaded into every process before any other library, with constructor functions executing at process start." \
      "If the .so file at $ld_preload_val is attacker-controlled, it executes in every new process automatically." \
      "Investigate the source and content of $ld_preload_val. Remove LD_PRELOAD from container image ENV directives unless strictly required."
  else
    ok "No NVIDIA Container Toolkit found and no suspicious LD_PRELOAD (CVE-2025-23266 not applicable)"
  fi
}

check_runc_masked_path() {
  hdr "26. runc masked path race (CVE-2025-31133 / -52565 / -52881)"

  local runc_found=false runc_version="not found" vulnerable=false
  local runc_bin
  runc_bin=$(command -v runc 2>/dev/null || \
             ls /usr/bin/runc /usr/local/bin/runc /usr/sbin/runc 2>/dev/null | head -1 || echo "")

  if [[ -n "$runc_bin" && -x "$runc_bin" ]]; then
    runc_found=true
    runc_version=$("$runc_bin" --version 2>/dev/null | grep "^runc version" | awk '{print $3}' || echo "unknown")
  fi

  local devnull_ok=true
  [[ ! -c /dev/null ]] && devnull_ok=false
  local core_pattern_writable=false
  [[ -w /proc/sys/kernel/core_pattern ]] && core_pattern_writable=true

  if [[ "$runc_found" == true && "$runc_version" != "unknown" ]]; then
    if echo "$runc_version" | grep -qE '^1\.(0|1|2)\.[0-7]($|-)' || \
       echo "$runc_version" | grep -qE '^1\.2\.[0-7]($|[^0-9])' || \
       echo "$runc_version" | grep -qE '^1\.3\.[0-2]($|[^0-9])' || \
       echo "$runc_version" | grep -qE '^1\.4\.0-rc\.[12]$'; then
      vulnerable=true
    fi
  fi

  if [[ "$vulnerable" == true ]]; then
    crit "VULNERABLE: runc $runc_version (CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881)"
    add_finding "cve_2025_31133_runc_masked" "CRITICAL" \
      "Vulnerable runc $runc_version — masked path race (CVE-2025-31133 / -52565 / -52881)" \
      "runc $runc_version is vulnerable to three race condition container escape CVEs disclosed November 2025. CVE-2025-31133: runc uses /dev/null to mask sensitive host files via maskedPaths but fails to verify the /dev/null inode is genuine — an attacker can replace /dev/null with a symlink during the mount window. CVE-2025-52565: similar via /dev/console. CVE-2025-52881: bypasses LSM labels (AppArmor/SELinux). /dev/null is genuine character device: $devnull_ok. core_pattern writable: $core_pattern_writable." \
      "Full container breakout by any attacker who can spawn containers. All three CVEs allow writing to /proc/sys/kernel/core_pattern or /proc/sysrq-trigger. CVE-2025-52881 specifically bypasses AppArmor and SELinux." \
      "Moderate complexity due to race condition. No public automated PoC at time of writing, but technical details are fully public. CVE-2025-31133 CVSS 7.3." \
      "Update runc immediately to >= 1.2.8, >= 1.3.3, or >= 1.4.0-rc.3. Enable user namespaces for containers. Use rootless containers where possible."
  elif [[ "$runc_found" == true ]]; then
    ok "runc $runc_version found — version appears patched for CVE-2025-31133/-52565/-52881"
    add_finding "cve_2025_31133_runc_masked" "INFO" \
      "runc masked path CVEs — version $runc_version appears patched" \
      "runc $runc_version is present and appears to be >= 1.2.8/1.3.3 (patched). core_pattern writable: $core_pattern_writable." \
      "N/A — runc version appears patched." "N/A" \
      "Verify with 'runc --version'. Ensure containerd/Docker are also updated to use the patched runc."
  else
    ok "runc binary not found in PATH — CVE-2025-31133 direct check not possible"
    if [[ "$core_pattern_writable" == true ]]; then
      warn "core_pattern is writable — runc masked path vulnerability may still apply via the container runtime"
      add_finding "cve_2025_31133_indirect" "HIGH" \
        "core_pattern writable — runc masked path bypass may be in effect" \
        "runc was not found in PATH but /proc/sys/kernel/core_pattern is writable, suggesting maskedPaths protection may not be functioning correctly." \
        "Writable core_pattern allows arbitrary host code execution on any process crash." \
        "High — core_pattern writability is itself a confirmed escape vector." \
        "Investigate why core_pattern is writable. Update the container runtime. Mount /proc/sys read-only."
    fi
  fi
}

check_user_namespace_mapping() {
  hdr "27. User namespace UID mapping"

  local uid; uid=$(id -u)
  local uid_map; uid_map=$(cat /proc/self/uid_map 2>/dev/null || echo "")
  local user_ns_isolated=false

  if [[ -n "$uid_map" ]]; then
    local inside outside count
    read -r inside outside count <<< "$uid_map"
    if [[ "$inside" == "0" && "$outside" != "0" ]]; then
      user_ns_isolated=true
      ok "User namespace remapping active: container UID 0 maps to host UID $outside"
    fi
  fi

  if [[ "$uid" == "0" && "$user_ns_isolated" == false ]]; then
    set_state ROOT_UNMAPPED "true"
    warn "Running as UID 0 with no user namespace remapping — root-in-container = root-on-host"
    add_finding "uid_zero_no_userns" "HIGH" \
      "Running as UID 0 with no user namespace remapping" \
      "This container is running as root (UID 0) with no user namespace remapping in effect (uid_map: '$uid_map'). UID 0 inside the container corresponds directly to UID 0 on the host kernel." \
      "Any host resource accessible to the container is accessed with full root privileges. This amplifies every other finding: a mount escape, socket access, or capability exploit all lead directly to host root." \
      "Not a standalone exploit, but a force multiplier. Eliminates a key isolation layer." \
      "1) Enable user namespace remapping in Docker: set 'userns-remap: default' in /etc/docker/daemon.json. 2) Set runAsNonRoot: true and runAsUser: <non-zero> in pod security context. 3) Deploy rootless Podman or rootless containerd where possible."
  elif [[ "$uid" != "0" ]]; then
    set_state ROOT_UNMAPPED "false"
    ok "Running as non-root UID $uid — UID 0 mapping not applicable"
  else
    set_state ROOT_UNMAPPED "false"
  fi
  set_state USERNS_REMAPPED "$user_ns_isolated"
}

check_ebpf_exposure() {
  hdr "28. eBPF exposure"

  local capeff; capeff=$(grep CapEff /proc/self/status | awk '{print $2}')
  local cap_dec; cap_dec=$(printf "%d" "0x${capeff}")
  local cap_bpf=$(( (cap_dec >> 39) & 1 ))
  local cap_sys_admin=$(( (cap_dec >> 21) & 1 ))
  local bpf_syscall_available=false unprivileged_bpf=false

  if python3 -c "
import ctypes, sys
NR_BPF = 321
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall(NR_BPF, 5, ctypes.c_void_p(0), 0)
err = ctypes.get_errno()
sys.exit(0 if err in (1, 22) else 1)
" 2>/dev/null; then bpf_syscall_available=true; fi

  local ubpf; ubpf=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "unknown")
  [[ "$ubpf" == "0" ]] && unprivileged_bpf=true

  local bpf_capable=false
  [[ "$cap_bpf" == "1" || "$cap_sys_admin" == "1" ]] && bpf_capable=true

  if [[ "$bpf_capable" == true && "$bpf_syscall_available" == true ]]; then
    crit "eBPF accessible with elevated capabilities (CAP_BPF=$cap_bpf, CAP_SYS_ADMIN=$cap_sys_admin)"
    add_finding "ebpf_privileged_access" "CRITICAL" \
      "eBPF accessible with CAP_BPF/CAP_SYS_ADMIN — kernel memory inspection possible" \
      "This container has CAP_BPF ($cap_bpf) or CAP_SYS_ADMIN ($cap_sys_admin) and the bpf(2) syscall is available and not seccomp-blocked. unprivileged_bpf_disabled: $ubpf." \
      "With CAP_BPF and bpf(2) available, an attacker can: (1) Load BPF programs that inspect and exfiltrate arbitrary kernel memory. (2) In kernels < 5.15, certain BPF verifier bypasses allowed arbitrary kernel writes. (3) Attach kprobes/uprobes to monitor any function in the kernel or any host process. (4) Create covert networking channels invisible to standard monitoring tools." \
      "High for memory inspection and monitoring. Kernel version-dependent for code execution. BPF verifier exploits have been published (CVE-2021-3490, CVE-2022-2785)." \
      "Remove CAP_BPF and CAP_SYS_ADMIN from containers that do not require eBPF. Apply seccomp blocking bpf(2) syscall (321 on x86_64). Set kernel.unprivileged_bpf_disabled=1 on the host."
  elif [[ "$unprivileged_bpf" == true && "$bpf_syscall_available" == true ]]; then
    warn "Unprivileged eBPF is enabled (kernel.unprivileged_bpf_disabled=0)"
    add_finding "ebpf_unprivileged" "MEDIUM" \
      "Unprivileged eBPF is enabled on this host" \
      "kernel.unprivileged_bpf_disabled=0, meaning any unprivileged process can load BPF socket filters and use BPF maps. The bpf(2) syscall is available." \
      "Unprivileged BPF enables certain BPF verifier attacks used to achieve kernel code execution. Historical examples: CVE-2021-3490, CVE-2020-8835." \
      "Moderate. Requires a BPF verifier bug for full privilege escalation, but the attack surface is significant." \
      "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/ on all container hosts. Included in CIS benchmarks."
  else
    ok "eBPF exposure is limited (CAP_BPF=$cap_bpf, CAP_SYS_ADMIN=$cap_sys_admin, unprivileged_bpf=$ubpf)"
  fi
}

check_debugfs() {
  hdr "29. debugfs / tracefs exposure"

  local debugfs_mounted=false debugfs_writable=false tracefs_mounted=false debugfs_mp=""

  grep -q "^debugfs\|^none.*debugfs\| debugfs " /proc/mounts 2>/dev/null && {
    debugfs_mounted=true
    debugfs_mp=$(grep "debugfs" /proc/mounts 2>/dev/null | awk '{print $2}' | head -1)
  }
  if [[ -d /sys/kernel/debug ]] && ls /sys/kernel/debug &>/dev/null 2>&1; then
    debugfs_mounted=true; debugfs_mp="${debugfs_mp:-/sys/kernel/debug}"
  fi
  [[ -w /sys/kernel/debug ]] && debugfs_writable=true
  { grep -q "tracefs" /proc/mounts 2>/dev/null || [[ -d /sys/kernel/tracing ]]; } && tracefs_mounted=true

  if [[ "$debugfs_mounted" == true ]]; then
    local severity="MEDIUM" access_type="readable"
    [[ "$debugfs_writable" == true ]] && severity="HIGH" && access_type="read-write"
    warn "debugfs is mounted and $access_type: ${debugfs_mp:-/sys/kernel/debug}"
    add_finding "debugfs_exposed" "$severity" \
      "debugfs mounted and $access_type (${debugfs_mp:-/sys/kernel/debug})" \
      "The Linux kernel debug filesystem (debugfs) is mounted and accessible at ${debugfs_mp:-/sys/kernel/debug}. Access mode: $access_type. tracefs also mounted: $tracefs_mounted." \
      "Accessible debugfs provides: (1) Kernel tracing via ftrace — capture arguments including memory contents and cryptographic material from all host processes. (2) x86/pat_memtype_list exposes memory type information. (3) Driver-specific debug interfaces may expose hardware state or DMA buffers." \
      "Moderate. Simply reading ftrace ring buffer content can passively capture sensitive data from host processes. Risk increases significantly with write access." \
      "Do not mount debugfs in production containers. If required, mount read-only. Ensure /sys/kernel/debug is not included in any volume mounts."
  else
    ok "debugfs does not appear to be accessible"
  fi
}

check_k8s_rbac_escalation() {
  hdr "30. Kubernetes RBAC escalation paths"

  local sa_dir="/var/run/secrets/kubernetes.io/serviceaccount"
  [[ -d "$sa_dir" && -r "$sa_dir/token" ]] || { ok "No service account token found — RBAC check skipped"; return; }

  local api_server="https://${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}:${KUBERNETES_SERVICE_PORT:-443}"
  local token ca_cert
  token=$(cat "$sa_dir/token" 2>/dev/null || echo "")
  ca_cert="$sa_dir/ca.crt"
  [[ -n "$token" ]] || return
  command -v curl &>/dev/null || { info "curl not available — RBAC API check skipped"; return; }

  local -A checks
  checks["create_pods"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"namespace":"kube-system","verb":"create","resource":"pods"}}}'
  checks["get_secrets"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"get","resource":"secrets"}}}'
  checks["list_secrets_all"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}'
  checks["exec_pods"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"create","resource":"pods/exec"}}}'
  checks["bind_clusterrole"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"bind","resource":"clusterrolebindings"}}}'
  checks["create_daemonsets"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"namespace":"kube-system","verb":"create","resource":"daemonsets"}}}'
  checks["impersonate_users"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"impersonate","resource":"users"}}}'
  checks["attach_pods"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"create","resource":"pods/attach"}}}'

  local escalation_paths=()
  for check_name in "${!checks[@]}"; do
    local result
    result=$(curl -s --max-time 5 --cacert "$ca_cert" \
      -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
      -X POST -d "${checks[$check_name]}" \
      "$api_server/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" 2>/dev/null || echo "")
    echo "$result" | grep -q '"allowed":true' && {
      escalation_paths+=("$check_name"); warn "RBAC escalation path: $check_name is ALLOWED"
    }
  done

  if [[ ${#escalation_paths[@]} -gt 0 ]]; then
    local paths_str="${escalation_paths[*]}"
    local severity="HIGH"
    echo "$paths_str" | grep -q "create_pods\|list_secrets_all\|bind_clusterrole\|create_daemonsets\|impersonate_users" && severity="CRITICAL"
    crit "Kubernetes RBAC escalation paths identified: ${paths_str}"
    add_finding "k8s_rbac_escalation" "$severity" \
      "Kubernetes RBAC escalation paths available: ${paths_str}" \
      "Active RBAC checks against $api_server confirm this service account has: ${paths_str}." \
      "create_pods in kube-system: can deploy a privileged pod to escape any namespace boundary. list_secrets (cluster-wide): can enumerate all secrets. exec_pods: can execute commands in other pods. bind_clusterrole: can grant cluster-admin to any service account. create_daemonsets: can run on every node. impersonate_users: can assume the identity of any user, group, or service account (including cluster-admin) on every request — a direct, often-overlooked path to full cluster control. attach_pods: can attach to running pods' process streams, equivalent to exec for stealing data or running commands in other workloads." \
      "Low-moderate complexity. Requires only kubectl or curl with the service account token. Tools such as peirates and rbac-police automate Kubernetes privilege escalation." \
      "Conduct a full RBAC audit. Remove all permissions not strictly required. Implement OPA/Gatekeeper or Kyverno admission controllers to enforce least-privilege service account policies."
  else
    ok "No high-value RBAC escalation paths identified via API check"
  fi
}

check_additional_runtime_sockets() {
  hdr "31. Additional container runtime sockets"

  local extra_sockets=(
    /run/podman/podman.sock /var/run/podman/podman.sock
    /run/buildkit/buildkitd.sock /var/run/buildkit/buildkitd.sock
    /run/kata-containers/kata-agent.sock /run/oci-runtime/oci-runtime.sock
    /var/run/io.containerd.runtime.v1.linux/moby /run/containerd/s/default
    /tmp/containerd.sock
  )

  local found=false
  for sock in "${extra_sockets[@]}"; do
    if [[ -S "$sock" ]]; then
      warn "Additional runtime socket accessible: $sock"
      add_finding "extra_runtime_socket_${sock//\//_}" "CRITICAL" \
        "Additional container runtime socket accessible: $sock" \
        "The container runtime socket at $sock is accessible. This provides administrative API access to the container runtime (Podman, BuildKit, Kata Containers, or containerd)." \
        "Depending on the runtime: Podman socket allows creating containers with arbitrary configurations. BuildKit socket allows injecting build steps or exfiltrating secrets. All provide pathways to escape container isolation." \
        "Similar to docker.sock. Runtime API access can be used to create a new container with host filesystem access." \
        "Remove this socket from the container's mounts. Audit all volume mounts for runtime socket paths."
      found=true
    fi
  done

  local inherited_socks
  inherited_socks=$(ls -la /proc/self/fd 2>/dev/null | grep -c "socket:")
  # Sanitise to a bare integer: grep -c always prints a single number, but guard
  # against empty output (no /proc/self/fd) and any stray whitespace so the
  # arithmetic test below cannot receive a malformed token.
  inherited_socks="${inherited_socks//[!0-9]/}"
  [[ -z "$inherited_socks" ]] && inherited_socks=0
  (( inherited_socks > 10 )) && info "Unusually high number of open socket file descriptors: $inherited_socks"

  [[ "$found" == false ]] && ok "No additional runtime sockets found"
}

check_kernel_keyring() {
  hdr "32. Kernel keyring exposure"

  local capeff; capeff=$(grep CapEff /proc/self/status | awk '{print $2}')
  local cap_dec; cap_dec=$(printf "%d" "0x${capeff}")
  local cap_sys_admin=$(( (cap_dec >> 21) & 1 ))
  local keyctl_available=false; command -v keyctl &>/dev/null && keyctl_available=true
  local key_count=0
  [[ "$keyctl_available" == true ]] && key_count=$(keyctl list @s 2>/dev/null | grep -c "key:")
  key_count="${key_count//[!0-9]/}"; [[ -z "$key_count" ]] && key_count=0
  local proc_keys_count=0
  [[ -r /proc/keys ]] && proc_keys_count=$(wc -l < /proc/keys 2>/dev/null)
  proc_keys_count="${proc_keys_count//[!0-9]/}"; [[ -z "$proc_keys_count" ]] && proc_keys_count=0
  local dm_crypt_keys=false
  grep -q "logon\|user\|encrypted\|fscrypt" /proc/keys 2>/dev/null && dm_crypt_keys=true

  if [[ "$cap_sys_admin" == "1" && "$key_count" -gt 0 ]]; then
    crit "CAP_SYS_ADMIN present with $key_count accessible kernel keyring keys"
    add_finding "kernel_keyring_exposure" "HIGH" \
      "Kernel keyring accessible with CAP_SYS_ADMIN ($key_count session keys visible)" \
      "CAP_SYS_ADMIN is present and $key_count keys are visible in the process keyring. The keyring stores: LUKS/dm-crypt volume encryption keys, Kerberos tickets, SSL/TLS private keys, ecryptfs passphrase tokens, and fscrypt directory encryption keys. /proc/keys shows $proc_keys_count total visible keys. dm-crypt/filesystem encryption keys detected: $dm_crypt_keys." \
      "With CAP_SYS_ADMIN, an attacker can: (1) Read any key in the session, user, or process keyring. (2) Extract LUKS volume encryption keys. (3) Read Kerberos TGTs for lateral movement. (4) Manipulate the keyring to inject malicious keys." \
      "Moderate-high. keyctl show and keyctl print commands are trivial if the keyctl binary is available." \
      "Remove CAP_SYS_ADMIN from containers that do not require keyring management. Apply seccomp to block keyctl(2) syscall (250 on x86_64). Use application-level key management (Vault, AWS KMS) instead."
  elif [[ "$proc_keys_count" -gt 0 ]]; then
    info "Kernel keyring: $proc_keys_count keys visible in /proc/keys (read access only without CAP_SYS_ADMIN)"
    add_finding "kernel_keyring_visible" "MEDIUM" \
      "Kernel keys visible in /proc/keys ($proc_keys_count keys)" \
      "/proc/keys is readable and shows $proc_keys_count keys. Without CAP_SYS_ADMIN the keys themselves cannot generally be read, but metadata is visible." \
      "Key metadata may reveal what encryption or authentication material is stored, informing further attack planning." \
      "Low — metadata only without elevated capabilities." \
      "Audit key permissions with keyctl show. Apply seccomp to block keyctl(2) if not required."
  else
    ok "Kernel keyring exposure appears limited"
  fi
}

check_oci_hooks() {
  hdr "33. OCI hook injection paths"

  local hook_dirs=(/run/oci/hooks.d /usr/share/containers/oci/hooks.d
                   /etc/containers/oci/hooks.d /usr/libexec/oci/hooks.d)
  local found=false
  for d in "${hook_dirs[@]}"; do
    [[ -e "$d" ]] || continue
    local accessible=true writable=false
    ls "$d" &>/dev/null 2>&1 || accessible=false
    [[ -w "$d" ]] && writable=true

    if [[ "$accessible" == true ]]; then
      local hook_count; hook_count=$(find "$d" -name "*.json" 2>/dev/null | wc -l)
      hook_count="${hook_count//[!0-9]/}"; [[ -z "$hook_count" ]] && hook_count=0
      local sev="MEDIUM" access_desc="readable"
      [[ "$writable" == true ]] && sev="CRITICAL" && access_desc="WRITABLE"
      warn "OCI hooks directory $access_desc: $d ($hook_count hook files)"
      add_finding "oci_hooks_${d//\//_}" "$sev" \
        "OCI hooks directory $access_desc: $d" \
        "The OCI hooks directory at $d is $access_desc and contains $hook_count hook definition files. OCI hooks specify programs to execute during container lifecycle events and run as the user who invoked the container runtime, often root on the host side." \
        "A writable OCI hooks directory allows injecting a malicious hook that executes arbitrary code on the host during the next container creation event. Related to the NVIDIAScape class of vulnerability (CVE-2025-23266)." \
        "CRITICAL if writable: write a new .json hook file pointing to a reverse shell. Executes on the next container creation with no further interaction required." \
        "Remove OCI hook directories from container mounts. Apply AppArmor profiles denying write access. Audit all hook definitions."
      found=true
    fi
  done
  [[ "$found" == false ]] && ok "No OCI hook directories accessible"
}

check_core_pattern_deep() {
  hdr "34. Core pattern and page cache write primitives"

  local splice_check=false pipe2_check=false page_cache_writable=false

  if python3 -c "
import ctypes, sys, os
NR_SPLICE = 275
libc = ctypes.CDLL(None, use_errno=True)
r, w = os.pipe()
ret = libc.syscall(NR_SPLICE, -1, None, w, None, 0, 0)
err = ctypes.get_errno()
os.close(r); os.close(w)
sys.exit(0 if err == 9 else 1)
" 2>/dev/null; then splice_check=true; fi

  if python3 -c "
import ctypes, sys
NR_PIPE2 = 293
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall(NR_PIPE2, ctypes.c_void_p(0), 0)
err = ctypes.get_errno()
sys.exit(0 if err == 14 else 1)
" 2>/dev/null; then pipe2_check=true; fi

  if touch /tmp/.pcc_test 2>/dev/null; then rm -f /tmp/.pcc_test; page_cache_writable=true; fi

  if [[ "$splice_check" == true && "$pipe2_check" == true ]]; then
    warn "Page cache write primitives available: splice(2)=$splice_check, pipe2(2)=$pipe2_check"
    add_finding "page_cache_write_primitives" "HIGH" \
      "Page cache write primitives available: splice(2) and pipe2(2) not seccomp-blocked" \
      "Both splice(2) and pipe2(2) syscalls are available and not blocked by seccomp. These are the two syscalls required for the Copy Fail (CVE-2026-31431) and DirtyPipe (CVE-2022-0847) page cache write primitives." \
      "The kernel page cache write technique is not blocked at the syscall level. If the kernel is unpatched, these syscalls are the attack mechanism." \
      "Moderate. Syscalls themselves are not exploits; exploitability depends on kernel patch status (see check 14 and CVE engine checks)." \
      "Apply a seccomp profile restricting splice(2) (syscall 275) and pipe2(2) (syscall 293) if not required by the workload."
  else
    ok "splice(2)=$splice_check pipe2(2)=$pipe2_check — page cache write primitives partially restricted"
  fi
}

check_proc_ns_leakage() {
  hdr "35. Procfs namespace file descriptor leakage"

  local self_pid=$$
  local visible_pids=() host_pids_visible=false setns_possible=false

  while IFS= read -r pid_dir; do
    local pid; pid=$(basename "$pid_dir")
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [[ "$pid" == "$self_pid" || "$pid" == "1" ]] && continue
    visible_pids+=("$pid")
  done < <(find /proc -maxdepth 1 -name '[0-9]*' -type d 2>/dev/null | head -20)

  local pid_count=${#visible_pids[@]} max_pid=0
  for pid in "${visible_pids[@]}"; do (( pid > max_pid )) && max_pid=$pid; done
  (( max_pid > 1000 && pid_count > 5 )) && host_pids_visible=true

  for pid in "${visible_pids[@]:0:5}"; do
    if [[ -r "/proc/$pid/ns/mnt" ]]; then
      if python3 -c "
import os, sys
try:
    fd = os.open('/proc/$pid/ns/mnt', os.O_RDONLY)
    os.close(fd); sys.exit(0)
except: sys.exit(1)
" 2>/dev/null; then setns_possible=true; break; fi
    fi
  done

  if [[ "$host_pids_visible" == true ]]; then
    local severity="MEDIUM"
    [[ "$setns_possible" == true ]] && severity="HIGH"
    warn "$pid_count foreign processes visible in /proc (max PID seen: $max_pid). setns fd openable: $setns_possible"
    add_finding "proc_ns_leakage" "$severity" \
      "Foreign process namespace file descriptors visible via /proc ($pid_count processes, max PID $max_pid)" \
      "$pid_count process entries visible in /proc beyond PID 1 and the current process. Maximum PID $max_pid suggests access to host processes. Namespace fd openable for setns: $setns_possible." \
      "If namespace file descriptors from host processes are openable, an attacker with CAP_SYS_ADMIN can call setns(2) to enter the host's mount, network, or PID namespace. Even without setns, /proc/<PID>/environ, cmdline, maps and fd entries may expose secrets from co-located workloads." \
      "Low-moderate for information gathering. High for setns namespace entry if CAP_SYS_ADMIN present." \
      "Mount /proc with hidepid=2. Avoid sharing host PID namespace (hostPID: false). Apply gvisor or Kata Containers for stronger /proc isolation."
  else
    ok "Foreign process visibility in /proc appears limited ($pid_count visible, max PID $max_pid)"
  fi
}
# ===========================================================================
# CHECK FUNCTIONS  —  Checks 36-47 (Kernel hardening posture)
#
# These checks are READ-ONLY. They report on the host kernel's hardening
# parameter state as visible from within the container. No sysctl writes,
# no module loads, no kernel modifications are performed.
#
# Each check reads from /proc/sys/* or /proc/modules and compares the
# current value against the hardened baseline. Findings are generated for
# parameters that are absent from or weaker than the recommended baseline.
#
# Context: values visible from inside a container reflect the HOST kernel
# configuration, not the container's own settings, making these findings
# directly applicable to the node's security posture.
# ===========================================================================

# ---------------------------------------------------------------------------
# Helper: read a sysctl value from /proc/sys
# Usage: _sysctl_read "kernel/kptr_restrict"
# Returns the trimmed value, or the string "UNREADABLE" on failure.
# ---------------------------------------------------------------------------
_sysctl_read() {
  local key="$1"
  local path="/proc/sys/${key//\.//}"
  local val
  val=$(cat "$path" 2>/dev/null | tr -d '[:space:]')
  if [[ -z "$val" ]]; then
    echo "UNREADABLE"
  else
    echo "$val"
  fi
}

# ---------------------------------------------------------------------------
# Helper: emit a kernel hardening finding
# Usage: _kh_finding <id> <sev> <title> <param> <current> <recommended>
#                    <what> <impact> <exploit> <rec>
# ---------------------------------------------------------------------------
_kh_finding() {
  local id="$1" sev="$2" title="$3"
  local param="$4" current="$5" recommended="$6"
  local what="$7" impact="$8" exploit="$9" rec="${10}"

  local full_what="Kernel parameter: ${param}. Current value: ${current}. Recommended: ${recommended}. ${what}"

  case "$sev" in
    CRITICAL) crit "$title (${param}=${current}, want ${recommended})" ;;
    HIGH)     warn "$title (${param}=${current}, want ${recommended})" ;;
    MEDIUM)   warn "$title (${param}=${current}, want ${recommended})" ;;
    INFO)     info "$title (${param}=${current})" ;;
  esac

  add_finding "$id" "$sev" "$title" \
    "$full_what" "$impact" "$exploit" "$rec"
}

# ===========================================================================
# 36. Kernel pointer restriction (kptr_restrict)
#
# Controls whether kernel symbol addresses are exposed in /proc/kallsyms,
# /proc/modules, and other kernel interfaces. Value 0 exposes all addresses;
# value 1 hides them from unprivileged users; value 2 hides them from all
# users including root.
# ===========================================================================
check_kh_kptr_restrict() {
  hdr "36. Kernel pointer restriction (kptr_restrict)"

  local val
  val=$(_sysctl_read "kernel/kptr_restrict")

  if [[ "$val" == "UNREADABLE" ]]; then
    ok "kptr_restrict: not readable from this container (restricted access is likely a good sign)"
    return
  fi

  case "$val" in
    "2")
      ok "kptr_restrict=2 — kernel pointers hidden from all users (hardened)"
      ;;
    "1")
      warn "kptr_restrict=1 — kernel pointers visible to root processes"
      add_finding "kh_kptr_restrict_1" "MEDIUM" \
        "kptr_restrict=1: kernel pointers visible to root (recommend 2)" \
        "kernel.kptr_restrict=1. Kernel symbol addresses are hidden from unprivileged users but still visible to root-level processes (UID 0 or CAP_SYSLOG). Current value: 1. Recommended: 2." \
        "Kernel Virtual Address Space Layout Randomisation (KASLR) is a primary exploit mitigation. kptr_restrict=1 means that any root-equivalent process — including processes in a privileged container — can read kernel pointer values from /proc/kallsyms, /proc/modules, and sysfs. This provides the KASLR bypass that is step one of almost every modern kernel exploitation chain. An attacker who has achieved UID 0 inside a container (e.g. via setuid binary, capability escalation, or this script's check 7) can immediately proceed to dereferencing kernel symbols." \
        "Low-moderate standalone. Combined with any kernel bug, the kernel pointer leak removes the address-space randomisation barrier. This is consistently the most valuable piece of information in a kernel exploitation attempt." \
        "Set kernel.kptr_restrict=2 in /etc/sysctl.d/99-hardening.conf on the host. This is non-breaking for all standard workloads and is included in the CIS Benchmark for Linux, DISA STIG, and ANSSI hardening guides."
      ;;
    "0")
      crit "kptr_restrict=0 — kernel pointers exposed to all users"
      _kh_finding "kh_kptr_restrict_0" "HIGH" \
        "kptr_restrict=0: kernel pointers fully exposed (KASLR defeated)" \
        "kernel.kptr_restrict" "0" "2" \
        "Kernel symbol addresses are exposed to all processes without restriction. Any unprivileged user can read the exact load address of every kernel symbol by reading /proc/kallsyms." \
        "KASLR is completely defeated. Any kernel memory corruption bug — present CVEs or future zero-days — can be exploited reliably without a separate information leak step. The attacker already has the base address of every kernel function and data structure. Combined with findings for CVE-2026-31431 (Copy Fail) or CVE-2026-43284 (Dirty Frag), this removes the primary probabilistic barrier to reliable exploitation." \
        "Trivial. 'sudo cat /proc/kallsyms | grep commit_creds' gives the exact kernel address needed for most privilege escalation exploits. No exploit code required." \
        "Set kernel.kptr_restrict=2 in /etc/sysctl.d/. This is a zero-risk change — no legitimate workload reads /proc/kallsyms at runtime. Apply immediately."
      ;;
    *)
      info "kptr_restrict=$val (unexpected value)"
      ;;
  esac
}

# ===========================================================================
# 37. Kernel log restriction (dmesg_restrict)
#
# Controls whether the kernel ring buffer (/dev/kmsg, dmesg) is readable
# by unprivileged users. Value 0 means world-readable; value 1 restricts
# to CAP_SYSLOG.
# ===========================================================================
check_kh_dmesg_restrict() {
  hdr "37. Kernel log restriction (dmesg_restrict)"

  local val
  val=$(_sysctl_read "kernel/dmesg_restrict")

  if [[ "$val" == "UNREADABLE" ]]; then
    ok "dmesg_restrict: not readable (likely already restricted)"
    return
  fi

  case "$val" in
    "1")
      ok "dmesg_restrict=1 — kernel log restricted to CAP_SYSLOG (hardened)"
      ;;
    "0")
      _kh_finding "kh_dmesg_restrict" "MEDIUM" \
        "dmesg_restrict=0: kernel log world-readable" \
        "kernel.dmesg_restrict" "0" "1" \
        "The kernel ring buffer is readable by any unprivileged process. dmesg output contains driver load addresses, hardware probe results, memory region information, boot-time cryptographic seed loading, and any kernel panic output including register dumps and stack traces." \
        "dmesg output provides: (1) hardware memory map useful for physical memory attacks; (2) driver load addresses that complement kptr_restrict bypass; (3) kernel panic backtraces with register contents, providing a complete execution context dump after a crash; (4) cryptographic subsystem initialisation messages which occasionally include key material diagnostics; (5) network driver details useful for traffic interception setup. In container contexts, dmesg reflects the host kernel's log, exposing all of the above for the host node." \
        "Zero effort. 'dmesg' is a standard command available in most container images. No privileges required when dmesg_restrict=0." \
        "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/. Included in CIS Benchmark Level 1. Zero operational impact — legitimate monitoring uses journald/syslog forwarding, not raw dmesg."
      ;;
    *)
      info "dmesg_restrict=$val"
      ;;
  esac
}

# ===========================================================================
# 38. Address Space Layout Randomisation (ASLR)
#
# randomize_va_space controls ASLR depth:
#   0 = disabled entirely
#   1 = randomise stack + mmap (no heap)
#   2 = full randomisation (stack + mmap + heap + brk)
# ===========================================================================
check_kh_aslr() {
  hdr "38. Address Space Layout Randomisation (randomize_va_space)"

  local val
  val=$(_sysctl_read "kernel/randomize_va_space")

  case "$val" in
    "2")
      ok "randomize_va_space=2 — full ASLR enabled (hardened)"
      ;;
    "1")
      _kh_finding "kh_aslr_partial" "MEDIUM" \
        "randomize_va_space=1: partial ASLR (heap not randomised)" \
        "kernel.randomize_va_space" "1" "2" \
        "ASLR is partially enabled. Stack and mmap regions are randomised but heap (brk) allocation is deterministic. Heap addresses are predictable across all processes." \
        "Heap-based memory corruption attacks (use-after-free, heap overflows) are significantly easier when the heap base is predictable. Many container escape exploits that operate via user-space heap corruption are more reliable against partially-randomised address spaces. Combined with kptr_restrict=0 (check 36), both the user-space and kernel-space attack surface lose probabilistic protection simultaneously." \
        "Moderate. Heap layout is deterministic — spray attacks against heap objects have high success rates without needing an information leak." \
        "Set kernel.randomize_va_space=2 in /etc/sysctl.d/. This is the default on all modern distributions and should never be 1 or 0 in production."
      ;;
    "0")
      _kh_finding "kh_aslr_disabled" "HIGH" \
        "randomize_va_space=0: ASLR completely disabled" \
        "kernel.randomize_va_space" "0" "2" \
        "ASLR is fully disabled. All memory regions (stack, heap, mmap, shared libraries) are loaded at fixed, predictable addresses on every process invocation." \
        "Every user-space memory corruption exploit becomes deterministic and maximally reliable. No information leak or heap spray is required — the attacker can hardcode target addresses. This eliminates one of the most effective exploit mitigations in Linux and affects all processes on the host node, including the container runtime and Kubernetes system components." \
        "High. Any memory corruption vulnerability — in the container, the runtime, or a co-hosted service — becomes trivially exploitable. Address-space guessing is eliminated entirely." \
        "Set kernel.randomize_va_space=2 immediately. This setting is disabled only for debugging purposes and should never be 0 in any production or security-sensitive environment."
      ;;
    "UNREADABLE")
      info "randomize_va_space: not readable"
      ;;
    *)
      info "randomize_va_space=$val"
      ;;
  esac
}

# ===========================================================================
# 39. Symbolic link and hard link protections
#
# Protected symlinks (fs.protected_symlinks=1): prevents following symlinks
# in world-writable sticky directories unless owner matches the process UID.
# Protected hardlinks (fs.protected_hardlinks=1): prevents creating hard
# links to files the current process cannot read/write.
#
# Both are required to close the /tmp-based symlink and hardlink races that
# have been exploited in container escape and privilege escalation for decades.
# ===========================================================================
check_kh_link_protections() {
  hdr "39. Symlink and hardlink protections"

  local sym
  sym=$(_sysctl_read "fs/protected_symlinks")
  local hard
  hard=$(_sysctl_read "fs/protected_hardlinks")

  if [[ "$sym" == "1" ]]; then
    ok "protected_symlinks=1 (hardened)"
  elif [[ "$sym" != "UNREADABLE" ]]; then
    _kh_finding "kh_protected_symlinks" "HIGH" \
      "protected_symlinks=0: /tmp symlink race attacks possible" \
      "fs.protected_symlinks" "$sym" "1" \
      "Symlink following in world-writable sticky directories (like /tmp) is unrestricted. Any process can create a symlink in /tmp pointing to a sensitive target file, and a privileged service that follows that symlink will operate on the target instead." \
      "This is the classic /tmp race condition attack vector. Many system services (cron jobs, package managers, backup scripts, setuid helpers) create files in /tmp under a privileged UID. Without protected_symlinks, an attacker can race the creation to point the path at /etc/passwd, /etc/sudoers, /root/.ssh/authorized_keys, or any other sensitive target. Within containers, the shared /tmp can be used to attack co-hosted processes or the container runtime itself if it writes to a shared temporary path." \
      "Low-moderate technical complexity. Race condition timing varies. Tools like inotifywait automate the timing. Many historical CVEs (TOCTOU races) depend on this protection being absent." \
      "Set fs.protected_symlinks=1 in /etc/sysctl.d/. Default on all modern Linux distributions. Should never be 0 in production."
  fi

  if [[ "$hard" == "1" ]]; then
    ok "protected_hardlinks=1 (hardened)"
  elif [[ "$hard" != "UNREADABLE" ]]; then
    _kh_finding "kh_protected_hardlinks" "HIGH" \
      "protected_hardlinks=0: hardlink attacks against privileged files possible" \
      "fs.protected_hardlinks" "$hard" "1" \
      "Hardlinks can be created to files the current process does not own and cannot write, including SUID root binaries and sensitive configuration files. This persists the inode across filesystem operations that would otherwise remove access." \
      "An attacker creates a hardlink to a SUID binary in an attacker-writable directory before a privileged process rotates it. The hardlink preserves the old inode — including the SUID bit and root ownership — even after the original file is replaced. The attacker then triggers execution of the old binary via the hardlink. Also used to keep deleted log files open, hindering forensic analysis." \
      "Low complexity. Creating a hardlink requires only a single ln command. Exploitation of the resulting state depends on finding a vulnerable privileged operation pattern." \
      "Set fs.protected_hardlinks=1 in /etc/sysctl.d/. Default on all modern distributions."
  fi
}

# ===========================================================================
# 40. FIFO and regular file protections in sticky directories
#
# protected_fifos and protected_regular prevent privileged processes from
# following attacker-created FIFOs or regular files in world-writable
# sticky dirs (e.g. /tmp). Extends the symlink protection model.
# ===========================================================================
check_kh_fifo_regular_protections() {
  hdr "40. FIFO and regular file protections (protected_fifos / protected_regular)"

  local fifos
  fifos=$(_sysctl_read "fs/protected_fifos")
  local regular
  regular=$(_sysctl_read "fs/protected_regular")

  if [[ "$fifos" == "2" ]]; then
    ok "protected_fifos=2 (hardened)"
  elif [[ "$fifos" == "1" ]]; then
    info "protected_fifos=1 (partial — only applies when sticky bit is set)"
  elif [[ "$fifos" != "UNREADABLE" ]]; then
    _kh_finding "kh_protected_fifos" "MEDIUM" \
      "protected_fifos=0: FIFO-based privilege escalation paths open" \
      "fs.protected_fifos" "$fifos" "2" \
      "Privileged processes can be tricked into opening attacker-created named pipes (FIFOs) in world-writable directories. Protected FIFOs (value 2) prevents processes running as a different user from opening FIFOs created in sticky world-writable directories." \
      "A privileged daemon (e.g. logrotate, backup job, package postinst script) that opens files in /tmp or /var/tmp by name can be directed to an attacker-created FIFO. The daemon's write operation blocks indefinitely (or is consumed by the attacker), causing denial of service or timing attacks. Some exploitation scenarios use FIFO stalling to extend race condition windows." \
      "Moderate. Requires identification of a privileged process opening files in world-writable paths — common in legacy system scripts." \
      "Set fs.protected_fifos=2 in /etc/sysctl.d/."
  fi

  if [[ "$regular" == "2" ]]; then
    ok "protected_regular=2 (hardened)"
  elif [[ "$regular" == "1" ]]; then
    info "protected_regular=1 (partial)"
  elif [[ "$regular" != "UNREADABLE" ]]; then
    _kh_finding "kh_protected_regular" "MEDIUM" \
      "protected_regular=0: regular file confusion in sticky directories not blocked" \
      "fs.protected_regular" "$regular" "2" \
      "Privileged processes opening files in world-writable sticky directories can be directed to attacker-created regular files. Without protected_regular=2, a privileged process using O_CREAT on a path in /tmp may open an existing attacker-owned file instead." \
      "An attacker pre-creates a regular file at the path a privileged process will write to, potentially injecting malicious content into privileged file operations. This is the 'O_CREAT without O_EXCL' pattern that has appeared in numerous CVEs." \
      "Low-moderate. Requires knowing the target filename in advance — often predictable from package names or known daemons." \
      "Set fs.protected_regular=2 in /etc/sysctl.d/."
  fi
}

# ===========================================================================
# 41. SYN flood protection (tcp_syncookies)
#
# Enables SYN cookies to defend against SYN flood DoS attacks.
# Required parameter in CIS benchmarks and considered a baseline hardening
# item for any network-facing host.
# ===========================================================================
check_kh_syncookies() {
  hdr "41. TCP SYN flood protection (tcp_syncookies)"

  local val
  val=$(_sysctl_read "net/ipv4/tcp_syncookies")

  case "$val" in
    "1"|"2")
      ok "tcp_syncookies=$val — SYN flood protection enabled (hardened)"
      ;;
    "0")
      _kh_finding "kh_syncookies" "MEDIUM" \
        "tcp_syncookies=0: host vulnerable to TCP SYN flood DoS" \
        "net.ipv4.tcp_syncookies" "0" "1" \
        "TCP SYN cookie generation is disabled. The kernel accepts all SYN packets and allocates connection state for each one, without any defence against flooding." \
        "An attacker can exhaust the host's TCP connection table with a SYN flood from spoofed source addresses, causing denial of service for all TCP services on the node — including the Kubernetes API server, etcd, and container runtime communications. In a Kubernetes context, network-accessible node ports and NodePort services are exposed to this attack without packet filtering." \
        "Low-moderate. Standard SYN flood tools (hping3, scapy) perform this automatically. From within a container with network access, a SYN flood targeting the host's management interfaces is possible if network isolation is insufficient." \
        "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.d/. This is a mandatory parameter in CIS Benchmark Level 1 and has been default-on in upstream kernels for over a decade."
      ;;
    "UNREADABLE")
      info "tcp_syncookies: not readable"
      ;;
  esac
}

# ===========================================================================
# 42. ICMP redirect and source routing controls
#
# Checks a set of network hardening parameters that prevent the host from
# accepting attacker-influenced routing decisions:
#   - accept_redirects: don't follow ICMP redirects from routers
#   - send_redirects: don't emit ICMP redirects
#   - accept_source_route: don't follow source-routed packets
#   - rp_filter: enforce reverse-path filtering (anti-spoofing)
# ===========================================================================
check_kh_network_routing() {
  hdr "42. Network routing and spoofing controls"

  # accept_redirects — both IPv4 and IPv6
  for proto in "ipv4" "ipv6"; do
    for iface in "all" "default"; do
      local key="net/${proto}/conf/${iface}/accept_redirects"
      local val
      val=$(_sysctl_read "$key")
      [[ "$val" == "UNREADABLE" ]] && continue
      if [[ "$val" != "0" ]]; then
        _kh_finding "kh_${proto}_${iface}_accept_redirects" "MEDIUM" \
          "${proto}/conf/${iface}/accept_redirects=${val}: ICMP redirect acceptance enabled" \
          "net.${proto}.conf.${iface}.accept_redirects" "$val" "0" \
          "The host will accept ICMP redirect messages from routers and update its routing table accordingly. An attacker on the same network segment can send crafted ICMP redirects to redirect traffic through an attacker-controlled gateway." \
          "Man-in-the-middle attack against all traffic originating from the host, including inter-pod communication, API server calls, and external service traffic. Particularly impactful on flat container network overlays where many pods share a subnet." \
          "Moderate. Requires L2 network adjacency or the ability to inject ICMP packets. From within a container sharing the host network namespace (hostNetwork: true), this may be trivially exploitable." \
          "Set net.${proto}.conf.all.accept_redirects=0 and net.${proto}.conf.default.accept_redirects=0 in /etc/sysctl.d/."
      fi
    done
  done

  # send_redirects — IPv4 only
  for iface in "all" "default"; do
    local val
    val=$(_sysctl_read "net/ipv4/conf/${iface}/send_redirects")
    [[ "$val" == "UNREADABLE" ]] && continue
    if [[ "$val" != "0" ]]; then
      _kh_finding "kh_ipv4_${iface}_send_redirects" "MEDIUM" \
        "ipv4/conf/${iface}/send_redirects=${val}: host emitting ICMP redirects" \
        "net.ipv4.conf.${iface}.send_redirects" "$val" "0" \
        "The host will generate and send ICMP redirect messages to clients, informing them of better routes. This behaviour can be abused to redirect traffic from legitimate clients." \
        "An attacker who achieves code execution on the host can leverage send_redirects to poison the routing caches of connected clients, redirecting their traffic through an attacker-controlled host. In shared network segments this affects all pods on the same subnet." \
        "Low standalone. Relevant as a post-exploitation tool to facilitate lateral movement." \
        "Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.d/."
    fi
  done

  # accept_source_route
  for proto in "ipv4" "ipv6"; do
    for iface in "all" "default"; do
      local val
      val=$(_sysctl_read "net/${proto}/conf/${iface}/accept_source_route")
      [[ "$val" == "UNREADABLE" ]] && continue
      if [[ "$val" != "0" ]]; then
        _kh_finding "kh_${proto}_${iface}_source_route" "MEDIUM" \
          "${proto}/conf/${iface}/accept_source_route=${val}: source routing accepted" \
          "net.${proto}.conf.${iface}.accept_source_route" "$val" "0" \
          "The host honours IP source routing options in packet headers, allowing senders to specify the exact route their packets take through the network." \
          "Source routing bypasses network-level access controls and firewalls by specifying a path that avoids filtering devices. An attacker can route packets through intermediaries that would normally be unreachable, enabling access to services protected by network topology." \
          "Low standalone. Primarily a pivot and evasion technique in post-exploitation." \
          "Set net.${proto}.conf.all.accept_source_route=0 in /etc/sysctl.d/."
      fi
    done
  done

  # rp_filter (reverse path filtering)
  for iface in "all" "default"; do
    local val
    val=$(_sysctl_read "net/ipv4/conf/${iface}/rp_filter")
    [[ "$val" == "UNREADABLE" ]] && continue
    if [[ "$val" == "0" ]]; then
      _kh_finding "kh_rp_filter_${iface}" "MEDIUM" \
        "ipv4/conf/${iface}/rp_filter=0: reverse path filtering disabled (spoofed source addresses accepted)" \
        "net.ipv4.conf.${iface}.rp_filter" "0" "1" \
        "Reverse path filtering (rp_filter) is disabled. The kernel will accept inbound packets regardless of whether the source address is reachable via the interface the packet arrived on." \
        "Spoofed-source-address attacks are uninhibited. From within a container with raw socket access (CAP_NET_RAW), an attacker can send packets with arbitrary source addresses. This facilitates reflection/amplification DoS attacks, IP address spoofing for access control bypass, and evasion of source-based network logging and intrusion detection." \
        "Low-moderate. Requires CAP_NET_RAW or access to a raw socket. Combined with host network namespace access, this becomes trivial." \
        "Set net.ipv4.conf.all.rp_filter=1 and net.ipv4.conf.default.rp_filter=1 in /etc/sysctl.d/."
    fi
  done

  ok "Network routing control check complete"
}

# ===========================================================================
# 43. IP forwarding
#
# ip_forward=1 turns the host into a router, forwarding packets between
# interfaces. Required for container networking (CNI) but should be scoped
# — containers should not be able to use it for unintended routing.
# Checking both IPv4 and IPv6. Also flags mc_forwarding (multicast).
# ===========================================================================
check_kh_ip_forwarding() {
  hdr "43. IP forwarding status"

  # Note: ip_forward=1 is expected and required on Kubernetes nodes for CNI.
  # We report it as INFO with context rather than a direct finding unless the
  # container also has CAP_NET_ADMIN (already flagged in check 2).
  local v4
  v4=$(_sysctl_read "net/ipv4/ip_forward")
  local v6
  v6=$(_sysctl_read "net/ipv6/conf/all/forwarding")

  if [[ "$v4" == "1" ]]; then
    info "net.ipv4.ip_forward=1 — host is forwarding IPv4 packets (expected on Kubernetes nodes; verify CNI policy enforces pod network isolation)"
    add_finding "kh_ipv4_forwarding_enabled" "INFO" \
      "net.ipv4.ip_forward=1 — IPv4 forwarding enabled on host" \
      "The host kernel is configured to forward IPv4 packets between network interfaces (net.ipv4.ip_forward=1). This is required and expected on Kubernetes worker nodes for CNI overlay networking. However, the presence of IP forwarding means the node will route packets between container and host networks." \
      "If a container has CAP_NET_ADMIN (see check 2) or access to the host network namespace, IP forwarding can be used to route traffic through the host node, bypassing NetworkPolicy controls and enabling man-in-the-middle positioning on the pod network. Even without extra capabilities, overly permissive CNI configuration combined with forwarding can allow containers to reach node-internal services." \
      "Low standalone. Meaningful when combined with CAP_NET_ADMIN or host network namespace access (see checks 2 and 3)." \
      "Verify CNI NetworkPolicy is enforced and that inter-pod traffic is filtered at the CNI level. Ensure iptables/nftables rules on the node restrict unexpected forwarding paths. This parameter should not be changed on Kubernetes nodes."
  fi

  if [[ "$v6" == "1" ]]; then
    info "net.ipv6.conf.all.forwarding=1 — host is forwarding IPv6 packets"
    add_finding "kh_ipv6_forwarding_enabled" "INFO" \
      "net.ipv6.conf.all.forwarding=1 — IPv6 forwarding enabled on host" \
      "IPv6 packet forwarding is enabled on the host. As with IPv4, this is often required for CNI but may allow containers with elevated network capabilities to route IPv6 traffic through the host." \
      "Same class of risk as IPv4 forwarding, but potentially less monitored. IPv6 NetworkPolicy is less consistently deployed than IPv4 policy in Kubernetes environments." \
      "Low standalone. Check whether Kubernetes NetworkPolicy covers IPv6 as well as IPv4 traffic in your CNI implementation." \
      "Audit IPv6 NetworkPolicy enforcement. If IPv6 is not used, consider disabling IPv6 at the node level via net.ipv6.conf.all.disable_ipv6=1."
  fi
}

# ===========================================================================
# 44. Unprivileged user namespace creation (unprivileged_userns_clone)
#
# User namespaces allow unprivileged users to create isolated environments
# with their own UID mappings. Required for rootless containers but
# dramatically expands the kernel attack surface available to unprivileged
# users — the majority of container escape CVEs since 2019 require user
# namespaces.
# ===========================================================================
check_kh_userns() {
  hdr "44. Unprivileged user namespace creation"

  # Kernel parameter name varies by distribution
  local val="UNREADABLE"
  local param_name=""

  # Debian/Ubuntu
  local deb_val
  deb_val=$(_sysctl_read "kernel/unprivileged_userns_clone")
  if [[ "$deb_val" != "UNREADABLE" ]]; then
    val="$deb_val"
    param_name="kernel.unprivileged_userns_clone"
  fi

  # Upstream / RHEL / Fedora (user_namespaces.max_user_namespaces)
  if [[ "$val" == "UNREADABLE" ]]; then
    local ns_max
    ns_max=$(_sysctl_read "user/max_user_namespaces")
    if [[ "$ns_max" != "UNREADABLE" ]]; then
      if [[ "$ns_max" == "0" ]]; then
        ok "user.max_user_namespaces=0 — unprivileged user namespace creation disabled (hardened)"
        set_state USERNS_RESTRICTED "true"
        return
      else
        val="$ns_max"
        param_name="user.max_user_namespaces (non-zero = enabled)"
      fi
    fi
  fi

  if [[ "$val" == "UNREADABLE" ]]; then
    info "unprivileged user namespace status not determinable from this container"
    set_state USERNS_RESTRICTED "unknown"
    return
  fi

  if [[ "$val" == "0" && "$param_name" == "kernel.unprivileged_userns_clone" ]]; then
    ok "unprivileged_userns_clone=0 — unprivileged user namespaces disabled (hardened)"
    set_state USERNS_RESTRICTED "true"
    return
  fi

  if [[ "$val" == "1" || ("$param_name" != "kernel.unprivileged_userns_clone" && "$val" != "0") ]]; then
    set_state USERNS_RESTRICTED "false"
    add_finding "kh_unprivileged_userns" "HIGH" \
      "Unprivileged user namespace creation is enabled — exposes significant kernel attack surface" \
      "Kernel parameter: ${param_name}=${val}. Unprivileged user namespace creation is enabled. Any unprivileged user can call unshare(CLONE_NEWUSER) to create a new user namespace with their own UID mappings, gaining access to capabilities within that namespace and the ability to create further namespaces." \
      "User namespaces dramatically expand the kernel attack surface accessible to unprivileged users. The following attack classes are only possible with user namespace access: (1) The majority of container escape CVEs since 2019, including cgroup release_agent escapes, overlayfs vulnerabilities, and namespace confusion attacks. (2) Copy Fail (CVE-2026-31431) is significantly easier to exploit with user namespace access. (3) Dirty Frag (CVE-2026-43284/CVE-2026-43500) uses standard sockets that are more accessible within user namespaces. (4) eBPF unprivileged access (check 28) is most dangerous when combined with user namespace creation. (5) The runc trilogy (CVE-2025-31133/-52565/-52881, check 26) is exploitable by anyone who can spawn containers — user namespaces make self-hosting containers feasible without root. Google, Red Hat, and Canonical all restrict or disable unprivileged user namespaces in hardened deployments." \
      "High. An unprivileged container user with network access can use user namespaces to access capabilities (CAP_NET_RAW, CAP_NET_BIND_SERVICE) within the namespace, enabling a wide range of subsequent attacks. Many published container escape PoCs begin with an unshare(CLONE_NEWUSER) call." \
      "1) On Debian/Ubuntu: set kernel.unprivileged_userns_clone=0 in /etc/sysctl.d/ if rootless containers are not required. 2) On RHEL/Fedora: set user.max_user_namespaces=0. 3) If rootless containers are required, restrict user namespace creation to specific users/groups via AppArmor or seccomp. 4) Ubuntu 24.04+ (Noble) and Debian 12+ support restricting user namespace creation per-process via AppArmor's 'userns' rule — use this as a middle ground."
    warn "Unprivileged user namespace creation enabled ($param_name=$val) — major kernel attack surface expansion"
  fi
}

# ===========================================================================
# 45. Perf event access (perf_event_paranoid)
#
# Controls access to the perf_event_open(2) syscall, which provides CPU
# performance counters, hardware events, and software events. Low values
# enable side-channel attacks. Also checked: kernel.perf_event_max_sample_rate.
# ===========================================================================
check_kh_perf_event() {
  hdr "45. Perf event access (perf_event_paranoid)"

  local val
  val=$(_sysctl_read "kernel/perf_event_paranoid")

  # Values:
  #  -1 = no restriction (all users, all events, kernel profiling)
  #   0 = allow CPU data but not raw tracepoints for unprivileged
  #   1 = allow CPU data only (default on many distros) — still too permissive
  #   2 = no unprivileged access to perf_event_open
  #   3 = full disabling (custom kernels; Debian ships this with nopatch)
  #  >=3 on some distros blocks even CAP_PERFMON

  case "$val" in
    "UNREADABLE")
      info "perf_event_paranoid: not readable"
      ;;
    "2"|"3"|"4")
      ok "perf_event_paranoid=$val — unprivileged perf access restricted (hardened)"
      ;;
    "1")
      _kh_finding "kh_perf_event_1" "MEDIUM" \
        "perf_event_paranoid=1: CPU performance counters accessible to unprivileged users" \
        "kernel.perf_event_paranoid" "1" "2" \
        "Unprivileged users have access to CPU-level performance counter data. At paranoid=1, unprivileged users can access CPU PMU data (Performance Monitoring Unit), cycle and instruction counts, and cache event statistics." \
        "CPU performance counters enable Spectre-class microarchitectural side-channel attacks, cache timing attacks, and FLUSH+RELOAD primitives that can recover cryptographic key material from co-located processes. In a container environment where multiple workloads share a CPU, this enables cross-container information leakage via hardware-level observations. Tools such as Flush+Reload and Prime+Probe work against perf event access." \
        "Moderate. Requires a workload with knowledge of the target's memory access patterns. Relevant on shared CPU multi-tenant nodes." \
        "Set kernel.perf_event_paranoid=2 (or higher) in /etc/sysctl.d/. Consider also setting kernel.perf_event_max_sample_rate=1 to further limit PMU sample rates."
      ;;
    "0"|"-1")
      _kh_finding "kh_perf_event_permissive" "HIGH" \
        "perf_event_paranoid=${val}: highly permissive perf event access — kernel profiling available to unprivileged users" \
        "kernel.perf_event_paranoid" "$val" "2" \
        "perf_event_paranoid=${val} grants unprivileged users access to kernel profiling data, raw hardware tracepoints, and full PMU event streams. At value -1 specifically, all access restrictions are lifted." \
        "At paranoid=0 or -1, an unprivileged user can: (1) Profile kernel execution paths, exposing kernel code addresses in profiling output (KASLR bypass without reading /proc/kallsyms). (2) Use hardware performance counters for high-precision timing of kernel operations, enabling Spectre variant exploitation without special tooling. (3) On multi-tenant CPU nodes, reconstruct memory access patterns of co-running processes to extract cryptographic material. (4) Certain perf_event_open configurations with raw PEBS events can read arbitrary kernel memory on affected microarchitectures." \
        "High. Unprivileged perf access combined with a Spectre gadget in kernel or another container's code provides a realistic cross-container information exfiltration channel. perf_event_open is the basis of most published Spectre PoC tools." \
        "Set kernel.perf_event_paranoid=2 in /etc/sysctl.d/ immediately. At minimum set to 1 — leaving it at 0 or -1 provides essentially no protection."
      ;;
    *)
      info "perf_event_paranoid=$val (unexpected value)"
      ;;
  esac
}

check_kh_dangerous_modules() {
  hdr "47. Loaded kernel module audit (dangerous/unnecessary modules)"

  # Format: <module_name> <reason> <severity> <cve_if_any>
  # Tab-separated for easy parsing
  local -A MOD_REASON MOD_SEV MOD_CVE MOD_REC

  # ── Active exploitation (in-the-wild as of May 2026) ─────────────────────
  MOD_REASON[algif_aead]="Copy Fail (CVE-2026-31431): AF_ALG AEAD crypto interface — page cache write primitive enabling LPE"
  MOD_SEV[algif_aead]="CRITICAL"; MOD_CVE[algif_aead]="CVE-2026-31431"
  MOD_REC[algif_aead]="rmmod algif_aead; echo 'install algif_aead /bin/false' > /etc/modprobe.d/copyfail.conf. On RHEL 9 with built-in algif_aead, use initcall_blacklist=algif_aead_init boot parameter."

  MOD_REASON[esp4]="Dirty Frag (CVE-2026-43284): IPsec ESP/IPv4 in-place decryption page cache write — active LPE exploit"
  MOD_SEV[esp4]="CRITICAL"; MOD_CVE[esp4]="CVE-2026-43284"
  MOD_REC[esp4]="rmmod esp4; echo 'install esp4 /bin/false' > /etc/modprobe.d/dirtyfrag.conf. WARNING: breaks IPsec if in use."

  MOD_REASON[esp6]="Dirty Frag (CVE-2026-43284): IPsec ESP/IPv6 in-place decryption page cache write — active LPE exploit"
  MOD_SEV[esp6]="CRITICAL"; MOD_CVE[esp6]="CVE-2026-43284"
  MOD_REC[esp6]="rmmod esp6; add 'install esp6 /bin/false' to /etc/modprobe.d/dirtyfrag.conf. WARNING: breaks IPv6 IPsec if in use."

  MOD_REASON[rxrpc]="Dirty Frag (CVE-2026-43500): RxRPC in-place decryption page cache write — active LPE exploit, currently unpatched on most distros"
  MOD_SEV[rxrpc]="CRITICAL"; MOD_CVE[rxrpc]="CVE-2026-43500"
  MOD_REC[rxrpc]="rmmod rxrpc; echo 'install rxrpc /bin/false' > /etc/modprobe.d/dirtyfrag.conf. NOTE: breaks AFS filesystem client if in use."

  # ── High-risk attack surface — frequently targeted ────────────────────────
  MOD_REASON[nf_conntrack_netlink]="Provides a Netlink interface for querying and modifying connection tracking state; exploited in multiple container network escape scenarios"
  MOD_SEV[nf_conntrack_netlink]="HIGH"; MOD_CVE[nf_conntrack_netlink]=""
  MOD_REC[nf_conntrack_netlink]="Blacklist if not required for NAT/firewall functionality: 'install nf_conntrack_netlink /bin/false'."

  MOD_REASON[binfmt_misc]="Registers additional binary format interpreters via a filesystem interface; if writable from a container, allows registering a handler that runs as root on the host when a container binary is executed"
  MOD_SEV[binfmt_misc]="HIGH"; MOD_CVE[binfmt_misc]=""
  MOD_REC[binfmt_misc]="Ensure /proc/sys/fs/binfmt_misc is mounted read-only or not at all in container contexts."

  MOD_REASON[udf]="UDF filesystem driver — historically vulnerable (multiple CVEs) and rarely needed; mounting UDF images from untrusted sources has caused kernel panics and LPE"
  MOD_SEV[udf]="MEDIUM"; MOD_CVE[udf]=""
  MOD_REC[udf]="Blacklist if UDF filesystems are not used: 'install udf /bin/false'."

  MOD_REASON[cifs]="CIFS/SMB client — wide attack surface, multiple historical CVEs (CVE-2022-0168, CVE-2023-38432), rarely legitimate in container workloads"
  MOD_SEV[cifs]="MEDIUM"; MOD_CVE[cifs]="CVE-2022-0168,CVE-2023-38432"
  MOD_REC[cifs]="Blacklist if SMB mounts are not required: 'install cifs /bin/false'."

  MOD_REASON[ksmbd]="In-kernel SMB3 server (ksmbd, since 5.15) — unauthenticated remote kernel RCE history (CVE-2022-47939 SMB2_TREE_DISCONNECT UAF, ZDI 10.0); large in-kernel network attack surface on port 445; almost never legitimate in container workloads. Prefer userspace Samba."
  MOD_SEV[ksmbd]="HIGH"; MOD_CVE[ksmbd]="CVE-2022-47939"
  MOD_REC[ksmbd]="Unload and blacklist unless an in-kernel SMB server is genuinely required: 'rmmod ksmbd 2>/dev/null; echo install ksmbd /bin/false > /etc/modprobe.d/ksmbd.conf'. Patch kernel to >= 5.15.61 / 5.19.2 for CVE-2022-47939. Restrict TCP/445 exposure."

  MOD_REASON[nfs]="NFS client — attack surface for server-side-confusion attacks; compromised NFS server can exploit NFS client bugs in the kernel"
  MOD_SEV[nfs]="MEDIUM"; MOD_CVE[nfs]=""
  MOD_REC[nfs]="Blacklist if NFS is not used: 'install nfs /bin/false'."

  MOD_REASON[bluetooth]="Bluetooth subsystem — large attack surface (BlueFrag, BIAS, KNOB class attacks); almost never legitimate in server/container workloads"
  MOD_SEV[bluetooth]="MEDIUM"; MOD_CVE[bluetooth]=""
  MOD_REC[bluetooth]="Blacklist: 'install bluetooth /bin/false; install btusb /bin/false'. Server workloads have no legitimate use for Bluetooth."

  MOD_REASON[dccp]="Datagram Congestion Control Protocol — no practical production use; multiple historical kernel LPE CVEs (CVE-2017-8824, CVE-2017-6074); not needed in any container workload"
  MOD_SEV[dccp]="MEDIUM"; MOD_CVE[dccp]="CVE-2017-8824,CVE-2017-6074"
  MOD_REC[dccp]="Blacklist: 'install dccp /bin/false'."

  MOD_REASON[sctp]="Stream Control Transmission Protocol — limited production use; multiple kernel CVEs (CVE-2021-3772, CVE-2022-0322); expands socket attack surface"
  MOD_SEV[sctp]="MEDIUM"; MOD_CVE[sctp]="CVE-2021-3772,CVE-2022-0322"
  MOD_REC[sctp]="Blacklist if SCTP is not used: 'install sctp /bin/false'. Verify no workloads depend on SCTP before blacklisting."

  MOD_REASON[rds]="Reliable Datagram Sockets — kernel subsystem with numerous historical vulnerabilities (CVE-2010-3904 and others); no common production use"
  MOD_SEV[rds]="MEDIUM"; MOD_CVE[rds]=""
  MOD_REC[rds]="Blacklist: 'install rds /bin/false'."

  MOD_REASON[rds_tcp]="RDS-over-TCP transport — second gate of PinTheft (CVE-2026-43494): the RDS zerocopy pin-reference bug is reached via rds/rds_tcp and chained with io_uring to overwrite the page cache. Cross-reference the io_uring reachability probe (check 48)."
  MOD_SEV[rds_tcp]="HIGH"; MOD_CVE[rds_tcp]="CVE-2026-43494"
  MOD_REC[rds_tcp]="Blacklist both RDS modules: printf 'install rds /bin/false\ninstall rds_tcp /bin/false\n' > /etc/modprobe.d/pintheft.conf; rmmod rds_tcp rds 2>/dev/null. Either this or disabling io_uring (kernel.io_uring_disabled=2) breaks the documented exploit chain."

  MOD_REASON[vsock]="Virtio/VM sockets core (AF_VSOCK) — host-guest socket transport; 'Attack of the Vsock' (CVE-2025-21756) is a use-after-free in this subsystem giving local privilege escalation. Rarely needed inside application containers."
  MOD_SEV[vsock]="HIGH"; MOD_CVE[vsock]="CVE-2025-21756"
  MOD_REC[vsock]="Blacklist if AF_VSOCK is not required (it usually is not in containers): 'install vsock /bin/false'. Patch the kernel for CVE-2025-21756."

  MOD_REASON[vmw_vsock_virtio_transport]="Virtio transport for AF_VSOCK — loads alongside vsock and exposes the same 'Attack of the Vsock' (CVE-2025-21756) UAF attack surface."
  MOD_SEV[vmw_vsock_virtio_transport]="HIGH"; MOD_CVE[vmw_vsock_virtio_transport]="CVE-2025-21756"
  MOD_REC[vmw_vsock_virtio_transport]="Blacklist with the rest of the vsock stack if AF_VSOCK is not required: 'install vmw_vsock_virtio_transport /bin/false'. Patch the kernel for CVE-2025-21756."

  MOD_REASON[atm]="Asynchronous Transfer Mode — legacy networking protocol; multiple historical kernel vulnerabilities; no production use in modern deployments"
  MOD_SEV[atm]="MEDIUM"; MOD_CVE[atm]=""
  MOD_REC[atm]="Blacklist: 'install atm /bin/false'."

  MOD_REASON[n_hdlc]="HDLC line discipline — niche serial protocol with exploitable history (CVE-2017-2636); unnecessary in container environments"
  MOD_SEV[n_hdlc]="MEDIUM"; MOD_CVE[n_hdlc]="CVE-2017-2636"
  MOD_REC[n_hdlc]="Blacklist: 'install n_hdlc /bin/false'."

  MOD_REASON[tipc]="Transparent IPC — cluster communications protocol with multiple kernel CVEs (CVE-2022-0435, CVE-2021-43267); rarely used in container deployments"
  MOD_SEV[tipc]="MEDIUM"; MOD_CVE[tipc]="CVE-2022-0435,CVE-2021-43267"
  MOD_REC[tipc]="Blacklist if TIPC is not used: 'install tipc /bin/false'."

  MOD_REASON[firewire_core]="FireWire (IEEE 1394) subsystem — DMA-capable bus; FireWire DMA allows direct physical memory read/write from the bus; no server use case"
  MOD_SEV[firewire_core]="HIGH"; MOD_CVE[firewire_core]=""
  MOD_REC[firewire_core]="Blacklist: 'install firewire_core /bin/false'. FireWire DMA is a physical-access attack vector but kernel driver vulnerabilities extend the risk."

  # ── Information on loaded vs affected ─────────────────────────────────────
  local any_dangerous=false
  local -A loaded_dangerous

  if [[ ! -r /proc/modules ]]; then
    info "/proc/modules not readable — skipping module audit"
    return
  fi

  while IFS=" " read -r modname _rest; do
    [[ -v MOD_REASON[$modname] ]] || continue
    loaded_dangerous[$modname]=true
    any_dangerous=true
  done < /proc/modules

  if [[ "$any_dangerous" == false ]]; then
    ok "No known-dangerous kernel modules detected in /proc/modules"
    return
  fi

  # Emit individual findings, critical/active-exploit modules first
  for pass in CRITICAL HIGH MEDIUM; do
    for modname in "${!loaded_dangerous[@]}"; do
      [[ "${MOD_SEV[$modname]}" != "$pass" ]] && continue
      local cve_str="${MOD_CVE[$modname]:-none}"
      local title_prefix=""
      [[ -n "${MOD_CVE[$modname]}" ]] && title_prefix="[${MOD_CVE[$modname]}] "

      case "$pass" in
        CRITICAL) crit "Dangerous module loaded: ${modname} (CVE: ${cve_str})" ;;
        HIGH|MEDIUM) warn "Dangerous module loaded: ${modname} (CVE: ${cve_str:-N/A})" ;;
      esac

      add_finding "kh_mod_${modname}" "$pass" \
        "${title_prefix}Dangerous kernel module loaded: ${modname}" \
        "Kernel module '${modname}' is currently loaded (visible in /proc/modules). Reason: ${MOD_REASON[$modname]}. Associated CVE(s): ${cve_str:-none documented in this check — see NVD for history}." \
        "Module-specific attack surface is active and exploitable. See the reason field above. For modules with active ITW CVEs (algif_aead, esp4, esp6, rxrpc), the host is exposed to current in-the-wild exploits providing local privilege escalation and container escape." \
        "Module is already loaded — no auto-load trigger needed. Exploit primitives (sockets, syscalls) are immediately accessible. Attack complexity depends on the specific module — see reasons above." \
        "${MOD_REC[$modname]:-Blacklist this module in /etc/modprobe.d/ and unload it with rmmod if not operationally required. Verify no workloads depend on it before proceeding.}"
    done
  done
}

# ===========================================================================
# CHECK FUNCTIONS  —  Checks 48-51 (gap-analysis behavioural probes, 2026-06)
#
# These checks were added to close coverage gaps identified by
# cve_monitor.py --gap-analysis. Each is a READ-ONLY / non-destructive probe:
# it tests reachability of a subsystem (syscall/socket/socket-file presence)
# without attempting to trigger any vulnerability. They complement the
# config-driven CVE engine, which handles version/module/socket detection.
# ===========================================================================

# ---------------------------------------------------------------------------
# Check 48 — io_uring exposure (CVE-2026-43121 zcrx OOB and io_uring CVE class)
# Read-only reachability probe: is io_uring_setup(2) callable from here, and
# is io_uring administratively restricted (kernel.io_uring_disabled)? Does NOT
# create rings beyond a minimal setup that is immediately closed, and never
# touches zcrx. io_uring is a recurring LPE/escape attack surface; many
# hardened container profiles disable it entirely.
# ---------------------------------------------------------------------------
check_io_uring_exposure() {
  hdr "48. io_uring exposure (CVE-2026-43121 zcrx and io_uring LPE class)"

  # Administrative restriction state (Linux >= 6.6 exposes this sysctl)
  local disabled_val="unset"
  if [[ -r /proc/sys/kernel/io_uring_disabled ]]; then
    disabled_val=$(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo "unset")
  fi

  # Reachability: try io_uring_setup(2). entries=1, params struct zeroed.
  # Return code convention from the probe:
  #   0 = ring created (io_uring reachable) — closed immediately
  #   1 = blocked (EPERM/EACCES/ENOSYS/EOPNOTSUPP) — not reachable
  #   2 = python3 unavailable (cannot test)
  local reach="unknown"
  if command -v python3 &>/dev/null; then
    if python3 -c "
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
# struct io_uring_params is 120 bytes on current kernels; zeroed is fine for probe.
buf = ctypes.create_string_buffer(120)
NR = 425  # __NR_io_uring_setup on x86_64/arm64 (common value)
fd = libc.syscall(NR, 1, ctypes.byref(buf))
err = ctypes.get_errno()
if fd >= 0:
    os.close(fd)
    sys.exit(0)         # reachable
# EPERM(1) EACCES(13) ENOSYS(38) EOPNOTSUPP(95) -> not reachable / disabled
sys.exit(1)
" 2>/dev/null; then
      reach="reachable"
    else
      local rc=$?
      [[ $rc -eq 2 ]] && reach="untestable" || reach="blocked"
    fi
  else
    reach="untestable (no python3)"
  fi

  if [[ "$reach" == "reachable" ]]; then
    local sev="HIGH"
    # If admin has set io_uring_disabled to a restrictive value but the ring
    # still opened, that is itself noteworthy; otherwise standard HIGH.
    warn "io_uring is reachable from this container (io_uring_disabled=${disabled_val})"
    add_finding "io_uring_exposure" "$sev" \
      "io_uring is reachable from this container (attack surface for CVE-2026-43121 and the io_uring LPE class)" \
      "io_uring_setup(2) succeeded from within this context, so the io_uring interface is reachable by unprivileged code here. kernel.io_uring_disabled=${disabled_val} (0=enabled for all, 1=disabled for unprivileged, 2=disabled for all; 'unset' means the sysctl is absent on this kernel). io_uring has a long history of kernel LPE and container-escape primitives; the most recent in this database is CVE-2026-43121 (zcrx freelist out-of-bounds write, fixed in stable 6.18.16)." \
      "io_uring reachability is a prerequisite for io_uring-based exploits. On an unpatched kernel, a reachable io_uring (and, for CVE-2026-43121 specifically, reachable zcrx zero-copy receive on an SMP host) can be leveraged for out-of-bounds kernel writes and privilege escalation. Even patched, io_uring substantially enlarges the unprivileged-reachable kernel attack surface." \
      "Reachability only — this probe does NOT attempt exploitation and does not confirm an unpatched kernel. Combine with the CVE engine's kernel-version result for CVE-2026-43121 to assess actual exploitability." \
      "1) If workloads do not require io_uring, disable it for unprivileged tasks: set kernel.io_uring_disabled=2 (all) or =1 (unprivileged) via /etc/sysctl.d/. 2) Alternatively block io_uring_setup(2), io_uring_enter(2), and io_uring_register(2) in the container seccomp profile (the RuntimeDefault profile blocks io_uring on recent runtimes). 3) Patch the kernel to >= 6.18.16 (or your distro backport) for CVE-2026-43121. 4) Disable zero-copy receive (zcrx) reachability where not needed."
  elif [[ "$reach" == "blocked" ]]; then
    ok "io_uring not reachable (blocked by seccomp/sysctl; io_uring_disabled=${disabled_val})"
  else
    info "io_uring reachability ${reach} (io_uring_disabled=${disabled_val})"
  fi
}

# ---------------------------------------------------------------------------
# Check 49 — kTLS / sockmap ULP exposure
# Gap analysis: KTLS+sockmap "Reverse Order" UAF and tls_sk_proto_close() ULP
# UAF (oss-security 2026-05/06). Read-only probe: can we attach the "tls" ULP
# to a TCP socket here (setsockopt(TCP_ULP,"tls"))? The kTLS ULP code path is
# the precondition for these UAF classes. The probe attaches the ULP to a
# freshly created, never-connected socket and closes it immediately; it does
# NOT drive the close-ordering race.
# ---------------------------------------------------------------------------
check_ktls_ulp_exposure() {
  hdr "49. kTLS / sockmap ULP exposure (TLS ULP use-after-free class)"

  local reach="unknown"
  if command -v python3 &>/dev/null; then
    # 0 = TLS ULP attachable (reachable); 1 = not available/blocked; 2 = untestable
    if python3 -c "
import socket, sys
TCP_ULP = 31
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
except Exception:
    sys.exit(1)
try:
    # Attaching the 'tls' ULP loads/engages the kTLS ULP code path.
    s.setsockopt(socket.IPPROTO_TCP, TCP_ULP, b'tls')
    s.close()
    sys.exit(0)            # ULP attached -> reachable
except OSError as e:
    import errno as E
    s.close()
    # ENOENT(2)/EOPNOTSUPP(95): tls ULP not built/loadable -> not reachable
    # EPERM(1)/EACCES(13): permission denied but path exists -> reachable surface
    # ENOSYS(38): setsockopt path blocked
    if getattr(e, 'errno', None) in (1, 13):
        sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
      reach="reachable"
    else
      local rc=$?
      [[ $rc -eq 2 ]] && reach="untestable" || reach="blocked"
    fi
  else
    reach="untestable (no python3)"
  fi

  # Supplementary signal: is the tls module loaded already?
  local tls_loaded="no"
  grep -q '^tls ' /proc/modules 2>/dev/null && tls_loaded="yes"

  if [[ "$reach" == "reachable" ]]; then
    warn "kTLS ULP is attachable from this container (tls module loaded=${tls_loaded})"
    add_finding "ktls_ulp_exposure" "MEDIUM" \
      "kTLS / sockmap ULP (\"tls\") is attachable to sockets from this container" \
      "setsockopt(TCP_ULP, \"tls\") succeeded (or returned a permission error indicating the path exists), so the kernel TLS upper-layer-protocol code is reachable from this context. tls module currently loaded: ${tls_loaded}. The kTLS/sockmap ULP machinery is the precondition for the recently reported use-after-free classes: the KTLS+sockmap 'Reverse Order' UAF/data-corruption issue and the tls_sk_proto_close() ULP UAF (oss-security, 2026-05/06), neither of which had a CVE assigned at the time of the gap analysis." \
      "kTLS ULP reachability is the attack surface for these socket-close-ordering use-after-free bugs, which can lead to kernel memory corruption and potential local privilege escalation. This probe confirms reachability only, not the presence of an unpatched bug." \
      "Reachability only — no exploitation attempted and no kernel version assertion made. Track the upstream fixes for the kTLS/sockmap UAF reports and re-assess once CVEs and fixed versions are published." \
      "1) If workloads do not use in-kernel TLS offload, block the ULP attach path: deny setsockopt(TCP_ULP) for 'tls'/'espintcp' via seccomp/LSM, or blacklist the 'tls' module ('install tls /bin/false') where it is not auto-required. 2) Keep the kernel current and watch for the kTLS/sockmap UAF fixes. 3) Restrict unprivileged user-namespace creation (check 44), which is commonly the route to reaching these socket primitives."
  elif [[ "$reach" == "blocked" ]]; then
    ok "kTLS ULP not attachable (blocked or tls ULP unavailable; tls module loaded=${tls_loaded})"
  else
    info "kTLS ULP reachability ${reach} (tls module loaded=${tls_loaded})"
  fi
}

# ---------------------------------------------------------------------------
# Check 50 — Kata Containers agent socket exposure (CVE-2026-41326)
# Gap analysis: Kata CopyFile policy subversion via symlinks. The behavioural
# signal reachable from inside a workload is the presence/accessibility of the
# kata-agent communication socket and the shared-directory mount the CopyFile
# symlink trick abuses. READ-ONLY: stat/listing only; nothing is written.
# ---------------------------------------------------------------------------
check_kata_agent_socket() {
  hdr "50. Kata Containers agent socket exposure (CVE-2026-41326 CopyFile)"

  local found=false

  # Known kata-agent / shared-dir artifacts. We only stat/list (read-only).
  local agent_sockets=(
    /run/kata-containers/agent.sock
    /run/vc/sbs/*/console.sock
    /run/kata/containers/agent.sock
  )
  local shared_dirs=(
    /run/kata-containers/shared/containers
    /run/kata-containers/shared
  )

  local sock
  for sock in "${agent_sockets[@]}"; do
    # Expand globs; skip if no match
    [[ -e "$sock" ]] || continue
    found=true
    warn "Kata agent-related socket present: $sock"
    add_finding "kata_agent_socket_${sock//\//_}" "HIGH" \
      "Kata Containers agent socket reachable: $sock" \
      "A kata-agent / Kata runtime socket is present and visible from this context ($sock). The kata-agent CopyFile API (CVE-2026-41326, Kata 3.4.0–3.28.0) validates only the destination path of a write and ignores file type/payload, allowing a host-side actor with access to the agent socket to create a symlink in an allowed directory and then write through it to overwrite an arbitrary guest file." \
      "If the agent is pre-3.29.0, an untrusted host (the threat model for Confidential VMs) can subvert guest image integrity — overwriting guest binaries, injecting code, or exfiltrating data — defeating the CVM isolation guarantee. Visibility of the agent socket from a workload context is itself an isolation concern." \
      "Detection is artifact-presence based; this probe does not exercise CopyFile or write anything. Confirm the Kata version to determine whether CVE-2026-41326 applies (fixed in 3.29.0)." \
      "1) Upgrade Kata Containers to >= 3.29.0. 2) Ensure the kata-agent ttrpc/gRPC socket is reachable only by the trusted shim, never by workload code. 3) Apply a kata-agent policy that validates symlink targets and rejects CopyFile writes whose resolved path escapes the permitted directory. 4) Treat any pre-3.29.0 agent as integrity-compromised in CVM deployments."
  done

  local d
  for d in "${shared_dirs[@]}"; do
    [[ -d "$d" ]] || continue
    local writable="read-only"
    [[ -w "$d" ]] && writable="WRITABLE"
    found=true
    local sev="MEDIUM"
    [[ "$writable" == "WRITABLE" ]] && sev="HIGH"
    warn "Kata shared directory present ($writable): $d"
    add_finding "kata_shared_dir_${d//\//_}" "$sev" \
      "Kata Containers shared directory present ($writable): $d" \
      "The Kata shared-containers directory ($d, $writable) is the location the CVE-2026-41326 CopyFile symlink subversion abuses: an attacker creates a symlink here (an 'allowed' path) that points outside the directory, then writes through it. Its presence/writability from this context is the observable precondition." \
      "On a vulnerable kata-agent (3.4.0–3.28.0), a writable shared directory enables the symlink-then-write primitive to overwrite arbitrary guest files. Even read-only visibility indicates Kata shared-fs plumbing is exposed to this context." \
      "Artifact presence/writability only; no write performed by this probe." \
      "Upgrade Kata to >= 3.29.0; restrict access to the shared directory and the agent socket; enforce a symlink-target-validating agent policy."
  done

  [[ "$found" == false ]] && ok "No Kata Containers agent socket or shared directory detected"
}

# ---------------------------------------------------------------------------
# Check 51 — KVM/arm64 vGIC-ITS guest-to-host exposure (CVE-2026-46316 ITScape)
# Gap analysis: first public KVM/arm64 guest-to-host escape. The meaningful
# signal differs by vantage point:
#   - On the HOST: is this an arm64 KVM host (/dev/kvm present, arch aarch64)?
#   - In a GUEST: are we an arm64 VM with a vGIC-ITS interrupt controller
#     (the exploitable in-kernel emulation) present?
# READ-ONLY: arch detection + presence of /dev/kvm, /proc/device-tree, and
# GICv3/ITS sysfs/devicetree nodes. No KVM ioctls are issued.
# ---------------------------------------------------------------------------
check_kvm_arm64_vgic_its() {
  hdr "51. KVM/arm64 vGIC-ITS guest-to-host exposure (CVE-2026-46316 ITScape)"

  local arch
  arch=$(uname -m 2>/dev/null || echo "unknown")

  if [[ "$arch" != "aarch64" && "$arch" != "arm64" ]]; then
    ok "Host architecture is ${arch} — CVE-2026-46316 (arm64-only) not applicable"
    return
  fi

  # We are on arm64. Distinguish host-KVM vs guest vantage points.
  local kvm_dev=false
  [[ -e /dev/kvm ]] && kvm_dev=true

  # GICv3 ITS presence signals (devicetree or sysfs). Read-only listing.
  local its_dt=false its_irqchip=false
  if compgen -G "/proc/device-tree/*/*its*" >/dev/null 2>&1 || \
     compgen -G "/sys/firmware/devicetree/base/*/*its*" >/dev/null 2>&1; then
    its_dt=true
  fi
  if grep -qi 'its\|gic' /sys/kernel/irq/*/* 2>/dev/null; then
    its_irqchip=true
  fi

  if [[ "$kvm_dev" == true ]]; then
    warn "arm64 KVM host indicators present (/dev/kvm accessible)"
    add_finding "kvm_arm64_itscape_host" "HIGH" \
      "arm64 KVM host — exposed to CVE-2026-46316 (ITScape) if running untrusted guests" \
      "This is an arm64 (${arch}) system with /dev/kvm accessible from this context, indicating an arm64 KVM host (or a context with KVM access). CVE-2026-46316 (ITScape) is a use-after-free in the arm64 KVM vGIC-ITS emulation (vgic_its_invalidate_cache double-put) that lets a malicious GUEST escape to the HOST with kernel privileges. GICv3/ITS devicetree node seen: ${its_dt}; ITS/GIC irq sysfs signal: ${its_irqchip}." \
      "On an unpatched arm64 KVM host running untrusted guests (e.g. multi-tenant arm64 cloud, or VM-isolated container runtimes such as Kata on arm64), a compromised guest can corrupt host kernel memory and execute code at host kernel privilege — a full guest-to-host escape. /dev/kvm being reachable from a container context is itself a serious exposure." \
      "This probe detects platform exposure (arm64 + KVM), not an unpatched kernel; combine with the CVE engine's kernel-version result for CVE-2026-46316. Public PoC exists; exploitation needs guest EL1 (root), normally held by a tenant in their own VM." \
      "1) Patch the host kernel to include mainline commit 13031fb6b835 (and CVE-2026-46317 / follow-ups); on Rocky/RLC use the patched 9.6/9/10 kernels. 2) There is no drop-in software mitigation — until patched, restrict arm64 KVM hosts to trusted guests/tenants. 3) Do NOT expose /dev/kvm to application containers; remove the device mount. 4) Prioritise multi-tenant arm64 virtualization hosts for patching."
  elif [[ "$its_dt" == true || "$its_irqchip" == true ]]; then
    info "arm64 guest with GICv3/ITS interrupt controller present (ITScape guest-side relevance)"
    add_finding "kvm_arm64_itscape_guest" "INFO" \
      "arm64 guest with vGIC-ITS present — ITScape (CVE-2026-46316) is a host-kernel bug reachable from arm64 guests" \
      "This arm64 (${arch}) context exposes a GICv3/ITS interrupt controller (devicetree node: ${its_dt}; irq sysfs: ${its_irqchip}) but /dev/kvm is not accessible here, consistent with running inside an arm64 guest. CVE-2026-46316 (ITScape) is exploited FROM an arm64 guest against the host KVM vGIC-ITS emulation." \
      "If this guest runs on an unpatched arm64 KVM host, the vGIC-ITS UAF could be used to escape to the host. The exposure is a property of the underlying host kernel, which cannot be confirmed from inside the guest." \
      "Informational from the guest vantage point — the fix must be applied on the host." \
      "Confirm with the infrastructure/cloud provider that the arm64 KVM host kernel includes the ITScape fix (mainline commit 13031fb6b835). Avoid running sensitive workloads on unpatched multi-tenant arm64 hosts."
  else
    ok "arm64 system without KVM-host or vGIC-ITS indicators detected for CVE-2026-46316"
  fi
}

# ---------------------------------------------------------------------------
# Check 52 — Container runtime versions (best-effort)
# Gives the manual-type runc CVE entries (CVE-2019-5736, CVE-2024-21626) a real
# three-state detection signal instead of inventory-only. Read-only: reads
# binaries and runs '<bin> --version'; never eval's output, never writes.
# ---------------------------------------------------------------------------
check_runtime_versions() {
  hdr "52. Container runtime versions (best-effort)"

  # Candidate binary locations reachable from a container when host paths leak.
  local -a runc_paths=(
    /usr/bin/runc /usr/sbin/runc /usr/local/sbin/runc /usr/local/bin/runc
    /run/torcx/unpack/docker/bin/runc /host/usr/bin/runc /host/usr/sbin/runc
  )
  local -a containerd_paths=(
    /usr/bin/containerd /usr/local/bin/containerd /host/usr/bin/containerd
  )
  local -a crio_paths=(
    /usr/bin/crio /usr/local/bin/crio /host/usr/bin/crio
  )

  # Extract a semver-ish token from a `--version` string without eval.
  _rt_version_of() {
    local bin="$1" out=""
    [[ -x "$bin" ]] || return 1
    out=$("$bin" --version 2>/dev/null | head -3) || return 1
    # runc:        "runc version 1.1.12"
    # containerd:  "containerd github.com/containerd/containerd v1.7.2 <sha>"
    # crio:        "crio version 1.28.4"
    local ver
    # Prefer a token following the word "version"; fall back to any leading-v semver
    # (containerd prints "containerd github.com/... v1.7.2 <sha>" with no "version" word).
    ver=$(printf '%s\n' "$out" | grep -oiE 'version[[:space:]]+v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)?' \
            | head -1 | grep -oiE 'v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)?')
    [[ -z "$ver" ]] && ver=$(printf '%s\n' "$out" | grep -oiE '\bv[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)?' | head -1)
    [[ -z "$ver" ]] && ver=$(printf '%s\n' "$out" | grep -oiE '\b[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)?' | head -1)
    [[ -n "$ver" ]] && { printf '%s' "${ver#v}"; return 0; }
    return 1
  }

  # dpkg-style "is A < B" using sort -V. Returns 0 (true) if $1 < $2.
  _ver_lt() { [[ "$1" == "$2" ]] && return 1; [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]; }

  local found_any=false

  # --- runc ---------------------------------------------------------------
  local runc_bin="" runc_ver=""
  for p in "${runc_paths[@]}"; do
    if runc_ver=$(_rt_version_of "$p" 2>/dev/null); then runc_bin="$p"; break; fi
  done

  # Cache globally so the CVE-database 'manual' check_type dispatch (used by
  # CVE-2019-5736 and CVE-2024-21626) can consult the ALREADY-established host
  # runc version instead of independently rendering a static advisory as if
  # no detection had happened. Empty string means "not reachable here" —
  # callers must treat that as unknown, not as evidence of anything.
  RUNC_DETECTED_VERSION="$runc_ver"
  RUNC_DETECTED_PATH="$runc_bin"
  RUNC_VERDICT_CVE_2019_5736=""
  RUNC_VERDICT_CVE_2024_21626=""

  if [[ -n "$runc_ver" ]]; then
    found_any=true
    # 1.1.12 fixes CVE-2024-21626; 1.0.0-rc7 fixes CVE-2019-5736 (both < 1.1.12).
    local runc_verdicts=""
    if _ver_lt "$runc_ver" "1.1.12"; then
      runc_verdicts+="CVE-2024-21626 (Leaky Vessels, fixed 1.1.12); "
      RUNC_VERDICT_CVE_2024_21626="vulnerable"
    else
      RUNC_VERDICT_CVE_2024_21626="fixed"
    fi
    # 5736 practically only matters on ancient runc (<= 1.0.0-rc6, fixed in 1.0.0-rc7).
    # NB: `sort -V` ranks "1.0.0-rc6" ABOVE "1.0.0", so do not use _ver_lt for the rc
    # boundary — detect the pre-release/pre-1.0 case explicitly instead.
    local runc_major_minor_patch="${runc_ver%%-*}"   # strip any -rcN / -dev suffix
    RUNC_VERDICT_CVE_2019_5736="fixed"
    if _ver_lt "$runc_major_minor_patch" "1.0.0"; then
      # e.g. 0.9.x — unambiguously pre-1.0
      runc_verdicts+="CVE-2019-5736 (/proc/self/exe overwrite, fixed 1.0.0-rc7); "
      RUNC_VERDICT_CVE_2019_5736="vulnerable"
    elif [[ "$runc_major_minor_patch" == "1.0.0" && "$runc_ver" =~ -rc([0-6])([^0-9]|$) ]]; then
      # 1.0.0-rc0 .. 1.0.0-rc6 are vulnerable; 1.0.0-rc7+ and 1.0.0 are fixed
      runc_verdicts+="CVE-2019-5736 (/proc/self/exe overwrite, fixed 1.0.0-rc7); "
      RUNC_VERDICT_CVE_2019_5736="vulnerable"
    fi
    if [[ -n "$runc_verdicts" ]]; then
      crit "runc ${runc_ver} at ${runc_bin} is affected by: ${runc_verdicts%; }"
      add_finding "runtime_runc_vulnerable" "CRITICAL" \
        "Vulnerable runc detected: ${runc_ver} (${runc_bin})" \
        "A runc binary reachable from this context reports version ${runc_ver}. This version predates fixes for: ${runc_verdicts%; }. Because the binary was reachable, this is a definitive VERIFY-ON-HOST verdict rather than an inventory-only advisory." \
        "These are container-to-host escape vulnerabilities: an attacker able to run a malicious image or exec into a container can break out to root on the node, compromising the host and co-located workloads." \
        "Definitive where the reachable binary is the one the node actually uses to run containers. If this binary is a leaked/host-mounted copy, confirm it matches the active runtime." \
        "Upgrade runc to >= 1.1.12 (and ensure Docker/containerd/CRI-O invoke the patched binary). Re-pull/rebuild node images. Verify with 'runc --version' on the node."
    else
      ok "runc ${runc_ver} (${runc_bin}) is at or above 1.1.12 — past the runc escape fixes tracked here"
    fi
  fi

  # --- containerd ---------------------------------------------------------
  local ctr_bin="" ctr_ver=""
  for p in "${containerd_paths[@]}"; do
    if ctr_ver=$(_rt_version_of "$p" 2>/dev/null); then ctr_bin="$p"; break; fi
  done
  [[ -n "$ctr_ver" ]] && { found_any=true; info "containerd ${ctr_ver} reachable at ${ctr_bin} (cross-check against CVE-2026-46680 fixed 1.7.32/2.0.9/2.2.4/2.3.1)"; }

  # --- cri-o --------------------------------------------------------------
  local crio_bin="" crio_ver=""
  for p in "${crio_paths[@]}"; do
    if crio_ver=$(_rt_version_of "$p" 2>/dev/null); then crio_bin="$p"; break; fi
  done
  [[ -n "$crio_ver" ]] && { found_any=true; info "cri-o ${crio_ver} reachable at ${crio_bin} (cross-check against CVE-2022-0811 cr8escape fixed 1.19.6/1.20.7/1.21.6/1.22.3)"; }

  # --- three-state fallback when NOTHING is reachable ---------------------
  if [[ "$found_any" == false ]]; then
    # Precondition signal: in-container root without userns remapping.
    # /proc/self/uid_map "0 0 <count>" means container-0 maps to host-0 (NOT remapped).
    local uidmap unmapped_root=false
    uidmap=$(awk 'NR==1{print $1, $2}' /proc/self/uid_map 2>/dev/null || echo "")
    [[ "$uidmap" == "0 0" && "$(id -u)" == "0" ]] && unmapped_root=true

    if [[ "$unmapped_root" == true ]]; then
      warn "No runtime version reachable, but in-container root is NOT userns-remapped — runc escape preconditions present"
      add_finding "runtime_version_unknown_exposed" "MEDIUM" \
        "Container runtime version not observable; runc-escape preconditions present" \
        "No runc/containerd/cri-o binary was reachable from this context, so the host runtime version could not be confirmed. However, this process is root inside the container and /proc/self/uid_map shows container UID 0 mapping directly to host UID 0 (no user-namespace remapping), which is the precondition required by CVE-2019-5736-class escapes." \
        "If the node's runc is unpatched, the escape path is available; the missing version means this cannot be ruled out. This is the POTENTIALLY-EXPOSED state, not a confirmed vulnerability." \
        "Cannot be scored without the host runtime version — treat as verify-required, not safe." \
        "Confirm 'runc --version' on the node (>= 1.1.12). Enable user-namespace remapping so container root is not host root, which blocks the CVE-2019-5736 overwrite regardless of runc version (see check 27)."
    else
      info "No container runtime binary reachable from this context and no unmapped-root precondition — runtime version UNKNOWN (not 'safe'). Confirm 'runc --version' on the node."
    fi
  fi

  # NB: _rt_version_of/_ver_lt are intentionally NOT unset here — the CVE-database
  # 'manual' check_type dispatch (CVE-2019-5736/CVE-2024-21626) reuses _ver_lt
  # against the RUNC_DETECTED_VERSION cached above.
}

check_docker_authz_bypass() {
  hdr "53. Docker Engine AuthZ plugin bypass (CVE-2026-34040)"

  # Self-contained version comparator, per this script's convention of
  # runtime/update probes carrying their own comparator rather than depending
  # on another check having already run and defined one.
  _da_ver_lt() { [[ "$1" == "$2" ]] && return 1; [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]; }

  local -a docker_sockets=(
    /var/run/docker.sock /run/docker.sock
    /host/var/run/docker.sock /host/run/docker.sock
  )
  local -a dockerd_paths=(
    /usr/bin/dockerd /usr/local/bin/dockerd /usr/sbin/dockerd
    /host/usr/bin/dockerd /host/usr/sbin/dockerd
  )

  local docker_sock="" have_curl=false
  command -v curl &>/dev/null && have_curl=true
  for s in "${docker_sockets[@]}"; do
    [[ -S "$s" ]] && { docker_sock="$s"; break; }
  done

  # --- Preferred path: query the daemon API directly over the socket. This
  # is the only way to also observe whether an AuthZ plugin is configured,
  # which is the precondition for CVE-2026-34040 to actually matter (a
  # vanilla Docker install with no AuthZ plugin is not affected). ----------
  local server_ver="" authz_plugins="" query_ok=false
  if [[ -n "$docker_sock" && "$have_curl" == true ]]; then
    local version_json info_json
    version_json=$(curl -fsS --max-time 3 --unix-socket "$docker_sock" http://localhost/version 2>/dev/null)
    info_json=$(curl -fsS --max-time 3 --unix-socket "$docker_sock" http://localhost/info 2>/dev/null)
    if [[ -n "$version_json" ]]; then
      query_ok=true
      server_ver=$(printf '%s' "$version_json" | grep -oE '"Version":"[0-9]+\.[0-9]+\.[0-9]+"' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    fi
    if [[ -n "$info_json" ]]; then
      # Plugins.Authorization is an array; treat "[]" as none configured.
      authz_plugins=$(printf '%s' "$info_json" | grep -oE '"Authorization":\[[^]]*\]' | head -1)
      [[ "$authz_plugins" == '"Authorization":[]' ]] && authz_plugins=""
    fi
  fi

  # --- Fallback: a dockerd binary reachable via a host-mounted path. This
  # confirms the engine build version but NOT the AuthZ plugin configuration
  # (that lives in daemon runtime state, not the binary), so the verdict
  # here is necessarily weaker than the socket-query path above. -----------
  local dockerd_bin="" dockerd_ver=""
  if [[ "$query_ok" == false ]]; then
    for p in "${dockerd_paths[@]}"; do
      if [[ -x "$p" ]]; then
        dockerd_ver=$("$p" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        [[ -n "$dockerd_ver" ]] && { dockerd_bin="$p"; break; }
      fi
    done
  fi

  local effective_ver="${server_ver:-$dockerd_ver}"
  local vulnerable=false
  [[ -n "$effective_ver" ]] && _da_ver_lt "$effective_ver" "29.3.1" && vulnerable=true

  if [[ "$query_ok" == true && "$vulnerable" == true && -n "$authz_plugins" ]]; then
    crit "VULNERABLE: Docker Engine ${effective_ver} at ${docker_sock} with AuthZ plugin(s) configured (CVE-2026-34040)"
    add_finding "cve_2026_34040_docker_authz" "CRITICAL" \
      "Docker Engine ${effective_ver} vulnerable to AuthZ bypass with plugin(s) configured (CVE-2026-34040)" \
      "The Docker daemon reachable at ${docker_sock} reports Server Version ${effective_ver} (< 29.3.1) and at least one Authorization plugin is configured (${authz_plugins}). The 2024 fix for CVE-2024-41110 only handled zero-length request bodies; a request body padded past 1MB is silently truncated before it reaches the AuthZ plugin, but the daemon itself still processes the full, untruncated request." \
      "Any principal whose Docker API access is gated by this AuthZ plugin can pad a container-creation request past 1MB so the plugin sees an empty body and approves it, while the daemon creates a privileged container with a full host filesystem mount — full host compromise, silently bypassing whatever policy (OPA, Prisma Cloud, a custom plugin) was meant to enforce it." \
      "Trivial. A single HTTP request with no race conditions or timing dependencies; no exploit tooling is required beyond padding the request body past 1MB." \
      "Upgrade Docker Engine to >= 29.3.1 (and Docker Desktop to >= 4.66.1) immediately. Until patched: do not rely on AuthZ plugins that inspect request bodies for security decisions, restrict Docker API access to trusted parties only, or run Docker in rootless mode / with --userns-remap to cap the blast radius if a bypass does occur."
  elif [[ "$query_ok" == true && "$vulnerable" == true ]]; then
    warn "Docker Engine ${effective_ver} at ${docker_sock} is pre-29.3.1 (CVE-2026-34040) but no AuthZ plugin detected"
    add_finding "cve_2026_34040_docker_authz" "MEDIUM" \
      "Docker Engine ${effective_ver} pre-29.3.1 (CVE-2026-34040) — no AuthZ plugin detected" \
      "Docker Engine ${effective_ver} at ${docker_sock} predates the CVE-2026-34040 fix, but /info reports no configured Authorization plugin. This specific bypass only matters where an AuthZ plugin makes access-control decisions based on request body content — a vanilla Docker install is not affected by this particular CVE." \
      "None from this CVE specifically while no AuthZ plugin is configured. The daemon socket itself remains a full administrative interface regardless — see the runtime-socket finding (check 4) for that separate, unconditional risk." \
      "N/A for this CVE without an AuthZ plugin present." \
      "Upgrade to >= 29.3.1 as routine hygiene, and re-check this finding if an AuthZ plugin is introduced later."
  elif [[ "$query_ok" == true ]]; then
    ok "Docker Engine ${effective_ver} at ${docker_sock} is >= 29.3.1 — patched for CVE-2026-34040"
    add_finding "cve_2026_34040_docker_authz" "INFO" \
      "Docker Engine ${effective_ver} — patched for CVE-2026-34040" \
      "Docker Engine ${effective_ver} at ${docker_sock} is at or above the fixed version 29.3.1." \
      "N/A — version appears patched." "N/A" \
      "Confirm Docker Desktop (if used for local image builds) is also >= 4.66.1."
  elif [[ -n "$dockerd_ver" ]]; then
    if [[ "$vulnerable" == true ]]; then
      warn "dockerd binary ${dockerd_ver} reachable at ${dockerd_bin} predates 29.3.1 (CVE-2026-34040) — AuthZ plugin status not observable from here"
      add_finding "cve_2026_34040_docker_authz_binary" "MEDIUM" \
        "dockerd ${dockerd_ver} (${dockerd_bin}) predates CVE-2026-34040 fix — AuthZ status unknown" \
        "A dockerd binary reachable from this context (likely via a host-mounted path) reports version ${dockerd_ver}, which predates 29.3.1. The daemon socket itself was not reachable from here, so whether an AuthZ plugin is configured — the precondition for this CVE to matter — could not be confirmed." \
        "If an AuthZ plugin relying on request-body inspection is configured on this host, the bypass described in CVE-2026-34040 applies in full." \
        "Cannot be scored without daemon-socket access to confirm AuthZ plugin configuration — treat as verify-required, not safe." \
        "Upgrade Docker Engine to >= 29.3.1. Confirm directly on the node with: docker info --format '{{.Plugins.Authorization}}'."
    else
      ok "dockerd ${dockerd_ver} (${dockerd_bin}) is >= 29.3.1 — patched for CVE-2026-34040"
      add_finding "cve_2026_34040_docker_authz_binary" "INFO" \
        "dockerd ${dockerd_ver} — patched for CVE-2026-34040" \
        "dockerd binary reachable at ${dockerd_bin} reports version ${dockerd_ver}, at or above the fixed 29.3.1." \
        "N/A — version appears patched." "N/A" "N/A"
    fi
  else
    info "No Docker daemon socket or dockerd binary reachable from this context — Docker Engine version UNKNOWN (not 'safe'). Confirm 'docker version --format {{.Server.Version}}' and AuthZ plugin config on the node directly."
  fi
}
# =============================================================================
# cve_check_engine.sh  —  Config-driven CVE check engine
# Drop-in addition to container_escape_audit.sh
#
# REPLACES the hardcoded check_copy_fail() (check 24) and
# check_dirty_frag() (check 46) with a single config-driven engine that reads
# cve_checks.conf and runs the appropriate test for every CVE entry.
#
# HOW TO INTEGRATE
# ----------------
# 1. Source or paste this file into container_escape_audit.sh, after the
#    existing helper functions and before the MAIN section.
# 2. In MAIN, replace the calls to check_copy_fail and check_dirty_frag with:
#       CVE_CONF="${CVE_CONF:-/etc/container-audit/cve_checks.conf}"
#       run_cve_checks "$CVE_CONF"
#    (The CVE_CONF variable can be overridden at the command line or via env.)
# 3. Add --cve-conf <path> to the CLI parser if desired (see bottom of file).
#
# CONFIG FILE
# -----------
# The engine reads cve_checks.conf (INI-style key=value blocks, blank-line
# separated). See cve_checks.conf for full format documentation.
#
# CHECK TYPES
# -----------
# kernel_version  — Parse uname -r and compare against introduced/fixed_versions.
#                   Flags if the running kernel is in the affected range and
#                   no fixed_version for this series has been reached.
#
# module_loaded   — Check /proc/modules. If any module_names entry is loaded,
#                   flag it.
#
# socket_family   — Try socket(AF, SOCK_TYPE, PROTO) in Python3. Reports if the
#                   socket family is reachable from within the container.
#
# kernel_symbol   — Grep /proc/kallsyms for kallsyms_sym. Reports if the
#                   vulnerable symbol is present and unobfuscated.
#
# compound        — Runs kernel_version + module_loaded + socket_family together
#                   and synthesises a combined severity based on all results.
#                   This is the most thorough check type and should be used for
#                   CVEs where both the kernel version AND module/socket access
#                   are meaningful.
# =============================================================================

# ---------------------------------------------------------------------------
# Default config file location — override via CVE_CONF env var or --cve-conf
# ---------------------------------------------------------------------------
# CVE_CONF default path resolved in MAIN (see bottom of script)

# ---------------------------------------------------------------------------
# _parse_cve_block: read one CVE block from the config into associative array
# Usage: _parse_cve_block declares global CVE_FIELD[key]=value
# ---------------------------------------------------------------------------
declare -A CVE_FIELD

_load_cve_block() {
  # CVE_BLOCK is a newline-separated string of key=value lines
  local block="$1"
  CVE_FIELD=()
  # Fields that are machine-parsed (numbers, versions, enums, lists). For these
  # we strip an inline "  # comment" and surrounding whitespace so authors can
  # annotate them in the config, e.g.  fixed_versions=6.18.16  # backport TBD.
  # Prose fields (what/impact/exploit/rec/notes/name/alias/mitigation) are left
  # byte-for-byte intact, since they legitimately contain '#' characters.
  local _machine_fields=" cve_id cvss severity check_type introduced fixed_versions upstream_fixed upstream_ranges distro_status vendor_defer itw poc_public cisa_kev subsystem module_names socket_af socket_type socket_proto arch component component_affected component_fixed kallsyms_sym "
  local key rest
  while IFS='=' read -r key rest; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    key="${key// /}"
    if [[ "$_machine_fields" == *" $key "* ]]; then
      # Strip a trailing inline comment introduced by whitespace + '#'
      if [[ "$rest" == *[[:space:]]#* ]]; then
        rest="${rest%%[[:space:]]#*}"
      fi
      # Trim leading/trailing whitespace
      rest="${rest#"${rest%%[![:space:]]*}"}"
      rest="${rest%"${rest##*[![:space:]]}"}"
    fi
    CVE_FIELD["$key"]="$rest"
  done <<< "$block"
}

# ---------------------------------------------------------------------------
# _kver_to_int: convert "x.y.z" to a comparable integer (x*1000000 + y*1000 + z)
# Handles "x.y" as "x.y.0"
# ---------------------------------------------------------------------------
_kver_to_int() {
  local ver="$1"
  # Strip any suffix like "-generic", "-aws", rc tags etc
  ver=$(echo "$ver" | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "0.0.0")
  local maj min pat
  IFS='.' read -r maj min pat <<< "$ver"
  maj="${maj:-0}"; min="${min:-0}"; pat="${pat:-0}"
  echo $(( maj * 1000000 + min * 1000 + pat ))
}

# ===========================================================================
# ENRICHED VERSION ENGINE  (distro/flavour-aware, scheme-correct comparators)
# ---------------------------------------------------------------------------
# Consumes the enriched schema fields upstream_fixed / distro_status /
# vendor_defer and produces an accurate five-state verdict. Validated against
# the dpkg oracle and known Ubuntu/upstream orderings. Accuracy rule: any
# unparseable version, unmatched flavour, or absent data resolves to UNKNOWN —
# never silently to fixed/not-affected.
# ===========================================================================

# --- scheme-aware comparators (print -1 / 0 / 1) ---------------------------
_ver_cmp_upstream() {
  local a="$1" b="$2"; a="${a#v}"; b="${b#v}"
  local a_main b_main a_rc b_rc
  a_main="${a%%-rc*}"; b_main="${b%%-rc*}"
  if [[ "$a" == *-rc* ]]; then a_rc="${a##*-rc}"; else a_rc="99999"; fi
  if [[ "$b" == *-rc* ]]; then b_rc="${b##*-rc}"; else b_rc="99999"; fi
  local IFS=.; local -a A=($a_main) B=($b_main); local i max=${#A[@]}
  (( ${#B[@]} > max )) && max=${#B[@]}
  for (( i=0; i<max; i++ )); do
    local x="${A[i]:-0}" y="${B[i]:-0}"; x="${x//[!0-9]/}"; y="${y//[!0-9]/}"
    x="${x:-0}"; y="${y:-0}"
    (( 10#$x < 10#$y )) && { echo -1; return; }
    (( 10#$x > 10#$y )) && { echo 1; return; }
  done
  (( 10#$a_rc < 10#$b_rc )) && { echo -1; return; }
  (( 10#$a_rc > 10#$b_rc )) && { echo 1; return; }
  echo 0
}

_ver_cmp_dpkg() {
  local a="$1" b="$2"
  if command -v dpkg >/dev/null 2>&1; then
    if dpkg --compare-versions "$a" lt "$b"; then echo -1; return; fi
    if dpkg --compare-versions "$a" gt "$b"; then echo 1; return; fi
    echo 0; return
  fi
  _dpkg_fallback_cmp "$a" "$b"
}

_dpkg_fallback_cmp() {
  local a="$1" b="$2" ea eb
  [[ "$a" == *:* ]] || a="0:$a"; [[ "$b" == *:* ]] || b="0:$b"
  ea="${a%%:*}"; eb="${b%%:*}"
  (( ea < eb )) && { echo -1; return; }
  (( ea > eb )) && { echo 1; return; }
  _dpkg_cmp_frag "${a#*:}" "${b#*:}"
}

_dpkg_cmp_frag() {
  local a="$1" b="$2"
  while [[ -n "$a" || -n "$b" ]]; do
    local an="" bn=""
    while [[ -n "$a" && "${a:0:1}" =~ [^0-9] ]]; do an+="${a:0:1}"; a="${a:1}"; done
    while [[ -n "$b" && "${b:0:1}" =~ [^0-9] ]]; do bn+="${b:0:1}"; b="${b:1}"; done
    local i max=${#an}; (( ${#bn} > max )) && max=${#bn}
    for (( i=0; i<max; i++ )); do
      local va vb; va=$(_dpkg_char_order "${an:i:1}"); vb=$(_dpkg_char_order "${bn:i:1}")
      (( va < vb )) && { echo -1; return; }
      (( va > vb )) && { echo 1; return; }
    done
    local ad="" bd=""
    while [[ -n "$a" && "${a:0:1}" =~ [0-9] ]]; do ad+="${a:0:1}"; a="${a:1}"; done
    while [[ -n "$b" && "${b:0:1}" =~ [0-9] ]]; do bd+="${b:0:1}"; b="${b:1}"; done
    ad="${ad:-0}"; bd="${bd:-0}"
    local adn=$((10#$ad)) bdn=$((10#$bd))
    (( adn < bdn )) && { echo -1; return; }
    (( adn > bdn )) && { echo 1; return; }
  done
  echo 0
}

_dpkg_char_order() {
  local c="$1"
  [[ -z "$c" ]] && { echo 0; return; }
  [[ "$c" == "~" ]] && { echo -1; return; }
  [[ "$c" =~ [a-zA-Z] ]] && { printf '%d\n' "'$c"; return; }
  printf '%d\n' $(( $(printf '%d' "'$c") + 256 ))
}

_ver_cmp_ubuntu() {
  local a="$1" b="$2" a_up a_rest b_up b_rest
  a_up="${a%%-*}"; a_rest="${a#*-}"; b_up="${b%%-*}"; b_rest="${b#*-}"
  local c; c=$(_ver_cmp_upstream "$a_up" "$b_up"); [[ "$c" != "0" ]] && { echo "$c"; return; }
  local a_abi="${a_rest%%.*}" a_upl="${a_rest#*.}" b_abi="${b_rest%%.*}" b_upl="${b_rest#*.}"
  a_abi="${a_abi//[!0-9]/}"; b_abi="${b_abi//[!0-9]/}"; a_upl="${a_upl//[!0-9]/}"; b_upl="${b_upl//[!0-9]/}"
  a_abi="${a_abi:-0}"; b_abi="${b_abi:-0}"; a_upl="${a_upl:-0}"; b_upl="${b_upl:-0}"
  (( 10#$a_abi < 10#$b_abi )) && { echo -1; return; }
  (( 10#$a_abi > 10#$b_abi )) && { echo 1; return; }
  (( 10#$a_upl < 10#$b_upl )) && { echo -1; return; }
  (( 10#$a_upl > 10#$b_upl )) && { echo 1; return; }
  echo 0
}

# ---------------------------------------------------------------------------
# _normalize_distro_id
# /etc/os-release's ID= field is a machine identifier and frequently does NOT
# match the vendor token cve_checks.conf's distro_status/vendor_defer fields
# use (those were written with the vendor's common name). Left unmapped, this
# silently breaks the match — e.g. Amazon Linux 2/2023 report ID="amzn", but
# every vendor_defer/distro_status row in the conf uses "amazon", so the
# comparison at cve_kernel_verdict()'s `[[ "$d" == "$RUN_DISTRO_ID" ]]` never
# succeeds on a real Amazon Linux host (a common EKS node OS). That vendor's
# rows become dead code and the engine silently falls through to the generic
# 'unknown' verdict instead of the more specific "consult ALAS" guidance.
# Same class of mismatch applies to SUSE (ID="sles", conf token "suse").
# Normalize known aliases in ONE place so new distros only need one entry.
# ---------------------------------------------------------------------------
_normalize_distro_id() {
  local id="$1"
  case "$id" in
    amzn)                                         echo "amazon" ;;
    sles|sled|opensuse-leap|opensuse-tumbleweed)   echo "suse" ;;
    ol)                                            echo "oracle" ;;
    mariner)                                        echo "azurelinux" ;;   # legacy CBL-Mariner 1.0/2.0 ID; Azure Linux 3.0+ already reports ID=azurelinux directly (confirmed against a real /etc/os-release: NAME="Microsoft Azure Linux", VERSION="3.0.20240824", ID=azurelinux)
    *)                                             echo "$id" ;;
  esac
}

# --- running-system detection (sets RUN_* globals; run once) ---------------
RUN_DISTRO_ID=""; RUN_DISTRO_REL=""; RUN_KFLAVOUR=""; RUN_KVER_RAW=""; RUN_KPKG_VER=""
# Populated by check_runtime_versions (check 52); consulted by the CVE-database
# 'manual' check_type dispatch so CVE-2019-5736/CVE-2024-21626 don't render a
# static advisory when the host runc version was already established elsewhere
# in the same run. Empty string = not reachable from this context (unknown).
RUNC_DETECTED_VERSION=""; RUNC_DETECTED_PATH=""
RUNC_VERDICT_CVE_2019_5736=""; RUNC_VERDICT_CVE_2024_21626=""
# Secondary distro-id alias for hosts whose OS is legitimately covered by
# TWO vendor tokens in cve_checks.conf at once (e.g. RHCOS reports ID=rhcos,
# but is RHEL-based (ID_LIKE="rhel fedora") AND has its own OpenShift-specific
# advisories). A single RUN_DISTRO_ID string can't match both an
# "openshift|..." row and a "rhel|..." row, so cve_kernel_verdict() also
# checks this alias when the primary ID doesn't match. Empty = no alias.
RUN_DISTRO_ID_ALIAS=""
detect_running_system() {
  RUN_KVER_RAW="$(uname -r 2>/dev/null || echo unknown)"
  local suffix="${RUN_KVER_RAW##*-}"
  if [[ "$suffix" =~ ^[a-z][a-z0-9]*$ && "$suffix" != "$RUN_KVER_RAW" ]]; then
    RUN_KFLAVOUR="$suffix"
  else
    RUN_KFLAVOUR="generic"
  fi
  [[ ! "$RUN_KVER_RAW" =~ - ]] && RUN_KFLAVOUR="vanilla"

  RUN_DISTRO_ID="unknown"; RUN_DISTRO_REL="unknown"; RUN_DISTRO_ID_ALIAS=""
  if [[ -r /etc/os-release ]]; then
    RUN_DISTRO_ID="$(awk -F= '/^ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null)"
    # RHCOS (OpenShift's node OS) is RHEL-based (ID_LIKE="rhel fedora") but also
    # has its own OpenShift-specific vendor advisories in the conf — surface it
    # as "openshift" (so an openshift|... row matches) while keeping "rhel" as
    # a fallback alias (so a plain rhel|... row still matches when no
    # OpenShift-specific row exists for a given CVE).
    if [[ "$RUN_DISTRO_ID" == "rhcos" ]]; then
      RUN_DISTRO_ID="openshift"
      RUN_DISTRO_ID_ALIAS="rhel"
    else
      RUN_DISTRO_ID="$(_normalize_distro_id "$RUN_DISTRO_ID")"
    fi
    RUN_DISTRO_REL="$(awk -F= '/^VERSION_ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null)"
    if [[ "$RUN_DISTRO_ID" == "debian" ]]; then
      local cn; cn="$(awk -F= '/^VERSION_CODENAME=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null)"
      [[ -n "$cn" ]] && RUN_DISTRO_REL="$cn"
    fi
  fi
  RUN_DISTRO_ID="${RUN_DISTRO_ID:-unknown}"; RUN_DISTRO_REL="${RUN_DISTRO_REL:-unknown}"

  # Running kernel PACKAGE version (what distro_status compares against).
  # Debian/Ubuntu: derive from the installed linux-image package; else uname -r.
  RUN_KPKG_VER="$RUN_KVER_RAW"
  if [[ "$RUN_KFLAVOUR" != "vanilla" ]] && command -v dpkg >/dev/null 2>&1; then
    local pkgver
    pkgver=$(dpkg-query -W -f='${Version}' "linux-image-${RUN_KVER_RAW}" 2>/dev/null)
    if [[ -n "$pkgver" ]]; then
      RUN_KPKG_VER="$pkgver"
    else
      # Fall back to reconstructing Ubuntu's UPSTREAM-ABI.UPLOAD from uname -r,
      # e.g. 6.17.0-35-generic -> need the .upload; query the meta if possible.
      # If we cannot get the packaged version, leave uname-derived and let the
      # comparator/verdict degrade to UNKNOWN rather than guess.
      RUN_KPKG_VER="$RUN_KVER_RAW"
    fi
  fi
}

# --- the five-state verdict ------------------------------------------------
# Prints "<verdict>|<evidence>"  verdict ∈ fixed|vulnerable|not-affected|defer|unknown
# --- NVD-range verdict for vanilla kernels ---------------------------------
# upstream_ranges format (from NVD CPE configuration), space-separated tokens:
#   introduced|<version>            global lower bound; below => not-affected
#   range|<from_incl>|<fixed_excl>  affected interval [from_incl, fixed_excl)
# A vanilla running version V is vulnerable iff it lies within any affected
# range; not-affected if below introduced; fixed otherwise. Uses the validated
# upstream comparator. Applied to VANILLA kernels only — never to distro
# packages (whose base version string does not reflect back-ported fixes).
nvd_vanilla_verdict() {
  local V="$1" ranges="$2" introduced="" tok
  for tok in $ranges; do
    local IFS='|'; local -a f=($tok); unset IFS
    [[ "${f[0]}" == "introduced" ]] && introduced="${f[1]}"
  done
  if [[ -n "$introduced" && "$(_ver_cmp_upstream "$V" "$introduced")" == "-1" ]]; then
    echo "not-affected|vanilla ${V} < introduced ${introduced} (NVD range)"; return
  fi
  for tok in $ranges; do
    local IFS='|'; local -a f=($tok); unset IFS
    [[ "${f[0]}" == "range" ]] || continue
    local from="${f[1]}" fixed="${f[2]}"
    if [[ "$(_ver_cmp_upstream "$V" "$from")" != "-1" && "$(_ver_cmp_upstream "$V" "$fixed")" == "-1" ]]; then
      echo "vulnerable|vanilla ${V} in NVD affected range [${from}, ${fixed}) — upstream fix at ${fixed}"; return
    fi
  done
  echo "not-affected|vanilla ${V} outside all NVD affected ranges (patched-or-never-affected under closed-world model)"
}

cve_kernel_verdict() {
  local up="${CVE_FIELD[upstream_fixed]:-}"
  local ur="${CVE_FIELD[upstream_ranges]:-}"
  local ds="${CVE_FIELD[distro_status]:-}"
  local vd="${CVE_FIELD[vendor_defer]:-}"
  local intro="${CVE_FIELD[introduced]:-0}"
  local running_pkg="${RUN_KPKG_VER:-$RUN_KVER_RAW}"

  if [[ -n "$ds" ]]; then
    local tok
    for tok in $ds; do
      local IFS='|'; local -a f=($tok); unset IFS
      local d="${f[0]}" rel="${f[1]}" flavour status version
      case "${f[2]}" in
        fixed|not-affected|vulnerable) flavour=""; status="${f[2]}"; version="${f[3]:-}" ;;
        *) flavour="${f[2]}"; status="${f[3]}"; version="${f[4]:-}" ;;
      esac
      [[ "$d" == "$RUN_DISTRO_ID" || ( -n "$RUN_DISTRO_ID_ALIAS" && "$d" == "$RUN_DISTRO_ID_ALIAS" ) ]] || continue
      [[ "$rel" == "$RUN_DISTRO_REL" ]] || continue
      [[ -n "$flavour" && "$flavour" != "$RUN_KFLAVOUR" ]] && continue
      case "$status" in
        not-affected) echo "not-affected|distro_status: ${d}/${rel}${flavour:+/$flavour} marked not-affected"; return ;;
        vulnerable)   echo "vulnerable|distro_status: ${d}/${rel}${flavour:+/$flavour} marked vulnerable (no fix in this package line)"; return ;;
        fixed)
          [[ -z "$version" ]] && { echo "unknown|${d}/${rel} says fixed but no version recorded"; return; }
          local cmp
          case "$d" in
            ubuntu) cmp=$(_ver_cmp_ubuntu "$running_pkg" "$version") ;;
            *)      cmp=$(_ver_cmp_dpkg "$running_pkg" "$version") ;;
          esac
          if [[ "$cmp" == "-1" ]]; then
            echo "vulnerable|running ${running_pkg} < fixed ${version} on ${d}/${rel}${flavour:+/$flavour}"
          else
            echo "fixed|running ${running_pkg} >= fixed ${version} on ${d}/${rel}${flavour:+/$flavour}"
          fi
          return ;;
      esac
    done
  fi

  if [[ -n "$vd" ]]; then
    local tok
    for tok in $vd; do
      local IFS='|'; local -a f=($tok); unset IFS
      local d="${f[0]}" adv="${f[1]:-vendor advisory}"
      [[ "$d" == "$RUN_DISTRO_ID" || ( -n "$RUN_DISTRO_ID_ALIAS" && "$d" == "$RUN_DISTRO_ID_ALIAS" ) ]] && { echo "defer|${d}: consult ${adv} — backport status not derivable from version string"; return; }
    done
  fi

  if [[ "$RUN_KFLAVOUR" == "vanilla" && -n "$ur" ]]; then
    # NVD per-series ranges are the most authoritative upstream signal; use
    # them in preference to the single-point upstream_fixed list when present.
    nvd_vanilla_verdict "$RUN_KVER_RAW" "$ur"
    return
  fi

  if [[ "$RUN_KFLAVOUR" == "vanilla" && -n "$up" ]]; then
    local run_series="${RUN_KVER_RAW%.*}"; run_series="${run_series%%-*}"
    local tok matched_ver="" mainline_ver=""
    for tok in $up; do
      local s="${tok%%:*}" v="${tok#*:}"
      [[ "$s" == "mainline" ]] && { mainline_ver="$v"; continue; }
      [[ "$s" == "$run_series" ]] && matched_ver="$v"
    done
    if [[ -n "$matched_ver" ]]; then
      local cmp; cmp=$(_ver_cmp_upstream "$RUN_KVER_RAW" "$matched_ver")
      [[ "$cmp" == "-1" ]] && echo "vulnerable|vanilla ${RUN_KVER_RAW} < upstream-stable fix ${matched_ver} (series ${run_series})" \
                           || echo "fixed|vanilla ${RUN_KVER_RAW} >= upstream-stable fix ${matched_ver} (series ${run_series})"
      return
    fi
    if [[ -n "$mainline_ver" ]]; then
      local cmp; cmp=$(_ver_cmp_upstream "$RUN_KVER_RAW" "$mainline_ver")
      [[ "$cmp" == "-1" ]] && echo "vulnerable|vanilla ${RUN_KVER_RAW} < mainline fix ${mainline_ver}, series ${run_series} absent from stable table" \
                           || echo "fixed|vanilla ${RUN_KVER_RAW} >= mainline fix ${mainline_ver}"
      return
    fi
  fi

  if [[ -n "$intro" && "$intro" != "0" && "$RUN_KFLAVOUR" == "vanilla" ]]; then
    local cmp; cmp=$(_ver_cmp_upstream "$RUN_KVER_RAW" "$intro")
    [[ "$cmp" == "-1" ]] && { echo "not-affected|vanilla ${RUN_KVER_RAW} predates introduced ${intro}"; return; }
  fi

  # --- Heuristic fallback (non-distro kernels with no matching data) --------
  # No distro_status row, no vendor_defer row, and (if flavour != vanilla)
  # the vanilla-only NVD/upstream_fixed branches above were skipped entirely.
  # By default we do NOT let this promote the verdict to fixed/not-affected/
  # vulnerable — distro backports can move independently of the upstream
  # x.y.z string within the SAME mainline series, so that comparison alone
  # would risk a confidently WRONG verdict in either direction.
  #
  # ONE exception, below: if the running kernel's base series is a full
  # mainline release series (not just a later point release) past the
  # highest known fix boundary — e.g. running 6.17.x when the fix landed in
  # the 6.16 series — that IS safe to promote to a confident not-affected.
  # kernel.org mainline releases are strictly cumulative: v6.17 is built on
  # top of, and therefore necessarily contains, every fix already in v6.16.
  # Distro packagers build FROM an upstream tag and layer patches on top of
  # it; they do not fork away from upstream history or drop prior mainline
  # fixes when moving to a newer base series. This is categorically
  # different from same-series proximity (e.g. running 6.16.50 vs a fix at
  # 6.16.45 upstream), where distro point-release numbering is independent
  # of upstream stable's and the comparison stays an unpromoted heuristic.
  local heuristic="" promote_verdict="" promote_evidence=""
  local base_ver="${RUN_KVER_RAW%%-*}"
  if [[ -n "$ur" ]]; then
    local hv; hv="$(nvd_vanilla_verdict "$base_ver" "$ur")"
    local hv_verdict="${hv%%|*}"
    heuristic=" Heuristic only (base kernel version vs NVD upstream ranges, NOT distro-backport-aware): ${hv#*|}."
    if [[ "$hv_verdict" == "not-affected" ]]; then
      local tok rest r_hi max_upper=""
      for tok in $ur; do
        case "$tok" in
          range\|*)
            rest="${tok#range|}"; r_hi="${rest#*|}"
            if [[ -z "$max_upper" ]] || [[ "$(_ver_cmp_upstream "$r_hi" "$max_upper")" == "1" ]]; then
              max_upper="$r_hi"
            fi
            ;;
        esac
      done
      if [[ -n "$max_upper" ]]; then
        local run_series fix_series
        run_series="$(cut -d. -f1,2 <<<"$base_ver")"
        fix_series="$(cut -d. -f1,2 <<<"$max_upper")"
        if [[ "$(_ver_cmp_upstream "$run_series" "$fix_series")" == "1" ]]; then
          promote_verdict="not-affected"
          promote_evidence="running series ${run_series} is a full mainline release series past the highest fix boundary (${max_upper}, series ${fix_series}) for this CVE — kernel.org mainline releases are strictly cumulative, so ${run_series} necessarily contains this fix regardless of distro packaging (this differs from same-series version-number proximity, which stays heuristic-only and unpromoted)"
        fi
      fi
    fi
  elif [[ -n "$up" ]]; then
    local run_series="${base_ver%.*}"
    local tok matched_ver="" mainline_ver=""
    for tok in $up; do
      local s="${tok%%:*}" v="${tok#*:}"
      [[ "$s" == "mainline" ]] && { mainline_ver="$v"; continue; }
      [[ "$s" == "$run_series" ]] && matched_ver="$v"
    done
    local ref_ver="${matched_ver:-$mainline_ver}"
    if [[ -n "$ref_ver" ]]; then
      local cmp; cmp=$(_ver_cmp_upstream "$base_ver" "$ref_ver")
      if [[ "$cmp" == "-1" ]]; then
        heuristic=" Heuristic only (base kernel version vs upstream-stable fix, NOT distro-backport-aware): ${base_ver} < ${ref_ver}, i.e. base version looks pre-fix."
      else
        heuristic=" Heuristic only (base kernel version vs upstream-stable fix, NOT distro-backport-aware): ${base_ver} >= ${ref_ver}, i.e. base version looks post-fix."
        # Same full-series-past-the-fix promotion as the upstream_ranges path above.
        if [[ -n "$mainline_ver" ]]; then
          local run_series2 fix_series2
          run_series2="$(cut -d. -f1,2 <<<"$base_ver")"
          fix_series2="$(cut -d. -f1,2 <<<"$mainline_ver")"
          if [[ "$(_ver_cmp_upstream "$run_series2" "$fix_series2")" == "1" ]]; then
            promote_verdict="not-affected"
            promote_evidence="running series ${run_series2} is a full mainline release series past the fix's mainline series (${mainline_ver}, series ${fix_series2}) — kernel.org mainline releases are strictly cumulative, so ${run_series2} necessarily contains this fix regardless of distro packaging"
          fi
        fi
      fi
    fi
  fi
  if [[ -n "$promote_verdict" ]]; then
    echo "${promote_verdict}|${RUN_DISTRO_ID}/${RUN_DISTRO_REL} flavour=${RUN_KFLAVOUR} (running ${RUN_KVER_RAW}) has no distro-specific tracking data, but ${promote_evidence} — treated as ${promote_verdict} on that basis rather than left unknown. If this distro backports fixes highly unusually (e.g. deliberately reverting an upstream commit), that would be exceptional and should be independently verified; this is not blanket confirmation of every CVE at once, only this one."
  else
    echo "unknown|no matching fixed-version data for ${RUN_DISTRO_ID}/${RUN_DISTRO_REL} flavour=${RUN_KFLAVOUR} (running ${RUN_KVER_RAW}); cannot assert patched — verify against vendor tracker.${heuristic} Distributions routinely backport fixes without changing the upstream version string, so this heuristic can be wrong in either direction — it is supporting context only, never a substitute for the vendor advisory."
  fi
}

# ---------------------------------------------------------------------------
# _kernel_in_affected_range
# Returns 0 (true) if the running kernel is in the affected range for a CVE.
# Returns 1 (false) if the kernel is at or above a known fixed version for
# its series, or below the introduced version.
#
# Logic:
#   1. Extract major.minor series from uname -r.
#   2. Look for a fixed_versions entry matching that series.
#      If found, compare running version against it.
#   3. If no series match, fall back to comparing against all fixed_versions
#      and flag as affected if the running version is >= introduced AND no
#      fixed version for any series is <= running version.
# ---------------------------------------------------------------------------
_kernel_in_affected_range() {
  # --- Preferred path: enriched schema (upstream_fixed/distro_status/vendor_defer)
  # When any enriched field is present, use the accurate distro/flavour-aware
  # verdict engine. Map its five states onto this function's affected/not
  # contract, recording precise evidence. Absent/unknown => treat as affected
  # (conservative) but labelled UNKNOWN so severity synthesis can reflect it.
  if [[ -n "${CVE_FIELD[upstream_fixed]:-}" || -n "${CVE_FIELD[distro_status]:-}" || -n "${CVE_FIELD[vendor_defer]:-}" ]]; then
    local vres verdict eviden
    vres="$(cve_kernel_verdict)"
    verdict="${vres%%|*}"; eviden="${vres#*|}"
    case "$verdict" in
      fixed)
        _ev PASS "Version verdict (enriched)" "$eviden"
        KVER_VERDICT="fixed"; return 1 ;;
      not-affected)
        _ev PASS "Version verdict (enriched)" "$eviden"
        KVER_VERDICT="not-affected"; return 1 ;;
      vulnerable)
        _ev FLAG "Version verdict (enriched)" "$eviden"
        KVER_VERDICT="vulnerable"; return 0 ;;
      defer)
        _ev INFO "Version verdict (enriched)" "$eviden"
        KVER_VERDICT="defer"; return 0 ;;   # can't clear -> treat as affected, but INFO evidence
      unknown|*)
        _ev INFO "Version verdict (enriched)" "$eviden"
        KVER_VERDICT="unknown"; return 0 ;;  # never a silent pass
    esac
  fi

  # --- Legacy fallback: flat fixed_versions= (transitional, pre-migration) ---
  local introduced="${CVE_FIELD[introduced]:-0}"
  local fixed_str="${CVE_FIELD[fixed_versions]:-none}"
  local kver
  kver=$(uname -r 2>/dev/null || echo "0.0.0")

  # Extract clean version number from uname output
  local kver_clean
  kver_clean=$(echo "$kver" | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "0.0.0")

  local kver_int
  kver_int=$(_kver_to_int "$kver_clean")

  # Check introduced — if kernel is below the introduced version, not affected
  if [[ "$introduced" != "0" ]]; then
    local intro_int
    intro_int=$(_kver_to_int "$introduced")
    if (( kver_int < intro_int )); then
      _ev PASS "Introduced-version gate" \
        "running ${kver_clean} (int ${kver_int}) < introduced ${introduced} (int ${intro_int}) — predates the bug, not affected"
      return 1  # Below introduced version — not affected
    fi
    _ev INFO "Introduced-version gate" \
      "running ${kver_clean} (int ${kver_int}) >= introduced ${introduced} (int ${intro_int}) — at/after the version that introduced the bug"
  else
    _ev INFO "Introduced-version gate" "no introduced version recorded (introduced=0) — gate skipped"
  fi

  # Parse fixed_versions: "series:version series:version ..."
  # Sentinels / malformed values that carry no confirmed fixed version must
  # flag conservatively (assume affected) rather than fall through to the
  # version math below, where a non-numeric token would be coerced to 0 by
  # _kver_to_int and wrongly clear the host. Handles:
  #   none   — no patch available yet
  #   VERIFY — fixed version not yet confirmed against the distro tracker
  #   any value without a "series:version" pair (no ':') — malformed/sentinel
  if [[ "$fixed_str" == "none" || "$fixed_str" == "VERIFY" ]]; then
    _ev FLAG "Fixed-version comparison" \
      "fixed_versions='${fixed_str}' — no confirmed fix to compare against; flagged conservatively as affected"
    return 0
  fi
  if [[ "$fixed_str" != *:* ]]; then
    _ev FLAG "Fixed-version comparison" \
      "fixed_versions='${fixed_str}' carries no usable series:version pair — treated as unconfirmed; flagged conservatively as affected"
    return 0  # no usable series:version — assume affected
  fi

  local kmaj kmin
  IFS='.' read -r kmaj kmin _ <<< "$kver_clean"
  local series="${kmaj}.${kmin}"

  local found_series=false
  local series_fixed_int=0
  local series_fixed_ver=""

  for entry in $fixed_str; do
    local s v
    IFS=':' read -r s v <<< "$entry"
    if [[ "$s" == "$series" ]]; then
      found_series=true
      series_fixed_ver="$v"
      series_fixed_int=$(_kver_to_int "$v")
      break
    fi
  done

  if [[ "$found_series" == true ]]; then
    # We know the fixed version for this series
    if (( kver_int >= series_fixed_int )); then
      _ev PASS "Fixed-version comparison" \
        "series ${series} fixed at ${series_fixed_ver} (int ${series_fixed_int}); running ${kver_clean} (int ${kver_int}) >= fixed — patched in this series"
      return 1  # Kernel is at or above the fix — not affected
    else
      _ev FLAG "Fixed-version comparison" \
        "series ${series} fixed at ${series_fixed_ver} (int ${series_fixed_int}); running ${kver_clean} (int ${kver_int}) < fixed — pre-fix, affected"
      return 0  # Kernel is below the fix — affected
    fi
  else
    # Series not in the fixed_versions list
    # This means either: (a) this series was never affected, or
    # (b) no backport exists yet (conservative: treat as affected)
    # Heuristic: if the running series is NEWER than the highest fixed series,
    # it is likely patched in mainline. If it is OLDER, it may be unpatched.
    local max_fixed_int=0
    local max_fixed_series_int=0
    local max_fixed_series_str=""
    for entry in $fixed_str; do
      local s v
      IFS=':' read -r s v <<< "$entry"
      local s_int
      s_int=$(_kver_to_int "${s}.0")
      if (( s_int > max_fixed_series_int )); then
        max_fixed_series_int=$s_int
        max_fixed_series_str="$s"
        max_fixed_int=$(_kver_to_int "$v")
      fi
    done

    local series_int
    series_int=$(_kver_to_int "${series}.0")

    # If running series is newer than the highest fixed series in the list,
    # assume the fix was merged into mainline and this series has it.
    if (( series_int > max_fixed_series_int )); then
      _ev PASS "Fixed-version comparison" \
        "series ${series} not listed in fixed_versions (${fixed_str}); newer than highest fixed series ${max_fixed_series_str} — fix presumed in mainline, not affected"
      return 1  # Likely patched in this newer series
    fi

    # Running series is older than or equal to the highest fixed series
    # and is not explicitly listed — flag as affected (conservative)
    _ev FLAG "Fixed-version comparison" \
      "series ${series} not listed in fixed_versions (${fixed_str}) and not newer than highest fixed series ${max_fixed_series_str} — cannot confirm a backport; flagged conservatively as affected"
    return 0
  fi
}

# ---------------------------------------------------------------------------
# _check_module_loaded
# Returns 0 if any of the CVE's module_names are loaded in /proc/modules.
# Outputs the list of loaded modules to stdout.
# ---------------------------------------------------------------------------
_check_module_loaded() {
  local mod_str="${CVE_FIELD[module_names]:-none}"
  [[ "$mod_str" == "none" ]] && return 1

  local loaded=()
  local notloaded=()
  for mod in $mod_str; do
    if grep -q "^${mod} " /proc/modules 2>/dev/null; then
      loaded+=("$mod")
    else
      notloaded+=("$mod")
    fi
  done

  if [[ ${#loaded[@]} -gt 0 ]]; then
    _ev FLAG "Module loaded (/proc/modules)" \
      "LOADED: ${loaded[*]}${notloaded:+; not loaded: ${notloaded[*]}}"
    _MOD_LOADED_RESULT="${loaded[*]}"
    echo "${loaded[*]}"
    return 0
  fi
  _ev PASS "Module loaded (/proc/modules)" \
    "none of [${mod_str}] present in /proc/modules"
  _MOD_LOADED_RESULT=""
  return 1
}

# ---------------------------------------------------------------------------
# _check_module_blacklisted
# Returns 0 if all module_names are blacklisted in /etc/modprobe.d/*.
# Outputs "yes" or a list of non-blacklisted modules.
# ---------------------------------------------------------------------------
_check_module_blacklisted() {
  local mod_str="${CVE_FIELD[module_names]:-none}"
  [[ "$mod_str" == "none" ]] && echo "yes" && return 0

  local not_blacklisted=()
  local blacklisted=()
  for mod in $mod_str; do
    local found=false
    for f in /etc/modprobe.d/*.conf /etc/modprobe.conf; do
      [[ -r "$f" ]] || continue
      if grep -q "install ${mod} /bin/false" "$f" 2>/dev/null; then
        found=true
        break
      fi
    done
    if [[ "$found" == false ]]; then
      not_blacklisted+=("$mod")
    else
      blacklisted+=("$mod")
    fi
  done

  if [[ ${#not_blacklisted[@]} -gt 0 ]]; then
    _ev FLAG "Module blacklist (/etc/modprobe.d)" \
      "NOT blacklisted: ${not_blacklisted[*]}${blacklisted:+; blacklisted: ${blacklisted[*]}} — auto-load on use remains possible"
    _MOD_NOT_BLACKLISTED_RESULT="${not_blacklisted[*]}"
    echo "${not_blacklisted[*]}"
    return 1
  fi
  _ev PASS "Module blacklist (/etc/modprobe.d)" \
    "all of [${mod_str}] blacklisted via 'install ... /bin/false'"
  _MOD_NOT_BLACKLISTED_RESULT=""
  echo "yes"
  return 0
}

# ---------------------------------------------------------------------------
# _check_socket_accessible
# Tries to open socket(AF, SOCK_TYPE, PROTO) in Python3.
# Returns 0 if the socket family is reachable; 1 if blocked/absent.
# ---------------------------------------------------------------------------
_check_socket_accessible() {
  local af="${CVE_FIELD[socket_af]:-none}"
  local st="${CVE_FIELD[socket_type]:-none}"
  local sp="${CVE_FIELD[socket_proto]:-0}"

  [[ "$af" == "none" ]] && return 1
  if ! command -v python3 &>/dev/null; then
    _ev SKIP "Socket reachability" "python3 not available — AF=${af} SOCK=${st} could not be probed"
    return 2  # Can't test without python3
  fi

  local sock_detail
  sock_detail=$(python3 -c "
import socket, sys
af=$af; st=$st; sp=$sp
try:
    s = socket.socket(af, st, sp)
    s.close()
    print('opened cleanly (AF reachable)')
    sys.exit(0)
except Exception as e:
    import errno as E
    err = getattr(e, 'errno', None)
    name = E.errorcode.get(err, 'UNKNOWN') if err is not None else 'NONE'
    # EPERM(1) or EACCES(13): socket family reachable but permission denied
    # EINVAL(22): socket reachable but invalid params
    # EPROTONOSUPPORT(93): AF known but proto not supported — AF reachable
    # EAFNOSUPPORT(97): AF completely absent/blocked
    # ENOSYS(38): syscall blocked by seccomp
    if err in (1, 13, 22, 93):
        print('errno %s (%s) — AF reachable' % (err, name))
        sys.exit(0)  # Reachable
    print('errno %s (%s) — AF not reachable' % (err, name))
    sys.exit(1)      # Not reachable
" 2>/dev/null)
  local rc=$?

  if [[ $rc -eq 0 ]]; then
    _ev FLAG "Socket reachability" "AF=${af} SOCK=${st} PROTO=${sp}: ${sock_detail:-reachable}"
  else
    _ev PASS "Socket reachability" "AF=${af} SOCK=${st} PROTO=${sp}: ${sock_detail:-blocked/absent}"
  fi
  return $rc
}

# ---------------------------------------------------------------------------
# _check_kernel_symbol
# Returns 0 if the symbol is present and not zeroed in /proc/kallsyms.
# ---------------------------------------------------------------------------
_check_kernel_symbol() {
  local sym="${CVE_FIELD[kallsyms_sym]:-}"
  [[ -z "$sym" ]] && return 1
  if [[ ! -r /proc/kallsyms ]]; then
    _ev SKIP "Kernel symbol (/proc/kallsyms)" "/proc/kallsyms not readable — symbol '${sym}' could not be checked"
    return 2
  fi
  # Zeroed addresses (00000000) indicate kptr_restrict is hiding them
  if grep -q "^[^0].*\b${sym}\b" /proc/kallsyms 2>/dev/null; then
    _ev FLAG "Kernel symbol (/proc/kallsyms)" "symbol '${sym}' present with a non-zero address — code path exposed"
    return 0
  fi
  _ev PASS "Kernel symbol (/proc/kallsyms)" "symbol '${sym}' not visible (absent or zeroed by kptr_restrict)"
  return 1
}

# ---------------------------------------------------------------------------
# _emit_cve_finding
# Wraps add_finding for a CVE entry with standard fields from CVE_FIELD.
# Extra context (e.g. "kernel in range, module loaded") is prepended to what.
# ---------------------------------------------------------------------------
_emit_cve_finding() {
  local extra_context="$1"
  local override_sev="${2:-}"
  local sev="${override_sev:-${CVE_FIELD[severity]:-HIGH}}"
  local cve="${CVE_FIELD[cve_id]}"
  local name="${CVE_FIELD[name]:-$cve}"
  local cvss="${CVE_FIELD[cvss]:-unknown}"
  local itw="${CVE_FIELD[itw]:-no}"
  local poc="${CVE_FIELD[poc_public]:-no}"
  local kev="${CVE_FIELD[cisa_kev]:-no}"

  local id_safe
  id_safe="${cve//-/_}"
  id_safe="${id_safe,,}"
  local sub_slug="${CVE_FIELD[subsystem]:-}"
  sub_slug=$(echo "$sub_slug" | tr "/. " "___")
  [[ -n "$sub_slug" ]] && id_safe="${id_safe}_${sub_slug}"

  local title="${name} (${cve}) — ${sev}"
  [[ "$itw" == "yes" ]] && title="${title} [ITW]"
  [[ "$kev" == "yes" ]] && title="${title} [CISA-KEV]"

  local kver
  kver=$(uname -r 2>/dev/null || echo "unknown")

  local what_prefix="CVE: ${cve}. Name: ${name}. CVSS: ${cvss}. Kernel: ${kver}. "
  [[ -n "$extra_context" ]] && what_prefix+="Detection context: ${extra_context}. "
  what_prefix+="ITW: ${itw}. Public PoC: ${poc}. CISA KEV: ${kev}. "
  what_prefix+="Subsystem: ${CVE_FIELD[subsystem]:-unknown}. Modules: ${CVE_FIELD[module_names]:-none}. "

  local full_what="${what_prefix}${CVE_FIELD[what]:-No description available.}"

  # Build the recommendation: full remediation (rec) plus the interim/compensating
  # control (mitigation), so every CVE finding consistently surfaces a mitigating
  # factor. If mitigation is absent or "none", say so explicitly rather than
  # silently omitting it — an operator should never be left wondering whether an
  # interim control exists.
  local rec_text="${CVE_FIELD[rec]:-No remediation guidance available.}"
  local mit_raw="${CVE_FIELD[mitigation]:-}"
  local mit_text
  case "${mit_raw,,}" in
    ""|"none"|"n/a"|"no"|"-")
      mit_text="Interim mitigation: none available — patching/upgrading is the only remediation." ;;
    *)
      mit_text="Interim mitigation (compensating control until patched): ${mit_raw}" ;;
  esac

  # Patch-status note. The fixed_versions field may carry a confirmed list of
  # "series:version" pairs, or a sentinel meaning the fixed version is not yet
  # established. In the sentinel cases the engine flags conservatively (assume
  # affected), so the operator MUST be told the "patched" boundary is unknown —
  # otherwise a VERIFY/none finding looks identical to one checked against a
  # real fixed version, and they cannot tell whether their kernel is genuinely
  # pre-fix or simply unverified. Keep this in _emit_cve_finding so it applies
  # to every check type that produces a finding, not just kernel_version.
  local fixed_raw="${CVE_FIELD[fixed_versions]:-none}"
  local patch_note=""
  case "$fixed_raw" in
    none)
      patch_note="Patch status: no fixed kernel version is recorded for this CVE (fixed_versions=none) — at disclosure no upstream fix was available, or this is a userspace/runtime CVE tracked separately. This finding cannot confirm a patched kernel; verify against your distribution's security advisory." ;;
    VERIFY|verify)
      patch_note="Patch status: the fixed kernel version is NOT yet confirmed in the CVE database (fixed_versions=VERIFY). This host is flagged conservatively as potentially affected; the engine cannot determine whether your kernel is patched. Confirm the fixed package version against your distribution's security tracker before treating this as resolved." ;;
    *:*)
      patch_note="Patch status: comparison was made against recorded fixed versions (${fixed_raw}). Distributions often backport fixes without changing the upstream version string, so confirm against your distribution's security advisory." ;;
    *)
      patch_note="Patch status: fixed_versions value '${fixed_raw}' is not a recognised series:version list; treated as unconfirmed and flagged conservatively. Confirm the fixed version against your distribution's security tracker." ;;
  esac

  add_finding "cve_${id_safe}" "$sev" "$title" \
    "$full_what" \
    "${CVE_FIELD[impact]:-No impact description available.}" \
    "${CVE_FIELD[exploit]:-No exploitability assessment available.}" \
    "${rec_text} ${mit_text} ${patch_note}" \
    "$(_ev_pack)"
}

# ---------------------------------------------------------------------------
# _run_single_cve_check
# Dispatches the check for the current CVE_FIELD according to check_type.
# Generates findings and terminal output.
# ---------------------------------------------------------------------------
_run_single_cve_check() {
  local cve="${CVE_FIELD[cve_id]:-UNKNOWN}"
  local name="${CVE_FIELD[name]:-$cve}"
  local check_type="${CVE_FIELD[check_type]:-kernel_version}"

  # Fresh evidence trail for this CVE
  _ev_reset

  # --- Config completeness check -------------------------------------------
  # Every CVE entry must carry both a remediation (rec) and a mitigating-factor
  # (mitigation) field so that findings always present a fix AND an interim
  # control. Warn (once per entry) if either is absent, so gaps surface at run
  # time rather than silently degrading to a generic fallback. 'mitigation=none'
  # is valid (means no compensating control exists) — only a missing field warns.
  if [[ -z "${CVE_FIELD[rec]+x}" ]]; then
    info "${cve} (${name}): config entry has no 'rec' (remediation) field — finding will use a generic fallback"
  fi
  if [[ -z "${CVE_FIELD[mitigation]+x}" ]]; then
    info "${cve} (${name}): config entry has no 'mitigation' field — add one (use 'mitigation=none' if no interim control exists)"
  fi
  # Lint: an embedded 'printf' invocation whose format-string argument isn't
  # quoted will have its \n escapes stripped and word-split by the shell
  # BEFORE printf ever sees them, silently truncating multi-line modprobe
  # blacklist commands to a single word (e.g. just "install") when copied
  # from the report and run. Only a quote character immediately after
  # 'printf ' protects against this. Flag any field where that's missing so
  # a broken copy-paste command surfaces at load time, not when a user runs it.
  for _lint_field in rec mitigation; do
    local _lint_val="${CVE_FIELD[$_lint_field]:-}"
    if [[ "$_lint_val" == *"printf "* && ! "$_lint_val" =~ printf[[:space:]]+[\'\"] ]]; then
      info "${cve} (${name}): '${_lint_field}' field contains an unquoted 'printf' invocation — its format-string argument must be wrapped in quotes (e.g. printf 'install foo /bin/false\\n...') or the shell will strip/word-split the \\n escapes before printf sees them, silently truncating the command. Verify before publishing."
    fi
  done
  # Build a unique, stable finding ID for this CVE (subsystem slug prevents
  # collisions when two entries share a CVE number, e.g. CVE-2025-38352)
  local _sub_slug
  _sub_slug=$(echo "${CVE_FIELD[subsystem]:-}" | tr "/. " "___")
  local _cve_id_slug="${cve//-/_}"
  _cve_id_slug="${_cve_id_slug,,}"
  [[ -n "$_sub_slug" ]] && _cve_id_slug="${_cve_id_slug}_${_sub_slug}"
  local kver
  kver=$(uname -r 2>/dev/null || echo "unknown")

  # --- Architecture gate ----------------------------------------------------
  # Some CVEs only affect a specific CPU architecture (e.g. CVE-2026-46316
  # ITScape is arm64-only). If the entry declares arch= and it does not match
  # the running machine, the kernel-version/module/socket tests would otherwise
  # produce a false positive purely on version. Short-circuit to an INFO finding
  # so the CVE still appears in inventory but is correctly marked N/A here.
  local _entry_arch="${CVE_FIELD[arch]:-any}"
  if [[ "$_entry_arch" != "any" && "$_entry_arch" != "all" && -n "$_entry_arch" ]]; then
    local _mach _arch_norm _entry_norm
    _mach=$(uname -m 2>/dev/null || echo "unknown")
    # Normalise common aliases to a canonical token
    case "$_mach" in
      aarch64|arm64)            _arch_norm="arm64" ;;
      x86_64|amd64)             _arch_norm="x86_64" ;;
      i386|i486|i586|i686)      _arch_norm="x86" ;;
      *)                        _arch_norm="$_mach" ;;
    esac
    case "$_entry_arch" in
      aarch64|arm64)            _entry_norm="arm64" ;;
      x86_64|amd64)             _entry_norm="x86_64" ;;
      i386|i486|i586|i686|x86)  _entry_norm="x86" ;;
      *)                        _entry_norm="$_entry_arch" ;;
    esac
    if [[ "$_arch_norm" != "$_entry_norm" ]]; then
      _ev SKIP "Architecture gate" \
        "CVE requires ${_entry_arch} (normalised ${_entry_norm}); host is ${_mach} (normalised ${_arch_norm}) — not applicable, version/module tests skipped"
      ok "${cve} (${name}): not applicable on this architecture (requires ${_entry_arch}; running ${_mach})"
      _ev_print_stdout
      add_finding "cve_${_cve_id_slug}" "INFO" \
        "${name} (${cve}) — not applicable on ${_mach} (requires ${_entry_arch})" \
        "CVE: ${cve}. This vulnerability affects the ${_entry_arch} architecture only. The host reports ${_mach} (uname -m), so the kernel-version/module/socket test is not applicable and was skipped to avoid a false positive on kernel version alone." \
        "N/A — wrong architecture." "N/A" \
        "No action required on this architecture. If you also operate ${_entry_arch} hosts, run the audit there and apply the vendor patch: ${CVE_FIELD[rec]:-see advisory}." \
        "$(_ev_pack)"
      return
    fi
    _ev INFO "Architecture gate" \
      "CVE requires ${_entry_arch} (normalised ${_entry_norm}); host ${_mach} (normalised ${_arch_norm}) matches — proceeding"
  fi

  case "$check_type" in

    # -----------------------------------------------------------------------
    kernel_version)
      KVER_VERDICT=""
      if _kernel_in_affected_range; then
        # Affected-or-inconclusive. Distinguish confirmed-vulnerable from
        # defer/unknown so we don't overstate confidence either way.
        case "$KVER_VERDICT" in
          defer)
            warn "${cve} (${name}): running on a vendor-tracked distro — version string cannot confirm patch status; consult the vendor advisory"
            _ev_print_stdout
            add_finding "cve_${_cve_id_slug}" "MEDIUM" \
              "${name} (${cve}) — patch status must be confirmed via vendor advisory" \
              "CVE: ${cve}. The running distribution backports fixes, so the kernel version string alone cannot determine whether this CVE is patched. Distro=${RUN_DISTRO_ID}/${RUN_DISTRO_REL}, kernel=${RUN_KVER_RAW}." \
              "Undetermined from version alone — do not assume patched. Verify against the vendor security advisory for this CVE." "N/A" \
              "Check your distribution's advisory for ${cve} and confirm the installed kernel package meets or exceeds the fixed build." \
              "$(_ev_pack)"
            ;;
          unknown)
            warn "${cve} (${name}): no fixed-version data matched this system — patch status UNKNOWN (not assumed safe)"
            _ev_print_stdout
            add_finding "cve_${_cve_id_slug}" "MEDIUM" \
              "${name} (${cve}) — patch status unknown for this system" \
              "CVE: ${cve}. No fixed-version data in the database matched distro=${RUN_DISTRO_ID}/${RUN_DISTRO_REL} flavour=${RUN_KFLAVOUR} (kernel ${RUN_KVER_RAW}), so patch status cannot be asserted." \
              "Undetermined — treated as potentially affected rather than silently passed. Verify against the vendor tracker." "N/A" \
              "Confirm exposure to ${cve} using your distribution's security tracker and the installed kernel package version." \
              "$(_ev_pack)"
            ;;
          *)
            local _fx="${CVE_FIELD[fixed_versions]:-none}"
            local _fx_tag=""
            case "$_fx" in
              VERIFY|verify) _fx_tag=" [fixed version UNCONFIRMED — flagged conservatively]" ;;
              none)          [[ -z "${CVE_FIELD[distro_status]:-}${CVE_FIELD[upstream_fixed]:-}" ]] && _fx_tag=" [no fixed version recorded]" ;;
            esac
            warn "${cve} (${name}): kernel ${kver} appears in the affected version range${_fx_tag}"
            _ev_print_stdout
            _emit_cve_finding "kernel ${kver} in affected range (verdict: ${KVER_VERDICT:-affected}; introduced: ${CVE_FIELD[introduced]:-unknown})"
            ;;
        esac
      else
        # Not affected — either confirmed fixed or genuinely not-affected.
        ok "${cve} (${name}): kernel ${kver} appears outside affected range (${KVER_VERDICT:-patched})"
        _ev_print_stdout
        add_finding "cve_${_cve_id_slug}" "INFO" \
          "${name} (${cve}) — kernel ${kver} appears patched (${KVER_VERDICT:-patched})" \
          "CVE: ${cve}. Verdict: ${KVER_VERDICT:-patched}. Distro=${RUN_DISTRO_ID}/${RUN_DISTRO_REL} flavour=${RUN_KFLAVOUR}, kernel ${RUN_KVER_RAW}." \
          "N/A — kernel version check passed." "N/A" \
          "Continue to apply kernel updates. Verify with your distribution's security advisory." \
          "$(_ev_pack)"
      fi
      ;;

    # -----------------------------------------------------------------------
    module_loaded)
      local loaded_mods
      loaded_mods=$(_check_module_loaded)
      if [[ $? -eq 0 ]]; then
        warn "${cve} (${name}): vulnerable module(s) loaded: ${loaded_mods}"
        _ev_print_stdout
        _emit_cve_finding "module(s) loaded: ${loaded_mods}"
      else
        ok "${cve} (${name}): no vulnerable modules loaded (${CVE_FIELD[module_names]:-none})"
        _ev_print_stdout
        add_finding "cve_${_cve_id_slug}" "INFO" \
          "${name} (${cve}) — no vulnerable modules loaded" \
          "CVE: ${cve}. Module(s) ${CVE_FIELD[module_names]:-none} are not currently loaded in /proc/modules. Note: without a blacklist entry, auto-loading on socket creation remains possible." \
          "N/A — modules not loaded." "N/A" \
          "Add a modprobe blacklist entry even when modules are not loaded: ${CVE_FIELD[mitigation]:-see vendor advisory}." \
          "$(_ev_pack)"
      fi
      ;;

    # -----------------------------------------------------------------------
    socket_family)
      local sock_result
      _check_socket_accessible
      sock_result=$?
      if [[ $sock_result -eq 0 ]]; then
        warn "${cve} (${name}): socket family AF=${CVE_FIELD[socket_af]} is accessible"
        _ev_print_stdout
        _emit_cve_finding "socket AF=${CVE_FIELD[socket_af]} SOCK=${CVE_FIELD[socket_type]} accessible from container"
      elif [[ $sock_result -eq 2 ]]; then
        info "${cve} (${name}): socket check skipped (python3 not available)"
        _ev_print_stdout
      else
        ok "${cve} (${name}): socket AF=${CVE_FIELD[socket_af]} not accessible"
        _ev_print_stdout
      fi
      ;;

    # -----------------------------------------------------------------------
    kernel_symbol)
      local sym_result
      _check_kernel_symbol
      sym_result=$?
      if [[ $sym_result -eq 0 ]]; then
        warn "${cve} (${name}): kernel symbol '${CVE_FIELD[kallsyms_sym]}' visible in /proc/kallsyms"
        _ev_print_stdout
        _emit_cve_finding "kernel symbol ${CVE_FIELD[kallsyms_sym]} present in /proc/kallsyms"
      elif [[ $sym_result -eq 2 ]]; then
        info "${cve} (${name}): /proc/kallsyms not readable — symbol check skipped"
        _ev_print_stdout
      else
        ok "${cve} (${name}): symbol '${CVE_FIELD[kallsyms_sym]}' not visible (kptr_restrict may be active)"
        _ev_print_stdout
      fi
      ;;

    # -----------------------------------------------------------------------
    compound)
      # Run kernel version, module, AND socket checks and synthesise severity.
      local kver_affected=false
      local mod_loaded_list=""
      local mod_not_blacklisted=""
      local socket_accessible=false
      local overall_sev="INFO"

      # 1 — kernel version
      _kernel_in_affected_range && kver_affected=true

      # 2 — module check
      # NB: call the helpers directly (not via $(...)) so the evidence they
      # append to CVE_EVIDENCE is not lost in a subshell. Their textual result
      # is published via the _MOD_*_RESULT globals.
      if [[ "${CVE_FIELD[module_names]:-none}" != "none" ]]; then
        _MOD_LOADED_RESULT=""
        _check_module_loaded >/dev/null
        mod_loaded_list="$_MOD_LOADED_RESULT"
        _MOD_NOT_BLACKLISTED_RESULT=""
        _check_module_blacklisted >/dev/null
        mod_not_blacklisted="$_MOD_NOT_BLACKLISTED_RESULT"
      fi

      # 3 — socket check
      if [[ "${CVE_FIELD[socket_af]:-none}" != "none" ]]; then
        _check_socket_accessible && socket_accessible=true
      fi

      # Whether a module gate even applies to this CVE (module_names != none),
      # and whether that gate is fully closed (module not currently loaded AND
      # confirmed blacklisted in /etc/modprobe.d).
      local mod_check_applicable=false
      [[ "${CVE_FIELD[module_names]:-none}" != "none" ]] && mod_check_applicable=true
      local mod_fully_blacklisted=false
      [[ "$mod_check_applicable" == true && -z "$mod_loaded_list" && -z "$mod_not_blacklisted" ]] && mod_fully_blacklisted=true

      # Severity logic:
      #   CRITICAL: kernel affected AND module currently loaded (blacklist is
      #             moot once it's already loaded)
      #   CRITICAL: kernel affected AND socket accessible AND (no module gate
      #             exists for this CVE, OR the module is confirmed NOT
      #             blacklisted — i.e. nothing stands between reachability and
      #             the vulnerable code)
      #   HIGH:     kernel affected AND socket accessible AND the module IS
      #             fully blacklisted. NOT downgraded to MEDIUM: the socket
      #             check only proves the socket *family* is reachable
      #             (e.g. AF_ALG core), not that the specific vulnerable
      #             transform/module can be loaded — a blacklist entry should
      #             block that at request_module() time, but this check
      #             cannot independently confirm the blacklist covers the
      #             exact code path exercised at bind()/use time, so the
      #             blacklist is treated as a real but UNVERIFIED-at-this-
      #             precision mitigation rather than a full clear.
      #   HIGH:     kernel affected AND module not loaded but NOT blacklisted
      #             (auto-load on use remains possible), regardless of socket
      #   MEDIUM:   kernel affected, no socket/module signal indicates active
      #             exposure (module fully blacklisted and socket not
      #             accessible/not applicable), or inconclusive
      #   INFO:     kernel not in affected range
      #
      # NOTE: "CRITICAL"/"HIGH" above are this branch's DEFAULT ceiling, not a
      # fixed value — overall_sev is taken from CVE_FIELD[severity] where the
      # conf specifies one lower (e.g. HIGH), so the printed [CRIT]/[WARN] tag
      # MUST be chosen from $overall_sev via _log_severity_tag, never
      # hardcoded to crit()/warn() directly — a hardcoded call here
      # previously caused the console tag to read [CRIT] while the actual
      # finding severity (and the "Severity synthesis" evidence line right
      # above it) correctly said HIGH.
      #
      # _log_severity_tag additionally renders [MITIGATED] instead of the
      # plain severity word — in the downgraded severity's own colour, not
      # a separate "mitigated" colour — when a branch explicitly marks
      # itself as a genuine detected control (module blacklisted), so the
      # operator can see at a glance that HIGH/MEDIUM here means "actively
      # downgraded by something we found" rather than "this CVE is
      # inherently HIGH" or "we simply have no better signal." The
      # mitigated flag is passed EXPLICITLY per branch rather than inferred
      # from "overall_sev < ceiling" — the auto-load-risk branch below also
      # computes a value below the CVE's ceiling, but found NO mitigating
      # control at all (module simply isn't loaded yet), so labelling that
      # one MITIGATED would be actively wrong/dangerous. The structured
      # finding severity passed to _emit_cve_finding is intentionally left
      # as the plain CRITICAL/HIGH/MEDIUM value in all cases — MITIGATED is
      # a console-display label only, so JSON output, --fail-on thresholds,
      # and severity aggregation elsewhere in the script are unaffected.
      _log_severity_tag() {
        local sev="$1" mitigated="$2"; shift 2
        local label="$sev"
        [[ "$mitigated" == true ]] && label="MITIGATED"
        case "$sev" in
          CRITICAL) [[ "$OUTPUT_JSON" == false ]] && echo -e "${RED}[${label}]${RESET}  $*" ;;
          HIGH|MEDIUM) [[ "$OUTPUT_JSON" == false ]] && echo -e "${YELLOW}[${label}]${RESET}  $*" ;;
          *) [[ "$QUIET" == false && "$OUTPUT_JSON" == false ]] && echo -e "${CYAN}[${label}]${RESET}  $*" ;;
        esac
      }

      # Phrase the kernel-version clause according to what KVER_VERDICT
      # actually established — "in range" implies a confirmed NVD/distro
      # range hit (KVER_VERDICT=vulnerable); when the real verdict is
      # unknown/defer (no matching distro_status/vendor_defer row), say so
      # explicitly rather than borrowing the confident "in range" phrasing
      # for what is actually a conservative default.
      local kver_clause
      case "$KVER_VERDICT" in
        vulnerable) kver_clause="kernel ${kver} confirmed in affected range" ;;
        defer)      kver_clause="kernel ${kver} version could not be cleared (deferred to vendor advisory) — treated conservatively as affected" ;;
        *)          kver_clause="kernel ${kver} version unknown for this distro/release — no matching distro_status/vendor_defer row; treated conservatively as affected, NOT a confirmed range hit" ;;
      esac

      if [[ "$kver_affected" == true ]]; then
        local _cfx="${CVE_FIELD[fixed_versions]:-none}"
        local _cfx_tag=""
        case "$_cfx" in
          VERIFY|verify) _cfx_tag=" [fixed version UNCONFIRMED]" ;;
          none)          _cfx_tag=" [no fixed version recorded]" ;;
        esac
        if [[ -n "$mod_loaded_list" ]]; then
          overall_sev="${CVE_FIELD[severity]:-CRITICAL}"
          _ev FLAG "Severity synthesis" \
            "kernel affected AND module currently loaded ('${mod_loaded_list}') -> ${overall_sev} (blacklist is moot once already loaded)"
          _log_severity_tag "$overall_sev" false "${cve} (${name}): LIKELY VULNERABLE — ${kver_clause}; module(s) loaded: ${mod_loaded_list}${_cfx_tag}"
          _ev_print_stdout
          _emit_cve_finding \
            "${kver_clause}; loaded modules: ${mod_loaded_list}; socket AF=${CVE_FIELD[socket_af]:-N/A} accessible: ${socket_accessible}" \
            "$overall_sev"
        elif [[ "$socket_accessible" == true && ( "$mod_check_applicable" == false || -n "$mod_not_blacklisted" ) ]]; then
          overall_sev="${CVE_FIELD[severity]:-CRITICAL}"
          _ev FLAG "Severity synthesis" \
            "kernel affected AND socket accessible AND module gate not closed (module_names=${CVE_FIELD[module_names]:-none}, not-blacklisted='${mod_not_blacklisted:-n/a}') -> ${overall_sev}"
          _log_severity_tag "$overall_sev" false "${cve} (${name}): LIKELY VULNERABLE — ${kver_clause}; socket accessible and no effective module gate${_cfx_tag}"
          _ev_print_stdout
          _emit_cve_finding \
            "${kver_clause}; socket AF=${CVE_FIELD[socket_af]:-N/A} accessible: ${socket_accessible}; modules not blacklisted: ${mod_not_blacklisted:-n/a (no module gate for this CVE)}" \
            "$overall_sev"
        elif [[ "$socket_accessible" == true && "$mod_fully_blacklisted" == true ]]; then
          overall_sev="HIGH"
          _ev FLAG "Severity synthesis" \
            "kernel affected; socket family reachable BUT module(s) confirmed blacklisted (${CVE_FIELD[module_names]:-none}) -> HIGH, not CRITICAL — socket check only confirms family-level reachability (e.g. AF_ALG core), not that the specific blacklisted transform can load; blacklist is a real but not fully-verified-at-this-precision mitigation"
          _log_severity_tag "$overall_sev" true "${cve} (${name}): ${kver_clause}; socket family reachable but module(s) blacklisted — downgraded from CRITICAL, verify blacklist covers the exact code path${_cfx_tag}"
          _ev_print_stdout
          _emit_cve_finding \
            "${kver_clause}; socket AF=${CVE_FIELD[socket_af]:-N/A} family is reachable, but module(s) ${CVE_FIELD[module_names]:-none} are confirmed blacklisted in /etc/modprobe.d — this blocks auto-load of the specific vulnerable transform at request_module() time, though this check cannot independently confirm the blacklist covers every code path the socket check's family-level probe does not exercise (e.g. bind()-time algorithm lookup)" \
            "$overall_sev"
        elif [[ -n "$mod_not_blacklisted" ]]; then
          overall_sev="HIGH"
          _ev FLAG "Severity synthesis" \
            "kernel affected; modules not loaded but not blacklisted (${mod_not_blacklisted}) — auto-load possible -> HIGH"
          _log_severity_tag "$overall_sev" false "${cve} (${name}): ${kver_clause}; module(s) not loaded but NOT blacklisted (auto-load risk): ${mod_not_blacklisted}${_cfx_tag}"
          _ev_print_stdout
          _emit_cve_finding \
            "${kver_clause}; modules not currently loaded but not blacklisted — auto-load on socket creation is possible: ${mod_not_blacklisted}" \
            "$overall_sev"
        else
          overall_sev="MEDIUM"
          _ev FLAG "Severity synthesis" \
            "kernel affected; modules not loaded and appear blacklisted/absent, socket not accessible/not applicable — interim mitigation likely, patch still required -> MEDIUM"
          _log_severity_tag "$overall_sev" true "${cve} (${name}): ${kver_clause}; modules appear blacklisted or absent${_cfx_tag}"
          _ev_print_stdout
          _emit_cve_finding \
            "${kver_clause}; modules not loaded and appear blacklisted, socket not accessible or not applicable — interim mitigation may be in effect, but kernel patch is still required" \
            "$overall_sev"
        fi
      else
        # kver_affected is false, but the five-state verdict distinguishes a
        # genuine not-affected/fixed from an inconclusive defer/unknown. Only the
        # former is a clean pass; defer/unknown must warn rather than reassure.
        case "$KVER_VERDICT" in
          defer|unknown)
            local _incon_sev="MEDIUM"
            _ev INFO "Severity synthesis" \
              "kernel version verdict '${KVER_VERDICT}' is inconclusive (not a confirmed fix); module state: loaded='${mod_loaded_list:-none}', not-blacklisted='${mod_not_blacklisted:-none}', socket=${socket_accessible} -> ${_incon_sev} (verify)"
            warn "${cve} (${name}): kernel patch status ${KVER_VERDICT} (not confirmed fixed) — verify; module(s) loaded='${mod_loaded_list:-none}' socket=${socket_accessible}"
            _ev_print_stdout
            _emit_cve_finding \
              "kernel version verdict inconclusive (${KVER_VERDICT}) — patch status not confirmed; loaded modules: ${mod_loaded_list:-none}; socket accessible: ${socket_accessible}. Verify against vendor advisory before assuming patched." \
              "$_incon_sev"
            ;;
          *)
            _ev PASS "Severity synthesis" "kernel not affected (${KVER_VERDICT:-not-affected}) -> INFO (not vulnerable on version)"
            ok "${cve} (${name}): kernel ${kver} not affected (${KVER_VERDICT:-not-affected})"
            _ev_print_stdout
            add_finding "cve_${_cve_id_slug}" "INFO" \
              "${name} (${cve}) — kernel ${kver} appears not affected (${KVER_VERDICT:-not-affected})" \
              "CVE: ${cve}. Compound check: kernel version verdict=${KVER_VERDICT:-not-affected} (not in affected range / at or above fix). Module status: loaded=${mod_loaded_list:-none}, not-blacklisted=${mod_not_blacklisted:-none}. Socket accessible: ${socket_accessible}." \
              "N/A — kernel version check passed." "N/A" \
              "Verify with distribution advisory. Continue applying kernel updates." \
              "$(_ev_pack)"
            ;;
        esac
      fi
      ;;

    # -----------------------------------------------------------------------
    manual)
      # Advisory/tracking entry for CVEs that do NOT reduce to a kernel
      # version, module, or socket test (e.g. container-runtime / userspace
      # CVEs). The actual behavioural detection, if any, lives in a dedicated
      # script check (named in the entry's rec/notes). Here we emit a finding at
      # the configured severity so the CVE id appears in the report for
      # inventory/compliance, with detection guidance carried in rec.
      local msev="${CVE_FIELD[severity]:-MEDIUM}"
      local comp="${CVE_FIELD[component]:-}"
      local comp_fixed="${CVE_FIELD[component_fixed]:-}"
      local ctx="manual/advisory tracking entry — no kernel version/module test applies"
      [[ -n "$comp" ]] && ctx="${ctx}; affected component: ${comp}"
      [[ -n "$comp_fixed" ]] && ctx="${ctx}; fixed in ${comp}: ${comp_fixed}"

      # --- Check-52 cross-reference (runc only) --------------------------
      # check_runtime_versions (check 52) runs earlier in this script and
      # actively probes for a reachable runc binary. If it found one, its
      # verdict is authoritative for this specific CVE and MUST be used
      # instead of falling through to the generic advisory below — otherwise
      # this entry silently ignores a detection result that already exists
      # in the same run, and always renders as CRITICAL with the conf's
      # static component_fixed= text even when the installed version is
      # years newer than the fix.
      local runc_verdict=""
      case "$cve" in
        CVE-2019-5736)  runc_verdict="$RUNC_VERDICT_CVE_2019_5736" ;;
        CVE-2024-21626) runc_verdict="$RUNC_VERDICT_CVE_2024_21626" ;;
      esac
      if [[ "$comp" == "runc" && -n "$runc_verdict" ]]; then
        if [[ "$runc_verdict" == "vulnerable" ]]; then
          crit "${cve} (${name}): CONFIRMED — runc ${RUNC_DETECTED_VERSION} at ${RUNC_DETECTED_PATH} predates the fix (${comp_fixed})"
          _ev FLAG "Check 52 cross-reference" \
            "runc ${RUNC_DETECTED_VERSION} detected at ${RUNC_DETECTED_PATH}; predates ${comp}'s fix (${comp_fixed}) — confirmed vulnerable, not advisory-only"
          _ev_print_stdout
          _emit_cve_finding \
            "runc ${RUNC_DETECTED_VERSION} detected at ${RUNC_DETECTED_PATH} (via check 52) — predates the ${comp_fixed} fix for this CVE. This is a definitive verdict from an actually-reachable binary, not an inventory-only advisory." \
            "$msev"
        else
          ok "${cve} (${name}): runc ${RUNC_DETECTED_VERSION} at ${RUNC_DETECTED_PATH} is at or above the ${comp_fixed} fix — not vulnerable"
          _ev PASS "Check 52 cross-reference" \
            "runc ${RUNC_DETECTED_VERSION} detected at ${RUNC_DETECTED_PATH}; at or above ${comp}'s fix (${comp_fixed})"
          _ev_print_stdout
          _emit_cve_finding \
            "runc ${RUNC_DETECTED_VERSION} detected at ${RUNC_DETECTED_PATH} (via check 52) — at or above the ${comp_fixed} fix for this CVE. Confirmed not vulnerable, not merely 'no signal'." \
            "INFO"
        fi
        return
      fi

      # --- Fallback: no check-52 detection available here -----------------
      # Dual-nature entries (e.g. CVE-2022-0492 cgroup release_agent) carry
      # enriched version data as a SUPPORTING signal even though the primary
      # verdict is behavioural. If any version field is present, run the verdict
      # and record it as evidence — it must not be silently ignored.
      if [[ -n "${CVE_FIELD[upstream_ranges]:-}" || -n "${CVE_FIELD[distro_status]:-}" || -n "${CVE_FIELD[upstream_fixed]:-}" || -n "${CVE_FIELD[vendor_defer]:-}" ]]; then
        local mvres mverdict meviden
        mvres="$(cve_kernel_verdict)"
        mverdict="${mvres%%|*}"; meviden="${mvres#*|}"
        case "$mverdict" in
          vulnerable)
            _ev FLAG "Version signal (supporting)" "$meviden — running kernel lacks the fix; combined with the behavioural precondition this CVE is exploitable"
            ctx="${ctx}; version signal: VULNERABLE (${meviden})" ;;
          fixed|not-affected)
            _ev PASS "Version signal (supporting)" "$meviden — kernel carries the fix/hardening; exploitability depends on the behavioural precondition only"
            ctx="${ctx}; version signal: ${mverdict} (${meviden})" ;;
          defer)
            _ev INFO "Version signal (supporting)" "$meviden" ;;
          *)
            _ev INFO "Version signal (supporting)" "$meviden" ;;
        esac
      fi

      _ev SKIP "Automated detection" \
        "primary detection is behavioural / component-version based; tracked as advisory at severity ${msev}${comp:+; component=${comp}}${comp_fixed:+; component fixed=${comp_fixed}} — confirm via dedicated check / installed component version"
      warn "${cve} (${name}): advisory tracking entry (severity ${msev}) — verify via dedicated check / component version"
      _ev_print_stdout
      _emit_cve_finding "$ctx" "$msev"
      ;;

    *)
      info "${cve} (${name}): unknown check_type '${check_type}' — skipping"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# run_cve_checks  —  main entry point
# Reads the config file and dispatches checks for each CVE block.
# ---------------------------------------------------------------------------
run_cve_checks() {
  local conf="${1:-$CVE_CONF}"

  hdr "CVE checks (config-driven) — ${conf}"

  # Detect the running distro/release/flavour/package-version once, up front,
  # so every kernel-version verdict uses accurate, scheme-correct comparison.
  detect_running_system
  info "Version context: distro=${RUN_DISTRO_ID}/${RUN_DISTRO_REL} flavour=${RUN_KFLAVOUR} kernel=${RUN_KVER_RAW} pkgver=${RUN_KPKG_VER}"

  if [[ ! -f "$conf" ]]; then
    warn "CVE config file not found: ${conf}"
    warn "Skipping config-driven CVE checks. Set CVE_CONF=/path/to/cve_checks.conf"
    add_finding "cve_conf_missing" "MEDIUM" \
      "CVE check config file not found: ${conf}" \
      "The config-driven CVE check engine could not find its database file at '${conf}'. CVE checks for Copy Fail, Dirty Frag, Flipping Pages, Attack of the Vsock, and other recent CVEs were skipped." \
      "CVE checks that were skipped may include actively exploited vulnerabilities. Running without the CVE database reduces audit coverage significantly." \
      "Not applicable — this is an audit tool configuration issue." \
      "Ensure cve_checks.conf is co-located with container_escape_audit.sh, or set the CVE_CONF environment variable to the correct path."
    return
  fi

  if [[ ! -r "$conf" ]]; then
    warn "CVE config file not readable: ${conf}"
    return
  fi

  info "Loading CVE database from: ${conf}"

  # Parse the config file into blocks separated by blank lines,
  # skipping comment lines (starting with #) and the file-level header comments.
  local current_block=""
  local block_count=0
  local check_count=0

  while IFS= read -r line; do
    # Skip pure comment lines at the file level (outside a block)
    if [[ "$line" =~ ^[[:space:]]*# && -z "$current_block" ]]; then
      continue
    fi

    # A line starting with 'cve_id=' starts a new block
    if [[ "$line" =~ ^cve_id= ]]; then
      # Flush any previous block that might not have had a trailing blank line
      if [[ -n "$current_block" ]]; then
        _load_cve_block "$current_block"
        if [[ -n "${CVE_FIELD[cve_id]:-}" ]]; then
          (( block_count++ ))
          _run_single_cve_check
          (( check_count++ ))
        fi
        current_block=""
      fi
    fi

    # Blank line = block terminator
    if [[ -z "${line// /}" ]]; then
      if [[ -n "$current_block" ]]; then
        _load_cve_block "$current_block"
        if [[ -n "${CVE_FIELD[cve_id]:-}" ]]; then
          (( block_count++ ))
          _run_single_cve_check
          (( check_count++ ))
        fi
        current_block=""
      fi
      continue
    fi

    # Accumulate non-comment, non-blank lines into current block
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    current_block+="${line}"$'\n'

  done < "$conf"

  # Flush final block (file may not end with a blank line)
  if [[ -n "$current_block" ]]; then
    _load_cve_block "$current_block"
    if [[ -n "${CVE_FIELD[cve_id]:-}" ]]; then
      (( block_count++ ))
      _run_single_cve_check
      (( check_count++ ))
    fi
  fi

  info "CVE database: ${check_count} checks run from ${conf}"
}

# ===========================================================================
# MAIN
# ===========================================================================

if [[ "$OUTPUT_JSON" == false ]]; then
  echo -e "${BOLD}${CYAN}"
  echo "========================================================"
  echo "  container_escape_audit.sh v${SCRIPT_VERSION}"
  echo "  Container escape vector detection"
  echo "  FOR AUTHORISED SECURITY ASSESSMENTS ONLY"
  echo "========================================================"
  echo -e "${RESET}"
  [[ "$NO_REPORT" == false && "$CHECK_UPDATES" == false ]] && echo -e "  Report will be written to: ${BOLD}${REPORT_FILE}${RESET}\n"
fi

check_for_updates

# --check-updates is a standalone mode: run the check, then exit — never
# fall through into the full audit as well.
if [[ "$CHECK_UPDATES" == true ]]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# Checks 1-23: original container escape checks
# ---------------------------------------------------------------------------
check_privileged
check_capabilities
check_namespaces
check_mounts
check_proc
check_k8s_serviceaccount
check_env_secrets
check_cron
check_auth_files
check_memory_access
check_security_profiles
check_cgroup_release_agent
check_suid
check_kernel
check_imds
check_kubelet_api
check_ld_preload
check_escape_tools
check_cgroupv2
check_secret_mounts
check_ssh_keys
check_module_loading
check_overlayfs

# ---------------------------------------------------------------------------
# Checks 24-35: extended escape / runtime checks (CVE checks now via config engine below)
# ---------------------------------------------------------------------------
check_nvidiascape
check_runc_masked_path
check_user_namespace_mapping
check_ebpf_exposure
check_debugfs
check_k8s_rbac_escalation
check_additional_runtime_sockets
check_kernel_keyring
check_oci_hooks
check_core_pattern_deep
check_proc_ns_leakage

# ---------------------------------------------------------------------------
# Checks 36-47: kernel hardening posture (read-only sysctl/module checks)
# ---------------------------------------------------------------------------
check_kh_kptr_restrict
check_kh_dmesg_restrict
check_kh_aslr
check_kh_link_protections
check_kh_fifo_regular_protections
check_kh_syncookies
check_kh_network_routing
check_kh_ip_forwarding
check_kh_userns
check_kh_perf_event
check_kh_dangerous_modules

# ---------------------------------------------------------------------------
# Checks 48-51: gap-analysis behavioural probes (2026-06)
# Read-only reachability probes for subsystems flagged by cve_monitor.py
# --gap-analysis. They complement the config-driven CVE engine below.
# ---------------------------------------------------------------------------
check_io_uring_exposure
check_ktls_ulp_exposure
check_kata_agent_socket
check_kvm_arm64_vgic_its

# ---------------------------------------------------------------------------
# Check 52: container runtime version probe (best-effort, read-only)
# Provides the detection signal referenced by the manual-type runc CVE entries.
# ---------------------------------------------------------------------------
check_runtime_versions

# ---------------------------------------------------------------------------
# Check 53: Docker Engine AuthZ plugin bypass (CVE-2026-34040)
# ---------------------------------------------------------------------------
check_docker_authz_bypass

# ---------------------------------------------------------------------------
# Config-driven CVE checks (reads cve_checks.conf)
# ---------------------------------------------------------------------------
# CVE_CONF was already resolved earlier (CLI flag > environment variable >
# script directory), right after argument parsing — see there.
run_cve_checks "$CVE_CONF"

# ---------------------------------------------------------------------------
# System-state registry dump (--dump-state)
# ---------------------------------------------------------------------------
# Prints the generic system-state facts published by the standard checks. This
# is the shared signal layer that composite CVE checks (step 2) will consume;
# exposing it makes the inputs to those verdicts inspectable and aids debugging.
if [[ "$DUMP_STATE" == true && "$OUTPUT_JSON" == false ]]; then
  echo ""
  echo -e "${BOLD}${CYAN}=============== SYSTEM-STATE REGISTRY ===============${RESET}"
  if [[ "${#SYS_STATE[@]}" -eq 0 ]]; then
    echo "  (empty — no standard checks published state)"
  else
    for k in $(printf '%s\n' "${!SYS_STATE[@]}" | sort); do
      printf "  %-22s %s\n" "$k" "${SYS_STATE[$k]}"
    done
  fi
  echo ""
fi

# ---------------------------------------------------------------------------
# Terminal summary
# ---------------------------------------------------------------------------
if [[ "$OUTPUT_JSON" == false ]]; then
  echo ""
  echo -e "${BOLD}${CYAN}==================== SUMMARY ====================${RESET}"
  local_crit=0; local_high=0; local_med=0; local_info=0
  for id in "${FINDING_ORDER[@]}"; do
    IFS="$SEP" read -r sev title _ _ _ _ _ <<< "${FINDINGS[$id]}"
    case "$sev" in
      CRITICAL) (( local_crit++ )); echo -e "  ${RED}[CRITICAL]${RESET} $title" ;;
      HIGH)     (( local_high++ )); echo -e "  ${YELLOW}[HIGH    ]${RESET} $title" ;;
      MEDIUM)   (( local_med++  )); echo -e "  ${YELLOW}[MEDIUM  ]${RESET} $title" ;;
      INFO)     (( local_info++ )) ;;
    esac
  done
  echo ""
  echo -e "  ${RED}CRITICAL${RESET}: $local_crit  |  ${YELLOW}HIGH${RESET}: $local_high  |  ${YELLOW}MEDIUM${RESET}: $local_med  |  ${CYAN}INFO${RESET}: $local_info"
  echo ""
fi

write_report
[[ "$OUTPUT_JSON" == true ]] && emit_json
