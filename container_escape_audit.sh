#!/usr/bin/env bash
# =============================================================================
# container_escape_audit.sh  —  v2.0
# Liam Romanis 20/04/2026
#
# Detects potential container escape vectors from within a running container.
# Intended for AUTHORISED security assessments only.
#
# Usage:
#   chmod +x container_escape_audit.sh
#   ./container_escape_audit.sh [options]
#
# Options:
#   --report <file>   Write a detailed human-readable report to <file>
#                     (default: container_escape_report_<timestamp>.txt)
#   --json            Also emit a machine-readable JSON summary to stdout
#   --quiet           Suppress info lines; print only WARN/CRITICAL to terminal
#   --no-report       Skip writing the report file entirely
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
REPORT_FILE="container_escape_report_$(date +%Y%m%d_%H%M%S).txt"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)       OUTPUT_JSON=true ;;
    --quiet)      QUIET=true ;;
    --no-report)  NO_REPORT=true ;;
    --report)     shift; REPORT_FILE="$1" ;;
    *) echo "Unknown option: $1" >&2 ;;
  esac
  shift
done

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
# Findings store
# Each finding: FINDINGS[id]="SEVERITY<SEP>TITLE<SEP>WHAT<SEP>IMPACT<SEP>EXPLOIT<SEP>REC"
# Using ASCII unit-separator (0x1F) as delimiter to avoid collisions with text
# ---------------------------------------------------------------------------
declare -A FINDINGS
FINDING_ORDER=()
SEP=$'\x1f'

add_finding() {
  # add_finding <id> <severity> <title> <what> <impact> <exploitability> <recommendation>
  local id="$1" severity="$2" title="$3"
  local what="${4:-}" impact="${5:-}" exploit="${6:-}" rec="${7:-}"
  FINDINGS["$id"]="${severity}${SEP}${title}${SEP}${what}${SEP}${impact}${SEP}${exploit}${SEP}${rec}"
  FINDING_ORDER+=("$id")
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
# Report writer  — called once at end
# ---------------------------------------------------------------------------
REPORT_LINES=()

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
      IFS="$SEP" read -r sev _ _ _ _ _ <<< "${FINDINGS[$fid]}"
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

    # Print findings grouped by severity, highest first
    for pass in CRITICAL HIGH MEDIUM INFO; do
      local printed_header=false
      for fid in "${FINDING_ORDER[@]}"; do
        IFS="$SEP" read -r sev title what impact exploit rec <<< "${FINDINGS[$fid]}"
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
emit_json() {
  local first=true
  echo "{"
  echo "  \"tool\": \"container_escape_audit\","
  echo "  \"version\": \"2.0\","
  echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"host\": \"$(hostname 2>/dev/null || echo 'unknown')\","
  echo "  \"kernel\": \"$(uname -r 2>/dev/null || echo 'unknown')\","
  echo "  \"findings\": ["
  for fid in "${FINDING_ORDER[@]}"; do
    IFS="$SEP" read -r sev title what impact exploit rec <<< "${FINDINGS[$fid]}"
    [[ "$first" == false ]] && echo ","
    first=false
    printf '    {\n      "id": "%s",\n      "severity": "%s",\n      "title": "%s",\n      "what": "%s",\n      "impact": "%s",\n      "exploitability": "%s",\n      "recommendation": "%s"\n    }' \
      "$fid" "$sev" \
      "${title//\"/\\\"}" \
      "${what//\"/\\\"}" \
      "${impact//\"/\\\"}" \
      "${exploit//\"/\\\"}" \
      "${rec//\"/\\\"}"
  done
  echo ""
  echo "  ]"
  echo "}"
}

# ===========================================================================
# CHECK FUNCTIONS
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. Privileged container
# ---------------------------------------------------------------------------
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
      "Trivial. No exploit required. 'mount /dev/sda1 /mnt && chroot /mnt' gives immediate host root access. Automated tools such as deepce and CDK detect this and perform the escape automatically. Extensively documented; used in real-world attacks." \
      "Never use --privileged in production. Grant only specific required capabilities via --cap-add. Enforce Pod Security Admission (PSA) at the 'restricted' or 'baseline' level to prevent privileged pods cluster-wide. Use OPA/Gatekeeper or Kyverno admission policies. Audit existing workloads with: kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'."
  else
    ok "Container does not appear fully privileged (CapEff=$capeff)"
  fi
}

# ---------------------------------------------------------------------------
# 2. Dangerous Linux capabilities
# ---------------------------------------------------------------------------
check_capabilities() {
  hdr "2. Dangerous Linux capabilities"
  local capeff
  capeff=$(grep CapEff /proc/self/status | awk '{print $2}')

  if command -v capsh &>/dev/null; then
    info "Decoded capabilities: $(capsh --decode="$capeff" 2>/dev/null || echo 'decode failed')"
  fi

  # Capability metadata: bit -> name|what|impact|exploit|rec
  local -A CAP_NAME CAP_WHAT CAP_IMPACT CAP_EXPLOIT CAP_REC

  CAP_NAME[21]="CAP_SYS_ADMIN"
  CAP_WHAT[21]="CAP_SYS_ADMIN grants a broad set of administrative kernel privileges: mounting filesystems, creating namespaces, loading eBPF programs, and manipulating cgroup hierarchies. It is sometimes described as 'root without the name'."
  CAP_IMPACT[21]="Near-equivalent to full host root. Enables cgroup release_agent escape, mount-based host filesystem access, namespace manipulation via unshare/nsenter, and in some kernel versions eBPF-based kernel memory writes. Multiple independent escape paths exist."
  CAP_EXPLOIT[21]="High. CAP_SYS_ADMIN alone is sufficient for the cgroup release_agent escape — a few shell commands. Tools such as CDK and deepce automate this. Widely documented with working PoCs for all major Linux distributions."
  CAP_REC[21]="Remove CAP_SYS_ADMIN entirely. If namespace creation is specifically needed, evaluate whether a user namespace is sufficient. Apply PSA restricted profile. Block mount(2) and clone(2) with namespace flags via seccomp."

  CAP_NAME[19]="CAP_SYS_PTRACE"
  CAP_WHAT[19]="CAP_SYS_PTRACE allows attaching a debugger to any visible process, reading and writing its memory, and intercepting its system calls via ptrace(2)."
  CAP_IMPACT[19]="If the host PID namespace is shared (or a privileged host process is visible), an attacker can attach to host processes to: extract secrets from memory (keys, tokens, passwords), inject shellcode, or take over host daemons entirely."
  CAP_EXPLOIT[19]="Medium. Requires a visible target process with elevated privilege. Once that condition is met, ptrace attachment is trivial (gdb -p <pid>, strace -p <pid>). Memory injection via /proc/<pid>/mem is well-documented."
  CAP_REC[19]="Remove CAP_SYS_PTRACE. Never share the host PID namespace with application workloads. Enforce ptrace_scope >= 1 via sysctl on the host. Use allowPrivilegeEscalation: false in pod security context."

  CAP_NAME[16]="CAP_SYS_MODULE"
  CAP_WHAT[16]="CAP_SYS_MODULE allows loading and unloading Linux kernel modules (.ko files) directly into the running kernel via init_module(2) and delete_module(2)."
  CAP_IMPACT[16]="Unrestricted kernel code execution. A malicious kernel module can open reverse shells from kernel space, patch LSM hooks to disable AppArmor/SELinux, disable seccomp enforcement, or hide malicious processes and files."
  CAP_EXPLOIT[16]="High if a compiler or pre-built module is available. A minimal reverse-shell kernel module is approximately 20 lines of C. Container images with build tools make this straightforward. Pre-compiled modules can be downloaded if network egress is available."
  CAP_REC[16]="Remove CAP_SYS_MODULE. Lock module loading with kernel.modules_disabled=1 after boot. Use immutable, minimal container images without build toolchains. Apply seccomp to block init_module(2) and finit_module(2) syscalls."

  CAP_NAME[17]="CAP_SYS_RAWIO"
  CAP_WHAT[17]="CAP_SYS_RAWIO allows direct read/write access to physical memory (/dev/mem, /dev/kmem) and to raw block devices, bypassing all filesystem abstractions."
  CAP_IMPACT[17]="Reading /dev/mem exposes all physical RAM including kernel secrets, other processes' memory, and encryption keys. Writing to it enables kernel patching and arbitrary code execution at the physical memory level."
  CAP_EXPLOIT[17]="Medium-high. Requires knowledge of memory layout or disk structure. Standard tools (dd, /dev/mem readers) assist. Most effective against kernels without strict /dev/mem access controls (CONFIG_STRICT_DEVMEM=n)."
  CAP_REC[17]="Remove CAP_SYS_RAWIO. Ensure /dev/mem and /dev/kmem are not exposed in containers. Build kernels with CONFIG_STRICT_DEVMEM=y. Block raw device access with seccomp."

  CAP_NAME[2]="CAP_DAC_READ_SEARCH"
  CAP_WHAT[2]="CAP_DAC_READ_SEARCH bypasses discretionary access control checks for reading files and searching directories, regardless of file permissions and ownership."
  CAP_IMPACT[2]="Enables the Shocker exploit: using open_by_handle_at(2) to open files on the host filesystem by inode number, bypassing chroot jails and bind-mount restrictions. A container can read /etc/shadow, SSH private keys, or any other sensitive host file."
  CAP_EXPLOIT[2]="Medium. The Shocker PoC is publicly available. Requires brute-forcing or guessing the inode number of target files, which is feasible (typical ext4 filesystems have predictable inode layouts for system files)."
  CAP_REC[2]="Remove CAP_DAC_READ_SEARCH. Apply a seccomp profile that blocks open_by_handle_at(2). Ensure container base images do not include tools that leverage this capability."

  CAP_NAME[12]="CAP_NET_ADMIN"
  CAP_WHAT[12]="CAP_NET_ADMIN grants control over the host's network stack: creating/deleting interfaces, modifying routing tables, adjusting iptables/nftables rules, and performing low-level packet operations."
  CAP_IMPACT[12]="An attacker can add host routes that redirect traffic, sniff packets between other pods and services, modify firewall rules to expose previously blocked services, or create tunnel interfaces for covert data exfiltration."
  CAP_EXPLOIT[12]="Medium. Requires network tooling in the container image. Impact is primarily lateral movement and traffic interception rather than direct host escape, but the damage can be significant in multi-tenant environments."
  CAP_REC[12]="Remove CAP_NET_ADMIN unless the workload manages network interfaces (e.g. CNI plugins, VPN gateways). Use Kubernetes NetworkPolicy for traffic control instead. Apply egress controls."

  CAP_NAME[7]="CAP_SETUID"
  CAP_WHAT[7]="CAP_SETUID allows changing the process's user ID to any value, including UID 0 (root), via setuid(2) and related syscalls."
  CAP_IMPACT[7]="An attacker can call setuid(0) to become root within the container. This then enables exploitation of any other misconfiguration (writable host mounts, shared namespaces, runtime sockets) that requires root."
  CAP_EXPLOIT[7]="Low-medium on its own, but High when combined with other findings. setuid(0) is a single syscall, trivially performed from any language."
  CAP_REC[7]="Remove CAP_SETUID. Set runAsNonRoot: true and a specific runAsUser in the pod security context. Set allowPrivilegeEscalation: false."

  CAP_NAME[6]="CAP_SETGID"
  CAP_WHAT[6]="CAP_SETGID allows changing the process's group ID to any value, including joining privileged groups such as docker, disk, or shadow."
  CAP_IMPACT[6]="Joining the docker group allows controlling the Docker daemon. Joining the disk group gives read/write access to all block devices. Joining the shadow group allows reading /etc/shadow."
  CAP_EXPLOIT[6]="Low-medium. Impact depends on which privileged groups exist and what access they provide in the specific environment."
  CAP_REC[6]="Remove CAP_SETGID. Run as a specific non-root user and group. Set allowPrivilegeEscalation: false."

  CAP_NAME[0]="CAP_CHOWN"
  CAP_WHAT[0]="CAP_CHOWN allows changing the ownership of any file to any user/group, bypassing normal ownership restrictions."
  CAP_IMPACT[0]="An attacker can chown any file on the container filesystem (or host-mounted paths) to themselves, including SUID binaries, sensitive config files, or key material, enabling further escalation."
  CAP_EXPLOIT[0]="Low-medium on its own. Most effective as a chaining capability alongside other misconfigurations."
  CAP_REC[0]="Remove CAP_CHOWN unless strictly required. Use readOnlyRootFilesystem: true. Run as a non-root user so chown of system files is meaningful."

  local cap_dec found_any=false
  cap_dec=$(printf "%d" "0x${capeff}")
  for bit in "${!CAP_NAME[@]}"; do
    local mask=$(( 1 << bit ))
    if (( (cap_dec & mask) != 0 )); then
      warn "Dangerous capability present: ${CAP_NAME[$bit]} (bit $bit)"
      add_finding "cap_${bit}" "HIGH" \
        "Dangerous capability present: ${CAP_NAME[$bit]}" \
        "${CAP_WHAT[$bit]}" "${CAP_IMPACT[$bit]}" "${CAP_EXPLOIT[$bit]}" "${CAP_REC[$bit]}"
      found_any=true
    fi
  done
  [[ "$found_any" == false ]] && ok "No individually dangerous capabilities detected"
}

# ---------------------------------------------------------------------------
# 3. Namespace sharing
# ---------------------------------------------------------------------------
check_namespaces() {
  hdr "3. Namespace isolation"

  local -A NS_WHAT NS_IMPACT NS_EXPLOIT NS_REC NS_SEV

  NS_SEV[pid]="HIGH"; NS_SEV[net]="HIGH"; NS_SEV[ipc]="MEDIUM"
  NS_SEV[uts]="MEDIUM"; NS_SEV[mnt]="HIGH"

  NS_WHAT[pid]="The container shares the host's PID namespace, meaning it can enumerate and interact with every process running on the host node."
  NS_WHAT[net]="The container shares the host's network namespace and uses the host's actual network interfaces rather than a virtual container network."
  NS_WHAT[ipc]="The container shares the host's IPC namespace, giving access to the host's shared memory segments, semaphores, and message queues."
  NS_WHAT[uts]="The container shares the host's UTS namespace; hostname and NIS domain changes affect the host system."
  NS_WHAT[mnt]="The container shares the host's mount namespace and can see the host's complete filesystem mount table."

  NS_IMPACT[pid]="An attacker can signal, inspect, and attach to any host process. /proc/<host_pid>/fd, /proc/<host_pid>/environ, and /proc/<host_pid>/mem may expose secrets from host processes. Combined with CAP_SYS_PTRACE, full host process compromise is possible."
  NS_IMPACT[net]="The container can bind to any port on the host's IP addresses, intercept traffic from host services, and access loopback-bound services (databases, admin consoles, metadata APIs) that are unreachable from normal containers."
  NS_IMPACT[ipc]="Applications using POSIX shared memory or System V IPC (databases, caching layers, X11) can be read or corrupted from within the container, enabling data leakage or service disruption."
  NS_IMPACT[uts]="Hostname changes may confuse monitoring, logging, and certificate validation. Lower severity than other namespace escapes."
  NS_IMPACT[mnt]="The container can enumerate all host mounts and interact with mount points that should be isolated from container workloads."

  NS_EXPLOIT[pid]="Immediately exploitable for process enumeration and /proc-based secret extraction. Ptrace-based exploitation requires CAP_SYS_PTRACE additionally."
  NS_EXPLOIT[net]="Immediately exploitable for port binding and traffic interception given appropriate network tooling in the image."
  NS_EXPLOIT[ipc]="Exploitability depends on what IPC objects are present. 'ipcs' enumerates them trivially."
  NS_EXPLOIT[uts]="Low direct exploitability."
  NS_EXPLOIT[mnt]="Exploitability depends on what is mounted on the host. Enumeration is trivial via /proc/mounts."

  NS_REC[pid]="Remove hostPID: true from pod specs. Restrict via PSA and admission policies. Audit with: kubectl get pods -A -o json | jq '.items[] | select(.spec.hostPID==true)'."
  NS_REC[net]="Remove hostNetwork: true unless the workload is a node-level network daemon. Use a proper CNI network and NetworkPolicy for required connectivity."
  NS_REC[ipc]="Remove hostIPC: true. Replace inter-process communication requirements with a proper messaging or API layer."
  NS_REC[uts]="Remove hostUTS: true. There are very few legitimate use cases for sharing the host UTS namespace."
  NS_REC[mnt]="Audit mount namespace configuration. Ensure the container runtime is configured with correct isolation defaults."

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

# ---------------------------------------------------------------------------
# 4. Dangerous filesystem mounts
# ---------------------------------------------------------------------------
check_mounts() {
  hdr "4. Dangerous filesystem mounts"

  # Runtime sockets
  for sock in /var/run/docker.sock /run/docker.sock \
              /run/containerd/containerd.sock /var/run/containerd/containerd.sock \
              /run/crio/crio.sock /var/run/crio/crio.sock; do
    [[ -S "$sock" ]] || continue
    crit "Container runtime socket accessible: $sock"
    add_finding "runtime_socket_${sock//\//_}" "CRITICAL" \
      "Container runtime socket accessible: $sock" \
      "The container runtime's UNIX domain socket is bind-mounted into the container. This socket is the administrative API for the container daemon, which runs as root on the host." \
      "Full host node compromise. An attacker uses the Docker/containerd/CRI-O API to create a new privileged container with the host root filesystem mounted, exec into it, and obtain a root shell on the host. All data on the node is accessible." \
      "Trivial. 'docker run -v /:/host --privileged alpine chroot /host' is a single command. CDK, deepce, and other tools perform this automatically on socket detection. Used in numerous real-world attacks including the Tesla cryptomining incident." \
      "Never mount the runtime socket into application containers. For CI/CD use cases that need container image building, use rootless Docker, Kaniko, or Buildah. Detect socket mounts with admission controllers. Audit with: find / -name '*.sock' 2>/dev/null."
  done

  # Dangerous path mounts
  local -A MOUNT_WHAT MOUNT_IMPACT MOUNT_EXPLOIT MOUNT_REC

  MOUNT_WHAT["/"]="The container's filesystem root (/) is a bind-mount of the host root filesystem, giving the container direct access to the entire host filesystem tree."
  MOUNT_IMPACT["/"]="Complete host filesystem read/write access. An attacker can add SSH keys to /root/.ssh/, create SUID binaries, overwrite init scripts, modify /etc/sudoers, install backdoors, or exfiltrate any data on the host. This is equivalent to having an interactive root shell on the host."
  MOUNT_EXPLOIT["/"]="Trivial. Standard filesystem commands (cp, cat, echo) are sufficient. No exploit required."
  MOUNT_REC["/"]="Never bind-mount the host root into containers. Use minimal, specific volume mounts for only the exact paths and data the container requires. Apply read-only mounts where write access is not needed."

  MOUNT_WHAT["/etc"]="/etc contains authentication databases, network configuration, and service configuration files. A bind-mount makes the host's /etc directory available inside the container."
  MOUNT_IMPACT["/etc"]="Writable access allows adding root accounts to /etc/passwd, granting passwordless sudo via /etc/sudoers, poisoning DNS resolution via /etc/hosts, or modifying service configurations to execute malicious code."
  MOUNT_EXPLOIT["/etc"]="'echo attacker::0:0::/root:/bin/bash >> /etc/passwd && su attacker' gives an immediate root shell. Requires write access to /etc/passwd only."
  MOUNT_REC["/etc"]="Use Kubernetes ConfigMaps for configuration injection rather than bind-mounting /etc. If a bind-mount is unavoidable, use read-only mode and mount only the specific files needed."

  MOUNT_WHAT["/proc/sys"]="The kernel's /proc/sys filesystem is mounted, exposing kernel parameter controls including core_pattern, sysrq-trigger, and network parameters."
  MOUNT_IMPACT["/proc/sys"]="Writable core_pattern allows executing arbitrary code as root on any process crash. Writable sysrq-trigger allows immediate host reboot or kernel panic. Writable network parameters can affect all containers on the node."
  MOUNT_EXPLOIT["/proc/sys"]="Writing a pipe handler to /proc/sys/kernel/core_pattern then triggering a crash executes arbitrary code as root outside all namespaces. Well-documented with working PoCs."
  MOUNT_REC["/proc/sys"]="Mount /proc/sys read-only in containers. Apply seccomp to block sysctl(2). Do not bind-mount kernel control interfaces into application containers."

  MOUNT_WHAT["/sys"]="The host's sysfs is mounted, exposing kernel subsystem interfaces including cgroup controls, hardware device state, and security module (LSM) interfaces."
  MOUNT_IMPACT["/sys"]="Writable sysfs enables the cgroup release_agent host escape, hardware power state manipulation, and in some configurations LSM policy modification via /sys/kernel/security."
  MOUNT_EXPLOIT["/sys"]="The cgroup release_agent escape via /sys/fs/cgroup is extensively documented and automated in container escape toolkits."
  MOUNT_REC["/sys"]="Mount sysfs read-only or not at all for application containers. Restrict writes with AppArmor or SELinux policies."

  MOUNT_WHAT["/dev"]="The host's /dev directory is mounted, exposing raw device files including physical disks (/dev/sda*), memory (/dev/mem, /dev/kmem), and hardware interfaces."
  MOUNT_IMPACT["/dev"]="Access to /dev/sda* allows direct disk read/write, completely bypassing filesystem permissions. /dev/mem exposes all physical RAM. Combined, these allow reading any data from the host and establishing persistent modifications to disk."
  MOUNT_EXPLOIT["/dev"]="'dd if=/dev/sda of=/tmp/disk.img' dumps the host disk. inode scanning can locate and extract specific files. Direct disk writes allow modifying any file on the host filesystem."
  MOUNT_REC["/dev"]="Never mount /dev into containers. For specific device requirements (GPU, hardware accelerators), use the Kubernetes device plugin framework with precisely scoped device paths only."

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
          "${MOUNT_WHAT[$prefix]:-Sensitive path $prefix is mounted.} Mountpoint: $mountpoint, mode: $rw_flag, fstype: $fstype." \
          "${MOUNT_IMPACT[$prefix]:-Sensitive host data may be accessible.}" \
          "${MOUNT_EXPLOIT[$prefix]:-Depends on path and permissions.}" \
          "${MOUNT_REC[$prefix]:-Review and restrict this mount.}"
      fi
    done
  done < /proc/mounts
}

# ---------------------------------------------------------------------------
# 5. /proc exposure
# ---------------------------------------------------------------------------
check_proc() {
  hdr "5. /proc filesystem exposure"

  if [[ -w /proc/sys/kernel/core_pattern ]]; then
    crit "/proc/sys/kernel/core_pattern is writable"
    add_finding "proc_core_pattern_writable" "CRITICAL" \
      "Writable /proc/sys/kernel/core_pattern" \
      "This kernel parameter specifies how crash dump files are named. When the value begins with '|', the kernel executes the specified program as root when any process crashes." \
      "An attacker sets core_pattern to '|/tmp/escape.sh' (containing a reverse shell). They then trigger a crash (e.g. kill -SIGSEGV \$\$). The kernel executes the script as root outside all container namespaces — a clean host escape." \
      "Widely known and tooled. Working PoCs exist for all major distributions. The crash can be forced in the same shell session. CDK implements this as an automated escape technique." \
      "Set core_pattern via sysctl on the host before launching containers. Mount /proc/sys read-only inside containers. Apply seccomp to block sysctl(2)."
  fi

  if [[ -w /proc/sysrq-trigger ]]; then
    crit "/proc/sysrq-trigger is writable"
    add_finding "proc_sysrq_writable" "CRITICAL" \
      "Writable /proc/sysrq-trigger" \
      "The SysRq trigger file sends magic key commands directly to the kernel regardless of running processes." \
      "Writing 'b' causes immediate host reboot. Writing 'c' causes kernel panic. Writing 'f' invokes the OOM killer. This constitutes instant denial of service on the host node, affecting all running containers and workloads." \
      "Immediate: 'echo b > /proc/sysrq-trigger' reboots the host. Requires only write access — no exploit, no credentials." \
      "Mount /proc read-only in containers. Apply AppArmor profiles denying writes to /proc/sysrq-trigger. This should never be writable in a production container."
  fi

  if [[ -r /proc/kcore ]]; then
    warn "/proc/kcore is readable"
    add_finding "proc_kcore_readable" "HIGH" \
      "Readable /proc/kcore (kernel memory exposure)" \
      "/proc/kcore exposes the entire host kernel virtual address space as an ELF core file, including all physical memory mapped by the kernel." \
      "An attacker can read all kernel memory to extract: cryptographic keys and secrets from any process on the host (not just the current container), ASLR offsets to facilitate further exploitation, and sensitive data from adjacent pods' memory." \
      "Moderate. Requires tooling to parse the ELF format and locate target data, but Volatility and custom scripts make this feasible. The file is often several gigabytes." \
      "Ensure /proc is mounted without exposing kcore. Apply seccomp to block open(2) on /proc/kcore. AppArmor can deny reads. Run containers as non-root to limit which /proc files are accessible."
  fi

  if [[ -r /proc/kmem || -w /proc/kmem ]]; then
    crit "/proc/kmem is accessible"
    add_finding "proc_kmem_accessible" "CRITICAL" \
      "/proc/kmem accessible (direct kernel memory access)" \
      "/proc/kmem provides direct read/write access to kernel virtual memory." \
      "Writing to kernel memory enables overwriting kernel code, patching security hooks, disabling LSM enforcement, or injecting arbitrary kernel payloads. This is a full kernel compromise primitive." \
      "High. Overwriting a kernel function pointer with a shellcode address gives unrestricted kernel code execution. Requires knowledge of kernel layout but KASLR can be bypassed via /proc/kallsyms or other info leaks." \
      "Ensure /proc/kmem and /dev/kmem are not accessible in containers. Block with seccomp. Mount /proc read-only."
  fi

  if [[ -r /proc/1/environ ]]; then
    warn "/proc/1/environ is readable (host PID1 environment exposed)"
    add_finding "proc_1_environ_readable" "HIGH" \
      "Host PID 1 environment file readable (/proc/1/environ)" \
      "/proc/1/environ contains all environment variables that were set when the host init process (PID 1) was started. This may be systemd, the container runtime, or a Kubernetes kubelet process." \
      "The host init environment may contain: API tokens for cloud services, Kubernetes bootstrap tokens, TLS private key paths, database connection strings, or other secrets passed at daemon startup. All are readable without any privilege." \
      "cat /proc/1/environ | tr '\0' '\n' displays all variables. No exploit required. Accessible when the container runs as root and /proc is mounted with default options." \
      "Run containers as non-root users (hidepid=2 on the /proc mount prevents non-root processes from reading other processes' proc entries). Audit what environment variables are passed to host-level daemons."
  fi

  ok "/proc check complete"
}

# ---------------------------------------------------------------------------
# 6. Kubernetes service account
# ---------------------------------------------------------------------------
check_k8s_serviceaccount() {
  hdr "6. Kubernetes service account"
  local sa_dir="/var/run/secrets/kubernetes.io/serviceaccount"
  [[ -d "$sa_dir" ]] || { ok "No Kubernetes service account directory found"; return; }

  info "Service account directory: $sa_dir"
  local token_file="$sa_dir/token"
  [[ -r "$token_file" ]] || { ok "Token not readable"; return; }

  warn "Service account token readable"
  add_finding "sa_token_readable" "HIGH" \
    "Kubernetes service account token is readable" \
    "Kubernetes mounts a service account JWT token at $token_file in every pod unless automountServiceAccountToken: false is explicitly set. This token authenticates the pod to the Kubernetes API server." \
    "Depending on RBAC permissions, an attacker can query the API to enumerate cluster resources, read secrets from any namespace, create privileged pods on other nodes, modify workloads, exfiltrate data, or gain cluster-admin. The impact scales directly with the service account's permissions." \
    "Low to Critical depending on RBAC. Reading the token requires no exploit — it is a regular file read. Tools such as kubectl, peirates, and CDK automate Kubernetes privilege escalation from a stolen token." \
    "Set automountServiceAccountToken: false on pod specs and ServiceAccount objects for workloads that do not call the Kubernetes API. Follow least-privilege RBAC. Regularly audit bindings: kubectl get clusterrolebindings,rolebindings -A -o wide."

  local api_server="https://${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}:${KUBERNETES_SERVICE_PORT:-443}"
  local ca_cert="$sa_dir/ca.crt"

  if command -v kubectl &>/dev/null; then
    local rules
    rules=$(kubectl auth can-i --list 2>/dev/null || echo "FAILED")
    if [[ "$rules" != "FAILED" ]]; then
      if echo "$rules" | grep -qE '^\*\s+\*|cluster-admin'; then
        crit "Service account appears to have cluster-admin or wildcard permissions"
        add_finding "sa_cluster_admin" "CRITICAL" \
          "Service account has cluster-admin or wildcard RBAC permissions" \
          "The service account bound to this pod has been granted cluster-admin or wildcard (*) RBAC permissions." \
          "Full Kubernetes cluster compromise. An attacker can read all secrets across all namespaces, create privileged pods on any node, modify any workload, exfiltrate all data, and establish persistent backdoors in the cluster." \
          "Trivial. 'kubectl --token=<token> get secrets -A' retrieves every secret in the cluster. Creating a privileged pod is a single API call." \
          "Immediately revoke the cluster-admin binding. Conduct a full RBAC audit. Rotate all potentially exposed secrets. Enable Kubernetes audit logging. Implement RBAC least-privilege across all service accounts."
      fi
      info "RBAC summary (first 5 rules): $(echo "$rules" | head -5)"
    fi
  elif command -v curl &>/dev/null; then
    local token ns_resp
    token=$(cat "$token_file")
    ns_resp=$(curl -s --max-time 5 --cacert "$ca_cert" \
      -H "Authorization: Bearer $token" \
      "$api_server/api/v1/namespaces" 2>/dev/null || echo "FAILED")
    if echo "$ns_resp" | grep -q '"NamespaceList"'; then
      crit "Service account can list all namespaces (over-privileged)"
      add_finding "sa_list_namespaces" "CRITICAL" \
        "Service account can list all cluster namespaces" \
        "The service account has permission to list all namespaces, indicating significant over-privilege in the RBAC configuration." \
        "Namespace listing enables full cluster enumeration. An attacker can then target specific namespaces containing secrets, privileged workloads, or sensitive data." \
        "A single curl with the bearer token confirms the permission. No exploit required." \
        "Restrict service account permissions to only the specific namespace and resources required. Use namespace-scoped Roles rather than ClusterRoles."
    fi
  fi
}

# ---------------------------------------------------------------------------
# 7. Environment variable secrets
# ---------------------------------------------------------------------------
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
        "The environment variable '$varname' matches patterns commonly associated with credentials, API keys, or secrets. Environment variables are accessible to all processes in the container and are frequently leaked in debug output, crash reports, and logs." \
        "Any process achieving code execution in the container can read these values. Env vars are also visible in: container inspect output, Kubernetes pod descriptions, system process listings on the host, and often in application logs where frameworks dump their configuration." \
        "'cat /proc/self/environ | tr '\''\\0'\'' '\''\\n'\''' lists all environment variables. No exploit required — this is a simple file read available to any process in the container." \
        "Use a secrets management solution (Kubernetes Secrets with encryption at rest, HashiCorp Vault, AWS Secrets Manager) and mount secrets as files with mode 0400 rather than environment variables. Files are not exposed in process listings or crash reports. Rotate the credential immediately if real data is present."
      found=true
    done < <(env 2>/dev/null | grep -i "$pat" || true)
  done
  [[ "$found" == false ]] && ok "No obviously sensitive environment variable names found"
}

# ---------------------------------------------------------------------------
# 8. Cron writability
# ---------------------------------------------------------------------------
check_cron() {
  hdr "8. Cron writability"
  local paths=(/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily
               /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs)
  for p in "${paths[@]}"; do
    [[ -e "$p" && -w "$p" ]] || continue
    crit "Writable cron path: $p"
    add_finding "writable_cron_${p//\//_}" "HIGH" \
      "Writable cron directory or file: $p" \
      "The cron path at $p is writable by the current process. Cron jobs placed here are executed by the system cron daemon, typically as root, on a scheduled interval (as often as every minute for /etc/cron.d entries)." \
      "An attacker writes a cron job that executes a reverse shell, creates a backdoor account, or exfiltrates data. If this path is on a host-mounted volume, the cron job executes on the host node itself — a clean host escape with automatic persistence." \
      "Writing a cron job requires only standard file write access. Execution is automatic and requires no further interaction. Persistence survives container restarts if the path is host-mounted." \
      "Mount cron directories read-only in containers or do not mount them. Run containers as non-root. Audit host cron jobs regularly. Use Kubernetes CronJobs rather than host-level cron for scheduled container tasks."
  done
  ok "Cron writability check complete"
}

# ---------------------------------------------------------------------------
# 9. Auth file writability
# ---------------------------------------------------------------------------
check_auth_files() {
  hdr "9. Authentication file writability"

  local -A AUTH_WHAT AUTH_IMPACT AUTH_EXPLOIT AUTH_REC

  AUTH_WHAT["/etc/passwd"]="/etc/passwd maps usernames to UIDs and specifies default login shells. It is read by PAM and su/login for authentication."
  AUTH_IMPACT["/etc/passwd"]="Adding an entry with UID 0 creates a new root account. The new user can immediately be switched to with su, giving a root shell. If host-mounted, this creates a root account on the host OS itself."
  AUTH_EXPLOIT["/etc/passwd"]="'echo backdoor::0:0::/root:/bin/bash >> /etc/passwd && su backdoor' gives an immediate root shell with no password. No exploit required — this is a standard text file append."
  AUTH_REC["/etc/passwd"]="Apply readOnlyRootFilesystem: true. Run containers as non-root. Do not bind-mount /etc. Use immutable container images."

  AUTH_WHAT["/etc/shadow"]="/etc/shadow stores hashed passwords for system users. It is readable only by root and the shadow group under normal circumstances."
  AUTH_IMPACT["/etc/shadow"]="Replacing root's password hash with a known value enables root login via su or SSH. Reading the file enables offline hash cracking of all user passwords."
  AUTH_EXPLOIT["/etc/shadow"]="Replace the root password field with a known hash (e.g. from openssl passwd) then 'su root' with the known password. Alternatively, read and crack other users' hashes offline."
  AUTH_REC["/etc/shadow"]="Apply readOnlyRootFilesystem: true. Never bind-mount /etc. Run as non-root."

  AUTH_WHAT["/etc/sudoers"]="/etc/sudoers controls which users can execute commands as root via sudo, including passwordless sudo rules."
  AUTH_IMPACT["/etc/sudoers"]="Adding 'ALL ALL=(ALL) NOPASSWD: ALL' grants every user passwordless root sudo. If host-mounted, this affects the host OS and allows any user to become root on the node."
  AUTH_EXPLOIT["/etc/sudoers"]="'echo ALL ALL=(ALL) NOPASSWD: ALL >> /etc/sudoers && sudo bash' gives an immediate root shell. No exploit required."
  AUTH_REC["/etc/sudoers"]="Apply readOnlyRootFilesystem: true. Do not bind-mount /etc. Run as non-root. Validate sudoers with 'visudo -c' in CI pipelines."

  AUTH_WHAT["/etc/sudoers.d"]="/etc/sudoers.d holds additional policy files automatically included by sudo. Writing a new file here has the same effect as modifying /etc/sudoers."
  AUTH_IMPACT["/etc/sudoers.d"]="Same as /etc/sudoers — allows granting passwordless root sudo to any user."
  AUTH_EXPLOIT["/etc/sudoers.d"]="Write a file containing permissive sudo rules. Instant root sudo on next execution."
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

# ---------------------------------------------------------------------------
# 10. Memory access and ptrace scope
# ---------------------------------------------------------------------------
check_memory_access() {
  hdr "10. Process memory access"

  local ptrace_scope
  ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "unknown")
  if [[ "$ptrace_scope" == "0" ]]; then
    warn "ptrace_scope=0: permissive process tracing policy"
    add_finding "ptrace_scope_0" "MEDIUM" \
      "Kernel ptrace_scope is 0 (permissive)" \
      "ptrace_scope=0 means any process owned by the same UID can attach to any other owned process via ptrace(2). This is a host-level kernel parameter readable from within the container." \
      "Combined with a shared host PID namespace, this allows attaching to host processes to read their memory (extracting keys, tokens, passwords), modify their execution flow, or inject shellcode. Even without host PID namespace sharing, this widens intra-container attack surface." \
      "Moderate. Requires a visible target process with value. gdb/strace attachment is trivial once a target is identified. /proc/<pid>/mem injection is well-documented." \
      "Set kernel.yama.ptrace_scope=1 (or higher) in /etc/sysctl.d/ on the host. Value 1 restricts ptrace to parent processes only. Include in host hardening baselines."
  else
    ok "ptrace_scope=$ptrace_scope"
  fi

  if [[ -r /dev/mem || -w /dev/mem ]]; then
    local access="readable"; [[ -w /dev/mem ]] && access="writable"
    crit "/dev/mem is $access"
    add_finding "dev_mem_${access}" "CRITICAL" \
      "/dev/mem is $access (physical memory device)" \
      "/dev/mem is a character device providing direct access to the host's physical memory address space." \
      "Reading exposes all physical RAM contents — kernel code, all running processes' memory, encryption keys, secrets from other containers. Writing enables kernel code patching and arbitrary host compromise." \
      "High. 'dd if=/dev/mem | strings' extracts readable data from all physical memory. Tools like LiME and avml automate memory acquisition. Kernel patching is more complex but well-documented." \
      "Ensure /dev/mem is not passed into containers via --device. Build kernels with CONFIG_STRICT_DEVMEM=y. Apply seccomp to block open(2) on device special files."
  fi
}

# ---------------------------------------------------------------------------
# 11. Security profiles
# ---------------------------------------------------------------------------
check_security_profiles() {
  hdr "11. Security profiles (Seccomp / AppArmor / SELinux)"

  local seccomp_mode
  seccomp_mode=$(grep Seccomp /proc/self/status 2>/dev/null | awk '{print $2}')
  case "$seccomp_mode" in
    0)
      warn "Seccomp: DISABLED"
      add_finding "seccomp_disabled" "MEDIUM" \
        "Seccomp is disabled for this container" \
        "Seccomp restricts the set of system calls available to a process. When disabled, all Linux syscalls are available to the container process." \
        "Many container escape techniques rely on syscalls that a proper seccomp profile would block: unshare(2), clone(2) with namespace flags, mount(2), init_module(2), open_by_handle_at(2), keyctl(2), and perf_event_open(2). Without seccomp, exploitation of capability misconfigurations is significantly easier and more techniques are available." \
        "Seccomp being disabled is not itself an escape vector, but it removes a critical defence-in-depth layer that would otherwise block or complicate most kernel-level escape techniques." \
        "Apply seccompProfile.type: RuntimeDefault to all pods in Kubernetes securityContext. For sensitive workloads, record the minimal required syscalls with tools like Inspektor Gadget or Tetragon and create a custom allowlist profile." ;;
    1) ok "Seccomp: strict mode (mode 1)" ;;
    2) ok "Seccomp: BPF filter active (mode 2)" ;;
  esac

  if [[ -f /proc/self/attr/current ]]; then
    local aa_label
    aa_label=$(cat /proc/self/attr/current 2>/dev/null || echo "")
    if [[ -z "$aa_label" || "$aa_label" == "unconfined" ]]; then
      warn "AppArmor: UNCONFINED"
      add_finding "apparmor_unconfined" "MEDIUM" \
        "AppArmor profile is not applied (unconfined)" \
        "AppArmor applies mandatory access control based on profiles that restrict file access, capabilities, and network operations. An unconfined process has no AppArmor restrictions." \
        "The Docker default AppArmor profile blocks writes to /proc/sys, restricts mount operations, and denies access to several dangerous file paths. Without it, these path-based restrictions are absent, increasing the exploitability of other misconfigurations." \
        "AppArmor being unconfined does not provide a direct escape, but removes protection against file-based attack paths and capability exploitation that the default profile would otherwise restrict." \
        "Ensure the runtime applies an AppArmor profile. Docker applies docker-default unless --security-opt apparmor=unconfined is specified. In Kubernetes, apply profiles via annotations or the securityContext.appArmorProfile field."
    else
      ok "AppArmor profile applied: $aa_label"
    fi
  fi

  if command -v sestatus &>/dev/null; then
    local se_status
    se_status=$(sestatus 2>/dev/null | grep "SELinux status" | awk '{print $NF}' || echo "unknown")
    if [[ "$se_status" != "enabled" ]]; then
      warn "SELinux: $se_status"
      add_finding "selinux_not_enabled" "MEDIUM" \
        "SELinux is not enabled (status: $se_status)" \
        "SELinux is a mandatory access control framework enforcing fine-grained policies on all process actions. Containers on SELinux hosts receive an svirt_lxc_net_t label that significantly restricts what they can access." \
        "Without SELinux, containers can access files and kernel interfaces that SELinux would deny, widening the attack surface for several escape techniques." \
        "SELinux being disabled is a defence-in-depth gap. It increases the impact and exploitability of other misconfigurations rather than providing a direct escape path." \
        "Enable SELinux in enforcing mode on container hosts. Install container-selinux. Never use setenforce 0 in production. Test SELinux denials with audit2allow only for specific understood cases."
    else
      ok "SELinux is enabled"
    fi
  fi
}

# ---------------------------------------------------------------------------
# 12. cgroup v1 release_agent
# ---------------------------------------------------------------------------
check_cgroup_release_agent() {
  hdr "12. cgroup v1 release_agent"
  local found=false
  while IFS= read -r agent_path; do
    [[ -w "$agent_path" ]] || continue
    crit "Writable cgroup release_agent: $agent_path"
    add_finding "cgroup_release_agent_${agent_path//\//_}" "CRITICAL" \
      "Writable cgroup v1 release_agent: $agent_path" \
      "In cgroup v1, the release_agent file specifies a binary that the kernel executes on the HOST (outside all container namespaces) when the last process in a cgroup exits. This is a kernel notification mechanism intended for resource accounting." \
      "Full host code execution as root with no namespace restrictions. The attacker writes a payload script to the container filesystem, sets release_agent to that path, enables notify_on_release, creates a child cgroup, forks a process into it, and kills it. The kernel executes the payload on the host." \
      "Well-documented and automated. Felix Wilhelm's original PoC is ~15 shell commands. CDK, deepce, and other tools implement this as an automated one-click escape. Reliable against any container with CAP_SYS_ADMIN and writable cgroupfs." \
      "Migrate to cgroup v2 (no release_agent). Mount cgroupfs read-only in containers. Remove CAP_SYS_ADMIN. Apply seccomp to block mount(2). Use restricted PSA profile. Detect with Falco: alert on writes to release_agent files."
    found=true
    local notify="${agent_path%/release_agent}/notify_on_release"
    [[ -w "$notify" ]] && warn "  notify_on_release also writable: $notify"
  done < <(find /sys/fs/cgroup -name "release_agent" 2>/dev/null || true)
  [[ "$found" == false ]] && ok "No writable cgroup release_agent found"
}

# ---------------------------------------------------------------------------
# 13. SUID/SGID binaries
# ---------------------------------------------------------------------------
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
        "$bin has the setuid or setgid bit set. It executes with the permissions of its owner (typically root) regardless of who runs it." \
        "If $bin is exploitable via a GTFOBins technique, command injection, argument injection, or library loading flaw, an attacker gains a root shell within the container. Combined with host-mounted filesystems or shared namespaces this may facilitate host escape." \
        "Check https://gtfobins.github.io/ for $bin. Many common SUID binaries (find, vim, python, perl, cp, bash, nmap, less, man) have documented one-liners that spawn root shells. Exploitation is trivial for listed binaries." \
        "Remove all unnecessary SUID/SGID bits: 'chmod u-s,g-s <binary>'. Set no-new-privileges: true in pod securityContext. Use readOnlyRootFilesystem to prevent new SUID binaries being created at runtime. Integrate SUID scanning into CI/CD image scanning pipelines (Trivy, Snyk)."
    done <<< "$bins"
  else
    ok "No SUID/SGID binaries found"
  fi
}

# ---------------------------------------------------------------------------
# 14. Kernel version and CVEs
# ---------------------------------------------------------------------------
check_kernel() {
  hdr "14. Kernel version and known CVEs"
  local kver
  kver=$(uname -r)
  info "Kernel version: $kver"
  add_finding "kernel_version" "INFO" \
    "Kernel version: $kver" \
    "The host kernel version is $kver. This should be cross-referenced against known container escape and privilege escalation CVEs." \
    "Outdated kernels may be vulnerable to container escape CVEs exploitable by unprivileged users inside containers, given that the required syscalls are available (seccomp not blocking them)." \
    "uname -r is available to any user. Version information is sufficient to identify applicable CVEs." \
    "Keep the host kernel patched and updated. Use a container-optimised OS (Flatcar, Bottlerocket, RHCOS) that provides automated security updates. Subscribe to distribution security advisories."

  local kmaj kmin kpatch
  IFS='.' read -r kmaj kmin kpatch <<< "$(echo "$kver" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"
  kmaj="${kmaj:-0}"; kmin="${kmin:-0}"; kpatch="${kpatch:-0}"

  # DirtyPipe: CVE-2022-0847
  if (( kmaj == 5 && kmin >= 8 )); then
    local dirty_pipe=false
    (( kmin > 16 )) && dirty_pipe=false
    (( kmin == 16 && kpatch >= 11 )) && dirty_pipe=false
    (( kmin == 15 && kpatch < 25 )) && dirty_pipe=true
    (( kmin >= 8 && kmin < 15 )) && dirty_pipe=true
    (( kmin == 16 && kpatch < 11 )) && dirty_pipe=true
    if [[ "$dirty_pipe" == true ]]; then
      warn "Kernel $kver may be vulnerable to CVE-2022-0847 (DirtyPipe)"
      add_finding "cve_2022_0847" "HIGH" \
        "Possible DirtyPipe (CVE-2022-0847) — kernel $kver" \
        "DirtyPipe is a kernel vulnerability in the pipe buffer implementation allowing an unprivileged process to overwrite read-only page-cache entries backed by files, including files on read-only bind mounts." \
        "An unprivileged container process can overwrite read-only host files visible via any shared mount: /etc/passwd on a host-mounted volume, SUID binary content on host paths, or other immutable host files. No capabilities required — exploitable by any user in the container." \
        "High. Public PoC exploits were published within 24 hours of CVE disclosure. Straightforward to weaponise (~100 lines of C). In-container exploitation against Kubernetes has been demonstrated." \
        "Update the kernel: 5.16.11+, 5.15.25+, or 5.10.102+ depending on your series. Verify with uname -r post-update. Apply Falco rules to detect anomalous splice operations."
    fi
  fi

  # DirtyCOW: CVE-2016-5195
  if (( kmaj < 4 || (kmaj == 4 && kmin < 8) || (kmaj == 4 && kmin == 8 && kpatch < 3) )); then
    warn "Kernel $kver may be vulnerable to CVE-2016-5195 (DirtyCOW)"
    add_finding "cve_2016_5195" "CRITICAL" \
      "Possible DirtyCOW (CVE-2016-5195) — kernel $kver" \
      "DirtyCOW is a race condition in the kernel's copy-on-write mechanism for memory-mapped files, allowing unprivileged users to write to read-only memory mappings." \
      "Allows overwriting any read-only file including SUID binaries and /etc/passwd as an unprivileged user. Weaponised in multiple real-world container escape incidents." \
      "Very high. Exploits have been available since 2016, are well-understood, and are included in container escape toolkits." \
      "This kernel is severely outdated. Update to a current supported kernel release immediately. Multiple other critical vulnerabilities will also be present on a kernel this old."
  fi

  # runc presence
  if command -v runc &>/dev/null; then
    local rv
    rv=$(runc --version 2>/dev/null | head -1 || echo "unknown")
    info "runc present: $rv"
    add_finding "runc_present" "INFO" \
      "runc binary present in container ($rv)" \
      "The runc container runtime binary is accessible within the container. runc is the OCI runtime used by Docker, containerd, and CRI-O." \
      "If the runc version is pre-1.0-rc6, CVE-2019-5736 allows overwriting the host runc binary by exploiting a file descriptor handling flaw, giving persistent root code execution on the host. The binary's presence also provides namespace manipulation tooling." \
      "Moderate for CVE-2019-5736 (version-dependent). Having runc available reduces the skill barrier for namespace escape attempts." \
      "Remove runc from container images unless strictly required. Update to runc >= 1.0-rc6. Apply seccomp to block the relevant syscalls."
  fi
}

# ---------------------------------------------------------------------------
# 15. Cloud IMDS
# ---------------------------------------------------------------------------
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
        "The cloud provider's IMDS at $url is reachable from within the container. IMDS provides metadata and temporary IAM credentials for the cloud instance role." \
        "An attacker retrieves the temporary IAM credentials and uses them to call cloud APIs. Depending on the instance role's permissions: read secrets from S3/Key Vault/GCS, access other cloud services, escalate IAM permissions, provision new infrastructure, or pivot to other cloud accounts. In many environments the cloud IAM blast radius exceeds that of a host OS escape." \
        "Trivial. A single curl command retrieves the credentials as JSON — no exploit, no special tools required. Automated tools (Pacu, ScoutSuite, CloudFox) perform full cloud enumeration from stolen IMDS credentials." \
        "Enable IMDSv2 (AWS) requiring a session token with hop-limit=1, blocking container access to the host IMDS. Use IRSA/Workload Identity so pods receive only the permissions they need without relying on the instance role. Apply NetworkPolicy or iptables rules to block pod egress to 169.254.169.254."
    else
      ok "IMDS not reachable: $provider (HTTP $code)"
    fi
  done
}

# ---------------------------------------------------------------------------
# 16. Kubelet API exposure
# ---------------------------------------------------------------------------
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
        "The kubelet exposes a read-only HTTP API on port 10255 that historically required no authentication. This endpoint lists all pods running on the node and their full specifications." \
        "An attacker enumerates all pods on the node including their environment variables (which may contain credentials), mounted volume paths, container images, and service account tokens. This provides detailed reconnaissance and may directly expose secrets." \
        "A single curl command returns the complete pod list in JSON. No authentication, no exploit, no credentials required." \
        "Disable the read-only port: set --read-only-port=0 in the kubelet configuration. Include this in your node hardening baseline. Apply NetworkPolicy or host firewall rules to block pod access to port 10255."
    fi

    local auth_code
    auth_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 \
      "https://${target}:10250/pods" 2>/dev/null || echo "000")
    if [[ "$auth_code" == "200" ]]; then
      crit "Kubelet main API accessible anonymously at ${target}:10250"
      add_finding "kubelet_anon_${target//./_}" "CRITICAL" \
        "Kubelet main API accessible without authentication: ${target}:10250" \
        "The kubelet's main API on port 10250 is accessible without credentials. This port provides /exec (command execution), /run (arbitrary execution), and /pods (enumeration) endpoints." \
        "Full code execution in any pod on the node without authentication. An attacker can exec into any container on the node, read all mounted secrets, and pivot to other nodes via the API server. Exploited in the Tesla cryptomining breach and multiple other public incidents." \
        "Trivial. 'curl -sk https://<node>:10250/run/<ns>/<pod>/<container> -d cmd=id' executes commands. Documented and automated in peirates and CDK." \
        "Set --anonymous-auth=false and --authorization-mode=Webhook in kubelet configuration. Restrict port 10250 with firewall rules. Run kube-bench to validate kubelet hardening. Rotate any credentials that may have been exposed."
    fi
  done
}

# ---------------------------------------------------------------------------
# 17. Library injection paths
# ---------------------------------------------------------------------------
check_ld_preload() {
  hdr "17. Dynamic linker injection paths"
  for p in /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d; do
    [[ -e "$p" && -w "$p" ]] || continue
    crit "Writable linker config: $p"
    add_finding "writable_ld_${p//\//_}" "HIGH" \
      "Writable dynamic linker configuration: $p" \
      "/etc/ld.so.preload specifies shared libraries loaded into every process before any other library. /etc/ld.so.conf.d/ specifies additional library search paths. Both are read by the dynamic linker at process startup." \
      "An attacker writes a malicious shared library to /tmp/evil.so, adds its path to /etc/ld.so.preload, and the library is loaded into every subsequent process — including any SUID binary that runs. The library's constructor executes as the SUID binary's UID (root). If shared with the host, this affects host processes too." \
      "Moderate. Requires writing a shared library (feasible with gcc or a pre-compiled payload). Once /etc/ld.so.preload is written, any SUID binary execution triggers the payload automatically." \
      "Apply readOnlyRootFilesystem: true in the pod security context. Use minimal container images without compilers. Implement file integrity monitoring on linker configuration files."
  done
  ok "Library injection path check complete"
}

# ---------------------------------------------------------------------------
# 18. Namespace escape tooling
# ---------------------------------------------------------------------------
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
      "Namespace/runtime escape tool present in container: $t" \
      "$t is a Linux utility for namespace manipulation, container runtime interaction, or filesystem pivoting. Its presence in an application container image is unexpected and increases the attack surface." \
      "nsenter and unshare allow creating or entering Linux namespaces. 'nsenter -t 1 -m -u -i -n -p -- /bin/bash' enters the host's namespaces directly when run with appropriate capabilities. runc, ctr, and crictl interact with container runtimes and can be used to create escape containers." \
      "Low standalone, High when combined with relevant capabilities. 'nsenter -t 1 -m -- /bin/bash' is a single command that enters the host mount namespace when CAP_SYS_ADMIN is present." \
      "Use minimal base images (distroless, scratch, alpine-minimal). Remove all tools not required by the application. Scan images in CI/CD for unexpected binaries. Use immutable, signed container images."
    found=true
  done
  [[ "$found" == false ]] && ok "No namespace escape tooling found in PATH"
}

# ---------------------------------------------------------------------------
# 19. cgroup v2
# ---------------------------------------------------------------------------
check_cgroupv2() {
  hdr "19. cgroup v2 writability"
  [[ -f /sys/fs/cgroup/cgroup.controllers ]] || { ok "cgroup v2 not detected"; return; }
  info "cgroup v2 unified hierarchy detected"

  if [[ -w /sys/fs/cgroup/cgroup.subtree_control ]]; then
    warn "cgroup v2 subtree_control is writable"
    add_finding "cgroupv2_subtree_writable" "MEDIUM" \
      "cgroup v2 cgroup.subtree_control is writable" \
      "cgroup.subtree_control determines which resource controllers are enabled in child cgroups. Writable access indicates broader cgroup write permissions than expected for a container." \
      "While cgroup v2 removes the release_agent escape vector present in v1, writable cgroup paths can be used to manipulate resource limits (DoS attacks against co-located containers or nodes), and in some kernel versions have been used in container escapes via the devices controller or eBPF programs." \
      "Lower than cgroup v1. Direct escape paths in cgroup v2 are less mature. Resource manipulation attacks (CPU starvation, memory pressure) against co-located workloads are straightforward." \
      "Mount cgroupfs read-only in containers. Remove CAP_SYS_ADMIN. Use cgroup v2 delegation correctly through the container runtime rather than direct root cgroup manipulation."
  else
    ok "cgroup v2 subtree_control is not writable"
  fi
}

# ---------------------------------------------------------------------------
# 20. Secret mount exposure
# ---------------------------------------------------------------------------
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
      "The directory $d contains files injected by Docker Swarm, Kubernetes, or a secrets management system. These files typically contain TLS certificates, API tokens, database passwords, or other credentials." \
      "Secrets mounted as files are readable by any process in the container with filesystem access. Misconfigured permissions may make them world-readable. Compromise may allow lateral movement to databases, APIs, or other services." \
      "ls and cat are sufficient. No exploit required. Files: $flist" \
      "Mount secrets with mode 0400 owned by the specific UID the application runs as. Use dynamic secrets management (Vault agent injector, External Secrets Operator) that injects secrets at runtime and revokes them after use. Regularly rotate secrets."
  done
  ok "Secret mount check complete"
}

# ---------------------------------------------------------------------------
# 21. SSH key exposure
# ---------------------------------------------------------------------------
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
          "An SSH private key at $f is readable from within the container. This may be a host-mounted path or a key that was incorrectly included in the container image." \
          "A readable host SSH private key allows direct SSH login to the host node or other nodes in the cluster that trust this key, bypassing the container entirely. This is a direct lateral movement and host escape vector." \
          "'ssh -i $f root@<host_ip>' — a single command if the key is usable. No exploit required." \
          "Never mount SSH key directories into containers. Audit container images for accidentally included private keys using image scanning tools. Rotate any exposed keys immediately."
        found=true
      fi
    done
  done
  [[ "$found" == false ]] && ok "No readable SSH private keys found"
}

# ---------------------------------------------------------------------------
# 22. Kernel module loading status
# ---------------------------------------------------------------------------
check_module_loading() {
  hdr "22. Kernel module loading status"
  local md
  md=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo "unknown")
  case "$md" in
    0)
      info "Module loading is ENABLED (modules_disabled=0)"
      add_finding "modules_loading_enabled" "INFO" \
        "Kernel module loading is enabled (modules_disabled=0)" \
        "modules_disabled=0 means kernel modules can be loaded at runtime. This is the default state. Combined with CAP_SYS_MODULE, this permits loading arbitrary kernel code." \
        "If CAP_SYS_MODULE is also present, a malicious .ko module can be loaded that performs any kernel-level operation: establishing persistence, spawning reverse shells, patching security functions, or disabling audit logging." \
        "High if CAP_SYS_MODULE is present; informational otherwise." \
        "Set kernel.modules_disabled=1 via sysctl after all necessary modules are loaded at boot. This is irreversible without a reboot. Include in host hardening scripts and CIS benchmarks." ;;
    1) ok "Kernel module loading is locked (modules_disabled=1)" ;;
    *) info "modules_disabled value unknown: $md" ;;
  esac
}

# ---------------------------------------------------------------------------
# 23. OverlayFS layer inspection
# ---------------------------------------------------------------------------
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
      "Container filesystems use OverlayFS, layering a writable upper directory over read-only image layers. The upper directory stores runtime modifications. If the upper path is accessible and writable from within the container, filesystem isolation may be weaker than expected." \
      "Access to the overlay upper path may allow reading files as they exist across different image layers (including data 'deleted' in a later layer that still exists in a lower layer), potentially revealing secrets removed during image build." \
      "Low-moderate. More useful for forensic analysis and layer secret extraction than active exploitation." \
      "Ensure the container runtime correctly isolates overlay mount paths. Apply readOnlyRootFilesystem where possible. Use image scanning to verify no sensitive files exist in any image layer."
  else
    ok "OverlayFS upper directory is not writable"
  fi
}

# ===========================================================================
# MAIN
# ===========================================================================

if [[ "$OUTPUT_JSON" == false ]]; then
  echo -e "${BOLD}${CYAN}"
  echo "========================================================"
  echo "  container_escape_audit.sh v2.0"
  echo "  Container escape vector detection"
  echo "  FOR AUTHORISED SECURITY ASSESSMENTS ONLY"
  echo "========================================================"
  echo -e "${RESET}"
  [[ "$NO_REPORT" == false ]] && echo -e "  Report will be written to: ${BOLD}${REPORT_FILE}${RESET}\n"
fi

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
# Terminal summary
# ---------------------------------------------------------------------------
if [[ "$OUTPUT_JSON" == false ]]; then
  echo ""
  echo -e "${BOLD}${CYAN}==================== SUMMARY ====================${RESET}"
  local_crit=0; local_high=0; local_med=0; local_info=0
  for id in "${FINDING_ORDER[@]}"; do
    IFS="$SEP" read -r sev title _ _ _ _ <<< "${FINDINGS[$id]}"
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
