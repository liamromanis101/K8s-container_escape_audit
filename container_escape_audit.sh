#!/usr/bin/env bash
# =============================================================================
# container_escape_audit.sh  —  v4.0
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
#   --report <file>   Write a detailed human-readable report to <file>
#                     (default: container_escape_report_<timestamp>.txt)
#   --json            Also emit a machine-readable JSON summary to stdout
#   --quiet           Suppress info lines; print only WARN/CRITICAL to terminal
#   --no-report       Skip writing the report file entirely
#   --cve-conf <file> Path to CVE check config file
#                     (default: same directory as this script / cve_checks.conf)
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
CVE_CONF=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)       OUTPUT_JSON=true ;;
    --quiet)      QUIET=true ;;
    --no-report)  NO_REPORT=true ;;
    --report)     shift; REPORT_FILE="$1" ;;
    --cve-conf)   shift; CVE_CONF="$1" ;;
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
# ---------------------------------------------------------------------------
declare -A FINDINGS
FINDING_ORDER=()
SEP=$'\x1f'

add_finding() {
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
  echo "  \"version\": \"4.0\","
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
    warn "Running as UID 0 with no user namespace remapping — root-in-container = root-on-host"
    add_finding "uid_zero_no_userns" "HIGH" \
      "Running as UID 0 with no user namespace remapping" \
      "This container is running as root (UID 0) with no user namespace remapping in effect (uid_map: '$uid_map'). UID 0 inside the container corresponds directly to UID 0 on the host kernel." \
      "Any host resource accessible to the container is accessed with full root privileges. This amplifies every other finding: a mount escape, socket access, or capability exploit all lead directly to host root." \
      "Not a standalone exploit, but a force multiplier. Eliminates a key isolation layer." \
      "1) Enable user namespace remapping in Docker: set 'userns-remap: default' in /etc/docker/daemon.json. 2) Set runAsNonRoot: true and runAsUser: <non-zero> in pod security context. 3) Deploy rootless Podman or rootless containerd where possible."
  elif [[ "$uid" != "0" ]]; then
    ok "Running as non-root UID $uid — UID 0 mapping not applicable"
  fi
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
    echo "$paths_str" | grep -q "create_pods\|list_secrets_all\|bind_clusterrole\|create_daemonsets" && severity="CRITICAL"
    crit "Kubernetes RBAC escalation paths identified: ${paths_str}"
    add_finding "k8s_rbac_escalation" "$severity" \
      "Kubernetes RBAC escalation paths available: ${paths_str}" \
      "Active RBAC checks against $api_server confirm this service account has: ${paths_str}." \
      "create_pods in kube-system: can deploy a privileged pod to escape any namespace boundary. list_secrets (cluster-wide): can enumerate all secrets. exec_pods: can execute commands in other pods. bind_clusterrole: can grant cluster-admin to any service account. create_daemonsets: can run on every node." \
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
  inherited_socks=$(ls -la /proc/self/fd 2>/dev/null | grep "socket:" | wc -l || echo "0")
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
  [[ "$keyctl_available" == true ]] && key_count=$(keyctl list @s 2>/dev/null | grep -c "key:" || echo "0")
  local proc_keys_count=0
  [[ -r /proc/keys ]] && proc_keys_count=$(wc -l < /proc/keys 2>/dev/null || echo "0")
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
      local hook_count; hook_count=$(find "$d" -name "*.json" 2>/dev/null | wc -l || echo "0")
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
        return
      else
        val="$ns_max"
        param_name="user.max_user_namespaces (non-zero = enabled)"
      fi
    fi
  fi

  if [[ "$val" == "UNREADABLE" ]]; then
    info "unprivileged user namespace status not determinable from this container"
    return
  fi

  if [[ "$val" == "0" && "$param_name" == "kernel.unprivileged_userns_clone" ]]; then
    ok "unprivileged_userns_clone=0 — unprivileged user namespaces disabled (hardened)"
    return
  fi

  if [[ "$val" == "1" || ("$param_name" != "kernel.unprivileged_userns_clone" && "$val" != "0") ]]; then
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
  while IFS='=' read -r key rest; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    key="${key// /}"
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
      return 1  # Below introduced version — not affected
    fi
  fi

  # Parse fixed_versions: "series:version series:version ..."
  # or "none" meaning no patch available yet
  [[ "$fixed_str" == "none" ]] && return 0  # No fix exists — assume affected

  local kmaj kmin
  IFS='.' read -r kmaj kmin _ <<< "$kver_clean"
  local series="${kmaj}.${kmin}"

  local found_series=false
  local series_fixed_int=0

  for entry in $fixed_str; do
    local s v
    IFS=':' read -r s v <<< "$entry"
    if [[ "$s" == "$series" ]]; then
      found_series=true
      series_fixed_int=$(_kver_to_int "$v")
      break
    fi
  done

  if [[ "$found_series" == true ]]; then
    # We know the fixed version for this series
    if (( kver_int >= series_fixed_int )); then
      return 1  # Kernel is at or above the fix — not affected
    else
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
    for entry in $fixed_str; do
      local s v
      IFS=':' read -r s v <<< "$entry"
      local s_int
      s_int=$(_kver_to_int "${s}.0")
      if (( s_int > max_fixed_series_int )); then
        max_fixed_series_int=$s_int
        max_fixed_int=$(_kver_to_int "$v")
      fi
    done

    local series_int
    series_int=$(_kver_to_int "${series}.0")

    # If running series is newer than the highest fixed series in the list,
    # assume the fix was merged into mainline and this series has it.
    if (( series_int > max_fixed_series_int )); then
      return 1  # Likely patched in this newer series
    fi

    # Running series is older than or equal to the highest fixed series
    # and is not explicitly listed — flag as affected (conservative)
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
  for mod in $mod_str; do
    if grep -q "^${mod} " /proc/modules 2>/dev/null; then
      loaded+=("$mod")
    fi
  done

  if [[ ${#loaded[@]} -gt 0 ]]; then
    echo "${loaded[*]}"
    return 0
  fi
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
  for mod in $mod_str; do
    local found=false
    for f in /etc/modprobe.d/*.conf /etc/modprobe.conf; do
      [[ -r "$f" ]] || continue
      if grep -q "install ${mod} /bin/false" "$f" 2>/dev/null; then
        found=true
        break
      fi
    done
    [[ "$found" == false ]] && not_blacklisted+=("$mod")
  done

  if [[ ${#not_blacklisted[@]} -gt 0 ]]; then
    echo "${not_blacklisted[*]}"
    return 1
  fi
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
  command -v python3 &>/dev/null || return 2  # Can't test without python3

  python3 -c "
import socket, sys
af=$af; st=$st; sp=$sp
try:
    s = socket.socket(af, st, sp)
    s.close()
    sys.exit(0)
except Exception as e:
    import errno as E
    err = getattr(e, 'errno', None)
    # EPERM(1) or EACCES(13): socket family reachable but permission denied
    # EINVAL(22): socket reachable but invalid params
    # EPROTONOSUPPORT(93): AF known but proto not supported — AF reachable
    # EAFNOSUPPORT(97): AF completely absent/blocked
    # ENOSYS(38): syscall blocked by seccomp
    if err in (1, 13, 22, 93):
        sys.exit(0)  # Reachable
    sys.exit(1)      # Not reachable
" 2>/dev/null
}

# ---------------------------------------------------------------------------
# _check_kernel_symbol
# Returns 0 if the symbol is present and not zeroed in /proc/kallsyms.
# ---------------------------------------------------------------------------
_check_kernel_symbol() {
  local sym="${CVE_FIELD[kallsyms_sym]:-}"
  [[ -z "$sym" ]] && return 1
  [[ -r /proc/kallsyms ]] || return 2
  # Zeroed addresses (00000000) indicate kptr_restrict is hiding them
  if grep -q "^[^0].*\b${sym}\b" /proc/kallsyms 2>/dev/null; then
    return 0
  fi
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

  add_finding "cve_${id_safe}" "$sev" "$title" \
    "$full_what" \
    "${CVE_FIELD[impact]:-No impact description available.}" \
    "${CVE_FIELD[exploit]:-No exploitability assessment available.}" \
    "${CVE_FIELD[rec]:-No remediation guidance available.}"
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
  # Build a unique, stable finding ID for this CVE (subsystem slug prevents
  # collisions when two entries share a CVE number, e.g. CVE-2025-38352)
  local _sub_slug
  _sub_slug=$(echo "${CVE_FIELD[subsystem]:-}" | tr "/. " "___")
  local _cve_id_slug="${cve//-/_}"
  _cve_id_slug="${_cve_id_slug,,}"
  [[ -n "$_sub_slug" ]] && _cve_id_slug="${_cve_id_slug}_${_sub_slug}"
  local kver
  kver=$(uname -r 2>/dev/null || echo "unknown")

  case "$check_type" in

    # -----------------------------------------------------------------------
    kernel_version)
      if _kernel_in_affected_range; then
        warn "${cve} (${name}): kernel ${kver} appears in the affected version range"
        _emit_cve_finding "kernel ${kver} in affected range (introduced: ${CVE_FIELD[introduced]:-unknown}, fixed_versions: ${CVE_FIELD[fixed_versions]:-none})"
      else
        ok "${cve} (${name}): kernel ${kver} appears outside affected range"
        add_finding "cve_${_cve_id_slug}" "INFO" \
          "${name} (${cve}) — kernel ${kver} appears patched" \
          "CVE: ${cve}. Kernel ${kver} is at or above the fixed version for this series, or below the introduced version. fixed_versions: ${CVE_FIELD[fixed_versions]:-none}." \
          "N/A — kernel version check passed." "N/A" \
          "Continue to apply kernel updates. Verify with your distribution's security advisory."
      fi
      ;;

    # -----------------------------------------------------------------------
    module_loaded)
      local loaded_mods
      loaded_mods=$(_check_module_loaded)
      if [[ $? -eq 0 ]]; then
        warn "${cve} (${name}): vulnerable module(s) loaded: ${loaded_mods}"
        _emit_cve_finding "module(s) loaded: ${loaded_mods}"
      else
        ok "${cve} (${name}): no vulnerable modules loaded (${CVE_FIELD[module_names]:-none})"
        add_finding "cve_${_cve_id_slug}" "INFO" \
          "${name} (${cve}) — no vulnerable modules loaded" \
          "CVE: ${cve}. Module(s) ${CVE_FIELD[module_names]:-none} are not currently loaded in /proc/modules. Note: without a blacklist entry, auto-loading on socket creation remains possible." \
          "N/A — modules not loaded." "N/A" \
          "Add a modprobe blacklist entry even when modules are not loaded: ${CVE_FIELD[mitigation]:-see vendor advisory}."
      fi
      ;;

    # -----------------------------------------------------------------------
    socket_family)
      local sock_result
      _check_socket_accessible
      sock_result=$?
      if [[ $sock_result -eq 0 ]]; then
        warn "${cve} (${name}): socket family AF=${CVE_FIELD[socket_af]} is accessible"
        _emit_cve_finding "socket AF=${CVE_FIELD[socket_af]} SOCK=${CVE_FIELD[socket_type]} accessible from container"
      elif [[ $sock_result -eq 2 ]]; then
        info "${cve} (${name}): socket check skipped (python3 not available)"
      else
        ok "${cve} (${name}): socket AF=${CVE_FIELD[socket_af]} not accessible"
      fi
      ;;

    # -----------------------------------------------------------------------
    kernel_symbol)
      local sym_result
      _check_kernel_symbol
      sym_result=$?
      if [[ $sym_result -eq 0 ]]; then
        warn "${cve} (${name}): kernel symbol '${CVE_FIELD[kallsyms_sym]}' visible in /proc/kallsyms"
        _emit_cve_finding "kernel symbol ${CVE_FIELD[kallsyms_sym]} present in /proc/kallsyms"
      elif [[ $sym_result -eq 2 ]]; then
        info "${cve} (${name}): /proc/kallsyms not readable — symbol check skipped"
      else
        ok "${cve} (${name}): symbol '${CVE_FIELD[kallsyms_sym]}' not visible (kptr_restrict may be active)"
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
      if [[ "${CVE_FIELD[module_names]:-none}" != "none" ]]; then
        local ml
        ml=$(_check_module_loaded) && mod_loaded_list="$ml"
        local mnb
        mnb=$(_check_module_blacklisted) || mod_not_blacklisted="$mnb"
      fi

      # 3 — socket check
      if [[ "${CVE_FIELD[socket_af]:-none}" != "none" ]]; then
        _check_socket_accessible && socket_accessible=true
      fi

      # Severity logic:
      # CRITICAL: kernel affected + (module loaded OR socket accessible)
      # HIGH:     kernel affected + module not blacklisted (auto-load possible)
      #           OR kernel possibly affected + socket accessible (no version data)
      # MEDIUM:   kernel affected but no module/socket info, or inconclusive
      # INFO:     kernel not in affected range

      if [[ "$kver_affected" == true ]]; then
        if [[ -n "$mod_loaded_list" || "$socket_accessible" == true ]]; then
          overall_sev="${CVE_FIELD[severity]:-CRITICAL}"
          crit "${cve} (${name}): LIKELY VULNERABLE — kernel ${kver} in range; module(s) loaded / socket accessible"
          _emit_cve_finding \
            "kernel in affected range; loaded modules: ${mod_loaded_list:-none}; socket AF=${CVE_FIELD[socket_af]:-N/A} accessible: ${socket_accessible}; non-blacklisted: ${mod_not_blacklisted:-none}" \
            "$overall_sev"
        elif [[ -n "$mod_not_blacklisted" ]]; then
          overall_sev="HIGH"
          warn "${cve} (${name}): kernel ${kver} in affected range; module(s) not loaded but NOT blacklisted (auto-load risk): ${mod_not_blacklisted}"
          _emit_cve_finding \
            "kernel in affected range; modules not currently loaded but not blacklisted — auto-load on socket creation is possible: ${mod_not_blacklisted}" \
            "HIGH"
        else
          overall_sev="MEDIUM"
          warn "${cve} (${name}): kernel ${kver} in affected range; modules appear blacklisted or absent"
          _emit_cve_finding \
            "kernel in affected range; modules not loaded and appear blacklisted — interim mitigation may be in effect, but kernel patch is still required" \
            "MEDIUM"
        fi
      else
        ok "${cve} (${name}): kernel ${kver} outside affected range or fixed"
        add_finding "cve_${_cve_id_slug}" "INFO" \
          "${name} (${cve}) — kernel ${kver} appears outside affected range" \
          "CVE: ${cve}. Compound check: kernel version check passed (not in affected range or at/above fixed version). Module status: loaded=${mod_loaded_list:-none}, not-blacklisted=${mod_not_blacklisted:-none}. Socket accessible: ${socket_accessible}." \
          "N/A — kernel version check passed." "N/A" \
          "Verify with distribution advisory. Continue applying kernel updates."
      fi
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
  echo "  container_escape_audit.sh v4.0"
  echo "  Container escape vector detection"
  echo "  FOR AUTHORISED SECURITY ASSESSMENTS ONLY"
  echo "========================================================"
  echo -e "${RESET}"
  [[ "$NO_REPORT" == false ]] && echo -e "  Report will be written to: ${BOLD}${REPORT_FILE}${RESET}\n"
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
# Config-driven CVE checks (reads cve_checks.conf)
# ---------------------------------------------------------------------------
# Resolve config file path: CLI flag > environment variable > script directory
if [[ -z "$CVE_CONF" ]]; then
  CVE_CONF="${CVE_CONF_ENV:-}"
fi
if [[ -z "$CVE_CONF" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  CVE_CONF="${SCRIPT_DIR}/cve_checks.conf"
fi
run_cve_checks "$CVE_CONF"

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
