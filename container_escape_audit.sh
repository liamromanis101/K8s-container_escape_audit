#!/usr/bin/env bash
# =============================================================================
# container_escape_audit.sh  —  v3.0
# Liam Romanis
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
  echo "  \"version\": \"3.0\","
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
# CHECK FUNCTIONS  —  Checks 1-23 (original)
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
  hdr "14. Kernel version and known CVEs"
  local kver
  kver=$(uname -r)
  info "Kernel version: $kver"
  add_finding "kernel_version" "INFO" \
    "Kernel version: $kver" \
    "The host kernel version is $kver. Cross-reference against known container escape and privilege escalation CVEs." \
    "Outdated kernels may be vulnerable to container escape CVEs exploitable by unprivileged users inside containers." \
    "uname -r is available to any user. Version information is sufficient to identify applicable CVEs." \
    "Keep the host kernel patched. Use a container-optimised OS with automated security updates."

  local kmaj kmin kpatch
  IFS='.' read -r kmaj kmin kpatch <<< "$(echo "$kver" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')"
  kmaj="${kmaj:-0}"; kmin="${kmin:-0}"; kpatch="${kpatch:-0}"

  if (( kmaj == 5 && kmin >= 8 )); then
    local dirty_pipe=false
    (( kmin == 15 && kpatch < 25 )) && dirty_pipe=true
    (( kmin >= 8 && kmin < 15 )) && dirty_pipe=true
    (( kmin == 16 && kpatch < 11 )) && dirty_pipe=true
    if [[ "$dirty_pipe" == true ]]; then
      warn "Kernel $kver may be vulnerable to CVE-2022-0847 (DirtyPipe)"
      add_finding "cve_2022_0847" "HIGH" \
        "Possible DirtyPipe (CVE-2022-0847) — kernel $kver" \
        "DirtyPipe allows an unprivileged process to overwrite read-only page-cache entries backed by files, including files on read-only bind mounts." \
        "An unprivileged container process can overwrite read-only host files visible via any shared mount. No capabilities required." \
        "High. Public PoC exploits published within 24 hours of CVE disclosure. In-container exploitation against Kubernetes demonstrated." \
        "Update the kernel: 5.16.11+, 5.15.25+, or 5.10.102+ depending on your series."
    fi
  fi

  if (( kmaj < 4 || (kmaj == 4 && kmin < 8) || (kmaj == 4 && kmin == 8 && kpatch < 3) )); then
    warn "Kernel $kver may be vulnerable to CVE-2016-5195 (DirtyCOW)"
    add_finding "cve_2016_5195" "CRITICAL" \
      "Possible DirtyCOW (CVE-2016-5195) — kernel $kver" \
      "DirtyCOW is a race condition in the kernel's copy-on-write mechanism allowing unprivileged users to write to read-only memory mappings." \
      "Allows overwriting SUID binaries and /etc/passwd as an unprivileged user. Weaponised in multiple container escape incidents." \
      "Very high. Exploits have been available since 2016 and are included in container escape toolkits." \
      "This kernel is severely outdated. Update to a current supported kernel release immediately."
  fi
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
# CHECK FUNCTIONS  —  Checks 24-35 (NEW — USP additions)
# ===========================================================================

# ---------------------------------------------------------------------------
# 24. Copy Fail — CVE-2026-31431
# Checks AF_ALG socket family and algif_aead availability — the two
# prerequisites for the Copy Fail privilege escalation exploit.
# ---------------------------------------------------------------------------
check_copy_fail() {
  hdr "24. Copy Fail (CVE-2026-31431) — AF_ALG algif_aead"

  local af_alg_available=false
  local aead_loaded=false
  local kver
  kver=$(uname -r 2>/dev/null || echo "unknown")

  # Check 1: can an AF_ALG socket be created?
  if python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.close()
    sys.exit(0)
except:
    sys.exit(1)
" 2>/dev/null; then
    af_alg_available=true
  fi

  # Check 2: is the algif_aead module loaded?
  if grep -q "^algif_aead" /proc/modules 2>/dev/null; then
    aead_loaded=true
  fi

  # Check 3: can we bind an authencesn AEAD socket (full prerequisite test)?
  local aead_bindable=false
  if python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(({'type': 'aead', 'name': 'authencesn(hmac(sha512),cbc(aes))'}))
    s.close()
    sys.exit(0)
except:
    sys.exit(1)
" 2>/dev/null; then
    aead_bindable=true
  fi

  # Check 4: splice syscall available (required for page cache write primitive)
  local splice_ok=false
  if grep -q "^splice" /proc/kallsyms 2>/dev/null || \
     python3 -c "import ctypes; ctypes.CDLL(None).splice" 2>/dev/null; then
    splice_ok=true
  fi

  local severity="INFO"
  local what impact exploit rec

  if [[ "$aead_bindable" == true ]]; then
    severity="CRITICAL"
    what="AF_ALG socket family is accessible and the authencesn AEAD algorithm can be bound from within this container. This is the complete prerequisite state for CVE-2026-31431 (Copy Fail). Kernel: $kver. algif_aead module loaded: $aead_loaded. splice available: $splice_ok."
    impact="Copy Fail (CVE-2026-31431) allows an unprivileged user to perform controlled 4-byte writes into the page cache of any readable executable via AF_ALG + splice(). By corrupting the in-memory copy of a setuid binary (e.g. /usr/bin/su), an attacker triggers privilege escalation when any privileged process runs the corrupted file. A public 732-byte Python PoC achieves reliable root on Ubuntu 24.04, Amazon Linux 2023, RHEL 10.1, SUSE 16, and any Linux distribution shipping a kernel built since 2017. Exploit is on the CISA KEV list with active in-the-wild exploitation confirmed."
    exploit="Trivial. A single Python script (~732 bytes, no dependencies beyond the standard library) achieves root reliably. CVSS 7.8. No capabilities required — any unprivileged user inside the container can exploit this if patches have not been applied."
    rec="1) Apply kernel patches from your distribution immediately (released by major distros from late April 2026). 2) Interim: unload algif_aead: 'rmmod algif_aead' and block reloading with 'echo install algif_aead /bin/false >> /etc/modprobe.d/disable-algif_aead.conf'. 3) Consider a seccomp profile that blocks AF_ALG socket creation if not required by workloads. 4) Verify patch status: python3 -c \"import socket; s=socket.socket(socket.AF_ALG,socket.SOCK_SEQPACKET); s.bind({'type':'aead','name':'authencesn(hmac(sha512),cbc(aes))'})\" should raise an exception on patched systems."
    crit "VULNERABLE to Copy Fail (CVE-2026-31431) — AEAD socket bindable, kernel $kver"

  elif [[ "$af_alg_available" == true ]]; then
    severity="HIGH"
    what="AF_ALG socket family is accessible from within this container but the full AEAD bind test failed. Kernel: $kver. algif_aead loaded: $aead_loaded."
    impact="The AF_ALG socket is reachable which is the first prerequisite for Copy Fail (CVE-2026-31431). The specific authencesn algorithm may not be available, but other AF_ALG-based attack paths may exist. The algif_aead module may be loadable even if not currently active."
    exploit="Moderate. The full PoC requires a bindable AEAD algorithm, but the AF_ALG surface being exposed warrants investigation."
    rec="Apply kernel patches. Block algif_aead loading via modprobe blacklist. Test full AEAD bindability and patch regardless of test result."
    warn "AF_ALG accessible but AEAD bind failed — partial Copy Fail exposure, kernel $kver"

  else
    severity="INFO"
    what="AF_ALG socket family does not appear to be accessible from this container. Kernel: $kver."
    impact="Copy Fail (CVE-2026-31431) requires AF_ALG access. If AF_ALG is blocked or absent, this specific exploit path is not available from this container."
    exploit="N/A — AF_ALG not accessible."
    rec="No action required for this specific check. Ensure the host kernel is patched regardless."
    ok "AF_ALG not accessible — Copy Fail (CVE-2026-31431) not directly reachable"
  fi

  add_finding "cve_2026_31431_copy_fail" "$severity" \
    "Copy Fail (CVE-2026-31431) AF_ALG exposure — $severity" \
    "$what" "$impact" "$exploit" "$rec"
}

# ---------------------------------------------------------------------------
# 25. NVIDIAScape — CVE-2025-23266
# NVIDIA Container Toolkit OCI hook LD_PRELOAD injection.
# Checks for vulnerable NCT version, NVIDIA runtime environment, and
# suspicious LD_PRELOAD values.
# ---------------------------------------------------------------------------
check_nvidiascape() {
  hdr "25. NVIDIAScape (CVE-2025-23266) — NVIDIA Container Toolkit"

  local nvidia_ctk_found=false
  local nvidia_ctk_version="not found"
  local vulnerable_version=false
  local nvidia_runtime=false
  local ld_preload_val="${LD_PRELOAD:-}"
  local ld_preload_suspicious=false
  local hooks_exposed=false

  # Check for nvidia-ctk binary and version
  if command -v nvidia-ctk &>/dev/null; then
    nvidia_ctk_found=true
    nvidia_ctk_version=$(nvidia-ctk --version 2>/dev/null | head -1 || echo "unknown")
    local ver_num
    ver_num=$(echo "$nvidia_ctk_version" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$ver_num" ]]; then
      local major minor patch
      IFS='.' read -r major minor patch <<< "$ver_num"
      # Vulnerable: <= 1.17.7
      if (( major < 1 )) || \
         (( major == 1 && minor < 17 )) || \
         (( major == 1 && minor == 17 && patch < 8 )); then
        vulnerable_version=true
      fi
    fi
  fi

  # Check for NVIDIA runtime indicators
  if env 2>/dev/null | grep -q "NVIDIA_VISIBLE_DEVICES\|NVIDIA_DRIVER_CAPABILITIES" || \
     grep -q "NVIDIA_VISIBLE_DEVICES\|NVIDIA_DRIVER_CAPABILITIES" /proc/1/environ 2>/dev/null; then
    nvidia_runtime=true
  fi

  # Check for suspicious LD_PRELOAD (attacker indicator)
  if [[ -n "$ld_preload_val" ]]; then
    # Suspicious if it points to a file in container-writable paths
    if echo "$ld_preload_val" | grep -qE '^(/tmp|/dev/shm|/run|/var/tmp)'; then
      ld_preload_suspicious=true
    fi
  fi

  # Check for OCI hooks directory accessibility
  if [[ -d /run/oci/hooks.d ]] || [[ -d /usr/share/containers/oci/hooks.d ]]; then
    hooks_exposed=true
  fi

  if [[ "$nvidia_ctk_found" == true && "$vulnerable_version" == true ]]; then
    crit "VULNERABLE: NVIDIA Container Toolkit $nvidia_ctk_version (CVE-2025-23266 NVIDIAScape)"
    add_finding "cve_2025_23266_nvidiascape" "CRITICAL" \
      "NVIDIAScape (CVE-2025-23266) — vulnerable NVIDIA Container Toolkit $nvidia_ctk_version" \
      "NVIDIA Container Toolkit version $nvidia_ctk_version is present and is <= 1.17.7 (the last vulnerable version). The toolkit's createContainer OCI hook inherits environment variables from the container image without sanitisation. An attacker sets LD_PRELOAD in a container image to point to a malicious .so file; the hook loads this library into a privileged host process during container initialisation, before namespace isolation is complete. LD_PRELOAD currently set: '${ld_preload_val:-none}'. NVIDIA runtime env vars present: $nvidia_runtime. OCI hooks directory exposed: $hooks_exposed." \
      "Full root access on the host from a three-line Dockerfile. CVSS 9.0. The vulnerability is particularly acute in shared GPU multi-tenant cloud environments (managed AI services) where a malicious customer image can escape to the host and access data from all other customers sharing the same GPU node. Affects all major cloud providers that offer GPU-accelerated container services." \
      "Trivial. A three-line Dockerfile (FROM nvidia/cuda base, ENV LD_PRELOAD=./evil.so, COPY evil.so .) is sufficient. No credentials, no kernel bugs, no GPU access required — just a crafted image scheduled to a GPU node. Working PoC published by Wiz Research (July 2025)." \
      "1) Upgrade NVIDIA Container Toolkit to >= 1.17.8 and GPU Operator to >= 25.3.1 immediately. 2) As an interim measure, disable the vulnerable hook: set 'disable-cuda-compat-lib-hook = true' in /etc/nvidia-container-toolkit/config.toml. 3) Scan running pods for images with LD_PRELOAD set to unusual library paths. 4) Restrict cluster-admin rights to prevent untrusted images being scheduled to GPU nodes. 5) Monitor for unexpected host processes spawned as children of containerd."

  elif [[ "$nvidia_ctk_found" == true && "$vulnerable_version" == false ]]; then
    ok "NVIDIA Container Toolkit $nvidia_ctk_version found — version appears patched (>= 1.17.8)"
    add_finding "cve_2025_23266_nvidiascape" "INFO" \
      "NVIDIAScape (CVE-2025-23266) — NVIDIA CTK present, version appears patched" \
      "NVIDIA Container Toolkit $nvidia_ctk_version is present. This version appears to be >= 1.17.8 (patched for CVE-2025-23266). Verify the patch is correctly applied." \
      "N/A — toolkit version appears patched." \
      "N/A" \
      "Verify the version with 'nvidia-ctk --version'. Ensure GPU Operator is also updated to >= 25.3.1 if used."

  elif [[ "$nvidia_runtime" == true ]]; then
    warn "NVIDIA runtime environment detected but nvidia-ctk binary not found in PATH"
    add_finding "cve_2025_23266_nvidiascape" "MEDIUM" \
      "NVIDIAScape (CVE-2025-23266) — NVIDIA runtime detected, CTK not in PATH" \
      "NVIDIA runtime environment variables are present (NVIDIA_VISIBLE_DEVICES or NVIDIA_DRIVER_CAPABILITIES), indicating this container is running on a GPU-enabled host with NVIDIA container tooling, but nvidia-ctk was not found in PATH for version verification. LD_PRELOAD: '${ld_preload_val:-none}'." \
      "If the host's NVIDIA Container Toolkit is <= 1.17.7, this environment is vulnerable to CVE-2025-23266. Cannot confirm without the nvidia-ctk binary being accessible." \
      "Moderate. Cannot confirm vulnerability without version check, but NVIDIA runtime presence warrants investigation." \
      "Verify the NVIDIA Container Toolkit version on the host node. Upgrade to >= 1.17.8 if not already patched."

  elif [[ "$ld_preload_suspicious" == true ]]; then
    warn "LD_PRELOAD points to suspicious path: $ld_preload_val"
    add_finding "ld_preload_suspicious" "HIGH" \
      "Suspicious LD_PRELOAD value pointing to writable path: $ld_preload_val" \
      "LD_PRELOAD is set to a path in a commonly writable directory ($ld_preload_val). Even without NVIDIA tooling, a suspicious LD_PRELOAD can indicate active exploitation, a misconfigured image, or preparation for library injection attacks." \
      "LD_PRELOAD libraries are loaded into every process in this container before any other library, with their constructor functions executing at process start. A malicious library can intercept any function call, exfiltrate data, or escalate privileges." \
      "If the .so file at $ld_preload_val is attacker-controlled, it executes in every new process automatically." \
      "Investigate the source and content of $ld_preload_val. Remove LD_PRELOAD from container image ENV directives unless strictly required. Apply AppArmor/SELinux to restrict unexpected library loading."

  else
    ok "No NVIDIA Container Toolkit found and no suspicious LD_PRELOAD (CVE-2025-23266 not applicable)"
  fi
}

# ---------------------------------------------------------------------------
# 26. runc masked path race — CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881
# Checks runc version and whether the maskedPaths bypass conditions are met.
# All three CVEs were patched in runc 1.2.8, 1.3.3, and 1.4.0-rc.3.
# ---------------------------------------------------------------------------
check_runc_masked_path() {
  hdr "26. runc masked path race (CVE-2025-31133 / -52565 / -52881)"

  local runc_found=false
  local runc_version="not found"
  local vulnerable=false

  # Locate runc — may be in /usr/bin, /usr/local/bin, or in the runtime path
  local runc_bin
  runc_bin=$(command -v runc 2>/dev/null || \
             ls /usr/bin/runc /usr/local/bin/runc /usr/sbin/runc 2>/dev/null | head -1 || echo "")

  if [[ -n "$runc_bin" && -x "$runc_bin" ]]; then
    runc_found=true
    runc_version=$("$runc_bin" --version 2>/dev/null | grep "^runc version" | awk '{print $3}' || echo "unknown")
  fi

  # Also check containerd/docker for the bundled runc version
  local bundled_runc_ver=""
  if command -v docker &>/dev/null; then
    bundled_runc_ver=$(docker info 2>/dev/null | grep -i "runc version" | awk '{print $NF}' || echo "")
  fi

  # Check if /dev/null is a genuine character device (if not, a symlink swap may be in progress)
  local devnull_ok=true
  if [[ ! -c /dev/null ]]; then
    devnull_ok=false
  fi

  # Check if /proc/sys/kernel/core_pattern is a masked path (should not be writable)
  local core_pattern_writable=false
  [[ -w /proc/sys/kernel/core_pattern ]] && core_pattern_writable=true

  # Version vulnerability check
  # Vulnerable: runc < 1.2.8, < 1.3.3, < 1.4.0-rc.3
  if [[ "$runc_found" == true && "$runc_version" != "unknown" ]]; then
    local major minor patch pre
    # Parse version like "1.2.7" or "1.4.0-rc.2"
    major=$(echo "$runc_version" | grep -oE '^[0-9]+' || echo "0")
    minor=$(echo "$runc_version" | grep -oE '^\d+\.([0-9]+)' | grep -oE '[0-9]+$' || echo "0")
    patch=$(echo "$runc_version" | grep -oE '^\d+\.\d+\.([0-9]+)' | grep -oE '[0-9]+$' || echo "0")
    pre=$(echo "$runc_version" | grep -oE 'rc\.[0-9]+' | grep -oE '[0-9]+$' || echo "99")

    # Simplified: flag if version string contains pre-1.2.8 indicators
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
      "runc version $runc_version is present and is vulnerable to three related race condition container escape CVEs disclosed in November 2025. CVE-2025-31133: runc uses /dev/null to mask sensitive host files via maskedPaths, but fails to verify the /dev/null inode is genuine — an attacker can replace /dev/null with a symlink during the mount window, causing runc to bind-mount the symlink target (e.g. /proc/sys/kernel/core_pattern) read-write into the container. CVE-2025-52565: similar attack via /dev/console bind-mount (/dev/pts/\$n symlink replacement). CVE-2025-52881: more sophisticated arbitrary write gadget via procfs write redirects, also bypasses LSM labels (AppArmor/SELinux). /dev/null is genuine character device: $devnull_ok. core_pattern currently writable: $core_pattern_writable." \
      "Full container breakout achievable by a low-privileged local attacker who can spawn containers. All three CVEs ultimately allow writing to arbitrary /proc files including /proc/sys/kernel/core_pattern (arbitrary host code execution on crash) and /proc/sysrq-trigger (immediate host reboot). CVE-2025-52881 specifically bypasses AppArmor and SELinux mitigations. OCI classifies this as high severity noting 'any attacker that can spawn containers' can exploit it." \
      "Moderate complexity due to race condition timing. Requires the ability to spawn containers (low privilege bar in many environments). No public automated PoC at time of writing, but technical details are fully public and the attack surface is well-understood. CVE-2025-31133 CVSS 7.3." \
      "Update runc immediately to >= 1.2.8, >= 1.3.3, or >= 1.4.0-rc.3. Verify: 'runc --version'. Enable user namespaces for containers (host root not mapped) — this blocks the most severe aspects as the procfs files use DAC permissions. Use rootless containers where possible. Note: AppArmor and SELinux provide limited mitigation due to CVE-2025-52881's LSM bypass."

  elif [[ "$runc_found" == true ]]; then
    ok "runc $runc_version found — version appears patched for CVE-2025-31133/-52565/-52881"
    add_finding "cve_2025_31133_runc_masked" "INFO" \
      "runc masked path CVEs (CVE-2025-31133/-52565/-52881) — version $runc_version appears patched" \
      "runc $runc_version is present. This version appears to be >= 1.2.8/1.3.3 (patched). core_pattern writable: $core_pattern_writable." \
      "N/A — runc version appears patched." "N/A" \
      "Verify with 'runc --version'. Ensure containerd/Docker are also updated to use the patched runc."

  else
    ok "runc binary not found in PATH — CVE-2025-31133 direct check not possible"
    if [[ "$core_pattern_writable" == true ]]; then
      warn "core_pattern is writable — runc masked path vulnerability may still apply via the container runtime"
      add_finding "cve_2025_31133_indirect" "HIGH" \
        "core_pattern writable — runc masked path bypass may be in effect" \
        "runc was not found in PATH but /proc/sys/kernel/core_pattern is writable. This suggests maskedPaths protection may not be functioning correctly, consistent with CVE-2025-31133 exploitation or misconfiguration." \
        "Writable core_pattern allows arbitrary host code execution on any process crash. This is the primary impact of CVE-2025-31133." \
        "High — core_pattern writability is itself a confirmed escape vector regardless of runc version." \
        "Investigate why core_pattern is writable. Update the container runtime. Mount /proc/sys read-only inside containers."
    fi
  fi
}

# ---------------------------------------------------------------------------
# 27. User namespace UID 0 mapping
# If the container runs as root (UID 0) without user namespace remapping,
# any host filesystem access means root-in-container = root-on-host.
# ---------------------------------------------------------------------------
check_user_namespace_mapping() {
  hdr "27. User namespace UID mapping"

  local uid
  uid=$(id -u)
  local uid_map
  uid_map=$(cat /proc/self/uid_map 2>/dev/null || echo "")
  local user_ns_isolated=false

  # Check if we're in a user namespace with UID 0 remapped
  # uid_map format: <inside_uid> <outside_uid> <count>
  if [[ -n "$uid_map" ]]; then
    local inside outside count
    read -r inside outside count <<< "$uid_map"
    # If inside=0 and outside=0, root in container = root on host (NO remapping)
    # If inside=0 and outside!=0, root in container is a non-root user on host (remapped)
    if [[ "$inside" == "0" && "$outside" != "0" ]]; then
      user_ns_isolated=true
      ok "User namespace remapping active: container UID 0 maps to host UID $outside"
    fi
  fi

  if [[ "$uid" == "0" && "$user_ns_isolated" == false ]]; then
    warn "Running as UID 0 with no user namespace remapping — root-in-container = root-on-host"
    add_finding "uid_zero_no_userns" "HIGH" \
      "Running as UID 0 with no user namespace remapping" \
      "This container is running as root (UID 0) and there is no user namespace remapping in effect (uid_map: '$uid_map'). Without user namespace remapping, the process's UID 0 inside the container corresponds directly to UID 0 (root) on the host kernel." \
      "Any host resource accessible to the container (mounted files, devices, /proc entries, kernel interfaces) is accessed with full root privileges. There is no UID-level isolation between the container and the host. This amplifies every other finding: a mount escape, socket access, or capability exploit all lead directly to host root with no UID boundary to cross." \
      "Not a standalone exploit, but a force multiplier. Eliminates a key isolation layer and means any other misconfiguration yields host root rather than an unprivileged foothold." \
      "1) Enable user namespace remapping in Docker: set 'userns-remap: default' in /etc/docker/daemon.json. 2) In Kubernetes, use rootless containers or configure the runtime with user namespace support (Kubernetes 1.30+ stable). 3) Set runAsNonRoot: true and runAsUser: <non-zero> in pod security context. 4) Deploy rootless Podman or rootless containerd where possible."
  elif [[ "$uid" != "0" ]]; then
    ok "Running as non-root UID $uid — UID 0 mapping not applicable"
  fi
}

# ---------------------------------------------------------------------------
# 28. eBPF exposure
# CAP_BPF or CAP_SYS_ADMIN + bpf(2) syscall availability enables
# kernel memory inspection and in some versions code execution.
# ---------------------------------------------------------------------------
check_ebpf_exposure() {
  hdr "28. eBPF exposure"

  local capeff
  capeff=$(grep CapEff /proc/self/status | awk '{print $2}')
  local cap_dec
  cap_dec=$(printf "%d" "0x${capeff}")

  # CAP_BPF = bit 39, CAP_SYS_ADMIN = bit 21, CAP_PERFMON = bit 38
  local cap_bpf=$(( (cap_dec >> 39) & 1 ))
  local cap_sys_admin=$(( (cap_dec >> 21) & 1 ))
  local cap_perfmon=$(( (cap_dec >> 38) & 1 ))

  local bpf_syscall_available=false
  local unprivileged_bpf=false

  # Check if bpf syscall is available (not seccomp-blocked)
  if python3 -c "
import ctypes, sys
NR_BPF = 321  # x86_64
libc = ctypes.CDLL(None, use_errno=True)
# BPF_PROG_TYPE_SOCKET_FILTER=1, BPF_PROG_LOAD=5 — passing invalid args to probe availability
ret = libc.syscall(NR_BPF, 5, ctypes.c_void_p(0), 0)
import ctypes.util
err = ctypes.get_errno()
# EPERM(1) or EINVAL(22) means syscall is available but we lack perms/args
# ENOSYS(38) means blocked or absent
sys.exit(0 if err in (1, 22) else 1)
" 2>/dev/null; then
    bpf_syscall_available=true
  fi

  # Check unprivileged BPF setting
  local ubpf
  ubpf=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "unknown")
  if [[ "$ubpf" == "0" ]]; then
    unprivileged_bpf=true
  fi

  local bpf_capable=false
  [[ "$cap_bpf" == "1" || "$cap_sys_admin" == "1" ]] && bpf_capable=true

  if [[ "$bpf_capable" == true && "$bpf_syscall_available" == true ]]; then
    crit "eBPF accessible with elevated capabilities (CAP_BPF=$cap_bpf, CAP_SYS_ADMIN=$cap_sys_admin)"
    add_finding "ebpf_privileged_access" "CRITICAL" \
      "eBPF accessible with CAP_BPF/CAP_SYS_ADMIN — kernel memory inspection possible" \
      "This container has CAP_BPF ($cap_bpf) or CAP_SYS_ADMIN ($cap_sys_admin) capability and the bpf(2) syscall is available and not seccomp-blocked. eBPF (extended Berkeley Packet Filter) is a powerful kernel subsystem that allows loading programs that run in kernel context. unprivileged_bpf_disabled: $ubpf." \
      "With CAP_BPF and bpf(2) available, an attacker can: (1) Load BPF programs that inspect and exfiltrate arbitrary kernel memory, including memory belonging to other containers and host processes — effectively reading all data in the system. (2) In kernels < 5.15 with appropriate conditions, certain BPF verifier bypasses allowed arbitrary kernel writes (CVE-2021-3490 class). (3) Attach kprobes/uprobes to monitor and intercept any function in the kernel or any process on the host. (4) Create covert networking channels invisible to standard monitoring tools." \
      "High for memory inspection and monitoring. Kernel version-dependent for code execution. BPF verifier exploits have been published (CVE-2021-3490, CVE-2022-2785). Even without a verifier bug, capability to load BPF programs and attach kprobes is a significant security boundary violation in a container context." \
      "Remove CAP_BPF and CAP_SYS_ADMIN from containers that do not specifically require eBPF functionality. Apply seccomp profile blocking bpf(2) syscall (syscall number 321 on x86_64). Set kernel.unprivileged_bpf_disabled=1 on the host. Use dedicated eBPF security tooling (Tetragon, Falco with eBPF) on the host rather than exposing BPF capabilities to workloads."

  elif [[ "$unprivileged_bpf" == true && "$bpf_syscall_available" == true ]]; then
    warn "Unprivileged eBPF is enabled (kernel.unprivileged_bpf_disabled=0)"
    add_finding "ebpf_unprivileged" "MEDIUM" \
      "Unprivileged eBPF is enabled on this host" \
      "kernel.unprivileged_bpf_disabled=0, meaning any unprivileged process can load BPF socket filters and use BPF maps without any special capability. The bpf(2) syscall is available." \
      "Unprivileged BPF enables certain BPF verifier attacks that have been used to achieve kernel code execution from unprivileged containers. Historical examples: CVE-2021-3490, CVE-2020-8835. Even without verifier bugs, socket filter BPF programs can be used for traffic analysis." \
      "Moderate. Requires a BPF verifier bug for full privilege escalation, but the attack surface is significant and has yielded practical exploits in the past." \
      "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/ on all container hosts. This is a recommended container host hardening step and included in CIS benchmarks."

  else
    ok "eBPF exposure is limited (CAP_BPF=$cap_bpf, CAP_SYS_ADMIN=$cap_sys_admin, unprivileged_bpf=$ubpf)"
  fi
}

# ---------------------------------------------------------------------------
# 29. debugfs mounted and accessible
# /sys/kernel/debug provides direct kernel subsystem access including
# tracing interfaces, hardware debugging, and DRAM access on some systems.
# ---------------------------------------------------------------------------
check_debugfs() {
  hdr "29. debugfs / tracefs exposure"

  local debugfs_mounted=false
  local debugfs_writable=false
  local tracefs_mounted=false
  local debugfs_mp=""

  # Check if debugfs is mounted
  if grep -q "^debugfs\|^none.*debugfs\| debugfs " /proc/mounts 2>/dev/null; then
    debugfs_mounted=true
    debugfs_mp=$(grep "debugfs" /proc/mounts 2>/dev/null | awk '{print $2}' | head -1)
  fi

  # Also check /sys/kernel/debug directly
  if [[ -d /sys/kernel/debug ]] && ls /sys/kernel/debug &>/dev/null 2>&1; then
    debugfs_mounted=true
    debugfs_mp="${debugfs_mp:-/sys/kernel/debug}"
  fi

  if [[ -w /sys/kernel/debug ]]; then
    debugfs_writable=true
  fi

  if grep -q "tracefs" /proc/mounts 2>/dev/null || [[ -d /sys/kernel/tracing ]]; then
    tracefs_mounted=true
  fi

  if [[ "$debugfs_mounted" == true ]]; then
    local severity="MEDIUM"
    [[ "$debugfs_writable" == true ]] && severity="HIGH"

    local access_type="readable"
    [[ "$debugfs_writable" == true ]] && access_type="read-write"

    warn "debugfs is mounted and $access_type: ${debugfs_mp:-/sys/kernel/debug}"
    add_finding "debugfs_exposed" "$severity" \
      "debugfs mounted and $access_type (${debugfs_mp:-/sys/kernel/debug})" \
      "The Linux kernel debug filesystem (debugfs) is mounted and accessible from within this container at ${debugfs_mp:-/sys/kernel/debug}. debugfs exposes kernel internals, hardware interfaces, driver state, and tracing mechanisms. Access mode: $access_type. tracefs also mounted: $tracefs_mounted." \
      "Accessible debugfs provides: (1) Kernel tracing via ftrace (/sys/kernel/debug/tracing) — an attacker can trace any kernel function or system call across the entire host, capturing arguments including file descriptors, memory contents, and cryptographic material from all processes. (2) On x86 systems, /sys/kernel/debug/x86/pat_memtype_list exposes memory type information useful for further attacks. (3) Writable tracing interfaces can be used to modify kernel tracing behaviour. (4) Driver-specific debug interfaces may expose hardware state, DMA buffers, or allow hardware manipulation. (5) Historical CVEs have used debugfs interfaces for privilege escalation." \
      "Moderate. Simply reading ftrace ring buffer content can passively capture sensitive data from host processes. Writing to tracing control files requires no exploit. Risk increases significantly with write access." \
      "Do not mount debugfs in production containers. If required for debugging, mount read-only and limit to specific debug interfaces via AppArmor. In Kubernetes, apply seccompProfile to block relevant syscalls. Ensure /sys/kernel/debug is not included in any volume mounts. On the host, consider masking debugfs after boot: 'mount -o remount,ro /sys/kernel/debug'."
  else
    ok "debugfs does not appear to be accessible"
  fi
}

# ---------------------------------------------------------------------------
# 30. Kubernetes cluster-admin via direct RBAC check
# Goes beyond the service account check (check 6) to actively enumerate
# whether this pod can reach the API server and create privileged pods.
# ---------------------------------------------------------------------------
check_k8s_rbac_escalation() {
  hdr "30. Kubernetes RBAC escalation paths"

  local sa_dir="/var/run/secrets/kubernetes.io/serviceaccount"
  [[ -d "$sa_dir" && -r "$sa_dir/token" ]] || {
    ok "No service account token found — RBAC check skipped"
    return
  }

  local api_server="https://${KUBERNETES_SERVICE_HOST:-kubernetes.default.svc}:${KUBERNETES_SERVICE_PORT:-443}"
  local token ca_cert
  token=$(cat "$sa_dir/token" 2>/dev/null || echo "")
  ca_cert="$sa_dir/ca.crt"
  [[ -n "$token" ]] || return

  command -v curl &>/dev/null || { info "curl not available — RBAC API check skipped"; return; }

  # Check for specific high-value RBAC permissions
  local -A checks
  checks["create_pods"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"namespace":"kube-system","verb":"create","resource":"pods"}}}'
  checks["get_secrets"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"get","resource":"secrets"}}}'
  checks["list_secrets_all"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}'
  checks["exec_pods"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"create","resource":"pods/exec"}}}'
  checks["bind_clusterrole"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"verb":"bind","resource":"clusterrolebindings"}}}'
  checks["create_daemonsets"]='{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"namespace":"kube-system","verb":"create","resource":"daemonsets"}}}'

  local escalation_paths=()

  for check_name in "${!checks[@]}"; do
    local payload="${checks[$check_name]}"
    local result
    result=$(curl -s --max-time 5 \
      --cacert "$ca_cert" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      -X POST \
      -d "$payload" \
      "$api_server/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" 2>/dev/null || echo "")

    if echo "$result" | grep -q '"allowed":true'; then
      escalation_paths+=("$check_name")
      warn "RBAC escalation path: $check_name is ALLOWED"
    fi
  done

  if [[ ${#escalation_paths[@]} -gt 0 ]]; then
    local paths_str="${escalation_paths[*]}"
    local severity="HIGH"
    # Escalate to CRITICAL if privileged pod creation or secret listing cluster-wide is allowed
    if echo "${paths_str}" | grep -q "create_pods\|list_secrets_all\|bind_clusterrole\|create_daemonsets"; then
      severity="CRITICAL"
    fi
    crit "Kubernetes RBAC escalation paths identified: ${paths_str}"
    add_finding "k8s_rbac_escalation" "$severity" \
      "Kubernetes RBAC escalation paths available: ${paths_str}" \
      "Active RBAC checks against the Kubernetes API server ($api_server) confirm this service account has the following permissions: ${paths_str}. These permissions allow escalation within or beyond the current namespace." \
      "create_pods in kube-system: can deploy a privileged pod with hostPID/hostNetwork/hostPath to escape any namespace boundary. list_secrets (cluster-wide): can enumerate all secrets in the cluster including registry credentials, certificates, and application secrets. exec_pods: can execute commands in other pods, including those in privileged namespaces. bind_clusterrole: can grant cluster-admin to any service account including this one. create_daemonsets in kube-system: can run a privileged DaemonSet on every node in the cluster." \
      "Low-moderate technical complexity. Requires only kubectl or curl with the service account token. Tools such as peirates and rbac-police automate Kubernetes privilege escalation from these permissions." \
      "Conduct a full RBAC audit. Remove all permissions not strictly required by this workload. Use namespace-scoped Roles rather than ClusterRoles where possible. Implement a Kubernetes admission controller (OPA/Gatekeeper, Kyverno) to enforce least-privilege service account policies. Consider using a service mesh with SPIFFE/SPIRE for workload identity rather than service account tokens."
  else
    ok "No high-value RBAC escalation paths identified via API check"
  fi
}

# ---------------------------------------------------------------------------
# 31. Containerd / CRI-O socket beyond docker.sock
# Checks for additional container runtime sockets not covered by check 4.
# ---------------------------------------------------------------------------
check_additional_runtime_sockets() {
  hdr "31. Additional container runtime sockets"

  # These are checked in check_mounts but we do a deeper scan here for
  # less obvious locations and podman/buildkit/kata sockets
  local extra_sockets=(
    /run/podman/podman.sock
    /var/run/podman/podman.sock
    /run/buildkit/buildkitd.sock
    /var/run/buildkit/buildkitd.sock
    /run/kata-containers/kata-agent.sock
    /run/oci-runtime/oci-runtime.sock
    /var/run/io.containerd.runtime.v1.linux/moby
    /run/containerd/s/default
    /tmp/containerd.sock
  )

  local found=false
  for sock in "${extra_sockets[@]}"; do
    if [[ -S "$sock" ]]; then
      warn "Additional runtime socket accessible: $sock"
      add_finding "extra_runtime_socket_${sock//\//_}" "CRITICAL" \
        "Additional container runtime socket accessible: $sock" \
        "The container runtime socket at $sock is accessible from within this container. This socket provides administrative API access to the container runtime (Podman, BuildKit, Kata Containers, or containerd)." \
        "Depending on the runtime: Podman socket allows creating containers with arbitrary configurations. BuildKit socket allows injecting build steps into CI/CD pipelines or exfiltrating build secrets. Kata Containers agent socket may expose VM management primitives. All provide pathways to escape container isolation or persist in the environment." \
        "Similar to docker.sock. Runtime API access via the socket can be used to create a new container with host filesystem access. Specific tooling depends on the runtime (podman, nerdctl, buildctl)." \
        "Remove this socket from the container's mounts. Audit all volume mounts for runtime socket paths. Never expose runtime sockets to application workloads."
      found=true
    fi
  done

  # Check for runtime socket file descriptors inherited by the process
  local inherited_socks
  inherited_socks=$(ls -la /proc/self/fd 2>/dev/null | grep "socket:" | wc -l || echo "0")
  if (( inherited_socks > 10 )); then
    info "Unusually high number of open socket file descriptors: $inherited_socks (may warrant investigation)"
  fi

  [[ "$found" == false ]] && ok "No additional runtime sockets found"
}

# ---------------------------------------------------------------------------
# 32. Kernel keyring exposure
# CAP_SYS_ADMIN allows manipulating the kernel keyring, which stores
# encrypted filesystem keys, Kerberos tickets, and PKI material.
# ---------------------------------------------------------------------------
check_kernel_keyring() {
  hdr "32. Kernel keyring exposure"

  local capeff
  capeff=$(grep CapEff /proc/self/status | awk '{print $2}')
  local cap_dec
  cap_dec=$(printf "%d" "0x${capeff}")
  local cap_sys_admin=$(( (cap_dec >> 21) & 1 ))

  # Check if keyctl is available
  local keyctl_available=false
  command -v keyctl &>/dev/null && keyctl_available=true

  # Check if we can read any keys from the process keyring
  local key_count=0
  if [[ "$keyctl_available" == true ]]; then
    key_count=$(keyctl list @s 2>/dev/null | grep -c "key:" || echo "0")
  fi

  # Check /proc/keys for visible keys
  local proc_keys_count=0
  if [[ -r /proc/keys ]]; then
    proc_keys_count=$(wc -l < /proc/keys 2>/dev/null || echo "0")
  fi

  # Check for LUKS/dm-crypt key indicators
  local dm_crypt_keys=false
  if grep -q "logon\|user\|encrypted\|fscrypt" /proc/keys 2>/dev/null; then
    dm_crypt_keys=true
  fi

  if [[ "$cap_sys_admin" == "1" && "$key_count" -gt 0 ]]; then
    crit "CAP_SYS_ADMIN present with $key_count accessible kernel keyring keys"
    add_finding "kernel_keyring_exposure" "HIGH" \
      "Kernel keyring accessible with CAP_SYS_ADMIN ($key_count session keys visible)" \
      "CAP_SYS_ADMIN is present in this container and $key_count keys are visible in the process keyring. The Linux kernel keyring stores cryptographic material: LUKS/dm-crypt volume encryption keys, Kerberos tickets, SSL/TLS private keys stored by the kernel, ecryptfs passphrase tokens, and fscrypt directory encryption keys. /proc/keys shows $proc_keys_count total visible keys. dm-crypt/filesystem encryption keys detected: $dm_crypt_keys." \
      "With CAP_SYS_ADMIN, an attacker can: (1) Read any key in the session, user, or process keyring including keys belonging to root processes. (2) On kernels with key_serial() vulnerabilities, escalate to arbitrary kernel memory access. (3) Extract LUKS volume encryption keys, allowing decryption of encrypted host volumes. (4) Read Kerberos TGTs for lateral movement to other kerberised services. (5) Manipulate the keyring to inject malicious keys affecting all processes sharing the keyring." \
      "Moderate-high. keyctl show and keyctl print commands are trivial if the keyctl binary is available. Kernel key vulnerabilities have been exploited in CTF and real-world settings." \
      "Remove CAP_SYS_ADMIN from containers that do not require keyring management. Apply seccomp to block keyctl(2) syscall (number 250 on x86_64). Run containers as non-root where possible. Use application-level key management (Vault, AWS KMS) rather than the kernel keyring for container workloads."

  elif [[ "$proc_keys_count" -gt 0 ]]; then
    info "Kernel keyring: $proc_keys_count keys visible in /proc/keys (read access only without CAP_SYS_ADMIN)"
    add_finding "kernel_keyring_visible" "MEDIUM" \
      "Kernel keys visible in /proc/keys ($proc_keys_count keys)" \
      "/proc/keys is readable and shows $proc_keys_count keys. Without CAP_SYS_ADMIN the keys themselves cannot generally be read, but metadata (key type, description, permissions) is visible." \
      "Key metadata may reveal what encryption or authentication material is stored in the keyring, informing further attack planning. If any key has world-readable permissions (visible in the permissions field), its contents may be directly accessible." \
      "Low — metadata only without elevated capabilities. Check for world-readable keys: keyctl list @s and inspect permission bits." \
      "Audit key permissions with keyctl show. Ensure no keys have overly permissive access modes. Apply seccomp to block keyctl(2) if not required."
  else
    ok "Kernel keyring exposure appears limited"
  fi
}

# ---------------------------------------------------------------------------
# 33. /run/oci/hooks.d OCI hook injection
# Writable OCI hooks directory allows injecting code that runs during
# container lifecycle events — including on the host side of the boundary.
# ---------------------------------------------------------------------------
check_oci_hooks() {
  hdr "33. OCI hook injection paths"

  local hook_dirs=(
    /run/oci/hooks.d
    /usr/share/containers/oci/hooks.d
    /etc/containers/oci/hooks.d
    /usr/libexec/oci/hooks.d
  )

  local found=false
  for d in "${hook_dirs[@]}"; do
    [[ -e "$d" ]] || continue
    local accessible=true
    local writable=false

    ls "$d" &>/dev/null 2>&1 || accessible=false
    [[ -w "$d" ]] && writable=true

    if [[ "$accessible" == true ]]; then
      local hook_count
      hook_count=$(find "$d" -name "*.json" 2>/dev/null | wc -l || echo "0")
      local sev="MEDIUM"
      [[ "$writable" == true ]] && sev="CRITICAL"
      local access_desc="readable"
      [[ "$writable" == true ]] && access_desc="WRITABLE"

      warn "OCI hooks directory $access_desc: $d ($hook_count hook files)"
      add_finding "oci_hooks_${d//\//_}" "$sev" \
        "OCI hooks directory $access_desc: $d" \
        "The OCI hooks directory at $d is $access_desc from within this container and contains $hook_count hook definition files. OCI hooks are JSON files specifying programs to execute during container lifecycle events: prestart, createRuntime, createContainer, startContainer, and poststart. These hooks run as the user who invoked the container runtime, often root on the host side." \
        "A writable OCI hooks directory allows injecting a malicious hook that executes arbitrary code on the host during the next container creation event — the hook runs in the host's namespace context before or after container isolation is established. This is related to the NVIDIAScape class of vulnerability (CVE-2025-23266): both exploit the OCI hook mechanism's trust in container-supplied input. Reading the hooks directory reveals what programs are executed on the host during container events, potentially exposing sensitive binary paths or configuration." \
        "CRITICAL if writable: write a new .json hook file pointing to a reverse shell or backdoor binary accessible on the host filesystem. The hook executes on the next container creation, with no further interaction required. HIGH for read: reveals host binary paths and execution context." \
        "Remove OCI hook directories from container mounts. Apply AppArmor profiles denying write access to hook directories. Audit all hook definitions and ensure hook binaries are immutable root-owned files. For NVIDIA workloads, verify nvidia-ctk sanitises environment variables passed to createContainer hooks (CVE-2025-23266 patch)."
      found=true
    fi
  done

  [[ "$found" == false ]] && ok "No OCI hook directories accessible"
}

# ---------------------------------------------------------------------------
# 34. Writable /proc/sys/kernel/core_pattern (standalone expanded check)
# Extended version with splice() and page cache context for Copy Fail.
# ---------------------------------------------------------------------------
check_core_pattern_deep() {
  hdr "34. Core pattern and page cache write primitives"

  # core_pattern writability is already covered in check_proc (check 5).
  # This check adds context specifically around page cache write primitives
  # that enable Copy Fail and similar attacks, and checks the splice() surface.

  local splice_check=false
  local page_cache_writable=false

  # Check if splice(2) is available (not seccomp-blocked)
  if python3 -c "
import ctypes, sys, os
NR_SPLICE = 275  # x86_64
libc = ctypes.CDLL(None, use_errno=True)
r, w = os.pipe()
# Call splice with invalid fd to probe availability
ret = libc.syscall(NR_SPLICE, -1, None, w, None, 0, 0)
err = ctypes.get_errno()
os.close(r); os.close(w)
# EBADF(9) means syscall reached argument validation — available
# ENOSYS(38) means blocked
sys.exit(0 if err == 9 else 1)
" 2>/dev/null; then
    splice_check=true
  fi

  # Check if pipe2 is available (also required for page cache write)
  local pipe2_check=false
  if python3 -c "
import ctypes, sys
NR_PIPE2 = 293
libc = ctypes.CDLL(None, use_errno=True)
ret = libc.syscall(NR_PIPE2, ctypes.c_void_p(0), 0)
err = ctypes.get_errno()
sys.exit(0 if err == 14 else 1)  # EFAULT(14) = syscall reached arg check
" 2>/dev/null; then
    pipe2_check=true
  fi

  # Check if a file in /tmp can be used as a page cache target
  if touch /tmp/.pcc_test 2>/dev/null; then
    rm -f /tmp/.pcc_test
    page_cache_writable=true
  fi

  if [[ "$splice_check" == true && "$pipe2_check" == true ]]; then
    warn "Page cache write primitives available: splice(2)=$splice_check, pipe2(2)=$pipe2_check"
    add_finding "page_cache_write_primitives" "HIGH" \
      "Page cache write primitives available: splice(2) and pipe2(2) not seccomp-blocked" \
      "Both splice(2) and pipe2(2) syscalls are available and not blocked by seccomp in this container. These are the two syscalls required for the Copy Fail (CVE-2026-31431) page cache write primitive, and for the DirtyPipe (CVE-2022-0847) attack. splice() transfers data between file descriptors via the kernel page cache. pipe2() creates pipes with O_DIRECT flag, enabling the controlled page cache write technique used by these CVEs." \
      "The availability of these primitives means the kernel page cache write technique is not blocked at the syscall level. If the kernel is unpatched for CVE-2026-31431 (Copy Fail) or CVE-2022-0847 (DirtyPipe), these syscalls are the attack mechanism. Even on patched kernels, the primitives remain and may be relevant to undiscovered vulnerabilities in the same class." \
      "Moderate. The syscalls themselves are not exploits; exploitability depends on kernel patch status (see checks 14 and 24). However, their availability confirms the attack surface is not reduced by seccomp filtering." \
      "Apply a seccomp profile that restricts splice(2) (syscall 275) and pipe2(2) (syscall 293) if not required by the workload. Ensure the kernel is fully patched for CVE-2026-31431 and CVE-2022-0847. Use RuntimeDefault seccomp profile as a baseline — it does not block these syscalls but provides defence-in-depth for other vectors."
  else
    ok "splice(2)=$splice_check pipe2(2)=$pipe2_check — page cache write primitives partially restricted"
  fi
}

# ---------------------------------------------------------------------------
# 35. Procfs namespace leakage
# Checks whether /proc/*/ns symlinks for other processes on the host
# are readable, allowing namespace fd-based attacks (setns).
# ---------------------------------------------------------------------------
check_proc_ns_leakage() {
  hdr "35. Procfs namespace file descriptor leakage"

  local self_pid=$$
  local visible_pids=()
  local host_pids_visible=false
  local setns_possible=false

  # Enumerate PIDs visible in /proc
  while IFS= read -r pid_dir; do
    local pid
    pid=$(basename "$pid_dir")
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [[ "$pid" == "$self_pid" || "$pid" == "1" ]] && continue
    visible_pids+=("$pid")
  done < <(find /proc -maxdepth 1 -name '[0-9]*' -type d 2>/dev/null | head -20)

  local pid_count=${#visible_pids[@]}

  # Check if we're seeing host PIDs (PIDs > threshold suggests host PID ns)
  local max_pid=0
  for pid in "${visible_pids[@]}"; do
    (( pid > max_pid )) && max_pid=$pid
  done

  # If we can see PIDs > 1000 that aren't ours, we likely share host PID ns
  # or at minimum can see other containers' processes
  if (( max_pid > 1000 && pid_count > 5 )); then
    host_pids_visible=true
  fi

  # Check if we can open a namespace fd from another process (setns attack surface)
  for pid in "${visible_pids[@]:0:5}"; do
    if [[ -r "/proc/$pid/ns/mnt" ]]; then
      # Can we open the namespace fd?
      if python3 -c "
import os, sys
try:
    fd = os.open('/proc/$pid/ns/mnt', os.O_RDONLY)
    os.close(fd)
    sys.exit(0)
except:
    sys.exit(1)
" 2>/dev/null; then
        setns_possible=true
        break
      fi
    fi
  done

  if [[ "$host_pids_visible" == true ]]; then
    local severity="MEDIUM"
    [[ "$setns_possible" == true ]] && severity="HIGH"

    warn "$pid_count foreign processes visible in /proc (max PID seen: $max_pid). setns fd openable: $setns_possible"
    add_finding "proc_ns_leakage" "$severity" \
      "Foreign process namespace file descriptors visible via /proc ($pid_count processes, max PID $max_pid)" \
      "$pid_count process entries are visible in /proc beyond PID 1 and the current process. Maximum observed PID is $max_pid, suggesting access to host or other container processes via the shared PID namespace or an unconfined /proc mount. Namespace file descriptor openable for setns: $setns_possible." \
      "If namespace file descriptors (/proc/\$PID/ns/*) from host processes are openable, an attacker with CAP_SYS_ADMIN can call setns(2) to enter the host's mount, network, or PID namespace, effectively crossing the container boundary. Even without setns capability, reading /proc/\$PID/environ, /proc/\$PID/cmdline, /proc/\$PID/maps, and /proc/\$PID/fd/\* for host processes may expose secrets, file descriptor contents, and memory layouts from co-located workloads." \
      "Low-moderate for information gathering (any user). High for setns namespace entry if CAP_SYS_ADMIN is present. 'nsenter -t <host_pid> -m -- ls /' enters the host mount namespace using a visible /proc entry." \
      "Mount /proc with hidepid=2 to prevent non-root processes from seeing other processes' entries. Avoid sharing the host PID namespace (hostPID: false in pod specs). Apply gvisor or Kata Containers for stronger /proc isolation. Restrict /proc namespace fd access via seccomp policy."
  else
    ok "Foreign process visibility in /proc appears limited ($pid_count visible, max PID $max_pid)"
  fi
}

# ===========================================================================
# MAIN
# ===========================================================================

if [[ "$OUTPUT_JSON" == false ]]; then
  echo -e "${BOLD}${CYAN}"
  echo "========================================================"
  echo "  container_escape_audit.sh v3.0"
  echo "  Container escape vector detection"
  echo "  FOR AUTHORISED SECURITY ASSESSMENTS ONLY"
  echo "========================================================"
  echo -e "${RESET}"
  [[ "$NO_REPORT" == false ]] && echo -e "  Report will be written to: ${BOLD}${REPORT_FILE}${RESET}\n"
fi

# Original checks (1-23)
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

# New checks (24-35)
check_copy_fail
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
