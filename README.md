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
curl -O https://raw.githubusercontent.com/<your-org>/container-escape-audit/main/container_escape_audit.sh
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
              curl -sO https://raw.githubusercontent.com/<your-org>/container-escape-audit/main/container_escape_audit.sh && \
              chmod +x container_escape_audit.sh && \
              ./container_escape_audit.sh --json
```

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

## Integration

### Falco (runtime detection complement)

This script performs point-in-time assessment. For continuous runtime detection of the same techniques, pair with [Falco](https://falco.org/) rules covering:

- Writes to `release_agent` or `core_pattern`
- Spawning of `nsenter`, `unshare`, or `runc` inside containers
- Access to `/var/run/docker.sock`
- Unexpected outbound connections to `169.254.169.254`

### CI/CD integration

```bash
# Fail pipeline if any CRITICAL findings are present
CRITICAL_COUNT=$(./container_escape_audit.sh --json --no-report | jq '[.findings[] | select(.severity=="CRITICAL")] | length')
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

## Legal

This tool is provided for **authorised security testing only**. Running it against systems without explicit written permission from the system owner may be illegal in your jurisdiction. The authors accept no liability for misuse.

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
