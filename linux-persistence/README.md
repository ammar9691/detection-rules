# Linux Persistence — Detection Rules

Twelve persistence techniques mapped to MITRE ATT&CK, each with multi-platform detection content and a benign test trigger. Each technique is a single self-contained writeup — Sigma rule, auditd rules, osquery query, Falco rule, lab test trigger, and false-positive guidance all in one file.

## MITRE ATT&CK coverage

Covers the persistence (TA0003) and privilege escalation (TA0004) tactics with focus on the most operationally relevant techniques for Linux environments.

| Technique | Sub-technique | Writeup |
|---|---|---|
| T1098 — Account Manipulation | .004 SSH Authorized Keys | [01-ssh-authorized-keys.md](01-ssh-authorized-keys.md) |
| T1556 — Modify Authentication Process | (parent) | [02-sshd-config-tamper.md](02-sshd-config-tamper.md) |
| T1053 — Scheduled Task/Job | .003 Cron, .006 Systemd Timers | [03-cron-systemd-timer.md](03-cron-systemd-timer.md) |
| T1543 — Create or Modify System Process | .002 Systemd Service | [04-systemd-service-persistence.md](04-systemd-service-persistence.md) |
| T1505 — Server Software Component | .003 Web Shell | [05-web-shell-drop.md](05-web-shell-drop.md) |
| T1059 / T1071 — Command and Scripting Interpreter / Application Layer Protocol | .004 Unix Shell | [06-reverse-shell-callback.md](06-reverse-shell-callback.md) |
| T1556 — Modify Authentication Process | .003 PAM | [07-pam-module-backdoor.md](07-pam-module-backdoor.md) |
| T1574 — Hijack Execution Flow | .006 Dynamic Linker Hijacking | [08-ld-preload-injection.md](08-ld-preload-injection.md) |
| T1547 — Boot or Logon Autostart Execution | .006 Kernel Modules and Extensions | [09-kernel-module-rootkit.md](09-kernel-module-rootkit.md) |
| T1546 — Event Triggered Execution | .004 Unix Shell Configuration Modification | [10-shell-rc-injection.md](10-shell-rc-injection.md) |
| T1548 — Abuse Elevation Control Mechanism | .001 Setuid and Setgid | [11-setuid-binary-drop.md](11-setuid-binary-drop.md) |
| T1548 — Abuse Elevation Control Mechanism | .003 Sudo and Sudo Caching | [12-sudoers-dropin.md](12-sudoers-dropin.md) |

## Detection philosophy

These rules optimize for **high signal-to-noise**, not maximum coverage. A noisy detection is a disabled detection — production SOC teams mute alerts that fire on every package update.

Where a technique has high false-positive potential (e.g. cron job creation, which happens during legitimate config management), the rule narrows on the **suspicious variant** — outbound network calls inside cron, base64-encoded payloads, callback URLs — rather than the technique generally.

## Multi-format approach

Each writeup includes detection content in four formats:

- **Sigma** — for SIEM/data-lake (Splunk, Elastic, Sentinel, Chronicle via sigmac)
- **auditd** — for kernel-level file/syscall monitoring on the host
- **osquery** — for fleet-wide periodic state inspection
- **Falco** — for runtime monitoring (especially containerized workloads)

Different organizations land in different parts of this stack. The four-format approach means the rule is usable wherever you collect telemetry.

## Testing

Each writeup includes a `Lab test trigger` script that triggers the technique using benign payloads. Run from a clean lab VM (see [`../tests/lab-setup.md`](../tests/lab-setup.md)), never in production.
