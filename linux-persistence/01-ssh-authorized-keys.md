# 01 — SSH Authorized Keys Injection

**MITRE ATT&CK:** T1098.004
**Detection difficulty:** Easy

---

## What this is

The simplest, most common, and arguably most reliable Linux persistence technique. After an attacker gains shell access (any vector), they append their public key to `~/.ssh/authorized_keys` for some user — often `root` or any user with sudo. From that point forward, they can SSH in directly using their private key, no password needed. Persistence survives password rotations, reboots, and most cleanup attempts that don't specifically check authorized_keys.

## Why it matters

Real-world incident reports show this is one of the first persistence actions in nearly every Linux compromise — from cryptominer crews to nation-state actors. Cheap to deploy, low forensic footprint, and many environments don't watch `authorized_keys` files.

## What the rules detect

- **Any write or attribute change to an `authorized_keys` file** under `/root/.ssh/` or `/home/*/.ssh/`.
- **New key entries** across the fleet, surfaced by comparing osquery results against the previous run.

The rules deliberately do not try to guess which processes are "legitimate" writers. Tools like Ansible and cloud-init write these files through generic interpreters (`python3`, `sh`), so a process-name allow-list is easy to get wrong and easy for an attacker to imitate. Tune by user or host instead — see the false positives section.

## Detection signal by format

| Format | What it watches | Latency |
|---|---|---|
| Sigma | File event logs (Sysmon for Linux, auditbeat) for writes to authorized_keys paths | Near real-time |
| auditd | `-w` watch on `.ssh` directories with `-p wa` (write/attribute) | Real-time |
| osquery | `authorized_keys` table joined against `users`; differential results show new entries | Periodic (5 min default) |
| Falco | `open_write` syscall against `*authorized_keys` files | Real-time |

## Testing

Run the lab test trigger below on a throwaway VM. Expected: each of the four detections fires within its stated latency.

## Tuning notes

See the false positives section at the end of this file. Legitimate sources include configuration management tools (Ansible, Puppet, Chef), cloud-init on instance launch, and container image builds.

---

## Sigma rule

```yaml
title: SSH authorized_keys File Modification
id: d5ca9ba1-1549-4399-83ed-2451bd3c916d
status: experimental
description: |
  Detects modification of any authorized_keys file under common SSH key paths.
  This is the most common Linux persistence technique post-compromise.
references:
  - https://attack.mitre.org/techniques/T1098/004/
author: Ammar
date: 2026-05-03
modified: 2026-09-02
tags:
  - attack.persistence
  - attack.t1098.004
logsource:
  product: linux
  category: file_event
detection:
  modification:
    TargetFilename|endswith:
      - '/.ssh/authorized_keys'
      - '/.ssh/authorized_keys2'
  condition: modification
falsepositives:
  - Configuration management tools (Ansible, Puppet, Chef, Salt) deploying keys
  - Cloud-init on first boot writing the instance launch key
  - Container image build steps that bake keys in
  - Legitimate user running ssh-copy-id from another host
level: high
```

## auditd rules

```
# T1098.004 — SSH Authorized Keys
# Watch .ssh directories for write/attribute change. Watching the directory
# (not just the file) also catches a brand-new authorized_keys being created.
# Key: ssh_authkeys_tamper

-w /root/.ssh -p wa -k ssh_authkeys_tamper

# auditd -w does not accept wildcards, so each user home needs its own line.
# Generate them with:
#   for d in /home/*; do echo "-w $d/.ssh -p wa -k ssh_authkeys_tamper"; done
# and paste the output below. Re-run when users are added.
-w /home/alice/.ssh -p wa -k ssh_authkeys_tamper
-w /home/bob/.ssh -p wa -k ssh_authkeys_tamper
```

## osquery query

```sql
-- T1098.004 — SSH Authorized Keys
-- Returns every authorized_keys entry across all users on the host.
-- Schedule as a differential query: new rows since the last run = investigation candidate.
-- Suggested interval: 300 (5 min)

SELECT
    u.username,
    u.uid,
    u.directory AS home,
    ak.key_file,
    ak.algorithm,
    ak.comment,
    ak.key
FROM users u
JOIN authorized_keys ak USING (uid)
WHERE u.directory LIKE '/home/%'
   OR u.directory = '/root';
```

## Falco rule

```yaml
- rule: SSH authorized_keys file modified
  desc: >
    Detects any write to an authorized_keys file. Common Linux persistence (T1098.004).
    Tune per environment by excluding known provisioning users or hosts.
  condition: >
    open_write
    and (fd.name endswith "/.ssh/authorized_keys" or fd.name endswith "/.ssh/authorized_keys2")
  output: >
    authorized_keys modified (user=%user.name proc=%proc.name cmdline=%proc.cmdline file=%fd.name container=%container.name)
  priority: WARNING
  tags: [host, container, persistence, mitre_persistence, T1098.004]
```

## Lab test trigger

```bash
#!/bin/bash
# T1098.004 test trigger — appends a benign test key to root's authorized_keys.
# Run as root in a lab VM only. Cleans up after itself.
set -euo pipefail

KEYS_FILE="/root/.ssh/authorized_keys"
MARKER="DETECTION-TEST-T1098-004-$(date +%s)"
TEST_KEY="ssh-rsa AAAAB3NzaC1yc2ETESTKEYDOESNOTWORKjustfortriggerdetection ${MARKER}"

mkdir -p /root/.ssh
chmod 700 /root/.ssh

echo "[+] Triggering authorized_keys modification (marker: ${MARKER})"
echo "${TEST_KEY}" >> "${KEYS_FILE}"
chmod 600 "${KEYS_FILE}"

echo "[+] Waiting 5s for detection latency..."
sleep 5

echo "[+] Cleaning up test key"
sed -i "/${MARKER}/d" "${KEYS_FILE}"

echo "[+] Done. Check your detection backend for an alert tagged with key ${MARKER}."
echo "    auditd:  ausearch -k ssh_authkeys_tamper -ts recent"
echo "    falco:   journalctl -u falco | grep ${MARKER}"
```

## False positives and tuning

### 1. Configuration management
**Tools:** Ansible, Puppet, Chef, Salt, Terraform user_data
**Why it triggers:** These tools push public keys to managed nodes as part of routine operations, often on a schedule (every 30 min, hourly).
**How to suppress:** Filter on the service account the tool runs as, not the process name (Ansible writes through `python3` on the target, which is not a safe thing to allow-list). In Sigma:
```yaml
detection:
  modification:
    TargetFilename|endswith:
      - '/.ssh/authorized_keys'
      - '/.ssh/authorized_keys2'
  filter_config_mgmt:
    User:
      - 'ansible'
      - 'puppet'
  condition: modification and not filter_config_mgmt
```

### 2. Cloud-init (first boot)
**Why it triggers:** AWS, GCP, Azure all use cloud-init to inject the launch SSH key into `~/.ssh/authorized_keys` for the default user.
**How to suppress:** First-boot only — exclude when uptime is low (under 5 min). Most SIEMs can correlate with the instance launch event from the cloud audit log.

### 3. Container image builds
**Why it triggers:** `Dockerfile` instructions like `COPY id_rsa.pub /root/.ssh/authorized_keys` modify the file at build time.
**How to suppress:** Don't run these rules during container image builds. At runtime (Falco), these don't matter — they fired in the build pipeline.

### 4. ssh-copy-id from a trusted admin
**Why it triggers:** `ssh-copy-id` appends to authorized_keys remotely. On the target host the write comes from a shell spawned by `sshd`, which is exactly what an attacker's write looks like too.
**How to distinguish:** Source IP is in your admin range and the session user is a known admin. Add a source-IP or user allow-list in the SIEM, not in the host rule.

### 5. PAM provisioning / IDP-pushed keys
**Why it triggers:** Identity providers (Okta SSH, Teleport, BastionZero) push ephemeral keys via PAM modules at session start.
**How to suppress:** Allow-list the PAM helper's service user. Better: point the rule at the IDP-managed key path (often `/etc/ssh/authorized_keys.d/<user>`) instead of the home-dir file.

### What is NOT a false positive

- **Modification by a process that should never write keys** (`bash`, `python`, `wget`, `curl`, web server daemons) outside a provisioning window
- **Modification when the auditd `uid` is the web server user** (`apache`, `www-data`, `nobody`)
- **Modification with no matching provisioning activity** in a non-build environment

These are high-confidence indicators of compromise — alert and investigate, do not suppress.
