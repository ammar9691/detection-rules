# Linux Persistence Detection Rules

Detection rules for the most common Linux persistence techniques used by attackers post-compromise. Each technique includes rules in four formats — Sigma, auditd, osquery, and Falco — plus a reproducible test script and a false-positive guide.

Built as a focused, complete reference rather than a sprawling collection: pick a technique, get production-ready coverage in the format your stack uses, and a test you can run in a lab to prove the rule fires.

## Why these twelve techniques

These are the techniques that show up in real Linux intrusion reports and red team engagements over and over again. They span every major persistence sub-tactic in MITRE ATT&CK and they cover both the "low effort but high frequency" tradecraft (authorized_keys, cron) and the "rarer but harder to detect" tradecraft (PAM modules, kernel rootkits).

If you can detect all twelve confidently, you have meaningful Linux persistence coverage.

## Coverage matrix

| # | Technique | MITRE ATT&CK | Detection difficulty |
|---|---|---|---|
| 01 | SSH authorized_keys injection | T1098.004 | Easy |
| 02 | SSHD config tampering | T1556 | Medium |
| 03 | Cron and systemd timer abuse | T1053.003 / T1053.006 | Easy |
| 04 | Systemd service persistence | T1543.002 | Medium |
| 05 | Web shell drop | T1505.003 | Medium |
| 06 | Reverse shell callback | T1059.004 / T1071 | Hard |
| 07 | PAM module backdoor | T1556.003 | Hard |
| 08 | LD_PRELOAD library injection | T1574.006 | Medium |
| 09 | Loadable kernel module rootkit | T1547.006 | Hard |
| 10 | Shell rc / profile injection | T1546.004 | Easy |
| 11 | Setuid binary drop | T1548.001 | Easy |
| 12 | Sudoers drop-in privilege grant | T1548.003 | Easy |

## Repository layout

```
linux-persistence/
  README.md                              Coverage matrix, philosophy, links to writeups
  01-ssh-authorized-keys.md              Each .md is a self-contained writeup containing:
  02-sshd-config-tamper.md                 - technique explanation + MITRE mapping
  03-cron-systemd-timer.md                 - Sigma rule (vendor-agnostic)
  04-systemd-service-persistence.md        - auditd rules (host-level)
  05-web-shell-drop.md                     - osquery query (fleet-level)
  06-reverse-shell-callback.md             - Falco rule (runtime / containers)
  07-pam-module-backdoor.md                - lab test trigger (benign)
  08-ld-preload-injection.md               - false-positive guide + tuning
  09-kernel-module-rootkit.md
  10-shell-rc-injection.md
  11-setuid-binary-drop.md
  12-sudoers-dropin.md

tests/
  lab-setup.md                           Reproducible Vagrant / Docker lab to test all rules
```

## How to use

1. **Open the technique writeup** — each `.md` file is self-contained: explanation, all four detection formats, lab test, and tuning notes.
2. **Pick the format your stack supports**:
   - SIEM with sigmac / Chainsaw / Hayabusa: copy the `Sigma rule` block
   - Standalone Linux host with auditd: drop the `auditd rules` block into `/etc/audit/rules.d/`
   - osquery fleet (Kolide, Fleet, etc.): import the `osquery query` as a scheduled query
   - Falco / Sysdig: include the `Falco rule` block
3. **Validate in a lab** before deploying. Each writeup has a `test.sh` block — run it against a clean VM (see `tests/lab-setup.md`) and confirm the rule fires.
4. **Read the `False positives and tuning` section** — every rule has legit edge cases. Tune before alerting in prod.

## Testing methodology

Every rule has been validated against a clean AlmaLinux 9 host with auditd and Falco running. The `test.sh` snippets simulate the technique using benign payloads (no actual malware, no exfiltration). The expected detection signal is documented in each writeup.

## Conventions

- Sigma rules use `level: high` for unambiguous indicators and `level: medium` for behavioral patterns that need tuning.
- auditd rules use unique `-k <key>` tags so alerts can be routed by key.
- osquery queries are designed for `interval: 300` (5 min) by default; tune per environment.
- Falco rules include MITRE tags for ATT&CK navigator integration.

## License

MIT. Use, modify, deploy. No warranty — test in a lab before production.
