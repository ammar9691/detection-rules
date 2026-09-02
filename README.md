# detection-rules

Detection rules I write for Linux persistence techniques. I run Wazuh and auditd on production servers as a sysadmin, and this repo is where I work out how to actually catch the things attackers do after they get a shell.

Each technique gets one markdown file with everything in it: what the technique is, a Sigma rule, auditd rules, an osquery query, a Falco rule, a small bash script to trigger it in a lab, and notes on what will false positive.

I picked these twelve because they keep showing up in Linux incident reports. I am adding them one at a time as I finish testing each one.

## Techniques

| # | Technique | ATT&CK | Status |
|---|---|---|---|
| 01 | [SSH authorized_keys injection](linux-persistence/01-ssh-authorized-keys.md) | T1098.004 | done |
| 02 | sshd config tampering | T1556 | writing |
| 03 | Cron and systemd timer abuse | T1053.003 / .006 | writing |
| 04 | Systemd service persistence | T1543.002 | writing |
| 05 | Web shell drop | T1505.003 | writing |
| 06 | Reverse shell callback | T1059.004 / T1071 | writing |
| 07 | PAM module backdoor | T1556.003 | writing |
| 08 | LD_PRELOAD injection | T1574.006 | writing |
| 09 | Kernel module rootkit | T1547.006 | writing |
| 10 | Shell rc / profile injection | T1546.004 | writing |
| 11 | Setuid binary drop | T1548.001 | writing |
| 12 | Sudoers drop-in | T1548.003 | writing |

## Using a rule

Open the technique file and copy the block for whatever you run:

- Sigma: convert with sigma-cli or pySigma for your SIEM
- auditd: drop the lines into a file under `/etc/audit/rules.d/` and run `augenrules --load`
- osquery: add the query to your schedule, 300 seconds is a sane default
- Falco: append the rule to your local rules file

Then run the lab trigger from the same file on a throwaway VM and check the alert shows up before you trust it in prod. Read the false positives section, every one of these rules has cases where it fires on normal admin work.

## Lab

`tests/lab-setup.md` has the VM setup I use for testing (coming with technique 02).

## License

MIT
