# Changelog (AlmaLinux-10)

## Version: AlmaLinux-10-Rev-3
27 October 2026

* **Crypto policy and `dnf`.** `system-kernel.crypto-policy` reads the repository metadata with `dnf makecache --refresh` before and after the change. If `dnf` worked before and fails after, the old policy comes back and the control says why. A real server showed the problem: under `FUTURE`, `dnf` refused a mirror whose certificate has a 2048-bit RSA key, and every later `dnf` step of the run failed. (27 October 2026, Danang Galuh Tegar Prasetyo)
* **/tmp.** `filesystem.tmp-hardening` works when `/tmp` is a plain directory on the root file system, as it is on AlmaLinux. It asked for the mount options of `/tmp` and failed. It now reads the file system that holds `/tmp`, and turns on the systemd `/tmp` mount. (27 October 2026, Danang Galuh Tegar Prasetyo)
* **Default umask.** `filesystem.default-umask` no longer reads the Debian file `/etc/pam.d/common-session`. It sets `UMASK` in `/etc/login.defs` and in `/etc/profile.d/zz-server-hardening-umask.sh`, and warns when no PAM session runs `pam_umask`. It does not edit the PAM files that `authselect` generates. (27 October 2026, Danang Galuh Tegar Prasetyo)
* **Audit daemon.** When `systemctl reload auditd` is not possible, the control sends SIGHUP to the daemon, and warns only if that fails too. (27 October 2026, Danang Galuh Tegar Prasetyo)

## Version: AlmaLinux-10-Rev-2
27 October 2026

* **Release naming.** The system is named "AlmaLinux 10", without a codename, because each 10.x release has its own. The README names 10.2, the release the controls are tested on, as Lavender Lion. (27 October 2026, Danang Galuh Tegar Prasetyo)
* **Recovery and routine.** `GUIDE.md`, the manual guide, is removed. Its recovery steps and its weekly and monthly routine moved to `OPERATIONS.md`, which is written against what the tool does. It covers SELinux (labelling the SSH port, permissive mode only while diagnosing), `dnf`, and what to prepare before a run. (27 October 2026, Danang Galuh Tegar Prasetyo)
* **README.** The README links `OPERATIONS.md` from the quick start, and its out-of-scope list now names containers, provider security settings, partition changes on a running system and port knocking. (27 October 2026, Danang Galuh Tegar Prasetyo)

## Version: AlmaLinux-10-Rev-1
26 October 2026

* **Interactive tool.** AlmaLinux 10 is now supported by the tool, with 56 controls in all ten categories, 44 of them ticked by default. Any 10.x release is accepted. The controls are written and tested against 10.2. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **What AlmaLinux ships.** The controls use `dnf`, `firewalld` (or `nftables`), SELinux, `authselect`, `wheel`, `chrony`, `dnf-automatic` and the system-wide cryptographic policy (`system-kernel.crypto-policy`). SELinux has `mac.selinux-enforcing` and the read-only `mac.selinux-audit`. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **EPEL.** EPEL is a separate control (`baseline.epel`), off by default. `ldp.fail2ban-sshd` needs it. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **Package mirror.** `baseline.dnf-mirror` takes any HTTPS mirror. There is no preset for a provider. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **File integrity.** `ldp.aide-dnf-hook` can only update the AIDE baseline after a `dnf` transaction, because `dnf` 4 has no hook that runs before one. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **Shared code.** The helpers that do not depend on the operating system (sysctl, SSH drop-ins, accounts, SSH keys, mounts, the firewall and `dnf`) live in `internal/` and are shared with Debian 13. (26 October 2026, Danang Galuh Tegar Prasetyo)

## Version: AlmaLinux-10-Rev-0
22 May 2026

* **Initial Release.** The manual step-by-step guide (`GUIDE.md`). (22 May 2026, Danang Galuh Tegar Prasetyo)
