# Changelog (AlmaLinux-10)

## Version: AlmaLinux-10-Rev-1
26 October 2026

* **Interactive tool.** AlmaLinux 10 is now supported by the tool, with 56 controls in all ten categories. Any 10.x release is accepted. The controls are written and tested against 10.2.
* Uses what AlmaLinux ships: `dnf`, `firewalld` (or `nftables`), SELinux, `authselect`, `wheel`, `chrony`, `dnf-automatic` and the system-wide cryptographic policy (`system-kernel.crypto-policy`).
* EPEL is a separate control (`baseline.epel`). `ldp.fail2ban-sshd` needs it.
* The package mirror (`baseline.dnf-mirror`) is any HTTPS mirror. There is no preset for a provider.
* `GUIDE.md`, the manual guide, stays as it was.

## Version: AlmaLinux-10-Rev-0
22 May 2026

* **Initial Release**
