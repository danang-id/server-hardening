# Roadmap

This file lists what Server Hardening does not do yet. Everything else is described in the [README](README.md) and is implemented. The items are intentions, not promises, and they have no dates. When an item ships, it moves out of this file and into the changelog of its system.

## Before the first release

These checks are open for what already exists.

- Run the tool on a real Debian 13 server and a real AlmaLinux 10.2 server or virtual machine: apply, check, revert, check, and compare the system before and after. The tests so far run against a simulated system.
- On AlmaLinux, check the things that were taken from documentation and not from a running system: the output of `dnf 4` commands such as `dnf remove --assumeno`, `dnf repoquery --unsatisfied` and `dnf needs-restarting -r`, the package names `python3-dnf-plugin-post-transaction-actions` and `fail2ban-selinux`, whether AIDE accepts the `@@include` line and reports the immutable flag, and the SELinux labels of the SSH port and of a swap file.
- Automate that round trip in a container or virtual machine with systemd, so it runs in continuous integration.
- Run `hardening.ps1` on a real Windows Server. It has only been written, not run.
- Run `sh scripts/third-party-licenses.sh` against the real modules, then publish the first tag (`v0.1.0`) and check the release it builds.
- Move what is still worth keeping out of `Debian/13/GUIDE.md` and `AlmaLinux/10/GUIDE.md` (recovery steps, the maintenance routine, prerequisites, scope), then delete both guides. They were the starting point of this repository, written before the tool existed.

## Systems

The tool supports Debian 13 and AlmaLinux 10. Linux and Windows have equal priority. macOS is not planned.

| System | Today | Wanted |
|---|---|---|
| Debian 12, 11 | Nothing | Controls for each version |
| AlmaLinux 9, 8 | Nothing | Controls for each version |
| Rocky Linux 10, 9 | Nothing | Controls for each version |
| Ubuntu 26.04, 24.04, 22.04 LTS | Nothing | Controls for each version |
| Windows Server 2025, 2022 | The entry script `hardening.ps1` and a Windows build of the tool exist, but there are no controls, so the script reports that Windows is not supported | Controls, records in `%ProgramData%\server-hardening`, and an automatic undo for lockout controls |

A new system needs:

1. A folder `<System>/<Version>/` with a `REFERENCES.md` and a `Controls` folder, as described under *File layout* in the README.
2. At least one control in every category, or a written reason that a category does not exist on the system (the *Coverage rule*).
3. A registered `System` that matches the operating system and architectures, so that `--print-support` lists it.
4. Tests that pass, including the repository tests.
5. A row in the README table and a changelog.

## Controls and features

- **`remote-access.ssh-port`** refuses to run when an nftables firewall that this tool did not set up is active. It should open the new port in that firewall.
- **`baseline.time-sync`** adds the servers you enter to the pool that Debian's `chrony` configuration lists. Decide whether it should replace the pool instead, and check the choice on a test VM.
- **`misc.notify`** sends to a webhook only. Email delivery is not part of it.
- **Automatic undo** for lockout controls needs systemd. On other systems the tool warns you and only the running session can undo the change.

- **AlmaLinux 10 has no `network.systemd-networkd` and no `network.dns-resolver`.** The Debian controls move the network configuration to `systemd-networkd` and `systemd-resolved`, and AlmaLinux uses `NetworkManager`. Decide whether to write versions for `NetworkManager`.
- **AlmaLinux and Debian share the mechanics but not the controls.** The helpers for sysctl, SSH drop-ins, accounts, mounts, firewall rules, `dnf` and records live in `internal/`, but many controls that are the same on both systems exist twice, once per system folder. Moving more of their logic into `internal/` would make a fix land once.
- **`ldp.aide-dnf-hook`** can only update the AIDE baseline after a transaction, because `dnf 4` has no hook that runs before one. The Debian hook can also check before. Revisit this when AlmaLinux moves to `dnf 5`.
- **`baseline.dnf-mirror`** takes any HTTPS mirror and has no preset for a hosting provider. Add presets only if there is a provider whose mirror layout is worth knowing.

## Not planned

Server roles (web, mail, database) and private networking such as Tailscale. See *Out of scope* in the README.
