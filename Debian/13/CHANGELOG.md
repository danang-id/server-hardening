# Changelog (Debian-13)

## Version: Debian-13-Rev-3
27 October 2026

* **Recovery and routine.** `GUIDE.md`, the manual guide, is removed. Its recovery steps and its weekly and monthly routine moved to `OPERATIONS.md`, which is written against what the tool does and also lists what to prepare before a run. (27 October 2026, Danang Galuh Tegar Prasetyo)
* **README.** The README links `OPERATIONS.md` from the quick start, and its out-of-scope list now names containers, provider security settings, partition changes on a running system and port knocking. (27 October 2026, Danang Galuh Tegar Prasetyo)

## Version: Debian-13-Rev-2
26 October 2026

* **Shared code.** The helpers that do not depend on the operating system (sysctl, SSH drop-ins, accounts, SSH keys, mounts and the firewall) moved to `internal/`, and the Debian controls call them. The behavior of the controls did not change. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **Install zsh.** `misc.zsh` now asks which framework to set up for the chosen accounts: none, Oh My Zsh or Zim. The separate `misc.oh-my-zsh` control is removed, so Debian 13 has 57 controls. Zim installs a pinned release after a SHA-256 check, with its default modules at pinned commits. A framework that fails half way shows as partial and the next run repairs it. An account that already has a framework directory the tool did not make is refused before any change. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **Questions that depend on an answer.** The Oh My Zsh theme and plugins are asked only when Oh My Zsh is chosen. The form, the plain prompts and the review screen follow this. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **Administrator account to be created.** The zsh question, the SSH allow-list and the `hidepid` group now offer the account that `aaa.admin-user` is about to create, labelled "to be created". Before, they listed only accounts that already existed. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **Controls applied in part.** The planner no longer counts a control that is applied in part as applied. A selected one is finished, and one that another control needs is offered. A control that has nothing left to do and only waits for a reboot or for the clock to synchronize (`baseline.time-sync`, `network.systemd-networkd`, `mac.apparmor-enable`) is now pending, not partial. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **Swap file.** `misc.swapfile` can be applied again after it was switched off or made readable, instead of stopping with "Revert it first". (26 October 2026, Danang Galuh Tegar Prasetyo)
* **debsums.** `asr.debsums-baseline` ignores missing files under `/usr/share/man`, `doc`, `info`, `locale` and `lintian`, which minimal images leave out. Other missing files still count. Before, a minimal image failed on over a thousand harmless lines. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **AIDE.** `ldp.aide` no longer calls `update-aide.conf`, which Debian removed in aide 0.17. AIDE reads `/etc/aide/aide.conf.d` itself. (26 October 2026, Danang Galuh Tegar Prasetyo)
* **AppArmor.** `mac.apparmor-enforce-profiles` installs `apparmor-utils`, which provides `aa-enforce`, before it enforces a profile. A server can run AppArmor without that package. (26 October 2026, Danang Galuh Tegar Prasetyo)

## Version: Debian-13-Rev-1
20 October 2026

* **Interactive tool.** Debian 13 is now supported by the tool, with 58 controls in all ten categories, 44 of them ticked by default. It has a full-screen interface with a plain-prompt fallback, entry scripts for Linux and Windows, and a release workflow. Controls check, apply and revert. (20 October 2026, Danang Galuh Tegar Prasetyo)

## Version: Debian-13-Rev-0 
22 May 2026

* **Initial Release.** The manual step-by-step guide (`GUIDE.md`). (22 May 2026, Danang Galuh Tegar Prasetyo)
