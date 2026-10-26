# Control Reference for AlmaLinux 10

This is the reference for every hardening control the tool offers on AlmaLinux 10. The tool links each control to its entry here, so you can read what a control does before you tick it.

It describes the controls. It does not contain commands to copy. The tool is the single place where the work is done, so this page cannot drift away from it. Names of files, packages, services and commands appear inline only so you can find and check them.

Part of [Server Hardening](../../README.md). Links in the tool point at the `latest` release of this file.

The controls support AlmaLinux 10, any minor release (10.0, 10.1, 10.2 and later), and are written and tested against **10.2**, the latest minor release at the time of writing. The tool matches on the major version. The controls are tested automatically against a simulated system. A run on a real AlmaLinux 10 server is listed in the [roadmap](../../ROADMAP.md).

## How to read an entry

Every control has a stable anchor named after its ID (for example `#remote-access.sftp`), so links keep working when files are renumbered.

| Field | Meaning |
|---|---|
| **ID** | The stable name: `<category-slug>.<name>` |
| **Default** | Whether the tool ticks it in *recommended defaults* mode. Only a suggestion. |
| **Weight** | Run priority across all categories. 500 is the default. |
| **Requires** | Controls that must be applied first. The tool asks before adding them. |
| **Tags** | `lockout` can cut your access if misconfigured. `reboot` needs a reboot. `input` asks you for values. `compat` can break some software. `external` downloads from outside AlmaLinux. `readonly` only checks and reports. It may install the tool it needs to check, but it changes no settings. `irreversible` is not revertible: it cannot be undone, should not be undone automatically, or has nothing to undo. The entry gives the reason. |
| **What it does** | In plain words. |
| **Why** | The risk it reduces. |
| **What it changes** | Packages installed, files written, services touched. A `readonly` control has **What it checks** instead. |
| **Inputs** | What the tool asks you, and the suggested answer. Each prompt shows the suggestion, and Enter accepts it. |
| **Side effects** | What might behave differently afterwards. |
| **How to verify** | How to confirm it is applied. This is also what the tool's own check does. |
| **Notifications** | Events the control reports through `misc.notify`. Only present when it reports any. |
| **Revert** | What the tool's revert does, or the reason there is none. |
| **Revert limits** | What it cannot restore. Only present when there are limits. |

## Category coverage

Every category has at least one control on AlmaLinux 10.

| No. | Category | Controls | Status |
|---|---|---|---|
| 01 | Operating System Baseline | 7 | Covered |
| 02 | Accounts, Authentication and Authorization (AAA) | 4 | Covered |
| 03 | Remote Access | 9 | Covered |
| 04 | Network Exposure | 5 | Covered |
| 05 | Attack-Surface Reduction (ASR) | 4 | Covered |
| 06 | Mandatory Access Control (MAC) | 2 | Covered |
| 07 | Logging, Detection and Prevention | 7 | Covered |
| 08 | System and Kernel | 6 | Covered |
| 09 | Filesystem and Storage | 6 | Covered |
| 10 | Miscellaneous | 6 | Covered |

No category is N/A on AlmaLinux 10.

## Control index

56 controls. Of these, 44 are ticked in recommended defaults mode. Weight is 500 unless shown.

| No. | ID | What it does | Default | Weight | Requires | Tags |
|---|---|---|---|---|---|---|
| 0101 | `baseline.hostname` | Set the hostname | Yes |  |  | input |
| 0102 | `baseline.timezone` | Set the time zone | Yes |  |  | input |
| 0103 | `baseline.dnf-mirror` | Configure the AlmaLinux package mirror | No |  |  | input |
| 0104 | `baseline.system-upgrade` | Upgrade all installed packages | Yes |  |  | reboot, irreversible |
| 0105 | `baseline.time-sync` | Enable time synchronization (chrony) | Yes |  |  | input |
| 0106 | `baseline.auto-security-updates` | Install security updates automatically | Yes |  |  | input |
| 0107 | `baseline.epel` | Enable the EPEL repository | No |  |  | external, input |
| 0201 | `aaa.admin-user` | Create a named administrator account | Yes |  |  | input, irreversible |
| 0202 | `aaa.password-quality` | Require strong local passwords | Yes |  |  | input |
| 0203 | `aaa.sudo-policy` | Set how administrators gain root | Yes |  | `aaa.admin-user` | input |
| 0204 | `aaa.password-lockout` | Lock accounts after failed password attempts | Yes |  |  | lockout, input |
| 0301 | `remote-access.authorized-key` | Install the administrator's SSH public key | Yes |  | `aaa.admin-user` | input |
| 0302 | `remote-access.sftp` | Enable SFTP (and therefore `scp`) | Yes |  |  |  |
| 0303 | `remote-access.ssh-banner` | Show a warning banner before login | Yes |  |  | input |
| 0304 | `remote-access.ssh-login-limits` | Limit login attempts and idle time | Yes |  |  | input |
| 0305 | `remote-access.ssh-port` | Move SSH to another port | No |  |  | lockout, input |
| 0306 | `remote-access.ssh-key-only` | Disable password login over SSH | Yes |  | `aaa.admin-user`, `remote-access.authorized-key` | lockout |
| 0307 | `remote-access.ssh-allow-users` | Allow only listed users to use SSH | Yes |  | `aaa.admin-user` | input, lockout |
| 0308 | `remote-access.ssh-no-root-login` | Disable root login over SSH | Yes |  | `aaa.admin-user`, `aaa.sudo-policy`, `remote-access.authorized-key` | lockout |
| 0309 | `remote-access.ssh-disable-forwarding` | Disable X11 and agent forwarding, restrict TCP forwarding | Yes |  |  | input |
| 0401 | `network.firewall` | Install a host firewall that blocks incoming traffic by default | Yes |  |  | lockout, input |
| 0402 | `network.open-ports` | Choose which ports stay open | Yes |  | `network.firewall` | input |
| 0403 | `network.firewall-log-denied` | Log dropped incoming packets | No |  | `network.firewall` | input |
| 0404 | `network.disable-ip-forwarding` | Disable IPv4 and IPv6 forwarding | Yes |  |  | compat |
| 0405 | `network.sysctl-network` | Harden the kernel's network behaviour | Yes |  |  | input |
| 0501 | `asr.dnf-integrity-audit` | Audit the trust of package sources | Yes |  |  | readonly |
| 0502 | `asr.remove-unneeded-packages` | Remove packages a server does not need | Yes |  |  | input, irreversible |
| 0503 | `asr.rpm-verify-baseline` | Check installed files against package checksums | Yes |  |  | readonly |
| 0504 | `asr.review-services` | Review and disable unneeded services | Yes |  |  | input |
| 0601 | `mac.selinux-enforcing` | Run SELinux in enforcing mode | Yes |  |  | compat |
| 0602 | `mac.selinux-audit` | Audit what SELinux blocks and what it does not confine | Yes |  |  | readonly |
| 0701 | `ldp.journald-persistent` | Keep system logs across reboots | Yes |  |  | input |
| 0702 | `ldp.auditd` | Install and enable the audit daemon | Yes |  |  | input |
| 0703 | `ldp.auditd-rules` | Add audit rules for sensitive files and actions | Yes |  | `ldp.auditd` | input |
| 0704 | `ldp.fail2ban-sshd` | Ban hosts that repeatedly fail SSH login | Yes |  | `network.firewall`, `baseline.epel` | input, external |
| 0705 | `ldp.aide` | Build the file integrity baseline (AIDE) | Yes | 930 |  | input |
| 0706 | `ldp.aide-dnf-hook` | Keep the AIDE database in step with dnf runs | Yes | 940 | `ldp.aide` |  |
| 0707 | `ldp.aide-scheduled-check` | Run a scheduled AIDE check | Yes | 950 | `ldp.aide` | input |
| 0801 | `system-kernel.sysctl-kernel` | Harden kernel settings | Yes |  |  | input |
| 0802 | `system-kernel.restrict-ptrace` | Restrict process tracing | Yes |  |  | input, compat |
| 0803 | `system-kernel.restrict-bpf` | Restrict eBPF to root | Yes |  |  | input |
| 0804 | `system-kernel.disable-kexec` | Disable loading a new kernel at runtime | Yes |  |  | compat |
| 0805 | `system-kernel.blacklist-rare-modules` | Disable rarely used kernel modules | No |  |  | input, compat |
| 0806 | `system-kernel.crypto-policy` | Tighten the system-wide cryptographic policy | Yes |  |  | input, compat, lockout |
| 0901 | `filesystem.tmp-hardening` | Mount /tmp with restrictive options | Yes |  |  | input, compat |
| 0902 | `filesystem.shm-hardening` | Mount shared memory with restrictive options | Yes |  |  | input, compat |
| 0903 | `filesystem.proc-hidepid` | Hide other users' processes | Yes |  |  | input |
| 0904 | `filesystem.default-umask` | Set a restrictive default umask | No |  |  | input, compat |
| 0905 | `filesystem.permission-audit` | Audit file permissions | Yes | 900 |  | readonly |
| 0906 | `filesystem.immutable-configs` | Mark key configuration files immutable | No | 960 |  | input |
| 1001 | `misc.basic-tools` | Install common administration tools | No |  |  | input |
| 1002 | `misc.swapfile` | Create a swap file | No |  |  | input |
| 1003 | `misc.vm-tuning` | Tune virtual memory settings | No |  |  | input |
| 1004 | `misc.zsh` | Install zsh | No |  |  | input, external |
| 1006 | `misc.health-check` | Check that the server is healthy after the changes | Yes | 990 |  | readonly |
| 1007 | `misc.notify` | Send event notifications to a webhook | No |  |  | input |

## Revert behavior

Most controls can be reverted from the tool's **Revert** mode. See [Reverting](../../README.md#reverting) for how it works. A revert uses the state the tool recorded before it made the change. Packages that a control installed stay installed, unconfigured and disabled, unless you choose to remove them.

Controls that are **not** revertible are tagged `irreversible`. They show greyed out in the revert list, with the reason:

| Control | Why there is no revert |
|---|---|
| `baseline.system-upgrade` | Cannot be undone. Downgrading packages is not safe. |
| `aaa.admin-user` | Deleting an account automatically could strand the server or destroy data. Remove it by hand if you need to. |
| `asr.remove-unneeded-packages` | Removed packages cannot be restored together with their configuration. Reinstall by hand if needed. |
| Controls tagged `readonly` | Nothing to undo. |

Controls that can be reverted only in part:

| Control | Revert limit |
|---|---|
| `baseline.hostname`, `baseline.timezone`, `baseline.dnf-mirror` | Restore the recorded previous value. With no record, the revert leaves them alone and says so. |
| `baseline.epel` | Packages installed from EPEL stay installed, but no longer get updates. |
| `asr.review-services` | Re-enables the services the control disabled. |
| `system-kernel.disable-kexec`, `system-kernel.restrict-bpf`, `system-kernel.restrict-ptrace` | The kernel may keep the setting until the next reboot. |
| `system-kernel.crypto-policy` | Programs that are already running keep the policy they read at start until they restart. |
| `ldp.auditd` | `auditd` cannot be stopped with `systemctl`. A service that was off before is turned off for the next boot. |
| `ldp.aide` | Removes the baseline database. |
| `misc.zsh` | Removes the framework, restores the recorded `.zshrc` and `.zimrc`, and puts back the recorded login shell. Edits made inside a framework are lost. The package stays. |

## 01 Operating System Baseline

<a id="baseline.hostname"></a>

### baseline.hostname

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Sets the server's hostname to a fully qualified name that you provide, for example `web-1.example.com`.

**Why.** The hostname appears in logs, alerts, TLS certificates and mail headers. A clear, consistent name makes incidents traceable and keeps services that check the name (mail, certificates) working.

**What it changes.** Writes `/etc/hostname` and sets the running hostname with `hostnamectl`. Installs nothing. It does not edit `/etc/hosts`, because AlmaLinux does not keep a line for the server's own name there. If software on the server must resolve the name, add it to your DNS or to `/etc/hosts` yourself.

**Inputs.** The fully qualified hostname. Default: the current hostname.

**Side effects.** Services that are already running keep the old name until they restart. On cloud images, `cloud-init` can reset the hostname at the next boot. When `cloud-init` is present, the control tells it to preserve the hostname.

**How to verify.** The running hostname and `/etc/hostname` both show the new name.

**Revert.** Restores the recorded previous hostname.

**Revert limits.** With no record of the previous hostname, the revert leaves it alone and says so.

<a id="baseline.timezone"></a>

### baseline.timezone

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Sets the system time zone.

**Why.** Log timestamps that use one agreed time zone make it much easier to correlate events across servers. UTC is the usual choice for servers.

**What it changes.** The system time zone setting (`/etc/localtime`), through `timedatectl`. Installs nothing.

**Inputs.** A time zone name from the standard list. Default: `Etc/UTC`.

**Side effects.** New log entries use the new zone. Cron jobs run on local time, so changing the zone shifts their schedule.

**How to verify.** The system reports the chosen time zone.

**Revert.** Restores the recorded previous time zone.

**Revert limits.** With no record, the revert leaves it alone and says so.

<a id="baseline.dnf-mirror"></a>

### baseline.dnf-mirror

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Points the AlmaLinux repositories at one mirror that you choose, over HTTPS, instead of the rotating mirror list.

**Why.** It makes sure updates come from a source you picked and can reach, for example your provider's mirror or a mirror you operate. Packages are still checked against the AlmaLinux signing key, so the mirror cannot swap a package without the check failing.

**What it changes.**
- Rewrites the AlmaLinux repository files in `/etc/yum.repos.d/` (`almalinux*.repo`). In each known repository (BaseOS, AppStream, CRB, extras and the other AlmaLinux ones) it adds a `baseurl` below the mirror and comments out the `mirrorlist`, `metalink` and old `baseurl` lines, marked with `# retired by server-hardening:`. Repositories that are not AlmaLinux's, such as EPEL, are left alone.
- The previous files are backed up first. The control reads the package metadata from the new mirror, and if that fails it puts the previous files back.
- Installs nothing. This control has no preset for any provider. The default is the AlmaLinux project's own mirror.

**Inputs.** The mirror base URL: the folder that holds the release folders (`10/BaseOS` and so on). It must start with `https://`. Default: `https://repo.almalinux.org/almalinux`.

**Side effects.** The server no longer gets the nearest mirror from the mirror list. If the mirror is slow or goes away, updates fail until you change it.

**How to verify.** The repository files point at the chosen mirror, and a metadata refresh succeeds.

**Revert.** Restores the recorded previous repository files.

**Revert limits.** Packages already installed from the mirror stay installed. With no record, the revert leaves the files alone and says so.

<a id="baseline.system-upgrade"></a>

### baseline.system-upgrade

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | reboot, irreversible |

**What it does.** Refreshes the package metadata and installs all available updates for the installed release (`dnf upgrade --refresh`).

**Why.** A fresh image is often weeks or months old. Most break-ins on new servers use flaws that already have fixes.

**What it changes.** Upgrades installed packages, which may restart services and may leave a reboot advisable, for example after a kernel update. It tells you at the end of the run. A minor release update, for example from 10.1 to 10.2, comes through this control too, because AlmaLinux 10 is one rolling stream of minor releases.

**Inputs.** None.

**Side effects.** Services restart during the upgrade, so network-facing services can drop connections briefly.

**How to verify.** After a metadata refresh, no updates remain. This control is a job, not a setting, so the tool never marks it as already applied. The metadata on a new image is old and always looks up to date, so "nothing to upgrade" from it would mean nothing. Whenever you choose it, it refreshes the metadata and runs the upgrade.

**Revert.** None.

**Why there is no revert.** Downgrading packages is not safe, so upgrades are never undone.

<a id="baseline.time-sync"></a>

### baseline.time-sync

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Installs and enables `chrony`, the time synchronization service of AlmaLinux, using the AlmaLinux pool servers.

**Why.** A wrong clock breaks TLS, mail, one-time passwords and log correlation, and makes incident analysis unreliable.

**What it changes.** Installs `chrony`, stops and disables any other time service that is running (`systemd-timesyncd`, `ntpd`, `ntpsec` or `openntpd`), and enables and restarts `chronyd`. If you enter servers, it writes them to `/etc/chrony.d/server-hardening.conf` and, when `/etc/chrony.conf` does not read that folder yet, adds a `confdir` line to it (the previous file is backed up).

**Inputs.** Extra time servers, separated by spaces. Leave empty to use the pool that `chrony` already lists.

**Side effects.** The clock may step once at the first synchronization. Servers you enter are used in addition to the pool that `/etc/chrony.conf` lists.

**How to verify.** The service reports that the clock is synchronised. Right after the start this can take a minute, and the tool shows the control as pending until it does.

**Revert.** Removes the drop-in, restores `/etc/chrony.conf`, stops `chronyd`, and re-enables the time service that was recorded as active before.

**Revert limits.** The `chrony` package stays installed, disabled.

<a id="baseline.auto-security-updates"></a>

### baseline.auto-security-updates

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Installs `dnf-automatic` and configures it to install security updates every day.

**Why.** Fixes reach the server within a day without waiting for a person. This is one of the most effective single hardening steps.

**What it changes.** Installs `dnf-automatic`. Sets `upgrade_type = security`, `download_updates = yes`, `apply_updates = yes` and the reboot choice in `/etc/dnf/automatic.conf` (the previous file is backed up, and its other settings stay). Adds a drop-in for `dnf-automatic-install.timer` that sets the time of the run, and enables that timer. The package's own configuration is otherwise kept.

**Inputs.** The time of the daily run (default 03:00, server time, with a random delay of up to an hour) and whether to reboot automatically when an update needs it (default: no).

**Side effects.** Services restart automatically after updates. Without automatic reboot, a kernel update waits until you reboot. If `ldp.aide-dnf-hook` is applied, it keeps the AIDE database in step with these upgrades. The result of a run goes to the system journal. This control sends no notifications.

**How to verify.** `dnf-automatic-install.timer` is enabled, and `/etc/dnf/automatic.conf` holds the settings above.

**Revert.** Restores `/etc/dnf/automatic.conf`, removes the timer drop-in, and puts the timer back to its recorded state.

**Revert limits.** The `dnf-automatic` package stays installed.

<a id="baseline.epel"></a>

### baseline.epel

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | external, input |

**What it does.** Enables EPEL (Extra Packages for Enterprise Linux), the large extra repository that the Fedora project maintains for the Red Hat family, and optionally the CRB repository that many EPEL packages need.

**Why.** Some tools that servers commonly use are not in AlmaLinux itself. `fail2ban` is the one this project needs (`ldp.fail2ban-sshd`). `htop` and `ncdu` in `misc.basic-tools` come from it too. Because EPEL is software from outside AlmaLinux, the control is off by default and tagged `external`.

**What it changes.** Installs `epel-release`, which adds the repository and its signing key, and runs `crb enable` if you chose to. It then refreshes the package metadata. Packages from EPEL are checked against the EPEL signing key. EPEL's own rules say that its packages must not replace packages from AlmaLinux.

**Inputs.** Whether to enable CRB too (default yes).

**Side effects.** Updates for packages installed from EPEL come from a repository that is not run by AlmaLinux. EPEL has no promise of the stability that AlmaLinux has, and it can drop a package. Install only what you need from it.

**How to verify.** The `epel` repository is enabled, and so is `crb` if you chose it.

**Revert.** Turns CRB off again if this control turned it on, and removes `epel-release` if this control installed it.

**Revert limits.** Packages that were installed from EPEL stay installed, but no longer get updates.

## 02 Accounts, Authentication and Authorization (AAA)

<a id="aaa.admin-user"></a>

### aaa.admin-user

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, irreversible |

**What it does.** Creates a named administrator account for day-to-day work, with a home directory and membership in the `wheel` group. If the account already exists, the control only makes sure it is in that group.

**Why.** Working as root means every command has full power and the logs cannot tell people apart. A named account lets you switch off root login and keeps actions traceable.

**What it changes.** Creates the user and its home directory (readable by the owner only, mode 0700), installs `sudo` if it is missing, and adds the user to the `wheel` group, which is the administrator group of AlmaLinux. It can also set the account's password. An existing account is never created again, and an existing system account (user ID below 1000) is refused.

**Inputs.** The username (default: the name of the user who started the tool, unless that is root). A password, hidden and asked twice. Leave it empty to create the account with a locked password, which only works with a `sudo` policy that does not ask for a password (see `aaa.sudo-policy`). For an account that already exists, an empty password leaves its password as it is.

**Side effects.** The account can use `sudo` as soon as the `sudo` policy allows it. If `aaa.password-quality` is already active, the password must meet its rules.

**How to verify.** The account exists and is a member of the `wheel` group.

**Revert.** None.

**Why there is no revert.** Deleting an account automatically could strand the server or destroy data. Remove it by hand if you need to.

<a id="aaa.password-quality"></a>

### aaa.password-quality

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Requires stronger local passwords: a minimum length, a mix of character types, no dictionary words, and nothing based on the username.

**Why.** Local passwords still matter for `sudo`, the console, and anything that bypasses SSH keys. Strong rules stop the weakest choices.

**What it changes.** Installs `libpwquality` and writes the drop-in `/etc/security/pwquality.conf.d/99-server-hardening.conf`. The rules also apply when root sets a password. It does not edit any PAM file: AlmaLinux builds its PAM stack with `authselect`, and the standard profiles already call `pam_pwquality`. If the stack of this server does not call it (a custom `authselect` profile), the control stops before it changes anything and says how to fix the profile.

**Inputs.** The minimum length (default 14, from 8 to 128), and how many of the four character types (lowercase, uppercase, digits, symbols) are required (default 3).

**Side effects.** Weak new passwords are rejected. Existing passwords are not checked. Scripts that set passwords can be rejected too.

**How to verify.** The drop-in is present and the PAM password stack lists the `pam_pwquality` module.

**Revert.** Removes the drop-in. An earlier file of the same name comes back.

**Revert limits.** The package stays installed, unused. Passwords that were already changed stay changed.

<a id="aaa.sudo-policy"></a>

### aaa.sudo-policy

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | `aaa.admin-user` |
| **Tags** | input |

**What it does.** Installs `sudo` and sets how administrators gain root: with their own password (default), with no password, or with root's password.

**Why.** `sudo` is the controlled, logged way to use root. The policy decides what a stolen SSH key or session is worth.

**What it changes.** Installs `sudo` if missing. Writes the drop-in `/etc/sudoers.d/99-server-hardening`, which is syntax-checked before it is activated. The rule is for the `wheel` group. The name sorts last, so it also overrides an earlier rule such as the `NOPASSWD` one that cloud-init writes. It runs `sudo` commands in their own pseudo-terminal (`use_pty`), and shortens the password cache to five minutes. `sudo` already logs every use to the system journal, so the control adds no log file. If you give a password for root with the root-password policy, it also sets root's password.

**Inputs.** The policy: `own password` (default), `no password`, or `root password`. For `root password`, optionally a new password for root (hidden, asked twice). Leave it empty to keep root's current password.

**Side effects.**
- With `no password`, anyone who gets a shell on the admin account gets root.
- With `own password`, the admin account needs a password (set in `aaa.admin-user`).
- With `root password`, `sudo` asks for root's password, so root must have one.
- Automation must be able to supply whatever the policy asks for.
- The control stops without changing anything if the policy could not work: `own password` when no administrator has a password, or `root password` when root has no usable password. A locked root (`passwd -l root`) makes `sudo` reject every attempt, even with the right password.

**How to verify.** The sudoers configuration passes validation, and the admin account can run a command as root under the chosen policy.

**Revert.** Removes the drop-in and checks the `sudoers` configuration again. If the check fails, the drop-in is put back and the revert stops. It also restores the recorded state of root's password if the control changed it.

**Revert limits.** The `sudo` package stays installed.

<a id="aaa.password-lockout"></a>

### aaa.password-lockout

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | lockout, input |

**What it does.** Locks a local account for a set time after too many failed password attempts.

**Why.** Slows down password guessing at the console and on `sudo` password prompts.

**What it changes.** Writes the rules to `/etc/security/faillock.conf` (the previous file is backed up, and its other settings stay). It then switches on the `with-faillock` feature of the active `authselect` profile (`authselect enable-feature with-faillock`), which makes `authselect` put `pam_faillock` into the PAM authentication stack. The feature is the supported way to do this on AlmaLinux, so package upgrades keep the result. If `authselect` cannot report its profile, the control stops before it changes anything.

**Inputs.** The number of failed attempts (default 5) and the lock time in minutes (default 15). Failures are counted over the same period.

**Side effects.** Applies to password logins and `sudo` password prompts. SSH key logins are not counted. Someone who knows a username can lock that account for the lock time on purpose. Root is not locked, so the console stays usable.

**How to verify.** After the chosen number of wrong passwords at the console, the account is refused. The lock state can be listed and cleared with the `faillock` command.

**Revert.** Restores the recorded `faillock.conf`, and switches the `with-faillock` feature off again, but only if it was off before this control.

**Revert limits.** None.

## 03 Remote Access

Safety for every `lockout` control: before the change is applied, the tool starts a one-off systemd timer (`server-hardening-undo-<control>`). Then it asks you to open a second session and confirm that you can still log in. If you confirm, the timer is stopped and the change stays. If you do not confirm within 10 minutes, or the connection is lost and you never answer, the timer runs `hardening --undo <control>` and the change is undone, with no session needed. The timer uses a copy of the tool kept in `/var/lib/server-hardening/bin`, so it works even if the original file is gone. Without systemd, or if the timer cannot be started, the tool warns you and only this session can undo the change. For a control that cannot be reverted, the tool warns you instead and asks you to keep your provider's console open.

SSH settings are written as drop-ins in `/etc/ssh/sshd_config.d/`. `sshd` uses the first value it reads, and it reads the files in alphabetical order, so every drop-in from this tool is named `00-server-hardening-<name>.conf`. That sorts before the files of AlmaLinux (`50-redhat.conf`) and of providers (`50-cloud-init.conf`). After every change the tool lets `sshd` check the whole configuration (`sshd -t`), reloads it, and reads back the effective settings (`sshd -T`). If `sshd` refuses the configuration, the reload fails, or another setting still overrides the new value, the previous state is put back and the error says why.

The algorithms that SSH accepts are not set here. AlmaLinux sets them for the whole system with the cryptographic policy, which is the control `system-kernel.crypto-policy` in category 08.

<a id="remote-access.authorized-key"></a>

### remote-access.authorized-key

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | `aaa.admin-user` |
| **Tags** | input |

**What it does.** Installs your SSH public key for the administrator account, so you can log in without a password.

**Why.** Key login is the foundation for switching off password login. Only the public half of a key is ever pasted or stored on the server.

**What it changes.** Creates `~/.ssh` and `authorized_keys` for the admin account with strict permissions and the right owner, and adds the keys you give, without duplicates.

**Inputs.** One or more public keys, one per line. The text box starts with the keys of the account that started the tool (or root's), so a key you already use is easy to reuse. Each line is checked to be a plain public key: `ssh-ed25519`, `ecdsa-sha2-*`, `ssh-rsa` with at least 2048 bits, and the security-key types `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`. A private key, a line with options such as `command=`, a DSA key and a certificate are refused. If more than one account is in the `sudo` group, the control stops and asks you to pick one with `aaa.admin-user` first.

**Side effects.** None.

**How to verify.** The file exists with the right owner and permissions and contains the key.

**Revert.** Removes the keys this control added, and leaves any other keys and lines alone. The `authorized_keys` file and the `.ssh` folder are removed only if this control created them and nothing else is in them. Because `remote-access.ssh-key-only` and `remote-access.ssh-no-root-login` require this control, the revert screen offers to revert them first.

**Revert limits.** None.

<a id="remote-access.sftp"></a>

### remote-access.sftp

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | none |

**What it does.** Turns on the SFTP service inside SSH. This also makes `scp` work, because current OpenSSH versions use the SFTP protocol for `scp`.

**Why.** A hardened SSH setup that omits the SFTP subsystem breaks `sftp` and `scp` with the error "subsystem request failed". Plain `ssh` and `rsync` keep working, which makes the problem easy to miss. This control makes file transfer work by design.

**What it changes.**
- Installs `openssh-server` if it is not present.
- Adds a small drop-in file in `/etc/ssh/sshd_config.d/` that declares the `internal-sftp` subsystem. The main `sshd_config` is not rewritten.
- Validates the configuration, then reloads `sshd`. Existing sessions are not cut.

**Inputs.** None.

**Side effects.** None expected. SFTP access follows the same users and keys as SSH.

**How to verify.** The effective `sshd` configuration lists the `sftp` subsystem, and an `sftp` login with your key succeeds.

**Revert.** Removes the drop-in file, validates the configuration, and reloads `sshd`. Afterwards the `sftp` subsystem is gone from the effective configuration.

**Revert limits.** None. `openssh-server` stays installed.

<a id="remote-access.ssh-banner"></a>

### remote-access.ssh-banner

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Shows a warning banner before login, stating that access is restricted and monitored.

**Why.** It makes the rules clear to anyone who connects, and some compliance frameworks ask for it. It does not stop an attack by itself.

**What it changes.** Writes the banner text to its own file and adds a drop-in that points `sshd` at it.

**Inputs.** The banner text. Default: a short standard notice.

**Side effects.** The banner is sent before authentication to every client, including `scp`, `sftp` and scripts. It appears on their error output, which is harmless but visible.

**How to verify.** Connecting shows the banner before the login prompt.

**Revert.** Removes the drop-in and the banner file.

**Revert limits.** None.

<a id="remote-access.ssh-login-limits"></a>

### remote-access.ssh-login-limits

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Limits how long and how often a connection can try to log in, and drops clients that stop responding.

**Why.** It cuts the time and attempts an attacker gets per connection, and cleans up dead sessions.

**What it changes.** A drop-in with: a limit on authentication attempts per connection, a time limit to complete login, a cap on simultaneous unauthenticated connections, and a keep-alive check that disconnects a client that stops answering.

**Inputs.** Authentication attempts per connection (default 3), seconds allowed to log in (default 30), the cap on simultaneous unauthenticated connections (default `10:30:60`, meaning random drops start at 10 and become certain at 60), and the keep-alive interval in seconds (default 300). A client that misses two checks in a row is disconnected, so the default drops a dead client after about 10 minutes.

**Side effects.** If your SSH agent offers many keys, each offered key counts as an attempt, so you can be refused before reaching the right one. Set `IdentitiesOnly yes` in your client configuration to avoid this. Long idle sessions stay open as long as your client keeps answering.

**How to verify.** The effective `sshd` configuration shows the limits.

**Revert.** Removes the drop-in.

**Revert limits.** None.

<a id="remote-access.ssh-port"></a>

### remote-access.ssh-port

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | lockout, input |

**What it does.** Moves the SSH server from port 22 to a port you choose.

**Why.** It removes most automated scanning noise from the logs. It is not a security control on its own, so it is off by default.

**What it changes.** It works in two steps, because the old port must not close before you know the new one works.
1. First, `sshd` listens on the old port and the new port. If `firewalld` is active, the new port is allowed before `sshd` listens on it. If `sshd` is started through a systemd socket (`sshd.socket`), the socket's listening ports are changed too (a drop-in under `sshd.socket.d`), because the `Port` setting is ignored in that mode. SELinux only lets `sshd` bind ports that carry the type `ssh_port_t`, so the control labels the new port with `semanage port -a -t ssh_port_t` (it installs `policycoreutils-python-utils` for that if it is missing). It refuses a port that SELinux has already given to another service. The control checks that `sshd` really listens on the new port, and undoes everything if it does not.
2. After you log in on the new port from a second session and confirm, the old port is removed from `sshd` (and from the socket). The firewall rule for the old port is not touched.

The control stops without changing anything if the port is in use by another service, if the port is already set in `/etc/ssh/sshd_config` or another drop-in (`sshd` adds all `Port` lines together, so the old port could not be closed), or if an `nftables` firewall that drops incoming traffic is active (this control cannot open a port in such a firewall; allow the new port yourself first).

**Inputs.** The new port number, 1 to 65535 except 22. There is no default.

**Side effects.** Every client, script and monitor that connects must use the new port. Providers' web consoles and some tools assume port 22.

**How to verify.** The server listens on the new port and a login on it succeeds.

**Revert.** Opens the old port in the firewall again, removes the drop-in, restores the socket setting if it was changed, and checks that `sshd` listens on the old port. Then it removes the firewall rule it added for the new port, and the SELinux label if this control added it. A rule or label that existed before stays. The same revert runs by itself if you do not confirm in time.

**Revert limits.** None.

<a id="remote-access.ssh-key-only"></a>

### remote-access.ssh-key-only

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | `aaa.admin-user`, `remote-access.authorized-key` |
| **Tags** | lockout |

**What it does.** Turns off password and keyboard-interactive login over SSH, so only keys work.

**Why.** Password guessing is the most common attack on SSH. Keys cannot be guessed.

**What it changes.** A drop-in that disables password authentication and keeps public-key authentication on. The configuration is validated before `sshd` is reloaded. The control first checks that an account with an authorized key exists.

**Inputs.** None.

**Side effects.** Nobody can log in over SSH with a password any more. The provider's web console is not affected, because it does not use SSH. Drop-ins are read in name order and the first value wins, so this drop-in must be read before provider files such as `50-cloud-init.conf`, which can switch passwords back on. The control names its file so it sorts first.

**How to verify.** The effective `sshd` configuration shows password authentication off, and a login with your key succeeds.

**Revert.** Removes the drop-in. Password login then follows the remaining configuration.

**Revert limits.** If another file, such as a provider's, enables passwords, they work again.

<a id="remote-access.ssh-allow-users"></a>

### remote-access.ssh-allow-users

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | `aaa.admin-user` |
| **Tags** | input, lockout |

**What it does.** Allows only the accounts you list to log in over SSH.

**Why.** System and service accounts cannot be used remotely, even if one of them gets a weak or default credential.

**What it changes.** A drop-in with the allowed user list. The configuration is validated before `sshd` is reloaded.

**Inputs.** The usernames to allow, separated by spaces or commas. Default: the admin account. Leave the field empty to allow only the admin account. Every name must be an existing account; patterns (`*`, `@group`, `!name`) are refused. The control refuses a list that leaves out every admin account, and a list that leaves out the account that started the tool.

**Side effects.** Accounts created later cannot log in until they are added. Root is also blocked unless it is listed.

**How to verify.** The effective `sshd` configuration shows the user list, and a listed account can log in.

**Revert.** Removes the drop-in.

**Revert limits.** None.

<a id="remote-access.ssh-no-root-login"></a>

### remote-access.ssh-no-root-login

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | `aaa.admin-user`, `aaa.sudo-policy`, `remote-access.authorized-key` |
| **Tags** | lockout |

**What it does.** Disables login as root over SSH.

**Why.** Root is the one account name every attacker knows. Without root login, remote access needs a named account, which also makes actions traceable.

**What it changes.** A drop-in that turns off root login. Before applying, the control checks that the admin account has a key in place and can use `sudo`.

**Inputs.** None.

**Side effects.** Backup jobs, rsync and automation that log in as root stop working. Switch them to the admin account with `sudo`. Root can still log in on the console.

**How to verify.** The effective `sshd` configuration shows root login off, and the admin account can log in and use `sudo`.

**Revert.** Removes the drop-in. The default of the system then applies again.

**Revert limits.** None.

<a id="remote-access.ssh-disable-forwarding"></a>

### remote-access.ssh-disable-forwarding

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Turns off the SSH features that make the server a relay: X11 forwarding and agent forwarding are switched off, and TCP forwarding follows your choice.

**Why.** A stolen key or a compromised account cannot then be used to reach internal networks through the server (an attacker with a shell can still bring their own tools). Agent forwarding off keeps your agent out of reach of anyone with root on the server.

**What it changes.** A drop-in with the forwarding settings.

**Inputs.** TCP forwarding mode:
- `no` (default): no tunnels at all.
- `local`: allows tunnels from your computer through the server, such as `ssh -L`, jump hosts (`-J`) and tools that tunnel over SSH.
- `remote`: allows tunnels back from the server to your computer (`ssh -R`).
- `yes`: both.

**Side effects.** With `no`, tunnels, jump hosts and tools that rely on them, such as VS Code Remote-SSH, can stop working. Shell, `sftp`, `scp` and `rsync` are not affected.

**How to verify.** The effective `sshd` configuration shows the chosen values.

**Revert.** Removes the drop-in.

**Revert limits.** None.

## 04 Network Exposure

AlmaLinux ships `firewalld`, so that is the default engine here. `nftables` is offered as the alternative for people who want one plain rule file. `ufw` is a Debian-family tool and is not offered.

<a id="network.firewall"></a>

### network.firewall

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | lockout, input |

**What it does.** Installs and turns on a host firewall that blocks incoming connections unless they are allowed. SSH is allowed automatically. You choose the firewall engine.

**Why.** A server that answers only on the ports it needs has far fewer ways in. A service that starts listening by accident, such as a database or an admin panel, is not exposed.

**What it changes.** For both engines, the control:
- Installs the engine's package.
- Allows loopback traffic, replies to connections the server started, ICMP and ICMPv6 (IPv6 needs it to work), and SSH on the ports `sshd` is really listening on, including the port of your current session. `remote-access.ssh-port` adds its new port to the rules too.
- Drops all other incoming traffic. Outgoing traffic is not restricted.
- Loads the rules at boot.

How each engine does it:
- `firewalld`: the default, and the firewall AlmaLinux ships. The control backs up the existing configuration, sets the default zone to `public` (which rejects everything that is not allowed), adds the SSH ports to it, and removes the `ssh` and `cockpit` services from the zone. The `ssh` service would keep port 22 open after SSH moved, and `cockpit` opens the web console on port 9090. The `dhcpv6-client` service stays, so IPv6 address assignment keeps working. Then it enables the service and reloads it.
- `nftables`: writes the rules to `/etc/nftables/server-hardening.nft`, as its own table (`inet server_hardening`), checks them with `nft -c`, and loads them in one step. A line in `/etc/sysconfig/nftables.conf` includes the file at boot. The service is enabled but not started, because starting it would flush the rules of other software such as Docker. Other firewall rules on the server are not flushed or replaced. The file is rebuilt from the records of `network.firewall`, `network.open-ports` and `network.firewall-log-denied` whenever one of them changes, so the three always agree. If `firewalld` is running, the control loads its own table first, and only then stops and disables `firewalld`, so the server is never without a firewall.

**Inputs.** The firewall engine:
- `firewalld`: a zone-based firewall manager, the default on AlmaLinux. This is the default answer.
- `nftables`: the packet filter of the kernel, driven directly. Choose it when you want one plain rule file and no daemon.

If an `nftables` firewall that drops incoming traffic is loaded and is not this tool's, the control refuses to add a second one. To switch engines, revert this control first. If no SSH port can be found, the control refuses, because it could lock you out. AlmaLinux does not ship `ufw`, and this tool does not offer it.

**Side effects.** Only traffic to the server itself is filtered. Container runtimes such as Docker publish ports through forwarding rules, which these firewalls may not filter, so restrict published ports in the runtime. Anything else that must be reachable has to be opened with `network.open-ports`. If `firewalld` had other zones or services configured, only the `public` zone and the default zone change.

**How to verify.** The engine's status shows it running with incoming traffic denied (`firewall-cmd --state`, or the loaded table `inet server_hardening`), and your SSH session still works.

**Revert.** Undoes the engine-specific part, using the state recorded before the change:
- `firewalld`: restores the backed-up configuration, and stops the service if it was not running before.
- `nftables`: removes the table and the boot-time loading, and if this control turned `firewalld` off, turns it on again first.

Other rules are left alone.

**Revert limits.** The engine's package stays installed.

<a id="network.open-ports"></a>

### network.open-ports

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | `network.firewall` |
| **Tags** | input |

**What it does.** Lets you choose which ports stay open for incoming connections, optionally only from certain addresses.

**Why.** Every open port is exposure. Opening only what the server's job needs keeps that small.

**What it changes.** Adds the allow rules in the engine chosen for `network.firewall`: ports and rich rules in the `public` zone for `firewalld`, or an include file for `nftables`. The rules are applied without dropping existing connections.

**Inputs.** A list of the ports that are listening on the server and reachable from outside (loopback-only sockets and SSH are left out), with the program that owns each, and a text box for more rules, one per line, in the form `PORT`, `PORT/PROTO` or `PORT/PROTO from ADDRESS` (for example `443/tcp`, `8000-8010/tcp`, or `51820/udp from 203.0.113.0/24`). Default: nothing beyond SSH. Running it again replaces the earlier list: rules that are no longer listed are closed.

**Side effects.** A port that is not allowed becomes unreachable from outside, even if a service is listening on it.

**How to verify.** The engine lists the allow rules (`firewall-cmd --list-ports` and `--list-rich-rules`, or the loaded table), and services answer from the allowed sources.

**Revert.** Removes the rules this control added, so only SSH stays open.

**Revert limits.** Services that were reachable through those rules become unreachable.

<a id="network.firewall-log-denied"></a>

### network.firewall-log-denied

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | `network.firewall` |
| **Tags** | input |

**What it does.** Logs dropped incoming packets to the system log.

**Why.** It shows who is probing the server and which ports they try.

**What it changes.** In the engine chosen for `network.firewall`: `firewalld` gets its denied-packet logging switched on (`firewall-cmd --set-log-denied`), and `nftables` gets a rate-limited logging rule at the end of the incoming chain.

**Inputs.** How much to log, in the engine's own terms:
- `firewalld`: the denied-packet mode (`all`, `unicast`, `broadcast` or `multicast`). Default: `unicast`.
- `nftables`: a rate. Default: 5 per minute.

**Side effects.** On a server exposed to the internet, the log still fills steadily with scan noise, even at low settings.

**How to verify.** The engine shows the logging setting, and dropped packets appear in the system log.

**Revert.** Removes the logging rule, or puts back the recorded previous logging setting.

**Revert limits.** None.

<a id="network.disable-ip-forwarding"></a>

### network.disable-ip-forwarding

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | compat |

**What it does.** Turns off IPv4 and IPv6 packet forwarding, so the server does not act as a router.

**Why.** A server that is not a router should not pass packets between networks. This stops it being used as a pivot.

**What it changes.** A kernel settings drop-in in `/etc/sysctl.d/`, applied immediately.

**Inputs.** None.

**Side effects.** Anything that routes traffic stops working: container networking such as Docker, VPN gateways and subnet routers, and NAT for virtual machines. Do not apply this control on such servers. Container runtimes also switch forwarding back on when they start, which undoes this control.

**How to verify.** The running forwarding settings are off for IPv4 and IPv6.

**Revert.** Removes the drop-in and puts back the recorded running values.

**Revert limits.** None.

<a id="network.sysctl-network"></a>

### network.sysctl-network

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Hardens the kernel's network behavior: it ignores ICMP redirects and source-routed packets, stops sending redirects, enables SYN cookies, ignores broadcast pings and bogus ICMP errors, turns on reverse-path filtering in the loose mode, and logs packets with impossible addresses. It can also make the server ignore IPv6 router advertisements. Each setting is written for all current and future interfaces.

**Why.** These settings close old tricks used to redirect traffic, spoof addresses or exhaust connection tables. Ignoring router advertisements stops another machine on the same network segment from handing the server a fake IPv6 route or address.

**What it changes.** A kernel settings drop-in, `/etc/sysctl.d/99-server-hardening-network.conf`, applied immediately. It sets, for `all` and `default`: `accept_redirects` 0 (IPv4 and IPv6), `secure_redirects` 0, `send_redirects` 0, `accept_source_route` 0 (IPv4 and IPv6), `rp_filter` 2 (loose), `log_martians` 1; and `tcp_syncookies` 1, `icmp_echo_ignore_broadcasts` 1, `icmp_ignore_bogus_error_responses` 1. With router advertisements off, it also sets `accept_ra` 0. A parameter the kernel does not have is skipped.

**Inputs.** Whether to accept IPv6 router advertisements (`yes` or `no`). The default depends on what the tool finds:
- `no` when the server's IPv6 address and route are static, for example set by `cloud-init` from the provider's dashboard.
- `yes` when the address or route came from a router advertisement, so IPv6 keeps working.

The other settings are a fixed list.

**Side effects.** If you choose `no` on a server whose IPv6 address comes from router advertisements, IPv6 connectivity is lost at the next renewal or reboot. The tool warns when it detects this. Logging of impossible addresses can add log lines on busy servers.

**How to verify.** The running values match the drop-in.

**Revert.** Removes the drop-in and puts back the recorded running values.

**Revert limits.** None.

## 05 Attack-Surface Reduction (ASR)

<a id="asr.dnf-integrity-audit"></a>

### asr.dnf-integrity-audit

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | readonly |

**What it does.** Checks that the server's package sources are signed and trusted, and reports anything unusual. It changes nothing.

**Why.** A tampered or unknown package source can install anything as root.

**What it checks.** It reads `/etc/dnf/dnf.conf` and the files in `/etc/yum.repos.d/`.
- Repositories, or the global settings in `dnf.conf`, that turn off the check of package signatures (`gpgcheck=0`) or of server certificates (`sslverify=0`).
- Package URLs that use plain HTTP or FTP, and signing keys (`gpgkey`) fetched over plain HTTP.
- Repositories on hosts other than AlmaLinux and the Fedora project (EPEL), so third-party repositories you may not know about stand out.

**Inputs.** None.

**Side effects.** None.

**How to verify.** The report lists the repositories and any findings. The control shows as partial while it has findings.

**Revert.** Nothing to revert. The control changes nothing.

<a id="asr.remove-unneeded-packages"></a>

### asr.remove-unneeded-packages

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, irreversible |

**What it does.** Shows packages that a server rarely needs and lets you choose which to remove.

**Why.** Every installed package is attack surface and something to patch.

**What it changes.** The tool builds the list from a built-in set of packages that servers rarely need, such as legacy network clients and servers (`telnet`, `rsh`, `tftp`, `ypbind`), desktop-style services (`avahi`, `bluez`, `ModemManager`, `cups`) and the web console `cockpit-ws`, and shows only those that are installed. The ones you tick are removed with `dnf remove`, and packages that were only needed by them are removed too. Next to each package the tool shows what else would go with it, and the full list is written to the log before anything is removed. The tool simulates the removal first (`dnf remove --assumeno`) and refuses it if it would take a package the server needs, such as `openssh-server`, `sudo`, `systemd`, `firewalld`, `NetworkManager`, `selinux-policy` or the kernel. Legacy clients and desktop-style services are ticked at first. `cockpit-ws` and the mail transfer agents are listed but not ticked.

**Inputs.** Tick the packages to remove. Nothing is removed that you do not tick.

**Side effects.** The services in those packages stop. For example, removing a mail transfer agent stops local mail delivery, including mail from cron jobs, and removing `cockpit-ws` removes the web console.

**How to verify.** The chosen packages are no longer installed. This control is a job, not a setting, so the tool never marks it as already applied. If none of the packages it looks for is installed, it is shown as "nothing to remove" and cannot be ticked, which is the normal state of a minimal server.

**Revert.** None.

**Why there is no revert.** Removed packages cannot be restored together with their configuration. Reinstall by hand if needed.

<a id="asr.rpm-verify-baseline"></a>

### asr.rpm-verify-baseline

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | readonly |

**What it does.** Compares installed files against the checksums stored in the RPM database, and reports files that differ or are missing. The result is saved as a baseline, so a later check can show only what changed since.

**Why.** It shows programs that were modified after installation, whether by tampering or by accident.

**What it changes.** Nothing on the system, and it installs nothing: `rpm` is always there. It runs `rpm -Va --nomtime` and reads the result. Configuration files, ghost files and documentation are ignored, because they are expected to change. Only a changed checksum or a missing file counts, not a changed time, size, mode or owner alone. The list of differing files is kept in the records, and a later run reports only the files that are new since then.

**Inputs.** None.

**Side effects.** None. The check reads every installed file and takes a few minutes on a large system.

**How to verify.** The report lists any differing files, and the baseline is saved in the records folder.

**Revert.** Nothing to revert.

<a id="asr.review-services"></a>

### asr.review-services

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Lists the enabled services and the ports they listen on, explains each one in plain words, and lets you choose which to stop and disable.

**Why.** A service you do not need is exposure for nothing.

**What it changes.** Stops and disables the services you pick, and records which ones it changed and whether each was running. Access and network services (`sshd`, `NetworkManager`, `systemd-*`, `cloud-*`, `crond`, `sssd`, logging, the firewall, `chronyd`, `auditd`, `tuned` and the tools of this project) are never listed. The ports shown next to a service are matched by the name of the process, so treat them as a hint.

**Inputs.** Tick the services to disable. Nothing is disabled without your confirmation.

**Side effects.** Software that depends on a disabled service may fail. The list says what each service is for, so you can judge.

**How to verify.** The chosen services are stopped and disabled.

**Revert.** Re-enables the services this control disabled, and starts the ones that were running before.

**Revert limits.** Only services this control changed are touched.

## 06 Mandatory Access Control (MAC)

AlmaLinux uses SELinux. It is installed and enforcing on a standard image, so the controls here keep it that way and show where it gets in the way. AppArmor, the Debian choice, does not exist on this system.

<a id="mac.selinux-enforcing"></a>

### mac.selinux-enforcing

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | compat |

**What it does.** Makes sure SELinux is in enforcing mode now and after every boot.

**Why.** SELinux confines each service to what its policy allows, so a hijacked web server or database cannot read your SSH keys or rewrite system files, even as root. AlmaLinux ships the policy and enables it. Servers that were moved to permissive mode "just to make something work" lose that protection without anyone noticing.

**What it changes.** Installs `libselinux-utils` if it is missing, sets `SELINUX=enforcing` in `/etc/selinux/config` (the previous file is backed up), and runs `setenforce 1` if the system is permissive. If SELinux is disabled, the control stops without changing anything, because the filesystem has to be relabeled before it can be enforcing: it prints the steps (set `SELINUX=permissive` in `/etc/selinux/config`, remove `selinux=0` from the kernel command line, run `fixfiles onboot`, reboot, then apply this control).

**Inputs.** None.

**Side effects.** Software that worked only because SELinux was permissive starts to fail with "permission denied" and an `AVC` record in the audit log. Fix it with the right file label or boolean, not by turning enforcing mode off. `mac.selinux-audit` lists what SELinux denied.

**How to verify.** `getenforce` prints `Enforcing` and `/etc/selinux/config` says `SELINUX=enforcing`. If only one of the two holds, the control shows as partial.

**Revert.** Restores `/etc/selinux/config` and puts the running mode back to permissive if it was permissive before.

**Revert limits.** None.

<a id="mac.selinux-audit"></a>

### mac.selinux-audit

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | readonly |

**What it does.** Checks the state of SELinux and reports what looks wrong. It changes nothing.

**Why.** Enforcing mode only helps when the policy really covers your services. The audit shows where it does not.

**What it checks.**
- Whether SELinux is permissive or disabled, and whether `/etc/selinux/config` asks for something different from the running mode.
- Access denials (`AVC` records) since the last boot, counted by the program that was denied (`ausearch -m AVC,USER_AVC -ts boot`). This needs the audit daemon, so apply `ldp.auditd` for a complete record.
- Processes that run in the `unconfined_service_t` domain, which means a service that has no SELinux policy of its own.

**Inputs.** None.

**Side effects.** None.

**How to verify.** The report lists the findings. The control shows as partial while it has findings.

**Revert.** Nothing to revert. The control changes nothing.

## 07 Logging, Detection and Prevention

AIDE, `fail2ban` and `auditd` differ from Debian in a few places that matter. AIDE has one configuration file and a compressed database, `dnf` offers a hook that runs after a transaction but not before it, and `fail2ban` comes from EPEL. Each entry says what that means.

<a id="ldp.journald-persistent"></a>

### ldp.journald-persistent

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Keeps the system logs on disk across reboots, within limits you set.

**Why.** Logs that vanish at reboot are useless after a crash or a break-in, which is exactly when you need them.

**What it changes.** A drop-in in `/etc/systemd/journald.conf.d/` that sets persistent storage and the limits, and creates the log directory. The journal service is restarted.

**Inputs.** The maximum disk space for logs (default `500M`) and how long to keep them (default 90 days).

**Side effects.** The logs use disk space up to the limit.

**How to verify.** The log directory exists and the journal lists entries from before the last boot.

**Revert.** Removes the drop-in. The journal goes back to its automatic storage mode.

**Revert limits.** Logs already written to disk stay there.

<a id="ldp.auditd"></a>

### ldp.auditd

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Installs and enables the Linux audit daemon, which records security-relevant events at the kernel level.

**Why.** The audit trail shows who ran what and which sensitive files were touched. The normal system log does not capture this. SELinux denials are recorded here too.

**What it changes.** Installs `audit` and `audit-rules`, and edits `/etc/audit/auditd.conf` for log size and rotation (the previous file is backed up). It enables the service at boot.

**Inputs.** The size of each audit log file in megabytes (default 50) and how many files to keep (default 5).

**Side effects.** A little more disk use and CPU. It records nothing useful until rules are added, which `ldp.auditd-rules` does. `auditd` refuses a manual `systemctl stop` on purpose.

**How to verify.** The audit status shows it enabled.

**Revert.** Restores the backed-up configuration. If the service was not enabled before, it is disabled. `auditd` cannot be stopped with `systemctl`, so a service that was not running before stops at the next reboot, and the tool tells you so.

**Revert limits.** The `audit` packages stay installed. Audit logs already written stay.

<a id="ldp.auditd-rules"></a>

### ldp.auditd-rules

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | `ldp.auditd` |
| **Tags** | input |

**What it does.** Adds a short, curated set of audit rules for the events that matter most.

**Why.** Watching everything produces noise nobody reads. These rules cover the changes an attacker usually makes.

**What it changes.** A rules file in `/etc/audit/rules.d/`, loaded straight away. It watches:
- Account and password files, and `sudo` configuration.
- SSH configuration.
- Login and `sudo` use.
- Kernel module loading.
- SELinux policy and configuration (`/etc/selinux/` and `/usr/share/selinux/`).
- Changes to the audit configuration itself.

**Inputs.** Whether to lock the rules until the next reboot (default no).

**Side effects.** Busy servers can produce many audit lines. If you lock the rules, they cannot be changed or removed until the server reboots.

**How to verify.** The list of loaded audit rules shows the watches.

**Revert.** Removes the rules file and reloads the rules.

**Revert limits.** If the rules were locked, the removal only takes effect after a reboot.

<a id="ldp.fail2ban-sshd"></a>

### ldp.fail2ban-sshd

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | `network.firewall`, `baseline.epel` |
| **Tags** | input, external |

**What it does.** Installs `fail2ban` and bans addresses that keep failing to log in over SSH.

**Why.** It cuts brute-force noise and load. With password login switched off, it mostly removes log clutter and the cost of handling junk connections.

**What it changes.**
- Installs `fail2ban`, `fail2ban-selinux` (so SELinux lets it work) and the module it needs to read the system journal. All three come from EPEL, which is why this control requires `baseline.epel`. AlmaLinux 10 writes SSH logins to the journal, so the jail reads the journal.
- Writes a jail for `sshd` that uses the ban method matching the firewall engine chosen in `network.firewall` (`firewalld` rich rules, or `nftables`), and watches the ports `sshd` really listens on.

**Inputs.** Failed attempts before a ban (default 5), the time window those count in (default 10 minutes), the ban time (default 1 hour), and addresses never to ban (default: the address of your current session).

**Side effects.** You can ban yourself with a typing streak of wrong attempts. Many users behind one shared address (NAT) can ban each other. If your address changes, the default exemption stops matching. The jail is written with the SSH ports of the time you apply the control: if you change the SSH port later, apply it again. The packages come from EPEL, not from AlmaLinux.

**How to verify.** `fail2ban-client status sshd` shows the jail running.

**Revert.** Removes the jail, lifts all its bans, and stops and disables `fail2ban` if it was not enabled before.

**Revert limits.** The `fail2ban` packages stay installed.

<a id="ldp.aide"></a>

### ldp.aide

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 930 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Installs AIDE and builds a baseline of file checksums and attributes, so later changes to system files can be detected.

**Why.** If an attacker replaces a program or edits a configuration, the checksums no longer match. The baseline is built late, after nearly all other controls, so it records the hardened system.

**What it changes.**
- Installs AIDE. AIDE on AlmaLinux reads one file, `/etc/aide.conf`, and has no folder for drop-ins. So the control leaves that file alone and writes its own `/etc/aide/server-hardening.conf`, which includes `/etc/aide.conf` and then leaves out volatile paths such as `/proc`, `/run`, `/tmp`, `/var/log`, and the package databases under `/var/lib/rpm` and `/var/lib/dnf`. The program below always uses this file.
- Builds the baseline database with `aide --init`, which writes `/var/lib/aide/aide.db.new.gz`, and moves it to `/var/lib/aide/aide.db.gz`. The scan reads the whole filesystem and takes a few minutes. The tool shows the SHA-256 checksum of the database.
- Installs the small program `/usr/local/libexec/server-hardening/aide-run`, which the dnf hook and the timer call. It logs to the system log and, if `misc.notify` is applied, sends a notification.
- AlmaLinux's AIDE package has no daily check of its own, so there is nothing to switch off.

**Inputs.** Extra paths to leave out of the baseline. Default: none.

**Side effects.** The scan uses disk and CPU while it runs. After an intended change the baseline must be updated, or reports repeat it. A person with root on the server can rebuild the baseline to hide a change, so keep a copy of the database and its checksum somewhere off the server.

**How to verify.** The baseline database exists and a check runs with no differences.

**Revert.** Removes the baseline database, `/etc/aide/server-hardening.conf` and the `aide-run` program. A database that existed before is put back.

**Revert limits.** The AIDE package stays installed.

<a id="ldp.aide-dnf-hook"></a>

### ldp.aide-dnf-hook

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 940 |
| **Requires** | `ldp.aide` |
| **Tags** | none |

**What it does.** Keeps the AIDE baseline in step with package changes: after every dnf transaction it updates the baseline.

**Why.** Without it, every upgrade changes files and the next scheduled report is full of legitimate changes, so people stop reading it.

**What it changes.** Installs the dnf plugin `post-transaction-actions` (the package `python3-dnf-plugin-post-transaction-actions`) and writes `/etc/dnf/plugins/post-transaction-actions.d/server-hardening-aide.action`. The one line in it runs `aide-run update` once after every transaction. The hook only updates the baseline. It never blocks dnf, and an AIDE failure does not fail a transaction.

**There is no check before the transaction.** The Debian version of this control can also check for differences before a package operation, so tampering that happened earlier is logged instead of silently accepted. dnf 4, the version in AlmaLinux 10, only has a hook that runs after a transaction. So here the scheduled check (`ldp.aide-scheduled-check`) is what catches earlier tampering, and an update can accept a change that happened between the last check and the transaction. Run the scheduled check often if that matters to you.

**Inputs.** None.

**Side effects.** Each dnf transaction takes as long as an AIDE scan, usually a few minutes. This includes the daily automatic security upgrades.

**How to verify.** The action file exists, the plugin is installed, and the log shows an AIDE entry after a package operation.

**Revert.** Removes the action file.

**Revert limits.** The baseline stays as it was last updated. The plugin package stays installed.

<a id="ldp.aide-scheduled-check"></a>

### ldp.aide-scheduled-check

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 950 |
| **Requires** | `ldp.aide` |
| **Tags** | input |

**What it does.** Runs an AIDE check on a schedule, using a systemd timer.

**Why.** A baseline only helps if something compares against it regularly.

**What it changes.** A systemd timer and service for the check (`server-hardening-aide-check`). The report goes to the system log, and the service shows as failed when the check finds differences. AlmaLinux's AIDE package has no timer or cron job of its own, so there is none to turn off.

**Inputs.** How often (daily or weekly; default weekly) and at what time (default 03:00).

**Side effects.** Disk and CPU use while it runs. Reports go to the system log. Without `misc.notify`, nobody is told about a report, so look in the log.

**Notifications.** If `misc.notify` is applied, a notification is sent when a check finds differences.

**How to verify.** The timer is active and shows its next run time.

**Revert.** Removes the timer and service.

**Revert limits.** None.

## 08 System and Kernel

<a id="system-kernel.sysctl-kernel"></a>

### system-kernel.sysctl-kernel

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Hardens kernel settings. It hides kernel addresses and the kernel log from ordinary users, restricts performance counters, protects against link and file tricks in shared directories, stops privileged programs from dumping core, turns on full address-space randomisation, and controls the Magic SysRq key.

**Why.** These settings make it harder for an attacker with a foothold to learn where things sit in memory, read kernel messages, or abuse shared directories to gain more privileges.

**What it changes.** A kernel settings drop-in in `/etc/sysctl.d/`, applied immediately.

**Inputs.** The Magic SysRq mode: `off` (default) or `safe` (allows only sync, remount read-only and reboot). The rest of the list is fixed.

**Side effects.** Ordinary users can no longer read the kernel log with `dmesg`, so use `sudo`. Some profiling tools lose access to kernel details. The protections for files in shared directories can break scripts that write to a file in `/tmp` that another user owns.

**How to verify.** The running values match the drop-in.

**Revert.** Removes the drop-in and puts back the recorded running values.

**Revert limits.** None.

<a id="system-kernel.restrict-ptrace"></a>

### system-kernel.restrict-ptrace

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, compat |

**What it does.** Restricts which processes may attach a debugger to another process (`ptrace`), using the Yama module.

**Why.** A compromised program can no longer read the memory or secrets of other running programs by attaching to them.

**What it changes.** A kernel settings drop-in with the ptrace scope, applied immediately.

**Inputs.** The scope:
- `1` (default): a process may attach only to its own children.
- `2`: only administrators may attach.
- `3`: nobody may attach, and the setting cannot be lowered until the next reboot.

**Side effects.** `strace -p` and `gdb -p` on a process that is not your own child need root at scope 1 and 2, and are blocked completely at scope 3. Crash-reporting tools may need adjusting.

**How to verify.** The running value matches the chosen scope.

**Revert.** Removes the drop-in and sets the recorded value back.

**Revert limits.** If scope 3 was chosen, the previous value only comes back after a reboot.

<a id="system-kernel.restrict-bpf"></a>

### system-kernel.restrict-bpf

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Stops ordinary users from loading eBPF programs, and hardens the eBPF compiler.

**Why.** eBPF runs code inside the kernel, and bugs in it are a frequent source of privilege-escalation exploits. Few servers need eBPF for ordinary users.

**What it changes.** A kernel settings drop-in that disables unprivileged eBPF and turns on hardening of the just-in-time compiler. Applied immediately.

**Inputs.** The mode:
- `2` (default): disabled for ordinary users, and root can switch it back later.
- `1`: disabled and locked until the next reboot.

**Side effects.** Tracing and monitoring tools that use eBPF as an ordinary user stop working. Tools run by root still work.

**How to verify.** The running value matches the chosen mode.

**Revert.** Removes the drop-in and sets the recorded values back.

**Revert limits.** If mode `1` was chosen, the previous values only come back after a reboot.

<a id="system-kernel.disable-kexec"></a>

### system-kernel.disable-kexec

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | compat |

**What it does.** Stops the running kernel from loading a replacement kernel (`kexec`).

**Why.** `kexec` lets root start a different kernel without the usual boot checks. Switching it off closes one route for tampering with the boot chain.

**What it changes.** A kernel settings drop-in, applied immediately.

**Inputs.** None.

**Side effects.** Crash dumps with `kdump` need `kexec`, so do not apply this control if you rely on `kdump`. The kernel keeps this setting until the next reboot.

**How to verify.** The running value shows loading is disabled.

**Revert.** Removes the drop-in.

**Revert limits.** The kernel does not allow the setting to be lowered while running, so it is only lifted at the next reboot.

<a id="system-kernel.blacklist-rare-modules"></a>

### system-kernel.blacklist-rare-modules

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, compat |

**What it does.** Prevents rarely used kernel modules from being loaded: obscure network protocols and legacy filesystems.

**Why.** Every module is code in the kernel. Modules nobody uses are attack surface, and several have had serious flaws that ordinary users could reach.

**What it changes.** A file in `/etc/modprobe.d/` that blocks the modules you pick. Modules that are already loaded are not unloaded.

**Inputs.** Tick the modules to block. Default: all of them.
- Network protocols: `dccp`, `sctp`, `rds`, `tipc`.
- Legacy filesystems: `cramfs`, `freevxfs`, `hfs`, `hfsplus`, `jffs2`.

Filesystems that cloud images use, such as `iso9660` and `udf`, are not in the list, because `cloud-init` can need them.

**Side effects.** Software that needs a blocked module stops working. For example, some telephony software uses `sctp`.

**How to verify.** Loading a blocked module fails.

**Revert.** Removes the file, so the modules load normally again.

**Revert limits.** None.

<a id="system-kernel.crypto-policy"></a>

### system-kernel.crypto-policy

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, compat, lockout |

**What it does.** Sets the system-wide cryptographic policy, the one setting that OpenSSH, TLS libraries (OpenSSL, GnuTLS, NSS), Kerberos and other programs on AlmaLinux read to decide which algorithms and key sizes they accept.

**Why.** On this system the crypto policy decides which SSH algorithms are used, so it takes the place of an explicit list of SSH algorithms. A single policy keeps every service consistent and moves forward with the OS, instead of a hand-written list that ages. The recommended choice, `DEFAULT:NO-SHA1`, additionally refuses SHA-1 signatures.

**What it changes.** Installs `crypto-policies-scripts` if it is missing, reads the current policy, and sets the new one with `update-crypto-policies --set`. The previous policy is recorded. It then lets `sshd` check its configuration (`sshd -t`) and reloads it. If `sshd` refuses its configuration under the new policy, the old policy comes back and the control reports the error. If the system is in FIPS mode, the control refuses and changes nothing, because FIPS mode is switched with `fips-mode-setup`.

**Inputs.** The policy:
- `DEFAULT:NO-SHA1`: the system default without SHA-1 signatures. This is the default answer.
- `FUTURE`: the strictest choice. It refuses RSA keys under 3072 bits, including the keys of people logging in.

**Side effects.** Old clients, old keys and old devices that depend on weak algorithms stop connecting. With `FUTURE`, check first that every authorized key and every host key is Ed25519 or RSA with 3072 bits or more. Programs that are already running read the policy again when they restart, so restart services or reboot to be sure. Because a bad policy can cut off SSH, this control is tagged `lockout`: the tool asks you to open a second session and confirm before it keeps the change.

**How to verify.** `update-crypto-policies --show` prints the chosen policy, and `update-crypto-policies --check` reports that the generated files match it.

**Revert.** Sets the policy that was in force before the first run, reloads `sshd`, and removes the record.

**Revert limits.** Programs that are already running keep the policy they read at start until they restart.

## 09 Filesystem and Storage

<a id="filesystem.tmp-hardening"></a>

### filesystem.tmp-hardening

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, compat |

**What it does.** Mounts `/tmp` with restrictive options: no set-user-ID programs, no device files, and optionally no running of programs from it. On AlmaLinux 10 `/tmp` is a normal directory on the root filesystem unless an administrator changed that, so the control normally turns on the systemd `/tmp` mount (a RAM-backed `tmpfs`) and sets its options.

**Why.** `/tmp` is writable by everyone. Attackers drop tools there, so blocking execution from it stops many simple attacks.

**What it changes.** A systemd mount drop-in (`/etc/systemd/system/tmp.mount.d/99-server-hardening.conf`) that sets the options and the size. If `/tmp` is not a `tmpfs` on the server, the control starts and enables the systemd `/tmp` mount (`tmp.mount`), which puts a `tmpfs` over the directory: files that are in `/tmp` now are hidden until the next reboot. If `/tmp` already is a `tmpfs`, the control remounts it through `systemctl reload tmp.mount`. If `/etc/fstab` has its own line for `/tmp`, the control stops with an explanation, because that line wins over the drop-in. Set the options in that line yourself.

**Inputs.** The size limit (default `50%` of RAM, which is the `tmpfs` default) and whether to block running programs from `/tmp` (default yes).

**Side effects.** `tmpfs` uses RAM, and its contents are lost at reboot. Some installers, build tools and scripts run programs from `/tmp` and fail with "permission denied" when execution is blocked.

**How to verify.** The mount table shows `/tmp` with the chosen options.

**Revert.** Removes the drop-in. If this control started the systemd `/tmp` mount, it stops and disables it again. Otherwise it remounts `/tmp` with the options it had before.

**Revert limits.** None.

<a id="filesystem.shm-hardening"></a>

### filesystem.shm-hardening

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, compat |

**What it does.** Mounts the shared memory area (`/dev/shm`) with restrictive options: no set-user-ID programs, no device files, and optionally no running of programs from it.

**Why.** Shared memory is writable by everyone, and attackers use it like `/tmp` to hold and run tools without touching the disk.

**What it changes.** The `/dev/shm` line in `/etc/fstab` (the previous file is backed up), and a remount.

**Inputs.** Whether to block running programs from shared memory (default yes).

**Side effects.** A few programs that compile or run code from shared memory can fail when execution is blocked. Examples are some browsers and runtimes with a just-in-time compiler.

**How to verify.** The mount table shows `/dev/shm` with the chosen options.

**Revert.** Restores the recorded `fstab` line and remounts.

**Revert limits.** None.

<a id="filesystem.proc-hidepid"></a>

### filesystem.proc-hidepid

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Hides other users' processes. Ordinary users see only their own processes, except members of one group you choose.

**Why.** Process lists show command lines, and command lines sometimes contain passwords or tokens. Hiding them also hides what else is running from a compromised account.

**What it changes.** The `/proc` line in `/etc/fstab` (the previous file is backed up), a remount, and, if needed, a group that is allowed to see everything. The login manager (`systemd-logind`) runs as root and is not affected, so it does not need to be added to the group.

**Inputs.** The hide level (`invisible`, default, or `noaccess`), the group allowed to see all processes (default: a new group named `procadmin`), and the accounts to put in that group (default: the admin accounts). If the group already exists, it is used, and the chosen accounts are added to it.

**Side effects.** Monitoring agents that run as an ordinary user cannot see other users' processes, unless they are added to the group. `ps` and `top` show fewer processes to ordinary users.

**How to verify.** An ordinary user sees only their own processes, and a member of the group sees all of them.

**Revert.** Restores the recorded `fstab` line, remounts, removes from the group the accounts this control added, and removes the group if this control created it.

**Revert limits.** None.

<a id="filesystem.default-umask"></a>

### filesystem.default-umask

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, compat |

**What it does.** Sets the default permissions for newly created files, so they are not readable by every user on the server. With the default value `027`, new files are `640` and new directories `750`.

**Why.** Files created with the usual `022` are readable by every account on the machine. Other accounts include service users and any process that gets compromised.

**What it changes.**
- Sets the value for every login session type through the PAM `pam_umask` module and `/etc/login.defs`, not only for terminal logins. This is meant to cover SFTP, `scp` and `rsync`, which skip shell startup files.
- Cron jobs and systemd services have their own umask and are not changed.

**Inputs.** The umask value. Default: `027`.

**Side effects.** Files you upload for a web server will not be readable by the web server's user, so the site returns "403 Forbidden". Give web content a shared group with group-readable permissions instead of loosening the umask.

**How to verify.** A file created over SFTP, and one created in a terminal, both get the permissions that the chosen value produces.

**Revert.** Puts back the recorded `UMASK` value in `/etc/login.defs` and removes the `pam_umask` line from the session PAM configuration.

**Revert limits.** Files already created keep their permissions. Open sessions keep their umask until the next login.

<a id="filesystem.permission-audit"></a>

### filesystem.permission-audit

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 900 |
| **Requires** | none |
| **Tags** | readonly |

**What it does.** Checks file and directory permissions and reports anything risky. It changes nothing.

**Why.** Wrong permissions are a quiet way for a hardened server to leak data or allow privilege escalation. It runs late (weight 900) so it sees the finished system.

**What it checks.**
- Permissions and owners of sensitive files, such as password files, SSH host keys, `sudo` configuration and the GRUB configuration (`/boot/grub2/grub.cfg`).
- Home directories that other users can read.
- World-writable files, and world-writable directories without the sticky bit.
- Files with no owner or group.
- The list of programs with the set-user-ID or set-group-ID bit, compared with the programs that AlmaLinux ships, so you can spot unexpected ones. `/usr/sbin` and `/usr/bin` are treated as the same folder, because a system that has merged them lists the same programs under either name.

**Inputs.** None.

**Side effects.** None. The scan reads the filesystem and takes a short time.

**How to verify.** The report lists the findings. The control shows as partial while it has findings, so run it again after you fixed them.

**Revert.** Nothing to revert. The control changes nothing.

<a id="filesystem.immutable-configs"></a>

### filesystem.immutable-configs

| | |
|---|---|
| **Default** | No |
| **Weight** | 960 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Marks configuration files as immutable, so even root cannot change or delete them until the flag is removed.

**Why.** If an attacker gets root, quietly editing the hardening configuration is one of the first things they try. An immutable flag makes that a deliberate, noisy extra step. It runs late (weight 960), after every control that writes configuration, including the three AIDE controls, so it can lock their files too.

**What it changes.** Sets the immutable flag (`chattr +i`) on the files you choose. It offers the files that this tool wrote itself (the files that carry its marker in the directories it writes to), for example SSH and `sudo` drop-ins, the firewall and audit rules, the AIDE configuration, the dnf hook, the helper programs and the notification settings. It does not offer system files such as the password files, because locking them would break user changes and package upgrades. The package databases (`/var/lib/rpm`, `/var/lib/dnf`) and the AIDE database directory are left out, so `rpm`, `dnf` and AIDE can maintain their own files.

**Inputs.** Tick the files to lock (default: all the files this tool wrote), and optionally add other paths.

**Side effects.** The AIDE baseline is built before the lock. Whether AIDE reports the immutable flag as a change is still to be checked on a test VM. Nothing can change these files, including package upgrades that try to replace them and this tool itself. To change one with this tool, revert this control first. The reverse run order does this automatically. The flag works on common disk filesystems such as `xfs` and `ext4`, and not on `tmpfs`.

**How to verify.** The chosen files show the immutable attribute.

**Revert.** Removes the immutable flag from the files this control locked.

**Revert limits.** None.

## 10 Miscellaneous

<a id="misc.basic-tools"></a>

### misc.basic-tools

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Installs a set of everyday administration tools that minimal server images often lack.

**Why.** When something goes wrong at night, you want `tmux`, `lsof` and `dig` already on the server. Every package is also code on the server, so the list is yours to choose and nothing extra is installed by default.

**What it changes.** Installs the packages you tick, from the AlmaLinux repositories. `htop` and `ncdu` are only in EPEL, so they are offered only when the `epel` repository is enabled (see `baseline.epel`).

**Inputs.** Tick the packages to install.
- Ticked by default: `curl`, `vim-enhanced`, `tmux`, `rsync`, `unzip`, `lsof`, `jq`, `bind-utils` (which provides `dig`), and `htop` (EPEL).
- Not ticked by default: `git`, `mtr`, and `ncdu` (EPEL).

**Side effects.** Uses a small amount of disk space. Each package adds files that must be kept up to date, but security updates arrive through the normal upgrade path.

**How to verify.** Every ticked package is installed.

**Revert.** Removes the record. The packages stay installed, and the log names the command that removes only the packages this control installed. Packages that were on the server before are never named.

**Revert limits.** The tool never removes these packages itself, because another program or an administrator may depend on them now.

<a id="misc.swapfile"></a>

### misc.swapfile

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Creates a swap file, so the kernel has somewhere to move rarely used memory instead of killing programs when RAM runs out.

**Why.** Many cloud images ship with no swap at all. A small amount of swap makes a memory spike survivable and lets the kernel keep RAM for useful data.

**What it changes.**
- Creates the file with permissions that only root can access, formats it as swap and turns it on.
- Adds an entry to `/etc/fstab` (the previous file is backed up) so it comes back after a reboot.
- Does nothing if the server already has swap, and says so.

**Inputs.**
- The size. Default: `2G`. The tool checks that the filesystem has enough free space and keeps a margin.
- The path. Default: `/swapfile`.

**Side effects.** Uses disk space. Swap on a slow disk is much slower than RAM, and a server that constantly swaps needs more memory. Swap files do not work on every filesystem. On `btrfs`, `ZFS`, `tmpfs`, `overlay` and network filesystems the tool refuses and explains why.

**How to verify.** The swap file is active, and its permissions allow only root.

**Revert.** Turns the swap file off, removes the `fstab` entry and deletes the file.

**Revert limits.** If the system is short of memory, turning swap off may fail until memory is freed. The tool then stops and tells you.

<a id="misc.vm-tuning"></a>

### misc.vm-tuning

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Tunes how the kernel uses memory and swap.

**Why.** The kernel defaults suit a desktop. A server that runs databases or caches usually wants the kernel to prefer RAM for its working data.

**What it changes.** A kernel settings drop-in in `/etc/sysctl.d/`, applied immediately.

**Inputs.**
- How eagerly the kernel swaps (`vm.swappiness`). Default: `10`. Range 0 to 100.
- How eagerly it drops cached file names (`vm.vfs_cache_pressure`). Default: `50`.

**Side effects.** Low swappiness keeps programs in RAM longer, so with very little free memory the system may reclaim cache more aggressively. The setting has no effect on a server without swap, so it pairs well with `misc.swapfile`.

**How to verify.** The running values match what you chose.

**Revert.** Removes the drop-in and sets the recorded running values back.

**Revert limits.** None.

<a id="misc.zsh"></a>

### misc.zsh

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input, external |

**What it does.** Installs `zsh` and, if you want, makes it the login shell for the accounts you pick. It can also set up a zsh framework for those accounts: Oh My Zsh or Zim.

**Why.** Some administrators prefer it for completion and history. A framework adds themes, completion and plugins. All of it is optional and has no security purpose.

**What it changes.**
- Installs the `zsh` package from the AlmaLinux repositories. For each chosen account, changes the login shell.
- With a framework: downloads it from its project on GitHub into the account's home directory, as that account, and writes the starter files of the framework (`.zshrc`, and `.zimrc` for Zim). An existing `.zshrc` is backed up first. Installs `git`, and `curl` for Zim, if they are missing.
- Oh My Zsh is one fixed commit (the last commit of 30 August 2026, chosen by this tool), not the newest version.
- Zim is one fixed release (v1.20.1). Its script is checked against a checksum kept in this tool before it runs, and the modules of the default setup (`environment`, `git`, `input`, `termtitle`, `utility`, `duration-info`, `asciiship`, `completion`) are fixed commits too. Nothing downloaded is run while installing, except the checked Zim script, which builds its start file from the modules already in place and needs no network.

**Inputs.**
- The accounts that get `zsh` as login shell. Default: the admin account only. Root is not offered by default, because a working root shell matters most when something is broken.
- The framework: none, Oh My Zsh or Zim. Default: none. It is set up for the accounts above.
- For Oh My Zsh only: the theme (default `robbyrussell`, it must exist in the framework) and the plugins, separated by spaces (default `git`, each must exist in the framework).

The control stops before any download if an account already has a directory of the framework (`.oh-my-zsh`, `.zim`) or a `.zimrc`, or has a different framework from this control. It removes what it downloaded if a step fails, and the next run installs the framework again. More frameworks can be added later.

**Side effects.** Scripts that expect `bash` as the login shell can behave differently. Automated logins such as `ssh host command` run through the login shell too. Forced commands and `sftp-only` accounts are not affected.

A framework runs third-party code from the internet inside your shell every time you log in. This is why the control is tagged `external`. Pinning to a release helps against a changed script, but it does not make the code reviewed. Plugins and modules also add startup time. Do not set a framework up for accounts that have access to sensitive data.

**How to verify.** `zsh` is installed, and each chosen account has it as login shell. With a framework, its directory exists for each chosen account, and `.zshrc` loads it.

**Revert.** Removes the framework directories, puts back the recorded `.zshrc` and removes the `.zimrc` the control wrote. Puts back each account's recorded previous login shell.

**Revert limits.** The `zsh` package stays installed, and so do `git` and `curl` if a framework needed them. Open sessions keep their current shell until the next login. Changes you made inside a framework directory are lost.

<a id="misc.health-check"></a>

### misc.health-check

| | |
|---|---|
| **Default** | Yes |
| **Weight** | 990 |
| **Requires** | none |
| **Tags** | readonly |

**What it does.** Runs at the very end and checks that the server is in a good state. It changes nothing.

**Why.** Hardening can quietly break things. A final check catches a service that no longer starts or a configuration that no longer loads, while you still have your session open.

**What it checks.**
- Each control that is applied on this server runs its own check. A control that no longer holds in full counts as a problem. Controls you did not apply are not checked.
- The SSH configuration passes `sshd -t`, and SSH listens on every configured port (only when the SSH server is running).
- The firewall is active, if `network.firewall` is applied. Ports that listen on the network and that no rule of this tool allows are listed as warnings, because another firewall rule may allow them.
- No systemd unit is in the failed state.
- The system clock is synchronised (a warning, because it can take minutes after a boot).
- The package system is healthy: `rpm --verifydb` reports nothing, and `dnf repoquery --unsatisfied` finds no installed package with missing dependencies. If dnf cannot read its repositories, for example without network, that is a warning.
- At least 500 MiB of disk space is free on `/` and `/var` (and `/boot` when it is separate), and at least 64 MiB of memory is available. Less than 10% of memory available is a warning.
- Whether a reboot is pending (information only, from `dnf needs-restarting -r`).

**Inputs.** None.

**Side effects.** None. The checks read state and take a short time.

**How to verify.** The tool prints each problem and each warning. If there is a problem, the control ends with an error that lists them, and shows as partial until a later run finds none. A failed check does not undo anything. It points you at the control to look at.

**Notifications.** A failed check sends the event `misc.health-check.failed`, if `misc.notify` is applied and has a webhook.

**Revert.** Nothing to revert. The control changes nothing.

<a id="misc.notify"></a>

### misc.notify

| | |
|---|---|
| **Default** | No |
| **Weight** | 500 |
| **Requires** | none |
| **Tags** | input |

**What it does.** Lets the server report events to you. It sends a POST request with the event details to a webhook URL that you provide. If no webhook URL is defined, nothing is ever sent. Email delivery is not part of this control.

**Why.** Several controls produce findings that nobody reads in a log: file changes found by AIDE, failed upgrades, a failed health check. A message to a channel you already watch makes sure someone sees them.

**What it changes.**
- Installs `curl` if it is missing, and a small helper command (`/usr/local/libexec/server-hardening/notify`) that sends the notification.
- Writes the webhook settings to `/etc/server-hardening/notify.conf`, which only root can read.
- Sends a test notification. If the receiver does not answer with `2xx`, nothing is kept and the control reports the error, so a wrong URL never stays behind.
- The controls that send notifications call the helper when something happens. They work the same whether this control is applied before or after them. If the helper is missing or not configured, they stay silent.

**What is sent.** The tool sends an HTTP POST with a JSON body in a fixed format that this project defines. The format is the same for every receiver. To reach Slack, Discord, Telegram or any other service that expects its own format, point the URL at your own webhook, which receives this body and forwards it in the format that service needs.

The body has these fields:

| Field | Type | Meaning |
|---|---|---|
| `schema` | number | Version of the body format. Starts at 1. |
| `time` | text | When the event happened, in UTC, in RFC 3339 format. |
| `hostname` | text | The server's fully qualified hostname. |
| `severity` | text | `info`, `warning` or `critical`. |
| `event` | text | A stable event ID (see below). |
| `title` | text | A one-line summary. |
| `message` | text | Details in plain text, limited in length. |

The request uses the content type `application/json` with UTF-8 text. If you gave an authorization header value, it is sent as the `Authorization` header. Any `2xx` answer counts as delivered. Other answers are retried a few times. Existing fields keep their meaning. If the format ever has to change in a way that breaks receivers, the `schema` number goes up. File contents, passwords and keys are never included.

**Events sent.**

| Event ID | Sent by | Severity |
|---|---|---|
| `ldp.aide-scheduled-check.differences` | The scheduled AIDE check | warning |
| `misc.health-check.failed` | The health check | critical |
| `misc.notify.test` | This control, when it is applied | info |

Bans by `fail2ban` are not sent, because on a server exposed to the internet they are too frequent to be useful.

**Inputs.**
- The webhook URL. If you leave it empty, the control does nothing.
- An optional authorization header value, for example a bearer token.
- A plain `http://` URL is accepted only after a warning and an explicit yes to a separate question, because the data would travel unencrypted.
- There is no format choice. The body format is fixed (see above).

**Side effects.**
- A webhook URL can contain a secret, such as a token. It is stored readable by root only and masked in the tool's logs.
- The receiving service sees the server's hostname and the event text.
- The URL and the authorization value are never passed to a program as an argument, so other users cannot see them in the process list. Event texts are passed as arguments.
- Notifications are sent in the background with a short timeout and a few retries. They never delay or block the job that triggered them. If the endpoint is down, the failure goes to the system log.

**How to verify.** The control sends a test notification when it is applied. It passes if the endpoint answers with a success code.

**Revert.** Removes the helper and the configuration file. The controls that send notifications keep working, silently.

**Revert limits.** `curl` stays installed. Notifications already delivered are not recalled.

## Notes on this release

- **Controls of the Debian 13 reference that are not here.** `network.systemd-networkd` and `network.dns-resolver` move the network configuration to `systemd-networkd` and `systemd-resolved`. AlmaLinux uses `NetworkManager`, so those two are not ported yet. They are listed in the [roadmap](../../ROADMAP.md). `mac.apparmor-enable` and `mac.apparmor-enforce-profiles` are replaced by the two SELinux controls, `remote-access.ssh-crypto` by `system-kernel.crypto-policy`, `baseline.apt-mirror` by `baseline.dnf-mirror`, and the Debian package checks (`asr.apt-integrity-audit`, `asr.debsums-baseline`) by `asr.dnf-integrity-audit` and `asr.rpm-verify-baseline`. `ldp.aide-apt-hook` is replaced by `ldp.aide-dnf-hook`. `baseline.epel` has no Debian counterpart.
- **Package sources.** `baseline.dnf-mirror` takes any HTTPS mirror. It has no preset for a hosting provider. EPEL is a separate, optional control because it is software from outside AlmaLinux.
- **Not yet checked on a real server.** The output formats of `dnf 4` (such as the removal plan of `dnf remove --assumeno`), the names of a few packages (`python3-dnf-plugin-post-transaction-actions`, `fail2ban-selinux`) and the behavior of AIDE with the `@@include` line are taken from the documentation. The controls are tested against a simulated system only.

## Notes moved out of the old guide

These were steps in the old guide that are not controls. They are written as plain notes here.

- **Before you run the tool:** take a snapshot or backup. The tool also reminds you at start-up.
- **Your SSH client setup and key generation** happen on your own computer, so the tool cannot do them. Notes on creating a key pair and a client configuration entry will go here.
- **Reconnect test:** after a change to SSH, keep your current session open and open a second one to confirm you can still log in. The tool asks you to do this after every `lockout` control (see category 03).
