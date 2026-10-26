# Server Hardening

General-purpose security hardening for freshly provisioned servers. You pick what to apply from an interactive menu. Nothing is mandatory, and the tool assumes nothing is installed on the server.

> **Status:** Debian 13 and AlmaLinux 10 are supported. Other systems and features are listed in the [roadmap](ROADMAP.md).

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/danang-id/server-hardening/refs/heads/main/hardening.sh | sh
```

No curl? Use wget:

```sh
wget -qO- https://raw.githubusercontent.com/danang-id/server-hardening/refs/heads/main/hardening.sh | sh
```

**Want to read the script first?** Download it, read it, then run it:

```sh
curl -fsSLO https://raw.githubusercontent.com/danang-id/server-hardening/refs/heads/main/hardening.sh
less hardening.sh
sh hardening.sh
```

The entry script shows your operating system, kernel and processor, and whether the tool supports them. If not, it says why and stops without downloading anything. If so, it downloads the matching binary from the latest release with a progress bar, checks it against the checksum list of that release, explains why administrator access is needed, waits for you to press Enter, and starts the tool. What is supported is not written in the script: the release carries a `SUPPORTED` file, so the script does not change when support grows. A machine that is not supported ends the script with exit status 1. The binary runs from a temporary directory. When `/tmp` is mounted `noexec`, which the tool's own `tmp-hardening` control does, the script tries `/var/tmp`, `/dev/shm` and your home directory, or the directory in `TMPDIR`, until one allows running programs. Arguments go to the tool: `sh hardening.sh --dry-run`, or `curl -fsSL <url> | sh -s -- --dry-run`. The checksum catches a broken download. It does not protect you from a tampered release, which is one more reason to read the script first.

Take a snapshot or backup of the server before you run it.

## How it works

1. The tool detects the operating system and loads the controls for that system.
2. One screen shows every category and control. The recommended ones are ticked already. Move with the arrow keys, tick with the space bar, and read what the control under the cursor does in the pane below the list. Press `?` for the keys and the symbols.
3. If a selected control needs another control, the tool asks before adding it. Declining skips only the control that needed it.
4. The tool asks for the inputs the selected controls need, one question at a time. Every input shows a suggested value that you can accept or change, and `Esc` goes back to the selection. Nothing is applied with a value you did not see.
5. A review lists the controls in run order with your answers (a secret is never shown). **Apply** starts the run. **Edit selection** goes back with your ticks kept.
6. Controls run one by one on a progress screen with the live log. A control that can lock you out asks you to confirm from a new session while the automatic undo counts down. A summary lists what was applied, skipped and failed, and stays in your terminal after you leave. The log is also written to `/var/log/server-hardening.log`.

The first screen shows the machine (operating system, kernel, processor architecture), whether this tool supports it, and the reason when it does not. **Start** is only available on a supported machine. On any other machine, for example a Mac, only **Exit** works.

Leaving with `q` or the **Exit** button is a normal end and the exit status is 0. Stopping with `Ctrl+C` is a forced stop and the exit status is 130. Neither prints anything. Selecting nothing exits cleanly. `--dry-run` shows what would run, and in which order, without changing anything.

| Option | What it does |
|---|---|
| `--dry-run` | Show what would run, in order, and change nothing. Needs no root. |
| `--revert` | Choose controls to undo. |
| `--plain` | Use simple one-question prompts instead of the full-screen interface. The tool falls back to them by itself when the terminal is not interactive or not UTF-8. |
| `--skip-welcome` | Go straight on when the machine is supported, without the start screen. `hardening.sh` uses it because it has already shown the same information. On a machine that is not supported the start screen still appears. |
| `--print-support` | Print the systems this tool supports, one per line, and exit. The release publishes this as `SUPPORTED`. |
| `--demo` | Try the interface on a pretend server. Nothing is changed and it runs on any computer, for example `go run ./cmd/hardening --demo`. |

The full-screen interface needs a terminal of at least 64 columns by 18 rows. It uses colors when the terminal has them, and respects `NO_COLOR`.

To undo controls later, run the tool again and choose **Revert** (or use `--revert`). See [Reverting](#reverting).

## Terms

| Term | Meaning |
|---|---|
| **Category** | A fixed area of hardening. Every system covers every category (see below). |
| **Control** | One independent, tickable hardening unit inside a category. |
| **Control ID** | The stable name of a control: `<category-slug>.<name>`, for example `remote-access.sftp`. Documentation and dependencies always refer to the ID. |
| **Control number** | The two-digit order of a control inside its category. |
| **Control weight** | A three-digit priority across all categories (see Run order). |

## Categories

The category number is the same for every system. Numbers are never reused or renumbered. A new category is appended as 11 or higher.

| No. | Slug | Category | Covers |
|---|---|---|---|
| 01 | `baseline` | Operating System Baseline | Hostname, time zone, package sources, system updates, time sync, automatic security updates |
| 02 | `aaa` | Accounts, Authentication and Authorization (AAA) | Administrator accounts, password policy, privilege escalation, lockout |
| 03 | `remote-access` | Remote Access | How administrators connect remotely: SSH or equivalent, keys, limits, allowed users |
| 04 | `network` | Network Exposure | Firewall, open ports, network stack settings |
| 05 | `asr` | Attack-Surface Reduction (ASR) | Removing unneeded software and services, integrity of installed software |
| 06 | `mac` | Mandatory Access Control (MAC) | AppArmor, SELinux or the system's equivalent |
| 07 | `ldp` | Logging, Detection and Prevention | Persistent logs, auditing, intrusion detection and prevention |
| 08 | `system-kernel` | System and Kernel | Kernel and system parameters |
| 09 | `filesystem` | Filesystem and Storage | Mount options, default permissions, protection of important files |
| 10 | `misc` | Miscellaneous | Optional extras and the final health check |

## Coverage rule

**Every system folder must offer at least one control in every category, including Miscellaneous.**

The only exception is a category that truly does not exist on that system, for a clear and logical reason. In that case the system declares the category **N/A with a written reason**.

- The N/A declaration and its reason live in the system's `Controls` folder.
- The same reason is repeated in that system's `REFERENCES.md` under a *Category coverage* table.
- In the menu, an N/A category is shown greyed out with its reason.
- A test fails the build if a category has neither an implemented control nor an N/A declaration, or if the two sources disagree.

At runtime no control is mandatory. Everything that runs is chosen by the user, apart from dependencies of chosen controls.

## Controls

- **Atomic.** A control works on its own and changes one thing.
- **Self-checking.** Every setting can check whether it is already applied. This is used for dependencies, safe re-runs, and the health check. A few controls are jobs, not settings, such as upgrading all packages and removing unneeded ones. They are never marked as applied, because "nothing left to do" today says nothing about tomorrow. They run whenever you choose them.
- **Revertible, unless marked otherwise.** Every control has a revert function. A few are marked `irreversible` and give a reason (see [Reverting](#reverting)).
- **Lockout protection.** Some changes can lock you out of the server, for example turning off password login. After a control tagged `lockout`, the tool pauses and asks you to open a new terminal and log in while your current session stays open. If you confirm, the change stays. If you do not confirm within 10 minutes, the server undoes the change by itself, even if your connection is lost: before the change, the tool starts a one-off systemd timer that runs `hardening --undo <control>`, and it stops the timer when you confirm. Without systemd, or if the timer cannot be started, the tool warns you and only this session can undo the change, so keep your provider's console open. An `irreversible` control cannot be undone, so the tool warns you first and asks you to keep the provider's console open.
- **Notifications.** The optional `misc.notify` control sends events to a webhook you provide (see [Notifications](#notifications)). Without a webhook URL, nothing is ever sent.
- **Metadata.** Title, description, default on or off, required controls, weight, tags (such as `lockout`, `reboot`, `input`, `compat`, `external`, `readonly`, `irreversible`), revert limits or the reason there is no revert, and the inputs it asks for.
- **Defaults are suggestions.** Nothing is forced by a default.
- **Dependencies.** A control can require other controls (see below).

### Dependencies

A control lists the controls it `requires`, by Control ID. Use this only for a hard prerequisite: something the control cannot work without, or cannot be applied safely without. A "nice to have" is not a dependency.

For example, `remote-access.ssh-no-root-login` requires `aaa.admin-user`, `aaa.sudo-policy` and `remote-access.authorized-key`. Without them, disabling root login could lock you out.

**What the user sees**

1. You tick controls and review them.
2. If a ticked control needs controls that are not applied yet, one consent screen lists them all.
3. **Yes** adds them to the run. **No** skips only the control that needed them. The rest of the run continues.
4. A dependency that is already applied is skipped, and a dependency shared by several controls is asked about once.
5. Dependencies of dependencies are resolved the same way.
6. The final summary lists every control that was added as a dependency, declined, or skipped.

**Where a dependency runs**

An added dependency does not jump the queue. It runs at its own place in the fixed run order (see Run order), which always comes before the control that needs it.

**What the tests check**

The tests run with `go test` in GitHub Actions on every push and pull request, and again before a release is built. A broken rule fails the build, never a user's run.

- Every required control exists in the same system folder.
- No control requires itself, and there are no circular requirements.
- The required control sorts earlier in the fixed run order. Its weight is lower or equal, and if equal, its category number or control number comes first.

### Reverting

Every control has a **revert** beside its check. Reverting undoes what the control did. Afterwards the control's check reports it as not applied.

**What the user sees**

1. Run the tool again with `--revert`. The list shows only controls whose check says they are applied, and nothing is ticked at first.
2. Tick what to revert. If other applied controls depend on a ticked control, one consent screen lists them. **Yes** reverts them too. **No** skips the ticked control, so nothing is left half-working.
3. Reverts run in the reverse of the normal run order. Controls that depend on others are undone first, and `filesystem.immutable-configs` unlocks its files before any other revert needs to edit them.
4. The summary lists what was reverted, what was skipped, and what was only partly reverted.

**What a revert restores**

- Files the control created are removed. Settings it changed are put back to the value recorded before the change.
- Before a control changes something that already exists (the hostname, time zone, package sources, a configuration file, a login shell, services it disables, packages it removes), it records the previous state. The revert uses that record. If there is no record, for example because the setting was changed by hand, the revert says so and leaves it alone.
- Packages a control installed stay installed, unconfigured and disabled, unless you choose to remove them on the revert screen.
- Records and backups are kept in a location only the administrator can write: `/var/lib/server-hardening`. They are not kept in the user's data folder, because the tool runs as root and must be able to trust them.
- Your answers are remembered. Going back to the selection (Edit selection) does not ask again what you already answered, and **Change answers** on the review screen asks the questions again with your answers filled in. After a control has been applied, its answers are saved in the same records location and become the suggested values the next time the tool runs. Passwords and other secrets are never saved. A dry run saves nothing.

**Limits**

**Not everything is revertible.** Every control has a revert function so the structure stays the same. A control is tagged `irreversible` when its change cannot be undone (package upgrades), should not be undone automatically (deleting an account, rewriting the network configuration), or has nothing to undo (`readonly`). An `irreversible` control gives its reason in words. Its revert does nothing, and the revert list shows it greyed out with that reason, the same way an N/A category is shown.

Other changes can be undone only in part, such as kernel settings that stay locked until the next reboot. Those controls state their revert limits in their metadata, and the revert screen shows them before you confirm. `REFERENCES.md` repeats both.

**What the tests check**

- Every control implements revert. A control without one fails the build.
- A control tagged `irreversible`, or one with revert limits, must state its reason or limits in words. A `readonly` control needs no reason.
- In the reverse run order, every control comes before the controls it requires.

### Notifications

The `misc.notify` control sends a notification to a webhook URL that you define. If no URL is defined, nothing is sent. Controls that report events, such as the file integrity check or the health check, call it when it is applied and stay silent when it is not.

The tool sends an HTTP `POST` with a JSON body in a fixed format that this project defines:

| Field | Meaning |
|---|---|
| `schema` | Version of the body format, starting at 1 |
| `time` | When the event happened, in UTC (RFC 3339) |
| `hostname` | The server's fully qualified hostname |
| `severity` | `info`, `warning` or `critical` |
| `event` | A stable event ID, for example `misc.health-check.failed` |
| `title` | A one-line summary |
| `message` | Details in plain text |

The format is the same for every receiver. To get notifications in Slack, Discord, Telegram or another service, point the URL at your own webhook, which receives this body and forwards it in the format that service needs. The tool has no per-service formats. The list of events is in each system's `REFERENCES.md`.

### File layout

```
<System>/<Version>/
├── REFERENCES.md     # reference for every control (what, why, side effects, how to undo)
└── Controls/
    └── <CC><NN>_<category>.<control-name>.go
```

`<CC>` is the category number and `<NN>` is the control number. For example, `0302_remote-access.sftp.go` is category 03, control 02. A test checks that the filename matches the control's own category and ID.

### Run order

All controls of a system are sorted once, by:

1. **control weight** (1 to 999, default 500, lowest first; 000 is not used)
2. **category number**
3. **control number**

This order is fixed. A user's selection only filters it, and dependencies are added into their normal place, so a run never reorders anything. A test requires every required control to sort earlier than the control that requires it.

| Weight | Meaning |
|---|---|
| 001 to 099 | Must run before everything else |
| 100 to 499 | Runs earlier than its category order would put it |
| **500** | **Default: runs in category order** |
| 501 to 799 | Runs later than its category order would put it |
| 800 to 899 | Disruptive: can cut the connection or needs a reboot |
| 900 to 999 | Seal: audit, lock or record the finished system |

## Supported systems

**Status key**

| Status | Meaning |
|---|---|
| **Interactive tool** | The tool supports the system. `REFERENCES.md` is the control reference. |
| **Manual guide** | Only a step-by-step guide (`GUIDE.md`) exists. The tool does not support the system. |

<table>
  <tbody>
    <tr>
      <td style="text-align:center; width: 120px; height: 150px; padding: 10px;">
        <img src="assets/Debian.svg" width="65"> <br/>
        <h2>Debian</h2>
      </td>
      <td style="min-width: 500px">
        <b><a href="Debian/13/REFERENCES.md">Debian 13.x (Trixie | current "stable")</a></b>
        <br/> <b>Interactive tool</b> | <a href="Debian/13/CHANGELOG.md">CHANGELOG</a>
      </td>
    </tr>
    <tr>
      <td style="text-align:center; width: 120px; height: 150px; padding: 10px;">
        <img src="assets/AlmaLinux.svg" width="65"> <br/>
        <h2>AlmaLinux</h2>
      </td>
      <td style="min-width: 500px">
        <b><a href="AlmaLinux/10/REFERENCES.md">AlmaLinux 10.x (Heliotrope Lion), tested on 10.2</a></b>
        <br/> <b>Interactive tool</b> | <a href="AlmaLinux/10/CHANGELOG.md">CHANGELOG</a>
      </td>
    </tr>
  </tbody>
</table>

Further systems are listed in the [roadmap](ROADMAP.md).

**Release binaries**

| Operating system | CPU | Binary |
|---|---|---|
| Linux | x86-64 (amd64) | `hardening-linux-amd64` |
| Linux | ARM64 | `hardening-linux-arm64` |
| Windows | x86-64 (amd64) | `hardening-windows-amd64.exe` |

One binary per operating system and CPU contains every supported version of that operating system. It reads the system it runs on and loads the matching controls. For any other CPU, see `BUILD.md`.

## Out of scope

This is general-purpose hardening. Server roles (web, mail, database) and private networking such as Tailscale are not part of it.

## Roadmap

[ROADMAP.md](ROADMAP.md) lists the systems and features that are not available yet, and what has to be verified before a release.

## More documents

- `ROADMAP.md`: what comes next
- `BUILD.md`: building the binary yourself, for CPUs without a release binary
- `DEPENDENCIES`: the Go libraries used and why
- `LICENSE`: the GNU General Public License, version 3
- `CONTRIBUTING.md`: how to contribute, and the sign-off every commit needs
- `Debian/13/GUIDE.md` and `AlmaLinux/10/GUIDE.md`: the manual step-by-step guides, written before the tool existed

## License

Server Hardening is free software. You can redistribute it and modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version (SPDX: `GPL-3.0-or-later`). `LICENSE` has the full text.

Copyright (C) 2026 Danang Galuh Tegar Prasetyo

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. It changes the configuration of the server it runs on, so read the plan on the review screen before you apply it.

- **Source and notices.** The source of every release is the tag of the same name in this repository. Each release also carries `LICENSE` and `THIRD_PARTY_LICENSES`, which holds the notices of the libraries and the Go standard library built into the binaries.
- **Documents.** The guides, references and changelogs are covered by the same license.
- **Logos.** The Debian and AlmaLinux logos in `assets/` belong to their owners. They are used only to name the supported systems and are not covered by this license.
- **Contributions.** Contributions are accepted under the same license. See `CONTRIBUTING.md`.
