# Operating a Debian 13 server after hardening

Part of [Server Hardening](../../README.md). This page is for the time before and after you run the tool: what to prepare, what to do when something goes wrong, and what to check now and then. For what each control does, see [REFERENCES.md](REFERENCES.md).

It replaces the recovery and maintenance parts of the manual guide that this repository started from. The tool does the configuration. This page covers what only a person can do.

The commands below were written from the tool's source and from Debian documentation. They have not been run on a real Debian 13 server yet (see the [roadmap](../../ROADMAP.md)).

## Before you run the tool

- Root SSH access to the server, or a user that can use `sudo`.
- A way to reach the server without SSH: the provider's web console (VNC or serial). Open it once and log in, so you know it works before you need it.
- A snapshot or backup from your provider, labelled with the date and the reason, for example `2026-10-27 before hardening`.
- If you give `baseline.apt-mirror` a mirror, use an official one from `debian.org/mirror/list`. `apt` checks packages against Debian's archive signing key, whichever mirror serves them, so a mirror cannot swap packages unnoticed.
- An SSH key pair on your own computer. The tool can install the public key for the administrator account, but it cannot create the private key for you.

If you use an SSH agent that offers many keys, such as a password manager, tell your client which key to use (`IdentitiesOnly yes` and an `IdentityFile` line in `~/.ssh/config`). With `remote-access.ssh-login-limits` applied, the server stops a connection after a few failed attempts, and the agent can use them all up before it tries the right key.

## What the tool does to protect you

- **Lockout protection.** After a control tagged `lockout`, the tool asks you to open a new terminal and log in while the old session stays open. If you do not confirm within 10 minutes, the change is undone by a systemd timer, even if your connection is gone. The timer is named `server-hardening-undo-<control>`, with dots changed to dashes. See the armed ones with `systemctl list-timers 'server-hardening-undo-*'`.
- **Records.** Before a control changes something, the previous state is saved in `/var/lib/server-hardening`. A revert uses these records.
- **A copy of the tool.** The timer runs a copy of the binary at `/var/lib/server-hardening/bin/hardening`, so you can use it even if the original download is gone.
- **Log.** Every run is logged to `/var/log/server-hardening.log`.

## If you are locked out or SSH does not answer

Use the provider console and log in as the administrator account you created. Work from the cheapest step to the most drastic one.

1. **Wait for the automatic undo.** If you were applying a `lockout` control, the timer undoes it after 10 minutes. Check with `systemctl list-timers 'server-hardening-undo-*'`.
2. **Undo it yourself.** Run `sudo /var/lib/server-hardening/bin/hardening --revert`, tick the control you changed last, and apply. If the server was left in a half-changed state, the tool reports what it could not restore.
3. **Look at the services.**
   - SSH: `sudo systemctl status ssh` and `sudo sshd -t`. `sshd -t` prints the line that is wrong in the configuration.
   - Firewall: `sudo firewall-cmd --list-all` if you chose firewalld, or `sudo nft list table inet server_hardening` if you chose nftables.
   - Network: `networkctl status`. If you applied `network.systemd-networkd`, the interface should read `routable (configured)`. `routable (unmanaged)` means systemd-networkd did not read the `.network` file, usually because of its permissions. They must be readable by the `systemd-network` user.
   - AppArmor: `sudo systemctl status apparmor` and `sudo aa-status`.
4. **If the SSH daemon refuses to start because of AppArmor**, put its profile in complain mode, restart it, find out what was denied, and enforce the profile again:
   ```sh
   sudo aa-complain /etc/apparmor.d/usr.sbin.sshd
   sudo systemctl restart ssh
   sudo journalctl -k --grep='apparmor="DENIED"' --since "1 hour ago"
   sudo aa-enforce /etc/apparmor.d/usr.sbin.sshd
   ```
5. **If the network is gone after `network.systemd-networkd`** and nothing above helps, go back to the old stack from the console: `sudo systemctl unmask networking && sudo systemctl start networking`. Then find out why systemd-networkd lost the interface before you try again.
6. **Last resort: restore the snapshot.** In the provider's control panel, pick the snapshot labelled for this change and restore it. This takes a few minutes. Afterwards log in and re-run the tool, choosing `misc.health-check`.

A locked account from too many wrong sudo passwords is not a lockout of the server. Reset it with `sudo faillock --user <name> --reset` from another session, or wait for the lock time.

## After a restore, or after a reboot

Run the tool and select `misc.health-check`. It runs the check of every control that you applied, tests the SSH configuration, looks for failed units, and reports a pending reboot. It changes nothing. Do this after every provider maintenance window too.

## Routine

### Before a significant change

Take a snapshot first, then change. Good moments: before a kernel upgrade, before you install a new service, before you apply or revert controls, and before you update the AIDE baseline. Label it with the date and the reason.

### Weekly (about 10 minutes)

```sh
# Banned addresses
sudo fail2ban-client status sshd

# What the file integrity check found, if ldp.aide-scheduled-check is applied
sudo journalctl -t server-hardening-aide --since "7 days ago"

# sudo use and SSH events
sudo ausearch -k privileged -ts this-week | aureport --summary
sudo journalctl _COMM=sshd --since "7 days ago" | grep -iE 'failed|accepted|invalid'

# New AppArmor denials
sudo journalctl -k --grep='apparmor="DENIED"' --since "7 days ago" | head -20
```

### Monthly

```sh
# What listens, and the firewall
ss -tlnp
sudo firewall-cmd --list-all              # or: sudo nft list table inet server_hardening
networkctl status

# What runs
systemctl list-units --type=service --state=running

# Audit summary for the month
sudo aureport --summary --start "$(date -d '1 month ago' '+%m/%d/%Y')" --end "$(date '+%m/%d/%Y')"

# Disk
df -h
sudo du -sh /var/log/audit /var/log/journal

# Packages
apt update -qq && apt list --upgradable
sudo debsums -c 2>/dev/null          # changed files; expect your own edited configs

# World-writable files outside /tmp and /dev/shm
sudo find / -xdev -not \( -path /tmp -prune \) -not \( -path /dev/shm -prune \) -perm -0002 -type f 2>/dev/null
```

The audit rules tag their events with these keys: `identity`, `logins`, `modules`, `privileged`, `sshd`, `sudoers` and `auditconfig`. Search with `ausearch -k <key>`.

### After you change something on purpose

Change, verify, then update the AIDE baseline. Otherwise the next check reports your own change as a difference.

```sh
sudo /usr/local/libexec/server-hardening/aide-run check    # shows the differences, exit status 1 if any
sudo /usr/local/libexec/server-hardening/aide-run update   # accepts the current state as the baseline
```

Package installs and upgrades through `apt` update the baseline for you if `ldp.aide-apt-hook` is applied. Keep a copy of the AIDE database and its checksum off the server. Someone with root on the server can rebuild the baseline to hide a change.

## Order matters in one place

The AIDE baseline is built from the state of the system at that moment. If you apply controls in several runs, build or update the baseline last. The tool runs `ldp.aide` late in each run for this reason, but a change in a later run still shows up as a difference until you update the baseline.
