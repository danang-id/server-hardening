# Operating an AlmaLinux 10 server after hardening

Part of [Server Hardening](../../README.md). This page is for the time before and after you run the tool: what to prepare, what to do when something goes wrong, and what to check now and then. For what each control does, see [REFERENCES.md](REFERENCES.md).

It replaces the recovery and maintenance parts of the manual guide that this repository started from. The tool does the configuration. This page covers what only a person can do.

The commands below were written from the tool's source and from AlmaLinux documentation. They have not been run on a real AlmaLinux 10.2 server yet (see the [roadmap](../../ROADMAP.md)).

## Before you run the tool

- Root SSH access to the server, or a user that can use `sudo`.
- A way to reach the server without SSH: the provider's web console (VNC or serial). Open it once and log in, so you know it works before you need it.
- A snapshot or backup from your provider, labelled with the date and the reason, for example `2026-10-27 before hardening`.
- If you give `baseline.dnf-mirror` a mirror, use one you trust. `dnf` checks packages against the distribution's signing key, whichever mirror serves them, so a mirror cannot swap packages unnoticed.
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
   - SSH: `sudo systemctl status sshd` and `sudo sshd -t`. `sshd -t` prints the line that is wrong in the configuration.
   - Firewall: `sudo firewall-cmd --list-all` if you chose firewalld, or `sudo nft list table inet server_hardening` if you chose nftables.
   - SELinux: `getenforce`, and `sudo ausearch -m avc -ts recent` for recent denials.
   - Network: `nmcli device status` and `ip addr`. The tool leaves NetworkManager in charge on AlmaLinux.
4. **If sshd fails to start on a new port**, the port probably has no SELinux label. SELinux allows `sshd` to bind only to ports labelled `ssh_port_t`, and port 22 is the only one labelled by default. `remote-access.ssh-port` registers the new port for you. To check or fix it by hand:
   ```sh
   sudo semanage port -l | grep ssh_port_t
   sudo semanage port -a -t ssh_port_t -p tcp <port>       # or -m if the port already has another label
   sudo systemctl restart sshd
   ```
5. **If SELinux blocks something else**, switch to permissive mode only for as long as it takes to find the cause. Never disable SELinux:
   ```sh
   sudo setenforce 0
   sudo systemctl restart sshd
   sudo ausearch -m avc -ts recent
   sudo setenforce 1
   ```
   `setenforce` lasts until the next reboot. `/etc/selinux/config` stays on `enforcing`.
6. **Last resort: restore the snapshot.** In the provider's control panel, pick the snapshot labelled for this change and restore it. This takes a few minutes. Afterwards log in and re-run the tool, choosing `misc.health-check`.

A locked account from too many wrong sudo passwords is not a lockout of the server. Reset it with `sudo faillock --user <name> --reset` from another session, or wait for the lock time.

## After a restore, or after a reboot

Run the tool and select `misc.health-check`. It runs the check of every control that you applied, tests the SSH configuration, looks for failed units, and reports a pending reboot. It changes nothing. Do this after every provider maintenance window too.

`sudo dnf needs-restarting -r` also tells you whether a reboot is pending.

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

# New SELinux denials
sudo ausearch -m avc -ts this-week | head -20
```

### Monthly

```sh
# What listens, and the firewall
ss -tlnp
sudo firewall-cmd --list-all              # or: sudo nft list table inet server_hardening

# What runs
systemctl list-units --type=service --state=running

# Audit summary for the month
sudo aureport --summary --start "$(date -d '1 month ago' '+%m/%d/%Y')" --end "$(date '+%m/%d/%Y')"

# Disk
df -h
sudo du -sh /var/log/audit /var/log/journal

# Packages
sudo dnf check-update
sudo rpm -Va 2>/dev/null             # changed files; expect your own edited configs

# World-writable files outside /tmp and /dev/shm
sudo find / -xdev -not \( -path /tmp -prune \) -not \( -path /dev/shm -prune \) -perm -0002 -type f 2>/dev/null

# SELinux booleans that differ from the default
sudo semanage boolean -l -C
```

The audit rules tag their events with these keys: `identity`, `logins`, `modules`, `privileged`, `selinux`, `sshd`, `sudoers` and `auditconfig`. Search with `ausearch -k <key>`.

### After you change something on purpose

Change, verify, then update the AIDE baseline. Otherwise the next check reports your own change as a difference.

```sh
sudo /usr/local/libexec/server-hardening/aide-run check    # shows the differences, exit status 1 if any
sudo /usr/local/libexec/server-hardening/aide-run update   # accepts the current state as the baseline
```

If `ldp.aide-dnf-hook` is applied, a `dnf` transaction updates the baseline for you afterwards. `dnf` 4 has no hook that runs before a transaction, so the check before it does not exist on AlmaLinux. Keep a copy of the AIDE database and its checksum off the server. Someone with root on the server can rebuild the baseline to hide a change.

## Order matters in one place

The AIDE baseline is built from the state of the system at that moment. If you apply controls in several runs, build or update the baseline last. The tool runs `ldp.aide` late in each run for this reason, but a change in a later run still shows up as a difference until you update the baseline.
