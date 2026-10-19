# VPS Hardening Guide (Debian-13)

|					|											|
| ----------------- | ----------------------------------------- |
| **Target OS**		| Debian 13.x (Trixie — current "stable")	|
| **Guide Version**	| Debian-13-Rev-0							|


## Contextual Preamble

### Prerequisites

- Root SSH access to the VPS
- VPS provider snapshot capability (take one before starting)
- An SSH key pair ready on your local machine (or generate one in Section 3)

### Out of Scope

- Partition restructuring on live systems
- Service-specific hardening (Nginx, Postfix, PostgreSQL, etc.)
- Container / Docker hardening
- Cloud provider security group configuration
- Multi-user access policies
- Port knocking (noted as optional escalation in Section 3, not prescribed)

### Guide Variables

Set these once before running any commands. Every command in this guide references these variables — substitute your own values here and the rest of the guide follows automatically.

```bash
# Create the persistent variables file with your configurations
cat << EOF > /root/setup_variables.sh
# ============================================================
# Guide Variables
# ============================================================
export VPS_USER="dan"								# your rootless admin username
export VPS_HOSTNAME="anila"							# your server hostname
export VPS_TIMEZONE="Asia/Jakarta"					# your timezone (timedatectl list-timezones)
export VPS_SSH_PORT="32022"							# your chosen non-standard SSH port
export VPS_MIRROR="kartolo.sby.datautama.net.id"	# your nearest Debian mirror
export VPS_IFACE="$(ip route show default | awk '/default/ {print $5}')"
EOF

# 3. Make the script executable and verify the contents
chmod +x /root/setup_variables.sh

source /root/setup_variables.sh
```

> ⚠️ These variables are set in your current shell session only. If you disconnect and reconnect, re-run this block before continuing.

### Customisation Reference

| Variable			| Example value						| Description																						|
| ----------------- | --------------------------------- | ------------------------------------------------------------------------------------------------- |
| `VPS_USER`		| `dan`								| Rootless admin user created in Section 2															|
| `VPS_HOSTNAME`	| `anila`							| Server hostname set in Section 1																	|
| `VPS_TIMEZONE`	| `Asia/Jakarta`					| Timezone set in Section 1																			|
| `VPS_SSH_PORT`	| `32022`							| Non-standard SSH port used in Sections 3 and 4													|
| `VPS_MIRROR`		| `kartolo.sby.datautama.net.id`	| Debian mirror used in Section 1; must be an official mirror listed at `debian.org/mirror/list`	|


## Section Order

|  # | Section																		|
| -- | ---------------------------------------------------------------------------- |
|  1 | [Operating System Baseline](#section-1--operating-system-baseline)			|
|  2 | [User & Authentication](#section-2--user--authentication)					|
|  3 | [Secure Shell (SSH)](#section-3--secure-shell-ssh)							|
|  4 | [Network & Firewall](#section-4--network--firewall)							|
|  5 | [Package Integrity](#section-5--package-integrity)							|
|  6 | [Mandatory Access Control (MAC)](#section-6--mandatory-access-control-mac)	|
|  7 | [Logging & Audit](#section-7--logging--audit)								|
|  8 | [Kernel Hardening](#section-8--kernel-hardening)								|
|  9 | [Filesystem Hardening](#section-9--filesystem-hardening)						|
| 10 | [Performance Optimization](#section-10--performance-optimization)			|
| 11 | [Intrusion Detection System](#section-11--intrusion-detection-system)		|
| 12 | [Maintenance Hygiene](#section-12--maintenance-hygiene)						|

---


## Section 1 — Operating System Baseline

**Goal:** Start from the leanest, most up-to-date system state possible. Every unnecessary package or service is an unmonitored attack surface.

### Checklist

- [ ] **1.1** Set correct hostname and add to `/etc/hosts`
- [ ] **1.2** Set correct timezone
- [ ] **1.3** Configure local mirror
- [ ] **1.4** Verify APT GPG verification is active, then apply all pending updates
- [ ] **1.5** Install essential baseline packages
- [ ] **1.6** Configure `unattended-upgrades` for security-only auto-updates
- [ ] **1.7** Remove known bloat packages
- [ ] **1.8** Disable and stop unused services
- [ ] **1.9** Verify `systemd-timesyncd` is running and synchronized

### Steps

---

#### 1.1 — Set correct hostname and add to `/etc/hosts`

A meaningful hostname prevents confusion in logs. Debian 13 defaults to `debian` — every log entry will be ambiguous if you ever cross-reference across machines.

The hostname must also be added to `/etc/hosts` immediately after being set. `sudo` performs a hostname lookup during initialization — if the hostname does not resolve, on some PAM configurations this causes the entire authentication stack to fail, making correct passwords appear wrong. `hostnamectl set-hostname` and `/etc/hosts` do not sync automatically.

```bash
# Guide variables
source /root/setup_variables.sh

hostnamectl set-hostname "$VPS_HOSTNAME"

# Add to /etc/hosts to prevent sudo hostname resolution failures:
echo "127.0.1.1 ${VPS_HOSTNAME}" >> /etc/hosts

# Verify:
hostnamectl status
grep "$VPS_HOSTNAME" /etc/hosts
```

---

#### 1.2 — Set correct timezone

Mismatched timezones corrupt log correlation. `UTC` is acceptable and often preferred for servers managed across regions. To list all available timezones, run `timedatectl list-timezones`.

```bash
timedatectl set-timezone "$VPS_TIMEZONE"

# Verify:
timedatectl status
```

---

#### 1.3 — Configure local mirror

Using a geographically close mirror reduces latency on every `apt` operation. All packages remain GPG-verified against Debian's archive signing key regardless of which mirror delivers them — using a local mirror does not weaken APT's verification chain. `VPS_MIRROR` must be an official Debian mirror listed at `debian.org/mirror/list` and must cover the trixie main archive, `trixie-security`, and `trixie-updates`.

Debian 13 uses DEB822-format sources in `/etc/apt/sources.list.d/debian.sources` alongside the traditional `/etc/apt/sources.list` — both files are active and processed by APT. After writing the new `debian.sources`, `sources.list` is emptied after backup to prevent duplicate source processing. The `debian.sources` backup step is guarded — on VPS images that ship without a `debian.sources` file the guard prevents a hard error.

```bash
# Test mirror reachability before committing:
curl -o /dev/null -s -w "HTTP %{http_code} — Time: %{time_total}s\n" \
	"https://${VPS_MIRROR}/debian/dists/trixie/Release"
# Expected: HTTP 200 — Time: <1s
# If unreachable, use the default deb.debian.org and skip the mirror change

# Backup sources.list:
cp /etc/apt/sources.list /etc/apt/sources.list.bak
rm /etc/apt/sources.list~

# Backup debian.sources only if it exists:
[ -f /etc/apt/sources.list.d/debian.sources ] && \
	cp /etc/apt/sources.list.d/debian.sources \
	/etc/apt/sources.list.d/debian.sources.bak

# Note any additional provider sources before proceeding:
ls /etc/apt/sources.list.d/

# Write new debian.sources pointing to the selected mirror:
cat > /etc/apt/sources.list.d/debian.sources << EOF
# Source Mirror: ${VPS_MIRROR}

# Base & Updates
Types: deb deb-src
URIs: https://${VPS_MIRROR}/debian
Suites: trixie trixie-updates
Components: main contrib non-free non-free-firmware
Architectures: amd64
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

# Security
Types: deb deb-src
URIs: https://${VPS_MIRROR}/debian-security
Suites: trixie-security
Components: main contrib non-free non-free-firmware
Architectures: amd64
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF

# Empty sources.list to prevent duplicate processing:
echo '# Replaced by /etc/apt/sources.list.d/debian.sources' \
	> /etc/apt/sources.list

# Update metadata and verify the mirror is responding:
apt update
# All repos should resolve against ${VPS_MIRROR}
```

> **Fallback:** If the mirror is unreachable, restore both source files and proceed with the Debian CDN:
> ```bash
> cp /etc/apt/sources.list.bak /etc/apt/sources.list
> [ -f /etc/apt/sources.list.d/debian.sources.bak ] && \
>	 cp /etc/apt/sources.list.d/debian.sources.bak \
>			/etc/apt/sources.list.d/debian.sources
> apt update
> ```

---

#### 1.4 — Verify GPG enforcement and apply full upgrade

APT enforces GPG signature verification by default — every package is checked against Debian's archive signing key before installation. Unlike `dnf`'s per-repo `gpgcheck` flag, APT's verification is archive-wide and cannot be silently disabled without explicit overrides like `[trusted=yes]` in sources or `--allow-unauthenticated` flags. This step confirms no such bypass is present, then runs a full upgrade. Hardening built on top of unpatched packages is built on a weak foundation.

```bash
# Confirm no source has a [trusted=yes] bypass:
grep -rE 'trusted=yes|allow-unauthenticated|AllowUnauthenticated' \
	/etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
# Expected: no output — any result here is a security concern

# Confirm Debian archive signing key is present:
ls /etc/apt/trusted.gpg.d/
# Expected: debian-archive-*.gpg files

# Check global APT config for unauthenticated bypasses:
grep -r 'AllowUnauthenticated\|allow-unauthenticated' \
	/etc/apt/apt.conf.d/ 2>/dev/null
# Expected: no output

# Full upgrade:
apt upgrade -y
```

> **Reboot if the kernel was upgraded** before continuing to Section 2.

---

#### 1.5 — Install essential baseline packages

A minimal Debian 13 VPS image does not ship with the tools this guide depends on. `cron` is required for Section 11 — without a cron daemon, `/etc/cron.d/aide-check` is silently ignored. On Debian, `auditd` is a single package that includes the daemon and all CLI tools (`auditctl`, `ausearch`, `aureport`, `augenrules`). Installing everything upfront in one pass makes the rest of the guide fully script-friendly.

```bash
apt install -y \
	nano \
	zsh \
	curl \
	cron \
	firewalld \
	fail2ban \
	auditd \
	aide \
	debsums \
	apt-show-versions \
	apparmor-utils \
	libpam-pwquality \
	git \
	apt-transport-https
```

---

#### 1.6 — Configure `unattended-upgrades` for security-only auto-updates

`unattended-upgrades` is Debian's equivalent of `dnf-automatic`. It applies security patches automatically without pulling in feature updates. The `Allowed-Origins` list is restricted to `trixie-security` only — non-security updates are not auto-applied and remain available for manual review.

```bash
apt install -y unattended-upgrades

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable --now unattended-upgrades

# Verify:
systemctl status unattended-upgrades
systemctl status apt-daily-upgrade.timer
```

---

#### 1.7 — Remove known bloat packages

Packages with no purpose are packages that can have vulnerabilities. Debian minimal images are lean — these may already be absent on your image. The `2>/dev/null || true` suppresses errors for packages that are not installed.

```bash
apt purge -y telnet rsh-client nis rpcbind avahi-daemon cups 2>/dev/null || true
apt autoremove -y
```

---

#### 1.8 — Disable and stop unused services

A stopped and disabled service cannot be exploited. This is a manual review step — audit what is running and make a deliberate decision about each service before continuing.

```bash
systemctl list-units --type=service --state=running
# Disable anything not intentionally needed:
# systemctl disable --now <service-name>
```

---

#### 1.9 — Verify `systemd-timesyncd` is running and synchronized

Debian 13 uses `systemd-timesyncd` for NTP synchronization by default — lighter than `chrony` and appropriate for general VPS use. Accurate time is not optional: TLS certificate validation, `auditd` timestamps, and `fail2ban` log parsing all depend on it.

```bash
systemctl enable --now systemd-timesyncd
timedatectl status
# Confirm: "NTP service: active" and "System clock synchronized: yes"
```

---

### [Back to Top](#section-order)

---


## Section 2 — User & Authentication

**Goal:** Eliminate root as an operable account. All human access flows through a rootless user with key-pair SSH and root-password-gated sudo. Root becomes a locked login account with a known password preserved for sudo.

### Checklist

- [ ] **2.1** Create rootless user — no password (key-only access)
- [ ] **2.2** Add user to the `sudo` group
- [ ] **2.3** Configure sudoers — user authenticates sudo with root's password
- [ ] **2.4** Set secure `umask` system-wide
- [ ] **2.5** Set `zsh` as default shell for the user and `root`
- [ ] **2.6** Install oh-my-zsh for `root`
- [ ] **2.7** Install oh-my-zsh for the user
- [ ] **2.8** Configure `fino-time` theme and `umask` in `.zshrc` for both
- [ ] **2.9** Set a known root password — root login blocked at SSH level, not by password lock
- [ ] **2.10** Harden PAM — limit login attempts via `pam_faillock`
- [ ] **2.11** Enforce password quality policy via `pwquality`

### Steps

---

#### 2.1 — Create rootless user with no password

The user has no password — `passwd -l` locks the password field in `/etc/shadow` immediately after account creation. SSH access is key-only (configured in Section 3). There is no password to brute-force and no password for PAM to authenticate during SSH sessions. Console login without a key is intentionally impossible.

```bash
# Guide variables — re-export if reconnected since initial setup
source /root/setup_variables.sh

useradd -m -s /bin/bash "$VPS_USER"
# Lock the password field immediately — key-only access, no password
passwd -l "$VPS_USER"

# Verify (locked entry starts with '!'):
grep "^${VPS_USER}:" /etc/shadow | cut -d: -f2
```

---

#### 2.2 — Add user to the `sudo` group

On Debian, the privilege escalation group is `sudo`, not `wheel`. The mechanism is identical — group membership grants sudo access via `/etc/sudoers`.

> ⚠️ Do not lock root before verifying the user can sudo. Doing it in the wrong order will lock you out of your own server.

```bash
usermod -aG sudo "$VPS_USER"
```

---

#### 2.3 — Configure sudoers to use root's password

By default, `sudo` authenticates the invoking user — it would ask for the user's password, which does not exist. `Defaults:$VPS_USER rootpw` in a drop-in sudoers file makes sudo prompt for root's password instead. This means `sudo <command>` prompts for root's password, and root SSH access remains blocked by `PermitRootLogin no` (Section 3) as a second independent layer.

The drop-in is written to `/etc/sudoers.d/$VPS_USER` and validated with `visudo -c` before installation.

```bash
cat > /tmp/sudoers-user << EOF
# ${VPS_USER}: full sudo access, authenticated with root's password
Defaults:${VPS_USER} rootpw
%sudo ALL=(ALL:ALL) ALL
EOF

# Validate syntax before installing:
visudo -c -f /tmp/sudoers-user
# Expected: /tmp/sudoers-user: parsed OK

install -m 0440 /tmp/sudoers-user "/etc/sudoers.d/${VPS_USER}"
rm /tmp/sudoers-user

# Verify the default sudoers file still has %sudo enabled:
grep -E '^\s*%sudo' /etc/sudoers
# Expected: %sudo	 ALL=(ALL:ALL)		ALL
```

---

#### 2.4 — Set `umask 027` system-wide

The default `umask 022` creates files readable by all users. `027` restricts new files to owner read/write, group read-only, and no access for others. Applied system-wide via `/etc/profile` — covers all login shells. Per-user `.zshrc` entries are added in step 2.8 to also cover interactive non-login zsh sessions.

```bash
echo 'umask 027' >> /etc/profile
```

---

#### 2.5 — Set zsh as default shell for user and root

`chsh -s /bin/zsh` updates `/etc/passwd` for both accounts. Root's shell is set here even though the account password is locked in step 2.9 — when you access root via `sudo -i` or `sudo su`, you get root's configured shell.

```bash
chsh -s /bin/zsh root
chsh -s /bin/zsh "$VPS_USER"

# Verify:
grep -E "^(root|${VPS_USER}):" /etc/passwd | cut -d: -f1,7
# Expected: root:/bin/zsh and <VPS_USER>:/bin/zsh
```

---

#### 2.6 — Install oh-my-zsh for root

oh-my-zsh is installed via its official `install.sh` script fetched over HTTPS from GitHub. The `--unattended` flag suppresses interactive prompts and does not change the default shell (handled in step 2.5) or launch zsh immediately.

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" \
	"" --unattended

# Verify:
ls /root/.oh-my-zsh/
```

---

#### 2.7 — Install oh-my-zsh for the user

We use `sudo -u` with `HOME` explicitly set rather than `su - $VPS_USER` to avoid the subshell/exit problem in a scripted context. This ensures oh-my-zsh is correctly owned by and configured for the user.

```bash
su - "${VPS_USER}"

sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" \
	"" --unattended

exit

# Verify:
ls "/home/${VPS_USER}/.oh-my-zsh/"
```

---

#### 2.8 — Configure `fino-time` theme and `umask` for both users

`fino-time` is a built-in oh-my-zsh theme — no additional download needed. We also append `umask 027` to each `.zshrc` to cover interactive non-login zsh sessions where `/etc/profile` is not sourced.

```bash
# Root:
sed -i 's/^ZSH_THEME=.*/ZSH_THEME="fino-time"/' /root/.zshrc
echo 'umask 027' >> /root/.zshrc

# User:
sed -i 's/^ZSH_THEME=.*/ZSH_THEME="fino-time"/' "/home/${VPS_USER}/.zshrc"
echo 'umask 027' >> "/home/${VPS_USER}/.zshrc"

# Verify:
grep 'ZSH_THEME' /root/.zshrc "/home/${VPS_USER}/.zshrc"
# Expected: ZSH_THEME="fino-time" in both files
```

---

#### 2.9 — Set a known root password and block root login at the SSH level

Root login is blocked at the SSH layer by `PermitRootLogin no` in `sshd_config` (Section 3) — not by locking the password hash. The password hash must remain **unlocked** (`$y$...` without a `!` prefix).

`sudo` with `Defaults rootpw` authenticates by calling `pam_unix` to verify the root password hash. `pam_unix` treats the `!` prefix from `passwd -l` as a locked account and rejects the password even when it is correct. **Do not run `passwd -l root`** — it breaks sudo authentication.

**Do not use `passwd root` interactively either.** Terminal encoding issues silently mangle password characters — `passwd` reports success but the stored hash does not match what you typed. Use `chpasswd` which reads from stdin and bypasses terminal encoding entirely.

```bash
# Step A: Set a strong known root password via chpasswd (not passwd)
# Type your password once at the prompt — hidden, no confirmation:
read -rs ROOT_PASS && echo "root:${ROOT_PASS}" | chpasswd
unset ROOT_PASS

# Verify the hash was written correctly (must NOT start with !):
grep '^root:' /etc/shadow | cut -d: -f2 | cut -c1-3
# Expected: '$y$' — hash present, no lock prefix

# Step B: VERIFY the user can sudo BEFORE continuing
# Open a second SSH session as the user and run: sudo whoami
# You will be prompted for root's password (set in Step A)
# Expected output: root
```

> **Root login is blocked by `PermitRootLogin no` in `sshd_config` (Section 3).** Do not run `passwd -l root` — it prevents sudo from authenticating even with the correct password, because `pam_unix` rejects the `!` prefix regardless of context.

> **If sudo fails:** The most common cause is terminal encoding mangling the password during `read -rs` entry. Try again with an alphanumeric-only password (letters and digits, no symbols) to rule out encoding issues. If faillock has locked the root account after repeated attempts, reset it: `faillock --user root --reset`.

---

#### 2.10 — Harden PAM with `pam_faillock`

Debian 13's `libpam-modules` (1.7.0-5) does not ship a `pam-auth-update` profile for `faillock` — `pam-auth-update` cannot manage it automatically. Manual `sed` insertion is required, but it must also update the `success=N` skip count on the `pam_unix` line.

The default Debian `common-auth` has `[success=1 default=ignore]` on `pam_unix.so` — meaning "on successful auth, skip the next 1 module." When `pam_faillock authfail` is inserted after `pam_unix`, the next module to skip becomes `authfail`. The `success=1` skips it and falls through to `pam_deny`, which always fails — breaking every authentication unconditionally. The fix is updating `success=1` to `success=2` before inserting the `authfail` line.

After correct insertion, `common-auth` must contain:
```
auth		required										pam_faillock.so preauth
auth		[success=2 default=ignore]	pam_unix.so nullok
auth		[default=die]							 pam_faillock.so authfail
auth		requisite									 pam_deny.so
auth		required										pam_permit.so
```

Since the user has no password, faillock only triggers on sudo authentication failures (wrong root password). SSH key auth bypasses PAM password stacks entirely.

```bash
# Check current state:
grep -n 'pam_faillock\|pam_unix' /etc/pam.d/common-auth

# Only insert if faillock is not already present:
if ! grep -q 'pam_faillock' /etc/pam.d/common-auth; then
	# Insert preauth line before pam_unix:
	sed -i '/^auth.*pam_unix\.so/i auth\trequired\t\t\t\tpam_faillock.so preauth' \
	/etc/pam.d/common-auth

	# CRITICAL: increment success count from 1 to 2 BEFORE inserting authfail.
	# success=1 would skip authfail and land on pam_deny — breaking all auth.
	# success=2 skips authfail on success and lands on pam_permit — correct.
	sed -i 's/\[success=1 default=ignore\]/[success=2 default=ignore]/' \
	/etc/pam.d/common-auth

	# Insert authfail line after pam_unix:
	sed -i '/^auth.*pam_unix\.so/a auth\t[default=die]\t\t\t\tpam_faillock.so authfail' \
	/etc/pam.d/common-auth
fi

if ! grep -q 'pam_faillock' /etc/pam.d/common-account; then
	echo 'account required		pam_faillock.so' >> /etc/pam.d/common-account
fi

# Verify the stack — success= MUST be 2, not 1:
grep -A6 'faillock\|pam_unix\|pam_deny\|pam_permit' /etc/pam.d/common-auth

# Configure faillock parameters (5 failed attempts → 15 min lockout):
sed -i 's/^#\s*deny\s*=.*/deny = 5/'												 /etc/security/faillock.conf
sed -i 's/^#\s*unlock_time\s*=.*/unlock_time = 900/'				 /etc/security/faillock.conf
sed -i 's/^#\s*fail_interval\s*=.*/fail_interval = 900/'		 /etc/security/faillock.conf

# Prevent faillock from locking the root account itself.
# Without this, repeated wrong sudo password attempts lock root out of PAM
# entirely — including the hash lookup sudo needs to authenticate.
sed -i 's/^#\s*even_deny_root\s*=.*/even_deny_root = false/' /etc/security/faillock.conf
grep -q '^even_deny_root' /etc/security/faillock.conf || \
	echo 'even_deny_root = false' >> /etc/security/faillock.conf

# Verify:
grep -E '^(deny|unlock_time|fail_interval|even_deny_root)' /etc/security/faillock.conf
```

> **PAM note:** If `pam-auth-update --force` is called by a future package install, it will overwrite `common-auth` and remove the manually added faillock lines. After any `pam-auth-update` run, re-verify with:
> ```bash
> grep -A6 'faillock\|pam_unix\|pam_deny\|pam_permit' /etc/pam.d/common-auth
> # If faillock lines are gone or success= reverted to 1, re-run the insertion block above
> ```

> **Unlocking a locked account:**
> ```bash
> faillock --user "$VPS_USER" --reset
> ```

---

#### 2.11 — Enforce password quality policy via `pwquality`

`libpam-pwquality` was installed in Section 1.5. Enforces password complexity when setting or changing passwords via `passwd`. Applies to root's password set in step 2.9 and any future password changes.

```bash
sed -i 's/^#\s*minlen\s*=.*/minlen = 12/'			 /etc/security/pwquality.conf
sed -i 's/^#\s*minclass\s*=.*/minclass = 3/'		/etc/security/pwquality.conf
sed -i 's/^#\s*maxrepeat\s*=.*/maxrepeat = 3/'	/etc/security/pwquality.conf
sed -i 's/^#\s*usercheck\s*=.*/usercheck = 1/'	/etc/security/pwquality.conf

# Verify:
grep -vE '^#|^$' /etc/security/pwquality.conf
```

---

### [Back to Top](#section-order)

---


## Section 3 — Secure Shell (SSH)

**Goal:** Make SSH access as narrow as possible. Only the rootless user can connect, only via key authentication, on a non-standard port, with all unnecessary SSH features disabled and brute-force attempts automatically banned.

> ⚠️ Complete Sections 1 and 2 fully before starting this section. In particular, the user must exist with an authorized key deployed (step 3.2) before sshd is restarted (step 3.7) — otherwise you will be locked out.

**Note on AppArmor and the SSH port:** No AppArmor port registration is needed. Unlike SELinux, AppArmor's sshd profile does not restrict which port the daemon binds to. Changing the SSH port requires no AppArmor policy update.

**Note on `UsePAM yes`:** The hardened `sshd_config` must include `UsePAM yes`. On Debian 13, OpenSSH is compiled with PAM support and requires `UsePAM yes` to run PAM account and session modules after key authentication. Without it, a key is accepted cryptographically but the session setup fails — producing `Permission denied (publickey)` even when the correct key is presented.

**Note on provider cloud-init drop-in:** This provider image ships `/etc/ssh/sshd_config.d/50-cloud-init.conf`. The default `sshd_config` processes this via an `Include /etc/ssh/sshd_config.d/*.conf` directive. Since the hardened `sshd_config` written here does not include that directive, the drop-in becomes orphaned — it is no longer loaded. It is moved to a backup explicitly to keep the system clean.

### Checklist

- [ ] **3.1** Generate an SSH key pair on your local machine
- [ ] **3.2** Deploy public key to the user's authorized keys — verify ownership
- [ ] **3.3** Create SSH warning banner
- [ ] **3.4** Remove provider cloud-init SSH drop-in, then write hardened `sshd_config`
- [ ] **3.5** Start `firewalld` and open the SSH port
- [ ] **3.6** Configure `fail2ban` for SSH
- [ ] **3.7** Configure local SSH client (`~/.ssh/config`)
- [ ] **3.8** Pre-flight ownership check, then restart `sshd` and verify new connection

### Steps

---

#### 3.1 — Generate an SSH key pair

Run this on your **local machine**, not the server. `ed25519` is the correct algorithm choice: smaller, faster, and more secure than RSA 4096.

```bash
# Run on your LOCAL machine:
ssh-keygen -t ed25519 -C "${VPS_USER}@${VPS_HOSTNAME}"
# Keys saved to: ~/.ssh/id_ed25519 (private) and ~/.ssh/id_ed25519.pub (public)
```

---

#### 3.2 — Deploy public key to the user's authorized keys

The `.ssh` directory and `authorized_keys` file must be owned by the user, not root. OpenSSH's `StrictModes yes` (the default) silently rejects authentication when ownership is wrong — the connection drops at preauth with no useful log entry at `INFO` loglevel. The `chown` and ownership verification at the end of this step are mandatory, not optional.

```bash
# Run on the SERVER as root:

# Guide variables — re-export if reconnected since initial setup
source /root/setup_variables.sh

mkdir -p "/home/${VPS_USER}/.ssh"
chmod 700 "/home/${VPS_USER}/.ssh"
nano "/home/${VPS_USER}/.ssh/authorized_keys"
# Paste your id_ed25519.pub content, save and exit
chmod 600 "/home/${VPS_USER}/.ssh/authorized_keys"

# CRITICAL: transfer ownership to the user — sshd will silently reject
# the key if .ssh/ or authorized_keys is owned by root
chown -R "${VPS_USER}:${VPS_USER}" "/home/${VPS_USER}/.ssh"

# Verify ownership and permissions before continuing:
ls -la "/home/${VPS_USER}/.ssh/"
# Expected:
# drwx------ 2 <VPS_USER> <VPS_USER> ... .ssh/
# -rw------- 1 <VPS_USER> <VPS_USER> ... authorized_keys

# Verify the key fingerprint matches your local public key:
ssh-keygen -lf "/home/${VPS_USER}/.ssh/authorized_keys"
# Compare this fingerprint against: ssh-keygen -lf ~/.ssh/id_ed25519.pub (on your local machine)
```

> ⚠️ **Do not proceed to step 3.3 until the ownership verification above shows `<VPS_USER>:<VPS_USER>` on both entries.** A root-owned `.ssh` directory causes silent authentication failure after sshd is restarted — the only symptom is `Connection closed by authenticating user ... [preauth]` in the auth log, with no indication of the actual cause.

---

#### 3.3 — Create SSH warning banner

The banner is displayed to every client before authentication occurs. It establishes the legal basis for action against unauthorized users. Must be `644` — world-readable so `sshd` can serve it to unauthenticated connections.

```bash
cat > /etc/ssh/banner << 'EOF'
WARNING: Unauthorized access to this system is prohibited.
All activity is monitored and logged.
EOF

chmod 644 /etc/ssh/banner
cat /etc/ssh/banner
```

---

#### 3.4 — Remove provider drop-in and write hardened `sshd_config`

Key settings in the hardened config: non-standard port, key-only auth, `KbdInteractiveAuthentication no` (explicitly required — omitting this line leaves it at the compiled default `yes` on Debian 13, independently of `PasswordAuthentication`), `UsePAM yes` (required for PAM session setup after key auth), explicit user allowlist, disabled forwarding features, and restricted ciphers/MACs/KexAlgorithms.

```bash
# Guide variables — re-export if reconnected since initial setup
source /root/setup_variables.sh

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Move the cloud-init drop-in to a backup:
[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ] && \
	mv /etc/ssh/sshd_config.d/50-cloud-init.conf \
	/etc/ssh/sshd_config.d/50-cloud-init.conf.bak

cat > /etc/ssh/sshd_config << EOF
# --- Port & Protocol ---
Port ${VPS_SSH_PORT}
AddressFamily any

# --- Banner ---
Banner /etc/ssh/banner

# --- Authentication ---
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30

# --- Access Control ---
AllowUsers ${VPS_USER}

# --- PAM ---
# UsePAM must be yes on Debian 13.
# OpenSSH requires it to run PAM account and session modules after key
# authentication. Without it the session setup fails with Permission denied.
UsePAM yes

# --- Features (all disabled) ---
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintMotd no
UseDNS no

# --- Hardened Algorithms ---
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# --- Misc ---
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# Verify config syntax before anything else:
sshd -t
# No output = no errors. Fix any errors before proceeding.
```

---

#### 3.5 — Start `firewalld` and open the SSH port

`firewalld` must be running before `fail2ban` starts in the next step. `fail2ban` uses `firewallcmd-rich-rules` as its banaction — if `firewalld` is not active when a ban fires, the ban fails silently.

```bash
# Guide variables — re-export if reconnected since initial setup
source /root/setup_variables.sh

systemctl enable --now firewalld
firewall-cmd --permanent --add-port="${VPS_SSH_PORT}/tcp"
firewall-cmd --reload

# Verify:
firewall-cmd --list-ports
# Expected: <VPS_SSH_PORT>/tcp
```

---

#### 3.6 — Configure `fail2ban` for SSH

Even on a non-standard port with key-only auth, automated scanners will eventually find the port. `fail2ban` watches `sshd` logs via systemd journal (`backend = systemd` is correct — `sshd` logs via journald on Debian 13) and bans offending IPs via `firewalld` rich rules. Configuration: 3 failed attempts → 1 hour ban.

```bash
# Guide variables — re-export if reconnected since initial setup
source /root/setup_variables.sh

cat > /etc/fail2ban/jail.d/sshd.local << EOF
[sshd]
enabled		= true
port		= ${VPS_SSH_PORT}
filter		= sshd
backend		= systemd
maxretry	= 3
bantime		= 3600
findtime	= 600
banaction	= firewallcmd-rich-rules
EOF

systemctl enable --now fail2ban

# Verify:
fail2ban-client status sshd
```

---

#### 3.7 — Configure local SSH client

Before restarting sshd, configure your local `~/.ssh/config` so the first connection attempt after the restart succeeds cleanly. With `MaxAuthTries 3` in the hardened config, SSH agents that offer multiple keys sequentially (such as 1Password) will exhaust the attempt limit before the correct key is tried — resulting in `Too many authentication failures` even when the right key is available.

`IdentitiesOnly yes` tells SSH to offer only the specified key and ignore everything else the agent provides. For keys stored in 1Password with no private key file on disk, use the `.pub` file as the `IdentityFile` hint — the agent sees the public key reference and knows which key to sign with.

```
# Add to ~/.ssh/config on your LOCAL machine:

Host <VPS_HOSTNAME>
	Hostname <your-server-ip>
	User <VPS_USER>
	Port <VPS_SSH_PORT>
	IdentityFile ~/.ssh/your-key			 # private key file, or .pub as hint for agent
	IdentitiesOnly yes
```

---

#### 3.8 — Pre-flight check, then restart `sshd`

Verify ownership one final time before restarting sshd. A root-owned `authorized_keys` file causes silent preauth failure — there is no obvious error message, making it extremely hard to diagnose after the fact.

```bash
# Pre-flight: confirm authorized_keys ownership is correct
ls -la "/home/${VPS_USER}/.ssh/"
# Both entries MUST show <VPS_USER>:<VPS_USER> ownership
# If either shows root:root — fix it first: chown -R "${VPS_USER}:${VPS_USER}" "/home/${VPS_USER}/.ssh"

# Pre-flight: confirm sshd config syntax is still valid
sshd -t
# No output = no errors

# Restart sshd:
systemctl restart sshd
systemctl status sshd

# Post-restart: confirm AppArmor has no sshd denials:
journalctl -k --grep='apparmor.*DENIED.*sshd' --since=boot
# Expected: no output
```

> ⚠️ **Keep this session open.** Open a NEW terminal and test the connection using the `~/.ssh/config` entry configured in step 3.7:
> ```bash
> ssh <VPS_HOSTNAME>
> ```
> The banner should appear before the key prompt. Only close this root session after the new connection succeeds and you have confirmed `sudo whoami` returns `root` from the new session.

---

### [Back to Top](#section-order)

---


## Section 4 — Network & Firewall

**Goal:** Migrate the network stack from `ifupdown`/`networking` (Debian's default) to `systemd-networkd`, mirror the existing network configuration exactly, then harden the resulting setup. A stable, predictable network stack managed by systemd is a prerequisite for consistent firewall and audit behaviour.

> ⚠️ This section carries the highest risk of network loss of any section in this guide. Take a VPS provider snapshot before starting. Have the provider's out-of-band console ready in case SSH becomes unreachable. Every step includes a recovery path.

### Checklist

- [ ] **4.1** Verify `firewalld` is running and confirm the active zone
- [ ] **4.2** Remove default permitted services from the `public` zone
- [ ] **4.3** Confirm the SSH port is the only open port
- [ ] **4.4** Enable denial logging
- [ ] **4.5** Detect the current network configuration — IPv4 and IPv6
- [ ] **4.6** Migrate to `systemd-networkd` — mirror existing IPv4 and IPv6 config
- [ ] **4.7** Verify network connectivity after migration
- [ ] **4.8** Disable and mask legacy networking services
- [ ] **4.9** Harden `systemd-networkd` — configure DNSSEC, disable LLMNR and mDNS
- [ ] **4.10** Reload and verify final network and firewall state

### Steps

---

#### 4.1 — Verify `firewalld` and confirm the active zone

`firewalld` was enabled in Section 3.5 as a prerequisite for `fail2ban`. This step confirms it is active and boot-enabled before further rule changes. The `public` zone is correct for an internet-facing VPS — it assumes no trust of other hosts and defaults to drop for inbound traffic.

```bash
systemctl enable --now firewalld
systemctl status firewalld

firewall-cmd --get-active-zones
# Expected: public with your network interface listed beneath it

# If your interface is not in the public zone, assign it:
# firewall-cmd --permanent --zone=public --change-interface=<interface>
# firewall-cmd --reload
```

---

#### 4.2 — Remove default permitted services

`firewalld`'s default `public` zone on Debian may ship with `ssh` and `dhcpv6-client` permitted — VPS provider images vary. The `ssh` service covers port 22, which is replaced by `VPS_SSH_PORT`. All removal commands use `2>/dev/null || true` since these services may not be present on all images.

```bash
# Inspect what is currently permitted:
firewall-cmd --permanent --zone=public --list-services

firewall-cmd --permanent --zone=public --remove-service=cockpit	2>/dev/null || true
firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client 2>/dev/null || true
firewall-cmd --permanent --zone=public --remove-service=ssh 2>/dev/null || true

# Verify nothing else is permitted:
firewall-cmd --permanent --zone=public --list-services
# Expected: (empty)
```

---

#### 4.3 — Confirm only the SSH port is open

After removing default services, the only open inbound path should be the SSH port added in Section 3.5.

```bash
# Guide variables — re-export if reconnected since initial setup
source /root/setup_variables.sh

firewall-cmd --permanent --zone=public --list-ports
# Expected: <VPS_SSH_PORT>/tcp

# If missing for any reason, re-add:
# firewall-cmd --permanent --zone=public --add-port="${VPS_SSH_PORT}/tcp"
```

---

#### 4.4 — Enable denial logging

Denial logging gives visibility into what is being blocked — useful during initial setup and periodic audits. On Debian 13, `firewalld` uses the `nftables` backend and manages both IPv4 and IPv6 stacks automatically.

```bash
firewall-cmd --set-log-denied=all
firewall-cmd --reload

# Verify final firewall state:
firewall-cmd --zone=public --list-all
# Expected: services empty, ports showing <VPS_SSH_PORT>/tcp only
```

---

#### 4.5 — Detect the current network configuration

Before migrating, capture the full existing network configuration — both IPv4 and IPv6. The migration in step 4.6 will mirror everything exactly into `systemd-networkd` format. Do not skip this step.

```bash
source /root/setup_variables.sh

# Identify the active network interface:
echo "Active interface: $VPS_IFACE"

# Full interface configuration — IPv4 and IPv6:
ip addr show "$VPS_IFACE"
echo "---"
ip route show
echo "---"
ip -6 route show

# Current networking config file:
cat /etc/network/interfaces 2>/dev/null || echo "No /etc/network/interfaces found"
cat /etc/network/interfaces.d/* 2>/dev/null || echo "No interfaces.d files found"

# Check which network manager is currently active:
systemctl is-active networking			2>/dev/null
systemctl is-active systemd-networkd	2>/dev/null
systemctl is-active NetworkManager		2>/dev/null

# DNS configuration:
cat /etc/resolv.conf
```

From the output above, note all values before proceeding to step 4.6:

| Value					| Where to find it									| Example					|
| --------------------- | ------------------------------------------------- | ------------------------- |
| Interface name		| `$VPS_IFACE`										| `eth0`					|
| IPv4 address/prefix	| `ip addr show` — the `inet` line					| `203.0.113.10/24`			|
| IPv4 gateway			| `ip route show` — the `default via` line			| `203.0.113.1`				|
| IPv6 address/prefix	| `ip addr show` — the `inet6` line (scope global)	| `2001:db8::1/64`			|
| IPv6 gateway			| `ip -6 route show` — the `default via` line		| `fe80::1`					|
| DNS servers			| `/etc/resolv.conf` — the `nameserver` lines		| `1.1.1.1`, `8.8.8.8`		|
| Config type			| `/etc/network/interfaces` — `dhcp`/`static`		| `static`					|

> **IPv6 note:** If `ip addr show` shows an `inet6` address with `scope global` — your provider assigns a static IPv6 address. If there is no `scope global` IPv6 address (only `scope link` for link-local) — your provider is IPv4 only and IPv6 can be disabled in the migration.

---

#### 4.6 — Migrate to `systemd-networkd`

This step creates the `.network` file that mirrors the existing configuration exactly — IPv4 and IPv6. Two things are critical here that are not obvious:

**File permissions must be `644`.** systemd-networkd runs as the `systemd-network` user, not root. With `umask 027` set in Section 2.4, any file created by root gets `640` by default — which locks out the `systemd-network` user with `Permission denied`. The file will appear to exist but systemd-networkd will silently ignore it, leaving the interface `unmanaged`.

**Match by MAC address, not interface name.** Using `Name=eth0` in `[Match]` works but generates a warning about unpredictable interface names. Matching by `MACAddress=` is stable across reboots regardless of how the kernel names the interface.

```bash
# Guide variable — re-export if reconnected:
source /root/setup_variables.sh

mkdir -p /etc/systemd/network

# Capture MAC address for stable matching:
VPS_MAC=$(ip link show "$VPS_IFACE" | awk '/link\/ether/ {print $2}')
echo "Interface MAC: $VPS_MAC"

# Detect IPv4 config type:
if grep -q 'dhcp' /etc/network/interfaces 2>/dev/null; then
	IPV4_TYPE="dhcp"
else
	IPV4_TYPE="static"
fi
echo "IPv4 config type: $IPV4_TYPE"

# Detect IPv6 — check for a global-scope address on this interface:
IPV6_ADDR=$(ip -6 addr show "$VPS_IFACE" scope global 2>/dev/null \
	| awk '/inet6/ {print $2}' | head -1)
IPV6_GW=$(ip -6 route show default 2>/dev/null \
	| awk '/default via/ {print $3}' | head -1)

if [ -n "$IPV6_ADDR" ]; then
	echo "IPv6 detected: ${IPV6_ADDR} via ${IPV6_GW}"
	IPV6_PRESENT=true
else
	echo "No global IPv6 address detected — IPv6 will be disabled"
	IPV6_PRESENT=false
fi

# Capture IPv4 static values if needed:
if [ "$IPV4_TYPE" = "static" ]; then
	VPS_IP=$(ip addr show "$VPS_IFACE" | awk '/inet / {print $2}')
	VPS_GW=$(ip route show default | awk '/default/ {print $3}')
fi

# Capture DNS from current resolv.conf:
VPS_DNS1=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | sed -n '1p')
VPS_DNS2=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | sed -n '2p')

# Build the .network file:
{
	echo "[Match]"
	echo "MACAddress=${VPS_MAC}"
	echo ""
	echo "[Network]"

	if [ "$IPV4_TYPE" = "dhcp" ]; then
		echo "DHCP=ipv4"
	else
		echo "Address=${VPS_IP}"
		echo "Gateway=${VPS_GW}"
	fi

	[ -n "$VPS_DNS1" ] && echo "DNS=${VPS_DNS1}"
	[ -n "$VPS_DNS2" ] && echo "DNS=${VPS_DNS2}"

	if [ "$IPV6_PRESENT" = true ]; then
		echo "Address=${IPV6_ADDR}"
		echo "IPv6AcceptRA=no"
	else
		echo "IPv6AcceptRA=no"
		echo "LinkLocalAddressing=ipv6"
	fi

	if [ "$IPV4_TYPE" = "dhcp" ]; then
		echo ""
		echo "[DHCP]"
		echo "UseDNS=yes"
		echo "UseRoutes=yes"
		echo "UseHostname=no"
	fi

	if [ "$IPV6_PRESENT" = true ] && [ -n "$IPV6_GW" ]; then
		echo ""
		echo "[Route]"
		echo "Gateway=${IPV6_GW}"
		echo "GatewayOnLink=yes"
	fi

} > "/etc/systemd/network/10-${VPS_IFACE}.network"

# CRITICAL: set 644 so systemd-network user can read the file.
# umask 027 from Section 2.4 creates files as 640 — which causes
# "Permission denied" and leaves the interface permanently unmanaged.
chmod 644 "/etc/systemd/network/10-${VPS_IFACE}.network"

# Review the generated file before switching:
echo "=== Generated network config ==="
cat "/etc/systemd/network/10-${VPS_IFACE}.network"
ls -la "/etc/systemd/network/10-${VPS_IFACE}.network"
echo "================================"
echo "Compare against detected values:"
echo "	MAC:	${VPS_MAC}"
echo "	IPv4: ${VPS_IP:-dhcp} via ${VPS_GW:-dhcp}"
[ "$IPV6_PRESENT" = true ] && echo "	IPv6: ${IPV6_ADDR} via ${IPV6_GW}"
echo "	DNS:	${VPS_DNS1} ${VPS_DNS2}"
```

> ⚠️ **Review the generated config and verify permissions before proceeding.** The `ls -la` output must show `-rw-r--r--` (644). If it shows `-rw-r-----` (640), run `chmod 644` on the file — systemd-networkd will silently fail to read it otherwise.

---

#### 4.7 — Start `systemd-networkd` and verify it takes ownership

The migration has two distinct phases that must both succeed before the legacy service is touched. Phase 1: start systemd-networkd and confirm it reads the `.network` file and brings the interface to `routable (configured)` state. Phase 2: only then disable the legacy service.

The key distinction is `routable (configured)` vs `routable (unmanaged)`. `unmanaged` means systemd-networkd sees the interface but is not managing it — the `.network` file was not read (usually a permissions problem). `configured` means systemd-networkd owns the interface and will maintain it when the legacy service stops.

```bash
# Enable and start systemd-networkd and systemd-resolved:
systemctl enable systemd-networkd systemd-resolved
systemctl start systemd-networkd systemd-resolved

# Wait 3 seconds for systemd-networkd to process the .network file:
sleep 3

# Check interface state — MUST show 'routable (configured)' before continuing:
networkctl status "$VPS_IFACE"
```

> ⚠️ **Hard gate:** The `State:` line must read `routable (configured)`. If it reads `routable (unmanaged)`:
> - Check file permissions: `ls -la /etc/systemd/network/` — must be `644`
> - Check systemd-networkd logs: `journalctl -u systemd-networkd -n 20 --no-pager`
> - Fix permissions: `chmod 644 /etc/systemd/network/10-${VPS_IFACE}.network`
> - Then: `systemctl restart systemd-networkd && sleep 3 && networkctl status $VPS_IFACE`
> - **Do not proceed to step 4.8 until the state shows `configured`.**

```bash
# Verify connectivity while both network stacks are still running:
ping -c 3 1.1.1.1
ping6 -c 3 2606:4700:4700::1111

# Switch DNS resolver to systemd-resolved:
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

# Verify DNS resolution:
dig debian.org +short
```

> **Recovery if anything fails here:** Both networking stacks are still running at this point. Your SSH session is safe. To abort the migration entirely:
> ```bash
> systemctl stop systemd-networkd systemd-resolved
> # Restore original resolv.conf if it was already switched:
> cp /etc/resolv.conf.bak /etc/resolv.conf 2>/dev/null || true
> ```

---

#### 4.8 — Disable and mask legacy networking

Only proceed here after step 4.7 confirms `routable (configured)` and both ping tests pass.

When `networking` is stopped, it briefly withdraws its routes before systemd-networkd re-establishes them — this causes a 2–5 second connectivity gap. Your SSH session will drop momentarily and reconnect on its own. This is expected behaviour, not a failure. If connectivity does not return within 30 seconds, use the provider console.

```bash
# Disable and mask the legacy networking service:
systemctl disable --now networking
systemctl mask networking

# NetworkManager if present:
systemctl disable NetworkManager 2>/dev/null || true
systemctl stop NetworkManager		2>/dev/null || true

# Wait for systemd-networkd to fully re-establish routes:
sleep 5

# Verify systemd-networkd is the sole manager:
networkctl list
# Expected: eth0 shows 'routable' and 'configured'
networkctl status "$VPS_IFACE"
# Expected: State: routable (configured), Network File shows 10-eth0.network
```

> **Recovery if connectivity does not return after 30 seconds:**
> ```bash
> # Via provider console as root:
> systemctl unmask networking
> systemctl start networking
> # Diagnose why systemd-networkd lost ownership, fix, then retry from step 4.7
> ```

---

#### 4.9 — Harden `systemd-networkd`

With the migration confirmed, apply network hardening. This step configures `systemd-resolved` with privacy-respecting DNS settings and disables network features that are not needed on a single-homed VPS.

```bash
# Configure systemd-resolved — disable LLMNR and mDNS, enable DNSSEC:
mkdir -p /etc/systemd/resolved.conf.d/

cat > /etc/systemd/resolved.conf.d/hardening.conf << 'EOF'
[Resolve]
# Disable link-local multicast name resolution — not needed on a VPS
LLMNR=no
# Disable multicast DNS — not needed on a VPS
MulticastDNS=no
# Enable DNSSEC validation where supported by upstream resolver
DNSSEC=allow-downgrade
# Do not cache negative results longer than necessary
NegativeTTL=0
EOF

# Set 644 — systemd-resolved runs as systemd-resolve user, not root.
# umask 027 from Section 2.4 would create this as 640, locking it out.
chmod 644 /etc/systemd/resolved.conf.d/hardening.conf

systemctl restart systemd-resolved

# Verify resolved is running with the new settings:
resolvectl status
# Confirm: LLMNR=no, MulticastDNS=no, DNSSEC=allow-downgrade
```

---

#### 4.10 — Reload and verify final network and firewall state

```bash
firewall-cmd --reload

echo "=== Network interface state ==="
networkctl status "$VPS_IFACE"

echo "=== IP configuration ==="
ip addr show "$VPS_IFACE"
ip route show

echo "=== DNS resolution ==="
resolvectl status
resolvectl query debian.org

echo "=== Firewall state ==="
firewall-cmd --zone=public --list-all
# Expected: ports <VPS_SSH_PORT>/tcp only, services empty

echo "=== IPv6 state ==="
ip -6 addr show "$VPS_IFACE"
# If IPv6 was detected and migrated: expect a global scope address here
# If IPv6 was disabled (IPv6AcceptRA=no, no Address= line): expect only link-local
ip -6 route show

echo "=== Active network services ==="
systemctl is-active systemd-networkd
systemctl is-active systemd-resolved
systemctl is-active networking	 # Expected: inactive
```

> **Note for service layering:** When adding services on top of this baseline, open only the exact ports needed:
> ```bash
> firewall-cmd --permanent --zone=public --add-port=<port>/tcp
> firewall-cmd --reload
> ```
> Never open port ranges or re-enable removed default services.

> **Recovery procedure if network is lost:** Use the provider's out-of-band console to log in as root, then:
> ```bash
> systemctl unmask networking
> systemctl start networking
> # Diagnose the systemd-networkd config, fix it, then retry step 4.7
> ```

---

### [Back to Top](#section-order)

---


## Section 5 — Package Integrity

**Goal:** Ensure every package on the system comes from a trusted, verified source and that no installed binary has been tampered with since installation.

### Checklist

- [ ] **5.1** Re-audit APT GPG verification across all active sources
- [ ] **5.2** Audit enabled repositories
- [ ] **5.3** Verify installed packages against shipped checksums via `debsums`
- [ ] **5.4** Check for held-back or drifted updates via `apt-show-versions`
- [ ] **5.5** Remove orphaned packages

### Steps

---

#### 5.1 — Re-audit APT GPG verification

APT's GPG enforcement was confirmed before the initial upgrade in Section 1.4. This step performs a full re-audit now that all packages from Sections 1–4 are installed and any provider-injected repos are fully visible. The goal is confirming no source has a `[trusted=yes]` override or a missing `Signed-By` field.

```bash
# Check for trusted=yes overrides:
grep -rE 'trusted=yes|allow-unauthenticated|AllowUnauthenticated' \
	/etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null
# Expected: no output

# Verify Debian archive signing key is present:
ls /etc/apt/trusted.gpg.d/
# Expected: debian-archive-*.gpg files

# Check global APT config for unauthenticated bypasses:
grep -r 'AllowUnauthenticated\|allow-unauthenticated' \
	/etc/apt/apt.conf.d/ 2>/dev/null
# Expected: no output
```

---

#### 5.2 — Audit enabled repositories

Every enabled repository is a potential source of packages installable onto your system. VPS providers typically inject their own agent or monitoring repos. Review each one — disable anything you cannot justify.

```bash
# Traditional format:
grep '^deb' /etc/apt/sources.list 2>/dev/null

# DEB822 format:
grep '^URIs:' /etc/apt/sources.list.d/*.sources 2>/dev/null

# Full policy view:
apt-cache policy

# Disable any repo you cannot justify — comment out the relevant line
# or delete the .list / .sources file:
# nano /etc/apt/sources.list.d/<provider-repo>.list
```

---

#### 5.3 — Verify installed packages via `debsums`

`debsums -c` verifies installed files against the MD5 checksums shipped inside each `.deb` package. This is Debian's equivalent of `rpm -Va`. Discrepancies on config files you modified during setup are expected — discrepancies on binaries are not.

```bash
debsums -c 2>/dev/null | tee /root/debsums-baseline.txt

# Output format: <filepath>	FAILED
# Expected: modified config files only (anything you changed during setup)
# Unexpected: modified binaries — investigate immediately
```

---

#### 5.4 — Check for update drift via `apt-show-versions`

`apt-show-versions` shows the installed version of every package alongside the available version across all configured repos. It identifies packages installed from a repo that has since been removed, packages held back from upgrading, and packages installed from a non-standard source.

```bash
apt update -qq

# Show all packages not at their latest available version:
apt-show-versions | grep -v 'uptodate' | tee /root/apt-drift-baseline.txt

# Packages with 'No available version' are orphaned from their source repo.
# Packages showing an older version have available updates — apply if security-relevant:
# apt install <package>=<version>
```

---

#### 5.5 — Remove orphaned packages

Packages installed as dependencies that are no longer required by anything.

```bash
apt autoremove -y
```

> **Baseline note:** Save `/root/debsums-baseline.txt` and `/root/apt-drift-baseline.txt`. After any major change or upgrade, re-run both and diff against these files to spot unexpected modifications or drift. These complement AIDE (Section 11) which provides ongoing monitoring.

---

### [Back to Top](#section-order)

---


## Section 6 — Mandatory Access Control (MAC)

**Goal:** Confirm AppArmor is loaded and that key service profiles are in enforce mode. Establish the correct approach to handling denials — targeted fixes, never disabling the module.

### Checklist

- [ ] **6.1** Verify AppArmor module is loaded and the service is active
- [ ] **6.2** Verify AppArmor is enabled at boot
- [ ] **6.3** Confirm the count and list of profiles in enforce mode
- [ ] **6.4** Review profiles in complain mode — enforce those covering running services
- [ ] **6.5** Audit AppArmor denials since boot and resolve any outstanding issues
- [ ] **6.6** Enforce any complain-mode profiles that should be enforced

### Steps

---

#### 6.1 — Verify AppArmor module and service

Debian 13 ships with AppArmor compiled into the kernel and the `apparmor` service enabled by default. Unlike SELinux's single global mode, AppArmor is profile-based — each profile is independently set to enforce or complain mode. If the service is inactive, no profiles are loaded and no MAC enforcement is active.

```bash
cat /sys/module/apparmor/parameters/enabled
# Expected: Y

systemctl is-active apparmor
systemctl status apparmor
aa-status
```

---

#### 6.2 — Verify AppArmor is enabled at boot

```bash
systemctl is-enabled apparmor
# Expected: enabled
```

---

#### 6.3 — List profiles in enforce mode

On a fresh Debian 13 VPS, expect 20–40+ profiles loaded, most in enforce mode. The exact count depends on installed packages.

```bash
aa-status | grep 'profiles are in enforce mode'

# List enforce-mode profile names:
aa-status | awk '/in enforce mode/{found=1; next} found && /in complain mode/{exit} found{print}' \
	| grep '^\s'
```

---

#### 6.4 — Review complain-mode profiles

Profiles in complain mode log denials without blocking. Every profile covering a service you actively run should be in enforce mode.

```bash
aa-status | grep 'profiles are in complain mode'

aa-status | awk '/in complain mode/{found=1; next} found && /processes have/{exit} found{print}' \
	| grep '^\s'

# For each profile in complain mode:
#	 - Is the service running? systemctl is-active <service>
#	 - If yes and it matters: enforce it (see step 6.6)
#	 - If the service is not installed: leave in complain or remove
```

---

#### 6.5 — Audit AppArmor denials since boot

After all configuration changes in Sections 1–5, sweep for any denials — particularly around `sshd`, `fail2ban`, and `auditd`. A post-restart check for sshd was already done in Section 3.7; this is a comprehensive sweep.

```bash
journalctl -k --grep='apparmor="DENIED"' --since=boot
# No output = no denials — ideal state

# Resolution hierarchy when denials exist:
#	 1. Fix the service configuration if the denial is caused by misconfiguration
#	 2. Add a local rule: /etc/apparmor.d/local/<profile-name>
#	 3. aa-complain /etc/apparmor.d/<profile> — temporary debug only
#	 Never: systemctl stop apparmor
```

---

#### 6.6 — Enforce complain-mode profiles

`aa-enforce` moves a profile from complain to enforce mode and reloads it. Local overrides survive package updates — add them to `/etc/apparmor.d/local/<profile-name>`.

```bash
# Enforce a specific profile (example: sshd):
# aa-enforce /etc/apparmor.d/usr.sbin.sshd

# Reload a profile after making local overrides:
# apparmor_parser -r /etc/apparmor.d/<profile-file>

# Verify final state:
aa-status
# Confirm: 0 profiles in complain mode (or only profiles for non-installed services)
```

> **Local overrides:** To extend a profile without modifying the base file:
> ```bash
> echo 'capability net_admin,' >> /etc/apparmor.d/local/usr.sbin.sshd
> apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd
> ```

---

### [Back to Top](#section-order)

---


## Section 7 — Logging & Audit

**Goal:** Ensure all security-relevant events are captured, stored persistently, and rotated safely. Logs are your only forensic trail if something goes wrong.

### Checklist

- [ ] **7.1** Enable persistent storage in `journald`
- [ ] **7.2** Cap `journald` maximum disk usage
- [ ] **7.3** Enable `auditd` for boot — without starting yet
- [ ] **7.4** Configure `auditd` log retention
- [ ] **7.5** Deploy hardened `auditd` rules
- [ ] **7.6** Start `auditd`
- [ ] **7.7** Verify log rotation is configured

### Steps

---

#### 7.1 — Enable `journald` persistent storage

By default on minimal installs, `journald` stores logs in memory only — all logs are lost on reboot. `Storage=persistent` writes logs to `/var/log/journal/`, surviving reboots.

```bash
mkdir -p /var/log/journal
sed -i 's/^#Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
grep -q '^Storage=' /etc/systemd/journald.conf || \
	echo 'Storage=persistent' >> /etc/systemd/journald.conf
```

---

#### 7.2 — Cap `journald` disk usage

Persistent logs without a cap will grow unbounded and eventually fill the disk. `SystemMaxUse=500M` sets a hard ceiling.

```bash
sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=500M/' /etc/systemd/journald.conf
grep -q '^SystemMaxUse=' /etc/systemd/journald.conf || \
	echo 'SystemMaxUse=500M' >> /etc/systemd/journald.conf

systemctl restart systemd-journald

# Verify:
journalctl --disk-usage
```

---

#### 7.3 — Enable `auditd` for boot without starting yet

`auditd` hooks directly into the kernel and records system calls — giving visibility into file access, privilege escalation, user/group changes, and network configuration modifications. Unlike AlmaLinux, Debian's `auditd` does not carry `RefuseManualStop=yes` and can be restarted normally. Retention config and rules are deployed before the first start so everything loads in one clean pass.

```bash
systemctl enable auditd
```

---

#### 7.4 — Configure `auditd` log retention

`auditd` manages its own log files in `/var/log/audit/`. A rolling set of 50MB per file, 10 files = 500MB maximum audit log retention.

```bash
sed -i 's/^max_log_file\s*=.*/max_log_file = 50/'					/etc/audit/auditd.conf
sed -i 's/^num_logs\s*=.*/num_logs = 10/'							/etc/audit/auditd.conf
sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = ROTATE/'	/etc/audit/auditd.conf

# Verify:
grep -E 'max_log_file|num_logs|max_log_file_action' /etc/audit/auditd.conf
```

---

#### 7.5 — Deploy hardened `auditd` rules

Rules are written to `/etc/audit/rules.d/hardening.rules` before `auditd` starts. On first start, `auditd` merges all files in `rules.d/` into `/etc/audit/audit.rules` and loads them into the kernel automatically. Both `pam_faillock` state directories are watched to cover the default path and any configured override.

```bash
mkdir -p /etc/audit/rules.d

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# --- Buffer size ---
-b 8192

# --- Failure mode: 1 = log, 2 = panic ---
-f 1

# --- Authentication & authorization ---
-w /etc/passwd                      -p wa -k identity
-w /etc/shadow                      -p wa -k identity
-w /etc/group                       -p wa -k identity
-w /etc/gshadow                     -p wa -k identity
-w /etc/sudoers                     -p wa -k sudoers
-w /etc/sudoers.d/                  -p wa -k sudoers

# --- SSH configuration ---
-w /etc/ssh/sshd_config             -p wa -k sshd_config

# --- Privilege escalation ---
-w /bin/su                          -p x -k privilege_escalation
-w /usr/bin/sudo                    -p x -k privilege_escalation

# --- User and group management tools ---
-w /usr/sbin/useradd                -p x -k user_mgmt
-w /usr/sbin/usermod                -p x -k user_mgmt
-w /usr/sbin/userdel                -p x -k user_mgmt
-w /usr/sbin/groupadd               -p x -k user_mgmt
-w /usr/sbin/groupmod               -p x -k user_mgmt
-w /usr/sbin/groupdel               -p x -k user_mgmt

# --- Network configuration ---
-w /etc/hosts                       -p wa -k network_config
-w /etc/systemd/network/            -p wa -k network_config
-w /etc/systemd/resolved.conf.d/    -p wa -k network_config

# --- Kernel module loading ---
-w /sbin/insmod                     -p x -k kernel_modules
-w /sbin/rmmod                      -p x -k kernel_modules
-w /sbin/modprobe                   -p x -k kernel_modules

# --- Login and session events ---
-w /var/log/lastlog                 -p wa -k logins
-w /run/faillock/                   -p wa -k logins
-w /var/lib/faillock/               -p wa -k logins

# --- Immutable flag: lock rules at runtime ---
# -e 2
# Uncomment only after rules are confirmed working.
# -e 2 makes rules immutable until next reboot.
# Leave commented during initial setup and first weeks of operation.
EOF
```

> **Note:** The network config audit rules now watch `/etc/systemd/network/` and `/etc/systemd/resolved.conf.d/` instead of the legacy `/etc/resolv.conf`. Both paths are monitored to cover the transition period.

---

#### 7.6 — Start `auditd`

With retention config and rules both in place, `auditd` is started. It picks up everything in one clean pass.

```bash
systemctl start auditd
systemctl status auditd

# Verify rules are active:
auditctl -l
# Expected: all rules from hardening.rules listed
```

---

#### 7.7 — Verify log rotation

On Debian 13, `auditd` manages its own log rotation internally — via the `max_log_file`, `num_logs`, and `max_log_file_action = ROTATE` settings configured in step 7.4. There is no `/etc/logrotate.d/auditd` file and none is needed. `logrotate` handles other system logs such as `syslog`, `auth.log`, and `fail2ban`.

```bash
# Verify auditd self-rotation config is active:
grep -E 'max_log_file|num_logs|max_log_file_action' /etc/audit/auditd.conf
# Expected:
# max_log_file = 50
# num_logs = 10
# max_log_file_action = ROTATE

# Verify logrotate is present and handling system logs:
ls /etc/logrotate.d/
# Expected: apt, dpkg, fail2ban, unattended-upgrades, wtmp, etc.
# Note: no auditd entry — this is correct on Debian 13

# Confirm audit log directory exists and auditd is writing to it:
ls -lh /var/log/audit/
```

> **Querying audit logs:**
> ```bash
> ausearch -k identity							# passwd/shadow/group changes
> ausearch -k privilege_escalation	# all sudo/su usage
> ausearch -k sshd_config					 # sshd_config modifications
> ausearch -k network_config				# network configuration changes
> aureport --summary								# summarised report of all events
> ```

> **Reloading rules on a running system:**
> ```bash
> systemctl restart auditd
> auditctl -l
> ```

---

### [Back to Top](#section-order)

---


## Section 8 — Kernel Hardening

**Goal:** Harden the Linux kernel's network stack and core behavior against IP spoofing, SYN floods, redirect attacks, and information leakage via persistent `sysctl` parameters.

### Checklist

- [ ] **8.1** Disable IP forwarding
- [ ] **8.2** Disable ICMP redirect acceptance and sending
- [ ] **8.3** Disable source routing
- [ ] **8.4** Enable reverse path filtering
- [ ] **8.5** Enable SYN cookies
- [ ] **8.6** Enable martian packet logging
- [ ] **8.7** Harden kernel information exposure
- [ ] **8.8** Harden ASLR and core dumps
- [ ] **8.9** Disable Magic SysRq key
- [ ] **8.10** Apply and persist all parameters

### Steps

---

#### 8.1–8.9 — Write all kernel hardening parameters

All parameters are written to a single drop-in file. The `99-` prefix ensures it loads last across all `sysctl.d` drop-ins, giving these values the highest precedence over any provider defaults.

```bash
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# ============================================================
# Network hardening
# ============================================================

# 8.1 — IP forwarding disabled (not a router)
net.ipv4.ip_forward = 0

# 8.2 — ICMP redirects disabled (prevents routing table manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# 8.3 — Source routing disabled (used almost exclusively for spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# 8.4 — Reverse path filtering, strict mode (drops spoofed packets)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 8.5 — SYN cookies (mitigates SYN flood exhaustion)
net.ipv4.tcp_syncookies = 1

# 8.6 — Martian packet logging (visibility into spoofing attempts)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ============================================================
# Kernel hardening
# ============================================================

# 8.7 — Restrict kernel information exposure
# dmesg_restrict: prevents unprivileged users reading kernel ring buffer
# kptr_restrict=2: hides kernel symbol addresses from all userspace
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# 8.8 — Full ASLR + disable SUID core dumps
# randomize_va_space=2: full address space randomization
# suid_dumpable=0: no core dumps for SUID processes (may expose credentials)
kernel.randomize_va_space = 2
fs.suid_dumpable = 0

# 8.9 — Magic SysRq disabled (unnecessary privileged control path on a VPS)
kernel.sysrq = 0
EOF
```

---

#### 8.10 — Apply and verify all parameters

```bash
sysctl --system

# Spot-check applied values:
sysctl net.ipv4.ip_forward
sysctl net.ipv4.tcp_syncookies
sysctl kernel.randomize_va_space
sysctl kernel.dmesg_restrict
sysctl kernel.kptr_restrict
sysctl fs.suid_dumpable
sysctl kernel.sysrq
# Expected: all match values set above
```

---

### [Back to Top](#section-order)

---


## Section 9 — Filesystem Hardening

**Goal:** Restrict what can be executed and by whom on key filesystem paths, eliminate unnecessary privileged binaries, and lock critical configuration files against modification.

### Checklist

- [ ] **9.1** Harden `/tmp` — `noexec`, `nosuid`, `nodev`
- [ ] **9.2** Harden `/dev/shm` — `noexec`, `nosuid`, `nodev`
- [ ] **9.3** Harden `/proc` — restrict process visibility with `hidepid`
- [ ] **9.4** Audit and remove unnecessary SUID/SGID binaries
- [ ] **9.5** Sweep for world-writable files and directories
- [ ] **9.6** Apply `chattr +i` to immutable configuration files

### Steps

---

#### 9.1 — Harden `/tmp`

`/tmp` is world-writable by design. The `noexec`, `nosuid`, and `nodev` mount flags prevent an attacker with write access from executing staged binaries. On Debian 13, `/tmp` is managed by systemd as a `tmpfs` mount — we override its options with a systemd drop-in rather than an fstab entry.

```bash
# Check how /tmp is currently mounted:
findmnt /tmp
# If Type is tmpfs — use the systemd drop-in below
# If Type is ext4/xfs — contact your provider; partition restructuring is out of scope

mkdir -p /etc/systemd/system/tmp.mount.d/
cat > /etc/systemd/system/tmp.mount.d/hardening.conf << 'EOF'
[Mount]
Options=mode=1777,strictatime,noexec,nosuid,nodev,size=50%
EOF

systemctl daemon-reload
systemctl restart tmp.mount

# Verify:
findmnt /tmp
# Expected options include: noexec, nosuid, nodev
```

---

#### 9.2 — Harden `/dev/shm`

`/dev/shm` is a shared memory filesystem — world-writable and abusable to stage and execute malicious code. This goes in `/etc/fstab` since it is not managed by a systemd unit.

```bash
cp /etc/fstab /etc/fstab.bak2

# Check if /dev/shm already has an fstab entry:
grep shm /etc/fstab

# If no entry exists, add one:
echo 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab

# If an entry already exists, edit it manually:
# nano /etc/fstab

# Remount immediately without reboot:
mount -o remount,noexec,nosuid,nodev /dev/shm

# Verify:
findmnt /dev/shm
```

---

#### 9.3 — Harden `/proc` with `hidepid`

By default every user can browse `/proc` and see all running processes — including command line arguments which frequently contain credentials or tokens. `hidepid=2` restricts `/proc/<pid>` entries so each user can only see their own processes.

```bash
# Guide variables — re-export if reconnected:
source /root/setup_variables.sh

# Create a dedicated group for processes that need full /proc visibility:
groupadd -r procadmin
usermod -aG procadmin "$VPS_USER"

# Add to fstab:
grep -q 'hidepid' /etc/fstab || \
	echo 'proc /proc proc defaults,hidepid=2,gid=procadmin 0 0' >> /etc/fstab

# Remount immediately:
mount -o remount,hidepid=2,gid=procadmin /proc

# Verify:
findmnt /proc
```

> Some systemd services read `/proc` entries of other processes during startup. If any service fails after applying `hidepid=2`, add it to the `procadmin` group:
> ```bash
> usermod -aG procadmin systemd-logind 2>/dev/null || true
> usermod -aG procadmin polkitd				2>/dev/null || true
> ```

---

#### 9.4 — Audit SUID/SGID binaries

Every unnecessary SUID binary is a potential privilege escalation path. Review the full list and remove the bit from anything that does not need it.

```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
	2>/dev/null | tee /root/suid-sgid-baseline.txt

# Common legitimate SUID binaries on Debian (keep these):
# /usr/bin/passwd, /usr/bin/su, /usr/bin/sudo, /usr/bin/newgrp
# /usr/bin/chsh, /usr/bin/chage, /usr/bin/ping
# /usr/sbin/unix_chkpwd, /usr/bin/gpasswd

# Remove SUID/SGID bit from anything not explicitly needed:
# chmod u-s /path/to/binary	 ← removes SUID
# chmod g-s /path/to/binary	 ← removes SGID
```

---

#### 9.5 — World-writable file sweep

Outside of intentional shared paths like `/tmp` and `/dev/shm`, world-writable files are a misconfiguration.

```bash
find / -xdev \
	-not \( -path '/tmp' -prune \) \
	-not \( -path '/dev/shm' -prune \) \
	-not \( -path '/proc' -prune \) \
	-not \( -path '/sys' -prune \) \
	-perm -0002 -type f 2>/dev/null \
	| tee /root/world-writable-baseline.txt

# Review and correct each entry:
# chmod o-w /path/to/file

# Also check world-writable directories:
find / -xdev \
	-not \( -path '/tmp' -prune \) \
	-not \( -path '/dev/shm' -prune \) \
	-not \( -path '/proc' -prune \) \
	-not \( -path '/sys' -prune \) \
	-perm -0002 -type d 2>/dev/null
```

---

#### 9.6 — Apply immutable flag to critical configs

The immutable flag prevents modification or deletion even by root until explicitly removed with `chattr -i`. Applied to files that should never change during normal operation.

`99-performance.conf` is created in Section 10 — a guard here skips it silently if not yet present. The definitive `chattr` for that file is in Section 10 after creation. AppArmor profile files are **not** made immutable — they must remain updateable by `apparmor_parser`.

```bash
chattr +i /etc/ssh/sshd_config
chattr +i /etc/ssh/banner
chattr +i /etc/sysctl.d/99-hardening.conf
chattr +i /etc/audit/rules.d/hardening.rules

# Guard — 99-performance.conf may not exist yet:
[ -f /etc/sysctl.d/99-performance.conf ] && \
	chattr +i /etc/sysctl.d/99-performance.conf

# Verify (the 'i' flag should be present):
lsattr /etc/ssh/sshd_config
lsattr /etc/sysctl.d/99-hardening.conf

# To temporarily modify any of these files later:
# chattr -i /path/to/file	→	make changes	→	chattr +i /path/to/file
```

---

### [Back to Top](#section-order)

---


## Section 10 — Performance Optimization

**Goal:** Allocate swap space equal to physical RAM and tune kernel memory management parameters for a general-purpose VPS workload.

### Checklist

- [ ] **10.1** Detect physical RAM size
- [ ] **10.2** Create, format, and activate swapfile using `dd`
- [ ] **10.3** Persist swapfile in `/etc/fstab`
- [ ] **10.4** Tune `vm.swappiness`
- [ ] **10.5** Tune dirty page ratios
- [ ] **10.6** Tune inode/dentry cache pressure
- [ ] **10.7** Apply, persist, and lock performance parameters

### Steps

---

#### 10.1 — Detect physical RAM size

```bash
RAM_MiB=$(free -m | awk '/^Mem:/{print $2}')
echo "Detected RAM: ${RAM_MiB} MiB — swapfile will be ${RAM_MiB}M"
```

---

#### 10.2 — Create, format, and activate swapfile

We use `dd` rather than `fallocate` — `fallocate` only reserves space without writing data, leaving previously deleted content in those blocks. A swapfile created with `fallocate` could expose old data when the kernel writes memory pages into those blocks. `dd` guarantees the swapfile is zeroed before it ever receives memory contents. Permissions must be `600` — a world-readable swapfile exposes memory contents to any local user.

```bash
dd if=/dev/zero of=/swapfile bs=1M count=${RAM_MiB} status=progress
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

# Verify:
swapon --show
free -h
```

---

#### 10.3 — Persist swapfile in `/etc/fstab`

`swapon` activates the swapfile for the current session only. The fstab entry ensures it mounts automatically on every boot.

```bash
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Verify:
grep swapfile /etc/fstab
```

---

#### 10.4–10.6 — Write performance sysctl parameters

- `vm.swappiness = 10` — default is 60; `10` tells the kernel to strongly prefer RAM over swap, only using swap under genuine memory pressure
- `vm.dirty_background_ratio = 5` — background flush starts at 5% dirty RAM, quietly without blocking processes
- `vm.dirty_ratio = 15` — at 15% dirty RAM, processes are forced to flush
- `vm.vfs_cache_pressure = 50` — default is 100; `50` favors keeping filesystem metadata (inode/dentry cache) longer, benefiting frequent directory lookups

```bash
cat > /etc/sysctl.d/99-performance.conf << 'EOF'
# ============================================================
# Memory management
# ============================================================

# 10.4 — Reduce swap aggressiveness
vm.swappiness = 10

# 10.5 — Dirty page flush thresholds
vm.dirty_background_ratio = 5
vm.dirty_ratio = 15

# 10.6 — Favor keeping inode/dentry cache
vm.vfs_cache_pressure = 50
EOF
```

---

#### 10.7 — Apply, persist, and lock parameters

```bash
sysctl --system

# Verify applied values:
sysctl vm.swappiness
sysctl vm.dirty_background_ratio
sysctl vm.dirty_ratio
sysctl vm.vfs_cache_pressure

# Mark immutable now that the file exists (definitive step — also guarded in Section 9.6):
chattr +i /etc/sysctl.d/99-performance.conf
lsattr /etc/sysctl.d/99-performance.conf
```

---

### [Back to Top](#section-order)

---


## Section 11 — Intrusion Detection System

**Goal:** Establish a cryptographic baseline of the filesystem after hardening is complete. Any unexpected file modification, addition, or deletion is detectable on subsequent checks.

### Resource Profile

| Operation			| Duration	| RAM Usage	| CPU			| Disk I/O		|
| ----------------- | --------- | --------- | ------------- | ------------- |
| `aide --init`		| 2–5 min	| ~80–120MB	| 100% (1 core) | Heavy read	|
| `aide --check`	| 1–3 min	| ~60–90MB	| 100% (1 core) | Heavy read	|
| Idle				| —			| 0			| 0				| None			|

All scans run with `nice -n 19 ionice -c 3` to minimize impact on live services.

### Checklist

- [ ] **11.1** Configure AIDE to monitor only high-value paths
- [ ] **11.2** Build the initial AIDE database (`--init`)
- [ ] **11.3** Move database to active location
- [ ] **11.4** Run a baseline check to confirm database integrity
- [ ] **11.5** Create a resource-conscious check script
- [ ] **11.6** Schedule periodic checks via `cron`

### Steps

---

#### 11.1 — Configure AIDE monitoring scope

On Debian 13, AIDE's config lives at `/etc/aide/aide.conf`. AIDE also processes all files in `/etc/aide/aide.conf.d/` in addition to the main config — drop-ins from installed packages may re-add paths you exclude. Review them and empty any conflicting ones before building the database.

Two attribute policies are defined. `NORMAL` is a full integrity check including inode. `BOOT` is identical but omits inode checking — used for `/boot` because the EFI partition uses FAT32, which generates synthetic inode numbers that change on every remount regardless of file content. `xattrs` is used instead of `selinux` — Debian uses AppArmor which does not store labels as SELinux xattrs.

```bash
cp /etc/aide/aide.conf /etc/aide/aide.conf.bak

# Check for drop-in configs that may re-add excluded paths:
ls /etc/aide/aide.conf.d/
# Review each file — empty any that conflict with exclusions below:
# echo '' > /etc/aide/aide.conf.d/<conflicting-file>

cat > /etc/aide/aide.conf << 'EOF'
# AIDE configuration — Debian 13, resource-conscious, high-value paths only

# Database locations
database_in=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz
database_new=file:/var/lib/aide/aide.db.new.gz
gzip_dbout=yes

# Suppress stribog (GOST) warnings from GnuTLS
database_attrs=sha256+sha512+md5+sha1+rmd160

# Report output
report_url=file:/var/log/aide/aide.log
report_url=stdout

# ============================================================
# Attribute policies
# ============================================================

# Full integrity check including inode
# xattrs used — Debian uses AppArmor (no SELinux xattrs)
NORMAL = sha256+sha512+ftype+p+i+n+u+g+s+acl+xattrs

# No inode checking — for FAT32 /boot which generates synthetic inodes
BOOT = sha256+sha512+ftype+p+n+u+g+s+acl+xattrs

# ============================================================
# Monitored paths
# ============================================================
/boot				BOOT
/bin				NORMAL
/sbin				NORMAL
/usr/bin			NORMAL
/usr/sbin			NORMAL
/lib/modules		NORMAL
/root				NORMAL
/etc				NORMAL

# ============================================================
# Exclusions within monitored paths
# ============================================================
!/etc/mtab
!/etc/aide/aide.conf
!/etc/resolv.conf
!/var/log
!/var/spool
!/var/cache
!/proc
!/sys
!/tmp
!/dev/shm
!/run

# Volatile root home files
!/root/.lesshst
!/root/.zsh_history
!/root/.bash_history
!/root/.zsh_sessions
EOF

mkdir -p /var/log/aide
chmod 700 /var/log/aide
```

---

#### 11.2 — Build the initial AIDE database

> ⚠️ Run this only after **all** hardening sections are complete. The database captures the current state as the trusted baseline — any change made after `--init` will appear as a false alert on the next check.

```bash
nice -n 19 ionice -c 3 aide --config=/etc/aide/aide.conf --init
# Takes 2–5 minutes with pegged vCPU — expected behaviour
```

---

#### 11.3 — Activate the database

AIDE writes to `aide.db.new.gz` and will not use it for checks until renamed — preventing automatic trust of an unreviewed database.

```bash
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

---

#### 11.4 — Run a baseline integrity check

```bash
nice -n 19 ionice -c 3 aide --config=/etc/aide/aide.conf --check
# Expected: AIDE found no differences between database and filesystem.
# Any output beyond this should be investigated before proceeding.
```

---

#### 11.5 — Create a resource-conscious check script

```bash
cat > /usr/local/bin/aide-check << 'EOF'
#!/bin/bash
# AIDE integrity check — resource-conscious wrapper

LOG=/var/log/aide/aide-check.log
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "========================================" >> "$LOG"
echo "AIDE check started: $TIMESTAMP"			>> "$LOG"
echo "========================================" >> "$LOG"

nice -n 19 ionice -c 3 aide --config=/etc/aide/aide.conf --check >> "$LOG" 2>&1
EXIT_CODE=$?

echo "Exit code: $EXIT_CODE" >> "$LOG"
echo "AIDE check finished: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"

# AIDE exit codes are a bitmask:
# 0 = no differences
# 1 = added files
# 2 = removed files
# 4 = changed files
# 8+ = errors during execution
if [ $EXIT_CODE -eq 0 ]; then
	echo "RESULT: CLEAN — no changes detected"	>> "$LOG"
elif [ $((EXIT_CODE & 8)) -ne 0 ] || [ $EXIT_CODE -ge 16 ]; then
	echo "RESULT: ERROR — AIDE encountered a problem (exit code: $EXIT_CODE)"	>> "$LOG"
else
	echo "RESULT: CHANGES DETECTED — review log (exit code: $EXIT_CODE)"		>> "$LOG"
fi
EOF

chmod 700 /usr/local/bin/aide-check
chown root:root /usr/local/bin/aide-check
```

---

#### 11.6 — Schedule periodic checks via `cron`

```bash
# Every Monday at 3:00 AM:
echo '0 3 * * 1 root /usr/local/bin/aide-check' \
	> /etc/cron.d/aide-check

chmod 644 /etc/cron.d/aide-check

# Verify:
cat /etc/cron.d/aide-check

# Run once manually to confirm the script works and to seed the log:
/usr/local/bin/aide-check
tail -5 /var/log/aide/aide-check.log
# Expected last line: RESULT: CLEAN — no changes detected
```

> **After intentional changes:** Rebuild the database after any deliberate modification to a monitored file:
> ```bash
> nice -n 19 ionice -c 3 aide --config=/etc/aide/aide.conf --update
> mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
> ```
> Habit: **change → verify → update database**.

---

### [Back to Top](#section-order)

---


## Section 12 — Maintenance Hygiene

**Goal:** Establish the operational habits that keep the hardened system hardened over time. A well-configured VPS degrades without a consistent maintenance rhythm.

### Checklist

- [ ] **12.1** Define snapshot discipline
- [ ] **12.2** Establish a weekly review routine
- [ ] **12.3** Establish a monthly review routine
- [ ] **12.4** Create a periodic hardening health-check script
- [ ] **12.5** Document your rollback procedure

### Steps

---

#### 12.1 — Snapshot discipline

A snapshot taken before any significant change gives you a clean rollback point. **Snapshot first, change second** — always.

Recommended triggers: before any `apt upgrade` that includes kernel packages, before installing any new service, before modifying any hardening configuration, before running an AIDE database update.

```bash
# Manual step at your VPS provider's control panel.
# Label snapshots with date and reason:
# e.g., "2025-05-01 pre-kernel-upgrade"
```

---

#### 12.2 — Weekly review

Short, focused checks covering `fail2ban` ban activity, AIDE check results, and a brief auth log scan. Should take under 10 minutes.

```bash
echo "=== fail2ban: banned IPs ==="
fail2ban-client status sshd

echo "=== AIDE: last check result ==="
tail -20 /var/log/aide/aide-check.log

echo "=== Auth log: recent sudo and SSH events ==="
ausearch -k privilege_escalation -ts today 2>/dev/null | aureport --summary
journalctl _COMM=sshd --since "7 days ago" | grep -i 'failed\|accepted\|invalid'

echo "=== AppArmor: any new denials ==="
journalctl -k --grep='apparmor="DENIED"' --since "7 days ago" | head -20
```

---

#### 12.3 — Monthly review

Deeper checks covering open ports, running services, `auditd` summary, disk usage, and package drift.

```bash
echo "=== Open ports ==="
ss -tlnp

echo "=== Network state ==="
networkctl status
firewall-cmd --zone=public --list-all

echo "=== Running services ==="
systemctl list-units --type=service --state=running

echo "=== Auditd monthly summary ==="
aureport --summary \
	--start "$(date -d '1 month ago' '+%m/%d/%Y')" \
	--end	 "$(date '+%m/%d/%Y')"

echo "=== Disk usage ==="
df -h
du -sh /var/log/audit/
du -sh /var/log/journal/

echo "=== Package update drift ==="
apt update -qq
apt-show-versions | grep -v 'uptodate'

echo "=== Pending non-security updates ==="
apt-get --just-print upgrade 2>/dev/null | grep '^Inst' | head -20

echo "=== debsums drift ==="
debsums -c 2>/dev/null

echo "=== World-writable files drift ==="
find / -xdev \
	-not \( -path '/tmp' -prune \) \
	-not \( -path '/dev/shm' -prune \) \
	-not \( -path '/proc' -prune \) \
	-not \( -path '/sys' -prune \) \
	-perm -0002 -type f 2>/dev/null

echo "=== New SUID/SGID binaries since baseline ==="
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
	| diff /root/suid-sgid-baseline.txt - 2>/dev/null \
	| grep '^>'
```

---

#### 12.4 — System health-check script

Runs key verification commands from every section and produces a concise pass/fail report. Run after every reboot or provider maintenance window.

```bash
# Guide variables — re-export if reconnected:
source /root/setup_variables.sh

cat > /usr/local/bin/system-health-check << EOF
#!/bin/bash
# System Posture Health Check
# Target OS: Debian 13
# Written by: Danang Galuh Tegar Prasetyo
#             https://github.com/danang-id

PASS="\e[32mPASS\e[0m"
FAIL="\e[31mFAIL\e[0m"
VPS_USER="${VPS_USER}"
VPS_SSH_PORT="${VPS_SSH_PORT}"

check() {
	local label="\$1"
	local result="\$2"
	local expected="\$3"
	if echo "\$result" | grep -qE "\$expected"; then
	echo -e "[\$PASS] \$label"
	else
	echo -e "[\$FAIL] \$label"
	echo "	Got: \$result"
	fi
}

echo "================================================"
echo " System Health Check — \$(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================"

# Section 1 — OS Baseline
check "timesyncd active"			"\$(systemctl is-active systemd-timesyncd)"						"active"
check "unattended-upgrades on"		"\$(systemctl is-enabled unattended-upgrades)"					"enabled"
check "hostname in /etc/hosts"		"\$(grep -c "\$(hostname)" /etc/hosts)"							"[1-9]"

# Section 2 — User & Auth
check "root SSH login blocked"		"\$(sshd -T | grep permitrootlogin)"							"no"
check "user password locked"		"\$(passwd -S \$VPS_USER | awk '{print \$2}')"					"L"
check "user in sudo group"			"\$(groups \$VPS_USER)"											"sudo"
check "sudo rootpw configured"		"\$(cat /etc/sudoers.d/\$VPS_USER 2>/dev/null)"					"rootpw"
check "PAM faillock success=2"		"\$(grep pam_unix /etc/pam.d/common-auth)"						"success=2"

# Section 3 — SSH
check "sshd running"				"\$(systemctl is-active sshd)"									"active"
check "sshd on correct port"		"\$(ss -tlnp | grep sshd)"										"\${VPS_SSH_PORT}"
check "PasswordAuth off"			"\$(sshd -T | grep passwordauthentication)"						"no"
check "KbdInteractive off"			"\$(sshd -T | grep kbdinteractiveauthentication)"				"no"
check "UsePAM enabled"				"\$(sshd -T | grep usepam)"										"yes"
check "fail2ban running"			"\$(systemctl is-active fail2ban)"								"active"

# Section 4 — Network & Firewall
check "systemd-networkd active"		"\$(systemctl is-active systemd-networkd)"						"active"
check "systemd-resolved active"		"\$(systemctl is-active systemd-resolved)"						"active"
check "legacy networking masked"	"\$(systemctl is-enabled networking 2>/dev/null)"				"masked"
check "firewalld running"			"\$(systemctl is-active firewalld)"								"active"
check "SSH port open"				"\$(firewall-cmd --zone=public --list-ports)"					"\${VPS_SSH_PORT}"

# Section 6 — AppArmor
check "AppArmor module loaded"		"\$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)"	"Y"
check "AppArmor service active"		"\$(systemctl is-active apparmor)"								"active"

SSH_DENIALS=\$(journalctl -k --grep='apparmor="DENIED".*sshd' 2>/dev/null | wc -l)
if [ "\$SSH_DENIALS" -eq 0 ]; then
	echo -e "[\$PASS] No AppArmor sshd denials"
else
	echo -e "[\$FAIL] AppArmor sshd denials found: \$SSH_DENIALS"
fi

# Section 7 — Audit & Logging
check "auditd running"				"\$(systemctl is-active auditd)"								"active"
check "auditd rules loaded"			"\$(auditctl -l | wc -l)"										"[1-9]"
check "journald persistent"			"\$(journalctl --disk-usage | grep 'Archived')"					"M|G"

# Section 8 — Kernel hardening
check "ip_forward disabled"			"\$(sysctl -n net.ipv4.ip_forward)"								"0"
check "SYN cookies enabled"			"\$(sysctl -n net.ipv4.tcp_syncookies)"							"1"
check "ASLR enabled"				"\$(sysctl -n kernel.randomize_va_space)"						"2"
check "dmesg restricted"			"\$(sysctl -n kernel.dmesg_restrict)"							"1"

# Section 9 — Filesystem
check "/tmp noexec"					"\$(findmnt /tmp		 | grep noexec)"						"noexec"
check "/dev/shm noexec"				"\$(findmnt /dev/shm | grep noexec)"							"noexec"

# Section 10 — Performance
check "swap active"					"\$(swapon --show | grep swapfile)"								"swapfile"
check "swappiness at 10"			"\$(sysctl -n vm.swappiness)"									"10"

# Section 11 — AIDE
check "AIDE database exists"		"\$(ls /var/lib/aide/aide.db.gz 2>/dev/null)"					"aide.db.gz"
check "AIDE cron scheduled"			"\$(cat /etc/cron.d/aide-check 2>/dev/null)"					"aide-check"

echo "================================================"
echo " Check complete"
echo "================================================"
EOF

chmod 700 /usr/local/bin/system-health-check
chown root:root /usr/local/bin/system-health-check

# Run immediately to confirm baseline passes:
/usr/local/bin/system-health-check
```

---

#### 12.5 — Document your rollback procedure

```bash
cat > /root/ROLLBACK.md << 'EOF'
# VPS Rollback Procedure

## Provider snapshot restore
1. Log in to provider control panel
2. Navigate to: [your VPS > Snapshots]
3. Select snapshot labeled with date and reason
4. Click Restore — confirm when prompted
5. Wait for restore to complete (typically 2–5 minutes)
6. SSH in to verify

## After restore — verify hardening posture
/usr/local/bin/harden-check

## If SSH is unreachable after restore
1. Use provider console (web-based VNC/serial)
2. Log in as the rootless user
3. Check sshd:						sudo systemctl status sshd
4. Check firewall:				sudo firewall-cmd --list-ports
5. Check network:				 networkctl status
6. Check AppArmor:				sudo systemctl status apparmor && sudo aa-status

## Emergency: if locked out completely
1. Provider console → log in as the rootless user
2. sudo systemctl restart sshd
3. If sshd fails: sudo aa-complain /etc/apparmor.d/usr.sbin.sshd → restart → diagnose → re-enforce
EOF

chmod 600 /root/ROLLBACK.md
echo "Rollback procedure written to /root/ROLLBACK.md"

# ROLLBACK.md was created after AIDE --init — update the database:
nice -n 19 ionice -c 3 aide --config=/etc/aide/aide.conf --update
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "AIDE database updated to include ROLLBACK.md"
```

---

### [Back to Top](#section-order)

---


## Quick Reference — Section Execution Order

Run sections in this exact order. Do not skip ahead.

```
1	→ OS Baseline				(updates, essentials, unattended-upgrades)
2	→ User & Auth				(create user, lock root)
3	→ SSH Hardening				(keys, authorized_keys ownership, sshd_config, client config, fail2ban)
4	→ Network & Firewall		(firewalld baseline, migrate to systemd-networkd, harden)
5	→ Package Integrity			(APT GPG re-audit, debsums, apt-show-versions)
6	→ AppArmor					(confirm loaded, audit profiles and denials)
7	→ Audit & Logging			(auditd rules, journald persistent)
8	→ Kernel Hardening			(sysctl security)
9	→ Filesystem Hardening		(tmp/shm/proc, SUID sweep, chattr)
10  → Performance				(swapfile, sysctl performance)
11  → AIDE						(init database LAST — after all changes)
12  → Maintenance Hygiene		(scripts, cron, rollback doc)
```

> ⚠️ **AIDE `--init` must be the final hardening action.** The database captures the trusted baseline state — any change made after `--init` will appear as a false alert on the next check.

### [Back to Top](#section-order)
