# VPS Hardening Guide (AlmaLinux-10)

| &nbsp; | &nbsp; |
| --- | --- |
| **Target OS** | AlmaLinux 10.1+ (Heliotrope Lion) |
| **Guide Version** | AlmaLinux-10-Rev-0 |

## Contextual Preamble

### Prerequisites

- Root SSH access to the VPS
- VPS provider snapshot capability (take one before starting)
- An SSH key pair ready on your local machine (or generate one in Section 3)

### Out of Scope

- Partition restructuring on live systems
- Service-specific hardening (Nginx, Postfix, MariaDB, etc.)
- Container / Docker hardening
- Cloud provider security group configuration
- Multi-user access policies
- Port knocking (noted as optional escalation in Section 3, not prescribed)


## Section Order

| # | Section |
|---|---------|
| 1 | [Operating System Baseline](#section-1--operating-system-baseline) |
| 2 | [User & Authentication](#section-2--user--authentication) |
| 3 | [Secure Shell (SSH)](#section-3--secure-shell-ssh) |
| 4 | [Firewall](#section-4--firewall) |
| 5 | [Package Integrity](#section-5--package-integrity) |
| 6 | [Mandatory Access Control (MAC)](#section-6--mandatory-access-control-mac) |
| 7 | [Logging & Audit](#section-7--logging--audit) |
| 8 | [Kernel Hardening](#section-8--kernel-hardening) |
| 9 | [Filesystem Hardening](#section-9--filesystem-hardening) |
| 10 | [Performance Optimization](#section-10--performance-optimization) |
| 11 | [Intrusion Detection System](#section-11--intrusion-detection-system) |
| 12 | [Maintenance Hygiene](#section-12--maintenance-hygiene) |

---

## Section 1 — Operating System Baseline

> Goal: Start from the leanest, most up-to-date system state possible. Every unnecessary package or service is an unmonitored attack surface.

### Checklist

- [ ] **1.1** Set correct hostname
- [ ] **1.2** Set correct timezone
- [ ] **1.3** Configure local Indonesian mirror
- [ ] **1.4** Verify `gpgcheck` is enabled, then apply all pending updates
- [ ] **1.5** Enable EPEL repository
- [ ] **1.6** Install essential baseline packages
- [ ] **1.7** Install `dnf-automatic` and enable security-only auto-updates
- [ ] **1.8** Remove known bloat packages
- [ ] **1.9** Disable and stop unused services
- [ ] **1.10** Verify `chrony` is running

### Rationale

**1.1 — Hostname**  
A meaningful hostname prevents confusion in logs. AlmaLinux 10 defaults to `localhost` — every log entry will be ambiguous if you ever cross-reference across machines.

**1.2 — Timezone**  
Set to your actual operational timezone. Mismatched timezones corrupt log correlation. `UTC` is acceptable and often preferred for servers managed across regions.

**1.3 — Local Indonesian mirror (`cermin.rumahweb.id`)**  
Cermin Rumahweb is operated by Rumahweb Indonesia, a major Indonesian hosting company. It is not listed as an official AlmaLinux mirror but carries AlmaLinux 10 BaseOS, AppStream, Extras, and CRB, as well as EPEL 10 — making it the only Indonesian source that covers both in a single mirror. All packages remain GPG-verified against AlmaLinux's and Fedora's respective signing keys regardless of which server delivers them — the mirror's unofficial status does not weaken the verification chain. HTTPS is supported and used throughout. Configuring this mirror before any `dnf` operation ensures all package downloads route domestically over Jetorbit's local peering.

**1.4 — GPG check + full update**  
Before running any `dnf` operation, confirm `gpgcheck=1` is set globally and per-repo — every package must be verified against its GPG key before installation. A full update must then run before any hardening step: hardening built on top of unpatched packages is built on a weak foundation. Reboot afterward if the kernel was updated.

**1.5 — Extra Packages for Enterprise Linux (EPEL)**  
The Extra Packages for Enterprise Linux repo is maintained by the Fedora project and is the standard source for packages not in AlmaLinux base repos. `fail2ban` (Section 3) and `aide` (Section 11) both require it. Enable it early so later sections don't hit missing dependency errors. After installation, the EPEL repo is redirected to `cermin.rumahweb.id` which carries EPEL 10 — keeping all package downloads on the same local Indonesian mirror.

**1.6 — Install essentials packages**  
Your VPS provider's AlmaLinux image does not ship with `nano`, `zsh`, `firewalld`, `fail2ban`, `auditd`, or `policycoreutils-python-utils`. On AlmaLinux 10, the audit toolchain is split across two packages: `audit` provides the `auditd` daemon, while `audit-rules` provides the CLI tools (`auditctl`, `augenrules`, `ausearch`, `aureport`). Both must be installed. Installing everything the guide depends on upfront in one pass makes the guide fully script-friendly — a single bootstrap run installs all prerequisites before any configuration begins.

**1.7 — `dnf-automatic` (security only)**  
Manually tracking CVEs is not realistic for a solo operator. `dnf-automatic` in security-only mode applies patches automatically without pulling in feature updates that could break running services. It logs what it applied — you stay informed without babysitting it.

**1.8 — Package removal**  
Packages with no purpose are packages that can have vulnerabilities. Common targets: `telnet`, `rsh`, `ypbind`, `rpcbind` (if not using NFS), `avahi-daemon`, `cups`.

**1.9 — Unused services**  
A stopped and disabled service cannot be exploited. Audit with `systemctl list-units --type=service --state=running` and be deliberate about everything that's active.

**1.10 — `chrony`**  
Already default on AlmaLinux — verify it's running and synced. Accurate time is not optional: TLS certificate validation, `auditd` timestamps, `fail2ban` log parsing all depend on it.

### Scriptable Commands

```bash
# --- 1.1 Set hostname ---
hostnamectl set-hostname your-hostname
# Verify:
hostnamectl status

# --- 1.2 Set timezone ---
timedatectl set-timezone Asia/Jakarta  # adjust to your zone
# Verify:
timedatectl status

# --- 1.3 Configure local Indonesian mirror ---
# Mirror: cermin.rumahweb.id (Rumahweb Indonesia)
# Covers: AlmaLinux 10 BaseOS, AppStream, Extras, CRB + EPEL 10
# Protocol: HTTPS

# Test mirror reachability before committing:
curl -o /dev/null -s -w "HTTP %{http_code} — Time: %{time_total}s\n" \
  https://cermin.rumahweb.id/almalinux/10/BaseOS/x86_64/os/repodata/repomd.xml
# Expected: HTTP 200 — Time: <1s
# If unreachable, skip this step and proceed with default mirrorlist

# Backup default repo files:
cp -r /etc/yum.repos.d /etc/yum.repos.d.original.bak

# For each AlmaLinux repo file: comment out mirrorlist/baseurl and inject local mirror
for repo_file in /etc/yum.repos.d/almalinux*.repo; do
  sed -i 's|^mirrorlist=|#mirrorlist=|g' "$repo_file"
  sed -i 's|^baseurl=|#baseurl=|g'      "$repo_file"
done

# Inject local mirror baseurl per repo section:
sed -i '/^\[baseos\]/a baseurl=https://cermin.rumahweb.id/almalinux/$releasever/BaseOS/$basearch/os/' \
  /etc/yum.repos.d/almalinux-baseos.repo 2>/dev/null || true

sed -i '/^\[appstream\]/a baseurl=https://cermin.rumahweb.id/almalinux/$releasever/AppStream/$basearch/os/' \
  /etc/yum.repos.d/almalinux-appstream.repo 2>/dev/null || true

sed -i '/^\[extras\]/a baseurl=https://cermin.rumahweb.id/almalinux/$releasever/extras/$basearch/os/' \
  /etc/yum.repos.d/almalinux-extras.repo 2>/dev/null || true

sed -i '/^\[crb\]/a baseurl=https://cermin.rumahweb.id/almalinux/$releasever/CRB/$basearch/os/' \
  /etc/yum.repos.d/almalinux-crb.repo 2>/dev/null || true

# Verify local mirror is in place:
grep -h 'baseurl' /etc/yum.repos.d/almalinux*.repo | grep cermin
# Expected: all base repos showing cermin.rumahweb.id

# Clean metadata and verify repos load correctly:
dnf clean all
dnf repolist
# All AlmaLinux base repos should appear as enabled

# --- 1.4 Verify gpgcheck, then full system update ---
# Confirm GPG checking is enabled globally:
grep 'gpgcheck' /etc/dnf/dnf.conf
# Expected: gpgcheck=1
# If missing, add it:
grep -q '^gpgcheck=' /etc/dnf/dnf.conf || echo 'gpgcheck=1' >> /etc/dnf/dnf.conf

# Confirm GPG checking is enabled per-repo:
grep -r 'gpgcheck' /etc/yum.repos.d/
# Every repo block should have gpgcheck=1
# If any repo has gpgcheck=0, fix it:
# sed -i 's/gpgcheck=0/gpgcheck=1/' /etc/yum.repos.d/<offending-repo>.repo

# Run full update (downloads from cermin.rumahweb.id):
dnf update -y
# Reboot if kernel was updated:
# reboot

# --- 1.5 Enable EPEL and redirect to local mirror ---
dnf install -y epel-release

# Import EPEL 10 GPG key from local mirror:
rpm --import https://cermin.rumahweb.id/epel/RPM-GPG-KEY-EPEL-10

# Redirect EPEL repo to cermin.rumahweb.id:
sed -i 's|^metalink=|#metalink=|g'    /etc/yum.repos.d/epel.repo
sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/epel.repo
sed -i 's|^baseurl=|#baseurl=|g'      /etc/yum.repos.d/epel.repo
sed -i '/^\[epel\]/a baseurl=https://cermin.rumahweb.id/epel/10/Everything/$basearch/' \
  /etc/yum.repos.d/epel.repo

# Verify:
grep 'baseurl' /etc/yum.repos.d/epel.repo
# Expected: cermin.rumahweb.id/epel/10/Everything/...

dnf clean all
dnf repolist
# EPEL should appear with cermin.rumahweb.id as source

# --- 1.6 Install essential packages ---
dnf install -y \
  nano \
  zsh \
  firewalld \
  fail2ban \
  audit \
  audit-rules \
  aide \
  policycoreutils-python-utils

# --- 1.7 dnf-automatic (security only) ---
dnf install -y dnf-automatic

sed -i 's/^upgrade_type.*/upgrade_type = security/'  /etc/dnf/automatic.conf
sed -i 's/^apply_updates.*/apply_updates = yes/'      /etc/dnf/automatic.conf
sed -i 's/^emit_via.*/emit_via = stdio/'              /etc/dnf/automatic.conf

systemctl enable --now dnf-automatic-install.timer
# Verify:
systemctl status dnf-automatic-install.timer

# --- 1.8 Remove bloat packages ---
dnf remove -y telnet rsh ypbind rpcbind avahi-daemon cups 2>/dev/null || true

# --- 1.9 Audit running services (manual review step) ---
systemctl list-units --type=service --state=running
# Disable anything not intentionally needed:
# systemctl disable --now <service-name>

# --- 1.10 Verify chrony ---
systemctl enable --now chronyd
chronyc tracking
# Confirm "System time" offset is small — indicates active sync
```

> **Fallback:** If `cermin.rumahweb.id` is unreachable on first run, restore defaults and proceed with the original mirrorlist:
> ```bash
> rm -rf /etc/yum.repos.d && cp -r /etc/yum.repos.d.original.bak /etc/yum.repos.d
> dnf clean all
> ```

### [Back to Top](#section-order)

---

## Section 2 — User & Authentication

> Goal: Eliminate root as an operable account. All human access flows through `dan` with a password and sudo. Root becomes a locked, inert account.

### Checklist

- [ ] **2.1** Create user `dan` with a strong password
- [ ] **2.2** Add `dan` to the `wheel` group (sudo access)
- [ ] **2.3** Verify `wheel` group is enabled in `sudoers`
- [ ] **2.4** Set secure `umask` system-wide and for `dan`
- [ ] **2.5** Set `zsh` as default shell for `dan` and `root`
- [ ] **2.6** Install oh-my-zsh for `root`
- [ ] **2.7** Install oh-my-zsh for `dan`
- [ ] **2.8** Configure `fino-time` theme and `umask` in `.zshrc` for both users
- [ ] **2.9** Lock the root account
- [ ] **2.10** Harden PAM — limit login attempts via `pam_faillock`
- [ ] **2.11** Enforce password quality policy via `pwquality`

### Rationale

**2.1 & 2.2 — Create `dan` and add to `wheel`**  
The VPS arrives with only a root account. Before locking root (2.9), `dan` must exist and be fully operational — including sudo access. **Do not lock root before verifying `dan` can sudo.** Doing it in the wrong order will lock you out of your own server.

**2.3 — Verify `wheel` in sudoers**  
AlmaLinux enables the `wheel` group in `/etc/sudoers` by default, but it's worth confirming. The line `%wheel ALL=(ALL) ALL` must be uncommented and active. We use the `wheel` group rather than a direct `sudoers` entry for `dan` — it's cleaner and easier to audit.

**2.4 — `umask 027`**  
The default `umask 022` creates files readable by all users. `027` restricts new files to owner read/write, group read-only, and no access for others. Applied system-wide via `/etc/profile` — this covers both bash and zsh login shells. Per-user `.zshrc` entries are added in step 2.8 to also cover interactive non-login zsh sessions.

**2.5 — Set zsh as default shell**  
`chsh -s /bin/zsh` updates `/etc/passwd` to set zsh as the login shell for both `dan` and `root`. Root's shell is set here even though the account is locked in step 2.9 — when you access root via `sudo -i` or `sudo su` from `dan`, you get root's configured shell. Having zsh consistently for both users avoids switching environments mid-session.

**2.6 & 2.7 — Install oh-my-zsh**  
oh-my-zsh is installed via its official `install.sh` script fetched over HTTPS from GitHub. The `--unattended` flag suppresses interactive prompts — it does not change the default shell (we handle that in 2.5) and does not launch zsh immediately. We install for `root` first while operating as root, then for `dan` using `sudo -u dan` to ensure oh-my-zsh is correctly owned by and configured for each user separately. Both users get their own independent `~/.oh-my-zsh/` installation and `~/.zshrc`.

**2.8 — Configure `fino-time` theme and `umask`**  
`fino-time` is a built-in oh-my-zsh theme — no additional download or plugin needed. It displays a clean prompt with the current time, username, host, and working directory. We set it by replacing the default `ZSH_THEME` value in each user's `.zshrc`. We also append `umask 027` to each `.zshrc` here to cover interactive non-login zsh sessions where `/etc/profile` is not sourced.

**2.9 — Lock root (`passwd -l root`)**  
Once `dan` is confirmed working with sudo, root should be completely inert. `passwd -l` places a `!` prefix on the password hash in `/etc/shadow` — no authentication method can unlock it without going through `dan` first. One account, one audit trail.

**2.10 — PAM `pam_faillock`**  
The modern replacement for `pam_tally2`, standard on RHEL 9+/AlmaLinux 10. Tracks failed authentication attempts and temporarily locks an account after a threshold. Configuration: 5 failed attempts → 15 minute lockout. Applies to console and SSH password attempts (SSH key auth bypasses it by design, which is correct).

**2.11 — `pwquality`**  
Enforces password complexity when setting or changing passwords via `passwd`. Since `dan` uses a password for `sudo` prompts and console login, this matters. Minimum length 12, require mixed character classes, reject passwords too similar to the username.

### Scriptable Commands

```bash
# --- 2.1 Create user dan with password ---
useradd -m -s /bin/bash dan
passwd dan
# You will be prompted to enter and confirm a password interactively

# --- 2.2 Add dan to wheel group ---
usermod -aG wheel dan

# --- 2.3 Verify wheel is active in sudoers ---
grep -E '^\s*%wheel' /etc/sudoers
# Expected output: %wheel  ALL=(ALL)       ALL
# If commented out, uncomment it (never edit /etc/sudoers directly):
# visudo

# --- 2.4 Set umask 027 system-wide ---
echo 'umask 027' >> /etc/profile
# Covers all login shells (bash and zsh)
# Per-user .zshrc entries added in step 2.8 after oh-my-zsh creates the files

# --- 2.5 Set zsh as default shell for dan and root ---
chsh -s /bin/zsh root
chsh -s /bin/zsh dan
# Verify:
grep -E '^(root|dan):' /etc/passwd | cut -d: -f1,7
# Expected: root:/bin/zsh and dan:/bin/zsh

# --- 2.6 Install oh-my-zsh for root ---
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" \
  "" --unattended
# Installs to /root/.oh-my-zsh and creates /root/.zshrc
# Verify:
ls /root/.oh-my-zsh/

# --- 2.7 Install oh-my-zsh for dan ---
su - dan
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" \
  "" --unattended
exit
# Installs to /home/dan/.oh-my-zsh and creates /home/dan/.zshrc
# Verify:
ls /home/dan/.oh-my-zsh/

# --- 2.8 Configure fino-time theme and umask for both users ---
# Root:
sed -i 's/^ZSH_THEME=.*/ZSH_THEME="fino-time"/' /root/.zshrc
echo 'umask 027' >> /root/.zshrc

# Dan:
sed -i 's/^ZSH_THEME=.*/ZSH_THEME="fino-time"/' /home/dan/.zshrc
echo 'umask 027' >> /home/dan/.zshrc

# Verify theme is set:
grep 'ZSH_THEME' /root/.zshrc /home/dan/.zshrc
# Expected: ZSH_THEME="fino-time" in both files

# --- VERIFY dan can sudo BEFORE locking root ---
# Open a second SSH session and run: sudo whoami
# Expected output: root
# Only proceed to 2.9 after confirming this works

# --- 2.9 Lock root account ---
passwd -l root
# Verify (locked hash starts with '!'):
grep root /etc/shadow | cut -d: -f2

# --- 2.10 PAM faillock hardening ---
sed -i 's/^#\s*deny\s*=.*/deny = 5/'                  /etc/security/faillock.conf
sed -i 's/^#\s*unlock_time\s*=.*/unlock_time = 900/'  /etc/security/faillock.conf
sed -i 's/^#\s*fail_interval\s*=.*/fail_interval = 900/' /etc/security/faillock.conf
# Verify:
grep -E 'deny|unlock_time|fail_interval' /etc/security/faillock.conf

# --- 2.11 Password quality policy ---
sed -i 's/^#\s*minlen\s*=.*/minlen = 12/'       /etc/security/pwquality.conf
sed -i 's/^#\s*minclass\s*=.*/minclass = 3/'    /etc/security/pwquality.conf
sed -i 's/^#\s*maxrepeat\s*=.*/maxrepeat = 3/'  /etc/security/pwquality.conf
sed -i 's/^#\s*usercheck\s*=.*/usercheck = 1/'  /etc/security/pwquality.conf
# Verify:
grep -vE '^#|^$' /etc/security/pwquality.conf
```

> ⚠️ **Critical order warning:** Always confirm `dan` can `sudo whoami` successfully in a separate session before running step 2.9. A locked root account with a broken sudo setup means a full OS reinstall.

### [Back to Top](#section-order)

---

## Section 3 — Secure Shell (SSH)

> Goal: Make SSH access as narrow as possible. Only `dan` can connect, only via key authentication, on a non-standard port, with all unnecessary SSH features disabled and brute-force attempts automatically banned.

### Checklist

- [ ] **3.1** Generate an SSH key pair on your local machine
- [ ] **3.2** Deploy public key manually to `dan`'s authorized keys
- [ ] **3.3** Create SSH warning banner at `/etc/ssh/banner`
- [ ] **3.4** Harden `sshd_config`
- [ ] **3.5** Register port 32022 with SELinux
- [ ] **3.6** Configure `fail2ban` for SSH
- [ ] **3.7** Open port 32022 in firewall
- [ ] **3.8** Restart `sshd` and verify new connection before closing current session

### Rationale

**3.1 & 3.2 — Key pair and manual deployment**  
Key authentication is non-negotiable. A private key is computationally infeasible to brute-force. The public key lives on the server in `~/.ssh/authorized_keys` — the private key never leaves your local machine. `ed25519` is the correct algorithm choice: smaller, faster, and more secure than RSA 4096.

**3.3 — SSH warning banner**  
The banner is displayed to every client that connects to SSH, before authentication occurs. It serves two purposes: it makes clear that the system is monitored and that unauthorized access is prohibited, and it establishes the legal basis for action against unauthorized users. The banner is referenced in `sshd_config` via the `Banner` directive pointing to `/etc/ssh/banner`. Permissions are set to `644` — it must be world-readable for `sshd` to serve it to unauthenticated connections.

**3.4 — `sshd_config` hardening**  
The OpenSSH default config is permissive for compatibility reasons. Key changes:
- `Port 32022` — reduces automated scanner noise significantly
- `AddressFamily any` — accepts both IPv4 and IPv6 connections
- `Banner /etc/ssh/banner` — serves the warning banner before authentication
- `PermitRootLogin no` — root is locked anyway (Section 2.9), this adds a second layer
- `PasswordAuthentication no` — key-only, no fallback to passwords
- `AllowUsers dan` — explicit whitelist, no other account can SSH in even if it exists
- `MaxAuthTries 3` — limits attempts per connection before disconnect
- `LoginGraceTime 30` — closes unauthenticated connections after 30 seconds
- Disable `X11Forwarding`, `AllowAgentForwarding`, `AllowTcpForwarding` — unused features are closed features
- Restrict ciphers, MACs, and KexAlgorithms to modern vetted algorithms only

**3.5 — SELinux port registration**  
SELinux enforces which ports each service is allowed to bind on via type labels. By default, `ssh_port_t` only covers port 22. Attempting to restart `sshd` on port 32022 without registering it will cause the service to fail — SELinux silently denies the bind. This step must come **before** restarting `sshd`.

**3.6 — `fail2ban`**  
Even on a non-standard port with key-only auth, automated scanners will find port 32022 eventually. `fail2ban` watches `sshd` logs and bans IPs that exceed the failed attempt threshold via a `firewalld` rule. Configuration: 3 failed attempts → 1 hour ban.

**3.7 — Open firewall port before restarting SSH**  
If you restart `sshd` with port 32022 configured but the firewall doesn't allow it yet, you lock yourself out. Firewall rule comes first, always.

**3.8 — Verify before closing session**  
Never close your existing SSH session until you've confirmed a new session connects successfully on port 32022. If anything is misconfigured, your old session is the recovery lifeline.

> **Optional escalation — Port Knocking:** Port knocking keeps SSH completely invisible to scanners until a specific sequence of ports is knocked in order. A daemon (`knockd`) then temporarily opens the SSH port for your IP only. This is a step beyond the current setup if near-zero exposure is desired. It adds a lockout risk if the sequence or config is lost, so it is not prescribed in this guide but noted as an available escalation.

### Scriptable Commands

```bash
# --- 3.1 Generate key pair (run on your LOCAL machine, not the server) ---
ssh-keygen -t ed25519 -C "dan@your-hostname"
# Keys saved to: ~/.ssh/id_ed25519 (private) and ~/.ssh/id_ed25519.pub (public)

# --- 3.2 Deploy public key manually ---
# Run on the SERVER as root:
mkdir -p /home/dan/.ssh
chmod 700 /home/dan/.ssh
nano /home/dan/.ssh/authorized_keys
# Paste your id_ed25519.pub content, save and exit
chmod 600 /home/dan/.ssh/authorized_keys
chown -R dan:dan /home/dan/.ssh

# --- 3.3 Create SSH warning banner ---
cat > /etc/ssh/banner << 'EOF'
WARNING: Unauthorized access to this system is prohibited.
All activity is monitored and logged.
EOF

chmod 644 /etc/ssh/banner
# Verify:
cat /etc/ssh/banner

# --- 3.4 Harden sshd_config ---
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat > /etc/ssh/sshd_config << 'EOF'
# --- Port & Protocol ---
Port 32022
AddressFamily any

# --- Banner ---
Banner /etc/ssh/banner

# --- Authentication ---
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30

# --- Access Control ---
AllowUsers dan

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

# --- 3.5 Register port 32022 with SELinux ---
semanage port -a -t ssh_port_t -p tcp 32022
# Verify:
semanage port -l | grep ssh
# Expected: ssh_port_t   tcp   32022, 22
# However, to ensure default port 22 is blocked by SELinux, we must overwrite default policy of
# ssh_port_t tcp port 22 and remap that port to unreserved_port_t
semanage port -m -t unreserved_port_t -p tcp 22
# Verify locally customized policy:
semanage port -l -C
# Local custom policy will takes precedence over the built-in policy at enforcement time

# --- 3.6 Configure fail2ban for SSH ---
cat > /etc/fail2ban/jail.d/sshd.local << 'EOF'
[sshd]
enabled   = true
port      = 32022
filter    = sshd
backend   = systemd
maxretry  = 3
bantime   = 3600
findtime  = 600
banaction = firewallcmd-rich-rules
EOF

systemctl enable --now fail2ban
# Verify:
fail2ban-client status sshd

# --- 3.7 Open port 32022 in firewall ---
systemctl enable --now firewalld
firewall-cmd --permanent --add-port=32022/tcp
firewall-cmd --reload
# Verify:
firewall-cmd --list-ports

# --- 3.8 Restart sshd ---
systemctl restart sshd
systemctl status sshd

# ⚠️  KEEP THIS SESSION OPEN
# Open a NEW terminal and test:
# ssh -p 32022 -i ~/.ssh/id_ed25519 dan@your-server-ip
# Banner should appear before the password/key prompt
# Only close this session after confirming the new connection works
```

> ⚠️ **Critical order:** SELinux port registration (3.5) → firewall port (3.7) → restart `sshd` (3.8) → verify new session → close old session. Skipping or reordering 3.5 will cause `sshd` to fail on restart.

### [Back to Top](#section-order)

---

## Section 4 — Firewall

> Goal: Default-deny all inbound traffic. Only explicitly permitted ports are open. This section establishes the baseline firewall state — service-specific ports are added in their respective service guides layered on top of this one.

### Checklist

- [ ] **4.1** Verify `firewalld` is running and set to start on boot
- [ ] **4.2** Confirm the active zone is `public` and your interface is assigned to it
- [ ] **4.3** Remove default permitted services from the `public` zone
- [ ] **4.4** Confirm port 32022 is the only open port
- [ ] **4.5** Enable logging of denied traffic
- [ ] **4.6** Reload and verify final firewall state including IPv6 coverage

### Rationale

**4.1 — `firewalld` running state**  
`firewalld` was enabled in Section 3.6 as a prerequisite for SSH. This step confirms it's active and boot-enabled before further rule changes. Never modify firewall rules against a stopped daemon.

**4.2 — Active zone**  
`firewalld` uses zones to group interfaces with a trust level. The `public` zone assumes no trust of other hosts on the network — correct for an internet-facing VPS. Rules applied to the wrong zone have no effect on your actual traffic.

**Default zone policies in `public`:**
- **Input:** `DROP` — inbound traffic is dropped unless explicitly permitted
- **Output:** `ACCEPT` — all outbound traffic is allowed by default
- **Forward:** `DROP` — packet forwarding between interfaces is dropped

**4.3 — Remove default services**  
AlmaLinux's default `public` zone ships with `cockpit`, `dhcpv6-client`, and `ssh` permitted. None belong on a hardened VPS: `cockpit` is a web-based admin UI unnecessary if you manage via SSH; `dhcpv6-client` is not needed with static IPv6 assignment; `ssh` covers port 22 which we have replaced with port 32022 — leaving the default `ssh` service open would expose an unused port unnecessarily.

**4.4 — Port 32022 only**  
After removing defaults, port 32022/tcp from Section 3.6 should be the only open inbound path. Every other port is closed until a service guide explicitly opens it.

**4.5 — Denial logging**  
Enabling denial logging to `syslog` gives visibility into what's being blocked — useful during initial setup and periodic audits. The default DROP input policy already handles all unlisted inbound traffic; no additional ICMP drop rule is needed.

**4.6 — IPv6 coverage**  
With IPv6 active, confirm `firewalld` applies the same zone policy to the IPv6 stack. `firewalld` manages both `iptables`/`ip6tables` (or `nftables`) automatically — the same zone rules apply to both stacks. This step verifies that is the case.

### Scriptable Commands

```bash
# --- 4.1 Verify firewalld is running ---
systemctl enable --now firewalld
systemctl status firewalld

# --- 4.2 Confirm active zone and interface assignment ---
firewall-cmd --get-active-zones
# Expected output example:
# public
#   interfaces: eth0

# If your interface is not in the public zone, assign it:
# firewall-cmd --permanent --zone=public --change-interface=eth0
# firewall-cmd --reload

# --- 4.3 Remove default permitted services ---
firewall-cmd --permanent --zone=public --remove-service=cockpit
firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client
firewall-cmd --permanent --zone=public --remove-service=ssh
# ssh service covers port 22 — we use port 32022 exclusively (step 3.7)

# Verify nothing else is permitted:
firewall-cmd --permanent --zone=public --list-services
# Expected: (empty)

# --- 4.4 Confirm port 32022 is present (from Section 3.6) ---
firewall-cmd --permanent --zone=public --list-ports
# Expected: 32022/tcp

# If missing for any reason, re-add:
# firewall-cmd --permanent --zone=public --add-port=32022/tcp

# --- 4.5 Enable denial logging ---
firewall-cmd --set-log-denied=all

# --- 4.6 Reload and verify final state ---
firewall-cmd --reload

echo "=== Active Zones ==="
firewall-cmd --get-active-zones

echo "=== Show All Information ==="
firewall-cmd --zone=public --list-all

# Expected final state:
# Services  : (empty)
# Ports     : 32022/tcp
# Rich rules: (empty)

# Verify firewalld is managing IPv6:
firewall-cmd --info-zone=public | grep -i ipv
```

> **Note for service layering:** When adding services on top of this baseline, open only the exact ports needed:
> ```bash
> firewall-cmd --permanent --zone=public --add-port=<port>/tcp
> firewall-cmd --reload
> ```
> Never open port ranges or re-enable removed default services.

### [Back to Top](#section-order)

---

## Section 5 — Package Integrity

> Goal: Ensure every package on the system comes from a trusted, verified source. Untrusted or unverified packages are a direct supply chain attack vector.

### Checklist

- [ ] **5.1** Re-audit GPG signature checking across all repos (including EPEL and provider repos now present)
- [ ] **5.2** Audit enabled repositories — disable any that are unnecessary or untrusted
- [ ] **5.3** Verify installed packages against RPM database
- [ ] **5.4** Remove orphaned packages

### Rationale

**5.1 — GPG enforcement (full re-audit)**  
GPG enforcement was confirmed before the initial update in Section 1.4. This step performs a full re-audit across all repos now that EPEL and any provider repos are present — catching anything added mid-setup. Every enabled repository must have `gpgcheck=1`.

**5.2 — Repository audit**  
Every enabled repository is a potential source of packages installable onto your system. On a clean AlmaLinux 10 + EPEL setup, you should only have: `baseos`, `appstream`, `extras` or `crb`, `epel`, and your VPS provider's repo (if present — audit carefully). Anything else should be explicitly justified or disabled.

**5.3 — RPM verification**  
`rpm -Va` verifies every installed package against the RPM database — checking file sizes, checksums, permissions, and ownership against what was originally installed. Discrepancies can indicate tampered binaries or misconfigured installs. Save the output as a baseline reference. On a fresh VPS some discrepancies are normal (config files modified during setup) — the goal is to know what they are and why.

**5.4 — Orphaned packages**  
Orphaned packages are installed packages no longer required by anything — left behind after dependency chains change. They represent unmonitored software. `dnf autoremove` cleans them safely.

### Scriptable Commands

```bash
# --- 5.1 Full GPG re-audit across all repos ---
grep -r 'gpgcheck' /etc/yum.repos.d/
# Every repo block should have gpgcheck=1
# Fix any repo with gpgcheck=0:
# sed -i 's/gpgcheck=0/gpgcheck=1/' /etc/yum.repos.d/<offending-repo>.repo

grep 'gpgcheck' /etc/dnf/dnf.conf
# Expected: gpgcheck=1

# --- 5.2 Audit enabled repositories ---
dnf repolist enabled
# Review — disable any repo you cannot justify:
# dnf config-manager --set-disabled <repo-id>

# --- 5.3 Verify installed packages against RPM database ---
rpm -Va 2>/dev/null | tee /root/rpm-verify-baseline.txt

# Output format: [attributes] <file>
# Key attribute flags:
#   S = file size differs
#   M = permissions differ
#   5 = MD5/SHA checksum differs
#   U = user ownership differs
#   G = group ownership differs
# Modified config files are expected.
# Modified binaries are not — investigate immediately.

# --- 5.4 Remove orphaned packages ---
dnf autoremove -y
```

> **Baseline note:** Save `/root/rpm-verify-baseline.txt` from step 5.3. After any major system change or update, re-run `rpm -Va` and diff against this file to spot unexpected modifications. This complements AIDE (Section 11) which provides ongoing monitoring.

### [Back to Top](#section-order)

---

## Section 6 — Mandatory Access Control (MAC)

> Goal: Confirm SELinux is in Enforcing mode and will stay there. Establish the correct approach to handling SELinux denials — targeted fixes, never blanket disabling.

### Checklist

- [ ] **6.1** Verify SELinux is in `Enforcing` mode at runtime
- [ ] **6.2** Verify `Enforcing` is set in `/etc/selinux/config` (persists across reboots)
- [ ] **6.3** Confirm the policy type is `targeted`
- [ ] **6.4** Check for any permissive domains — none should exist on a fresh system
- [ ] **6.5** Audit SELinux denials from boot and resolve any outstanding issues
- [ ] **6.6** Review and audit SELinux booleans

### Rationale

**6.1 & 6.2 — Enforcing mode, runtime and config**  
SELinux has three modes: `Enforcing` (violations are blocked), `Permissive` (violations are only logged), and `Disabled` (SELinux is completely off). AlmaLinux 10 ships in `Enforcing` by default — but some VPS providers switch it to `Permissive` or `Disabled` in their images for compatibility convenience. Both the runtime state and the config file must be `Enforcing`. The config file governs boot mode — a runtime-only change via `setenforce 1` does not survive a reboot.

**6.3 — `targeted` policy**  
AlmaLinux uses the `targeted` policy, which confines specific high-risk system services while leaving most user processes unconfined. This is the correct balance for a general-purpose server.

**6.4 — Permissive domains**  
Individual processes can be set to `Permissive` mode without switching the entire system — a common workaround when someone couldn't be bothered to fix a denial properly. On a fresh hardened system there should be zero permissive domains.

**6.5 — Denial audit**  
After all configuration changes in Sections 1–5, SELinux may have logged denials — particularly around SSH port registration, `fail2ban`, or `auditd`. The critical one was already fixed in Section 3.4 (sshd port 32022). This step sweeps for any remaining denials and resolves them correctly.

**6.6 — Boolean audit**  
SELinux booleans are on/off toggles controlling specific policy behaviors. The defaults are conservative and correct for a baseline. This step lists all non-default booleans currently `on` — anything enabled by the provider image that you didn't explicitly set should be reviewed and disabled if not needed.

### Scriptable Commands

```bash
# --- 6.1 Verify runtime SELinux mode ---
getenforce
# Expected: Enforcing
# If Permissive or Disabled:
setenforce 1
getenforce

# --- 6.2 Verify SELinux config (boot-persistent) ---
grep 'SELINUX=' /etc/selinux/config
# Expected:
# SELINUX=enforcing
# SELINUXTYPE=targeted

# If not enforcing, fix:
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
# Note: config change takes effect on next reboot
# setenforce 1 handles the current session immediately

# --- 6.3 Confirm targeted policy ---
sestatus | grep 'Loaded policy'
# Expected: Loaded policy name: targeted

# --- 6.4 Check for permissive domains ---
semanage permissive -l
# Expected: empty output
# If any are listed and you did not set them:
# semanage permissive -d <domain_name>

# --- 6.5 Audit SELinux denials since boot ---
ausearch -m avc -ts boot 2>/dev/null
# No output = no denials — ideal state
# If denials exist, get a human-readable summary and resolve

# Correct resolution hierarchy:
#   1. semanage port / fcontext / boolean  ← always prefer this
#   2. Custom policy module via audit2allow ← only if no other option
#   3. semanage permissive -a <domain>     ← last resort, document why

# Verify Section 3.4 SELinux port fix is in place:
semanage port -l | grep ssh
# Expected: ssh_port_t    tcp    32022, 22

# --- 6.6 Audit non-default booleans ---
semanage boolean -l | grep 'on$' | grep -v '^#'
# Review each boolean that is 'on'
# Disable any you did not explicitly set and cannot justify:
# setsebool -P <boolean_name> off
```

> **The cardinal rule of SELinux:** When something breaks, the answer is never `setenforce 0`. Identify the specific denial with `ausearch -m avc`, understand what is being blocked and why, then apply the narrowest possible fix. Disabling SELinux system-wide to fix one misbehaving service trades your strongest mandatory access control layer for convenience.

### [Back to Top](#section-order)

---

## Section 7 — Logging & Audit

> Goal: Ensure all security-relevant events are captured, stored persistently, and rotated safely. Logs are your only forensic trail if something goes wrong.

### Checklist

- [ ] **7.1** Enable persistent storage in `journald`
- [ ] **7.2** Cap `journald` maximum disk usage
- [ ] **7.3** Enable `auditd` for boot — without starting yet
- [ ] **7.4** Configure `auditd` log retention
- [ ] **7.5** Deploy hardened `auditd` rules
- [ ] **7.6** Start `auditd` — first start loads rules and retention config together
- [ ] **7.7** Verify log rotation is configured for both `auditd` and `journald`

### Rationale

**7.1 — `journald` persistent storage**  
By default on some minimal installs, `journald` stores logs in memory only — meaning all logs are lost on reboot. `Storage=persistent` writes logs to `/var/log/journal/`, surviving reboots. Essential for post-incident analysis.

**7.2 — `journald` disk cap**  
Persistent logs without a cap will grow unbounded and eventually fill your disk, causing service failures. `SystemMaxUse=500M` sets a hard ceiling — enough for meaningful retention without risk of disk exhaustion.

**7.3 — Enable `auditd` without starting**  
`auditd` hooks directly into the kernel and records system calls — giving visibility into file access, privilege escalation, user/group changes, and network configuration modifications at the lowest level. On AlmaLinux 10 with audit 4.x, `auditd` carries `RefuseManualStop=yes` — once running it cannot be restarted manually. This means rules and retention config must be in place before the first start. We enable it for boot here but defer the actual start to step 7.6.

**7.4 — `auditd` log retention**  
`auditd` manages its own log files in `/var/log/audit/`. We configure a rolling set: 50MB per file, 10 files = 500MB max audit log retention. Configured before the first start so these settings are active from the moment auditd launches.

**7.5 — `auditd` rules**  
The default `auditd` ruleset is essentially empty. We deploy rules targeting events that matter most:
- Authentication events — logins, sudo usage
- Privilege escalation — any execution of `su` or `sudo`
- Sensitive file modifications — `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/`
- User and group management tools
- Network configuration changes
- Kernel module loading

Rules are written to `/etc/audit/rules.d/hardening.rules` before auditd starts. On first start, auditd merges all files in `rules.d/` into `/etc/audit/audit.rules` and loads them into the kernel automatically.

**7.6 — Start `auditd`**  
With retention config and rules both in place, auditd is started for the first time. It picks up everything from `auditd.conf` and `rules.d/` in a single clean start — no reload or restart needed.

**7.7 — Log rotation**  
Verify `logrotate` is handling both `auditd` and system logs. AlmaLinux includes rotation configs for both by default — this step confirms they're in place.

### Scriptable Commands

```bash
# --- 7.1 Enable journald persistent storage ---
mkdir -p /var/log/journal
sed -i 's/^#Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
grep -q '^Storage=' /etc/systemd/journald.conf || \
  echo 'Storage=persistent' >> /etc/systemd/journald.conf

# --- 7.2 Cap journald disk usage ---
sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=500M/' /etc/systemd/journald.conf
grep -q '^SystemMaxUse=' /etc/systemd/journald.conf || \
  echo 'SystemMaxUse=500M' >> /etc/systemd/journald.conf

systemctl restart systemd-journald
# Verify:
journalctl --disk-usage

# --- 7.3 Enable auditd for boot (do NOT start yet) ---
systemctl enable auditd
# auditd refuses manual restart once running (RefuseManualStop=yes)
# Rules and retention config must be in place before the first start

# --- 7.4 Configure auditd log retention ---
sed -i 's/^max_log_file\s*=.*/max_log_file = 50/'                   /etc/audit/auditd.conf
sed -i 's/^num_logs\s*=.*/num_logs = 10/'                           /etc/audit/auditd.conf
sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf

# Verify:
grep -E 'max_log_file|num_logs|max_log_file_action' /etc/audit/auditd.conf
# Expected:
# max_log_file = 50
# num_logs = 10
# max_log_file_action = ROTATE

# --- 7.5 Deploy auditd rules ---
# rules.d is created by the audit-rules package — mkdir -p as safety net:
mkdir -p /etc/audit/rules.d

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# --- Buffer size ---
-b 8192

# --- Failure mode: 1 = log, 2 = panic ---
-f 1

# --- Authentication & authorization ---
-w /etc/passwd          -p wa -k identity
-w /etc/shadow          -p wa -k identity
-w /etc/group           -p wa -k identity
-w /etc/gshadow         -p wa -k identity
-w /etc/sudoers         -p wa -k sudoers
-w /etc/sudoers.d/      -p wa -k sudoers

# --- SSH configuration ---
-w /etc/ssh/sshd_config -p wa -k sshd_config

# --- Privilege escalation ---
-w /bin/su              -p x  -k privilege_escalation
-w /usr/bin/sudo        -p x  -k privilege_escalation

# --- User and group management tools ---
-w /usr/sbin/useradd    -p x  -k user_mgmt
-w /usr/sbin/usermod    -p x  -k user_mgmt
-w /usr/sbin/userdel    -p x  -k user_mgmt
-w /usr/sbin/groupadd   -p x  -k user_mgmt
-w /usr/sbin/groupmod   -p x  -k user_mgmt
-w /usr/sbin/groupdel   -p x  -k user_mgmt

# --- Network configuration ---
-w /etc/hosts           -p wa -k network_config
-w /etc/resolv.conf     -p wa -k network_config

# --- Kernel module loading ---
-w /sbin/insmod         -p x  -k kernel_modules
-w /sbin/rmmod          -p x  -k kernel_modules
-w /sbin/modprobe       -p x  -k kernel_modules

# --- Login and session events ---
-w /var/log/lastlog     -p wa -k logins
-w /var/run/faillock/   -p wa -k logins

# --- Immutable flag: lock rules at runtime ---
# -e 2
# Uncomment only after rules are confirmed working.
# -e 2 makes rules immutable until next reboot.
# Leave commented during initial setup and first weeks of operation.
EOF

# --- 7.6 Start auditd ---
# First start: auditd merges rules.d/*.rules into /etc/audit/audit.rules
# and loads them into the kernel automatically
systemctl start auditd
systemctl status auditd

# Verify rules are active:
auditctl -l
# Expected: all rules from hardening.rules listed

# --- 7.7 Verify log rotation configs are present ---
ls /etc/logrotate.d/
# audit and syslog entries should be present

cat /etc/logrotate.d/audit
# Confirm rotation is configured for /var/log/audit/audit.log
```

> **Querying audit logs:**
> ```bash
> ausearch -k identity              # passwd/shadow/group changes
> ausearch -k privilege_escalation  # all sudo/su usage
> ausearch -k sshd_config           # sshd_config modifications
> aureport --summary                # summarized report of all events
> ```

> **Updating rules on a running system:** auditd refuses manual restart. To reload rules immediately without rebooting:
> ```bash
> auditctl -D                                          # clear all kernel rules
> auditctl -R /etc/audit/rules.d/hardening.rules      # reload from file
> auditctl -l                                          # verify
> ```
> Rules in `/etc/audit/rules.d/` are also loaded automatically on every boot.

### [Back to Top](#section-order)

---

## Section 8 — Kernel Hardening 

> Goal: Harden the Linux kernel's network stack and core behavior against IP spoofing, SYN floods, redirect attacks, and information leakage via persistent `sysctl` parameters.

### Checklist

- [ ] **8.1** Disable IP forwarding
- [ ] **8.2** Disable ICMP redirect acceptance and sending
- [ ] **8.3** Disable source routing
- [ ] **8.4** Enable reverse path filtering
- [ ] **8.5** Enable SYN cookies
- [ ] **8.6** Enable martian packet logging
- [ ] **8.7** Harden kernel information exposure (`dmesg`, kernel pointers)
- [ ] **8.8** Harden ASLR and core dumps
- [ ] **8.9** Disable Magic SysRq key
- [ ] **8.10** Apply and persist all parameters

### Rationale

**8.1 — IP forwarding**  
IP forwarding allows the kernel to route packets between interfaces — necessary for routers, completely unnecessary for a VPS. Leaving it enabled means a compromised process could potentially route traffic through your server.

**8.2 — ICMP redirects**  
ICMP redirect messages instruct a host to update its routing table. This is a classic attack vector on public networks — a malicious actor can send crafted ICMP redirects to manipulate your routing table. Disable both accepting and sending redirects.

**8.3 — Source routing**  
IP source routing allows the sender to specify the route a packet takes. Almost exclusively used for spoofing and evasion today. No legitimate use case on a VPS.

**8.4 — Reverse path filtering**  
Validates that incoming packets arrive on the interface that would be used to reply to the source IP. Packets failing this check are likely spoofed and are dropped. `rp_filter = 1` enables strict mode — correct for a single-interface VPS.

**8.5 — SYN cookies**  
A SYN flood exhausts the server's connection table by sending large volumes of TCP SYN packets without completing the handshake. SYN cookies allow the kernel to handle SYN floods without allocating state for each half-open connection.

**8.6 — Martian packet logging**  
Martian packets have source addresses impossible on the public internet. Logging them gives visibility into spoofing attempts. Low volume on a normal VPS — high volume is a signal worth investigating.

**8.7 — Kernel information exposure**  
`dmesg_restrict = 1` prevents unprivileged users from reading kernel ring buffer messages (which can leak hardware details and memory addresses). `kptr_restrict = 2` hides kernel symbol addresses from all users in userspace — makes kernel exploit development significantly harder.

**8.8 — ASLR and core dumps**  
`randomize_va_space = 2` enables full Address Space Layout Randomization — the kernel randomizes the memory layout of every process, making memory corruption exploits dramatically harder. `fs.suid_dumpable = 0` disables core dumps for SUID processes — core dumps of privileged processes can expose sensitive memory contents including credentials.

**8.9 — Magic SysRq**  
Allows direct low-level kernel commands via keyboard input. On a VPS there is no physical keyboard, but the interface may be accessible via the provider's console. Disabling it removes an unnecessary privileged control path.

### Scriptable Commands

```bash
# --- 8.1 to 8.9 Write all security sysctl parameters ---
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# ============================================================
# Network hardening
# ============================================================

# 8.1 Disable IP forwarding
net.ipv4.ip_forward = 0

# 8.2 Disable ICMP redirect acceptance and sending
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# 8.3 Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# 8.4 Enable reverse path filtering (strict mode)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 8.5 Enable SYN cookies
net.ipv4.tcp_syncookies = 1

# 8.6 Martian packet logging
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ============================================================
# Kernel hardening
# ============================================================

# 8.7 Restrict kernel information exposure
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# 8.8 Full ASLR + disable SUID core dumps
kernel.randomize_va_space = 2
fs.suid_dumpable = 0

# 8.9 Disable Magic SysRq
kernel.sysrq = 0
EOF

# --- 8.10 Apply all parameters ---
sysctl --system

# Verify a sample of applied values:
sysctl net.ipv4.ip_forward
sysctl net.ipv4.tcp_syncookies
sysctl kernel.randomize_va_space
sysctl kernel.dmesg_restrict
sysctl kernel.kptr_restrict
sysctl fs.suid_dumpable
sysctl kernel.sysrq
# Expected: all match values set above
```

> **On `99-hardening.conf`:** The `99-` prefix ensures this file is loaded last among all `sysctl.d` drop-ins, giving our values the highest precedence. A VPS provider that ships custom sysctl defaults will have them in a lower-numbered file — ours overrides them cleanly without modifying provider files.

### [Back to Top](#section-order)

---

## Section 9 — Filesystem Hardening

> Goal: Restrict what can be executed and by whom on key filesystem paths, eliminate unnecessary privileged binaries, and lock critical configuration files against modification. All steps apply to an existing VPS without partition restructuring.

### Checklist

- [ ] **9.1** Harden `/tmp` mount options — `noexec`, `nosuid`, `nodev`
- [ ] **9.2** Harden `/dev/shm` mount options — `noexec`, `nosuid`, `nodev`
- [ ] **9.3** Harden `/proc` — restrict process visibility with `hidepid`
- [ ] **9.4** Audit and remove unnecessary SUID/SGID binaries
- [ ] **9.5** Sweep for world-writable files and directories
- [ ] **9.6** Apply `chattr +i` to immutable configuration files

### Rationale

**9.1 — `/tmp` hardening**  
`/tmp` is world-writable by design. Without mount restrictions, an attacker who gains write access can drop and execute a malicious binary. Three mount flags eliminate this:
- `noexec` — binaries in `/tmp` cannot be executed
- `nosuid` — SUID/SGID bits on files in `/tmp` are ignored
- `nodev` — device files in `/tmp` are ignored

On AlmaLinux 10, `/tmp` is managed by systemd as a `tmpfs` mount via `tmp.mount`. We override its options with a systemd drop-in.

**9.2 — `/dev/shm` hardening**  
`/dev/shm` is a shared memory filesystem used for inter-process communication. Like `/tmp`, it is world-writable and can be abused to stage and execute malicious code. This one goes in `/etc/fstab` since it is not managed by a systemd unit.

**9.3 — `/proc` `hidepid`**  
By default every user can browse `/proc` and see all running processes — including command line arguments which frequently contain credentials or tokens. `hidepid=2` restricts `/proc/<pid>` entries so each user can only see their own processes. Root and members of a designated group retain full visibility.

**9.4 — SUID/SGID audit**  
SUID/SGID bits on executables allow them to run with the privileges of the file owner regardless of who executes them. Every unnecessary SUID binary is a potential privilege escalation path. We enumerate all of them, review the list, and remove the bit from anything that doesn't need it.

**9.5 — World-writable files**  
Outside of intentional shared paths like `/tmp` and `/dev/shm`, world-writable files anywhere else are a misconfiguration that should be corrected.

**9.6 — `chattr +i` (immutable flag)**  
The immutable flag prevents a file from being modified, deleted, or renamed — even by root — until explicitly removed with `chattr -i`. Applied selectively to configuration files that should never change during normal operation. We deliberately do **not** apply it to `/etc/passwd`, `/etc/shadow`, or `/etc/sudoers` — those need to remain modifiable for routine operations like password changes and user management.

### Scriptable Commands

```bash
# --- 9.1 Harden /tmp via systemd drop-in ---

# Check how /tmp is currently mounted:
findmnt /tmp
# If Type is tmpfs — use the systemd drop-in method below
# If Type is ext4/xfs — contact your provider

# systemd drop-in method:
mkdir -p /etc/systemd/system/tmp.mount.d/
cat > /etc/systemd/system/tmp.mount.d/hardening.conf << 'EOF'
[Mount]
Options=mode=1777,strictatime,noexec,nosuid,nodev,size=50%
EOF

systemctl daemon-reload
systemctl restart tmp.mount

# Verify:
findmnt /tmp
# Expected options: noexec, nosuid, nodev

# --- 9.2 Harden /dev/shm via fstab ---
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

# --- 9.3 Harden /proc with hidepid ---
# Create a dedicated group for processes that need full /proc visibility:
groupadd -r procadmin
usermod -aG procadmin dan

# Add /proc hardening to fstab:
grep -q 'hidepid' /etc/fstab || \
  echo 'proc /proc proc defaults,hidepid=2,gid=procadmin 0 0' >> /etc/fstab

# Remount immediately:
mount -o remount,hidepid=2,gid=procadmin /proc

# Verify:
findmnt /proc

# --- 9.4 Audit SUID/SGID binaries ---
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
  2>/dev/null | tee /root/suid-sgid-baseline.txt

# Review the list carefully.
# Common legitimate SUID binaries on AlmaLinux (keep these):
# /usr/bin/passwd, /usr/bin/su, /usr/bin/sudo
# /usr/bin/newgrp, /usr/bin/chsh, /usr/bin/chage
# /usr/bin/ping, /usr/sbin/unix_chkpwd

# Remove SUID/SGID bit from anything not explicitly needed:
# chmod u-s /path/to/binary   ← removes SUID
# chmod g-s /path/to/binary   ← removes SGID

# --- 9.5 World-writable file sweep ---
find / -xdev \
  -not \( -path '/tmp'     -prune \) \
  -not \( -path '/dev/shm' -prune \) \
  -not \( -path '/proc'    -prune \) \
  -not \( -path '/sys'     -prune \) \
  -perm -0002 -type f 2>/dev/null \
  | tee /root/world-writable-baseline.txt

# Review and correct each entry:
# chmod o-w /path/to/file

# Also check world-writable directories:
find / -xdev \
  -not \( -path '/tmp'     -prune \) \
  -not \( -path '/dev/shm' -prune \) \
  -not \( -path '/proc'    -prune \) \
  -not \( -path '/sys'     -prune \) \
  -perm -0002 -type d 2>/dev/null

# --- 9.6 Apply immutable flag to critical configs ---
chattr +i /etc/ssh/sshd_config
chattr +i /etc/ssh/banner
chattr +i /etc/sysctl.d/99-hardening.conf
chattr +i /etc/sysctl.d/99-performance.conf
chattr +i /etc/audit/rules.d/hardening.rules

# Verify (the 'i' flag should be present):
lsattr /etc/ssh/sshd_config
lsattr /etc/sysctl.d/99-hardening.conf

# To temporarily modify any of these files later:
# chattr -i /path/to/file
# <make your changes>
# chattr +i /path/to/file
```

> **On `hidepid` and systemd:** Some systemd services read `/proc` entries of other processes during startup. If any service fails after applying `hidepid=2`, add it to the `procadmin` group: `usermod -aG procadmin <service-user>`.

> **Baseline files:** `/root/suid-sgid-baseline.txt` and `/root/world-writable-baseline.txt` serve as reference snapshots. Re-run those `find` commands periodically and diff against these files — new SUID binaries or world-writable files appearing outside of your own actions are a red flag.

### [Back to Top](#section-order)

---

## Section 10 — Performance Optimization

> Goal: Allocate swap space equal to physical RAM and tune kernel memory management parameters for a general-purpose VPS workload.

### Checklist

- [ ] **10.1** Detect physical RAM size in MiB
- [ ] **10.2** Create, format, and activate swapfile using `dd`
- [ ] **10.3** Persist swapfile in `/etc/fstab`
- [ ] **10.4** Tune `vm.swappiness`
- [ ] **10.5** Tune dirty page ratios
- [ ] **10.6** Tune inode/dentry cache pressure
- [ ] **10.7** Apply and persist performance `sysctl` parameters

### Rationale

**10.1 & 10.2 — Swapfile with `dd`**  
A swapfile provides an overflow buffer when physical RAM is exhausted. Sizing it equal to physical RAM is a practical general-purpose default. We use `dd` to write actual zeros to every block — unlike `fallocate` which only reserves space without writing data, leaving previously deleted data in those blocks. A swapfile created with `fallocate` could expose old data when the kernel writes memory pages into those blocks. `dd` guarantees the swapfile is clean before it ever receives memory contents. Permissions must be `600` — a world-readable swapfile exposes memory contents to any local user.

**10.3 — `/etc/fstab` persistence**  
`swapon` activates the swapfile for the current session only. Adding it to `/etc/fstab` ensures it is mounted automatically on every boot.

**10.4 — `vm.swappiness = 10`**  
Controls how aggressively the kernel moves memory pages to swap. The default is `60`. For a VPS where RAM is the primary performance resource, `10` tells the kernel to strongly prefer keeping data in RAM and only swap under genuine memory pressure.

**10.5 — Dirty page ratios**  
- `vm.dirty_background_ratio = 5` — at 5% of RAM dirty, background kernel threads start writing to disk quietly without blocking processes
- `vm.dirty_ratio = 15` — at 15% of RAM dirty, processes themselves are forced to flush

Tightening these slightly reduces the risk of large write bursts causing I/O stalls, particularly noticeable on VPS storage which is often network-backed with variable latency.

**10.6 — `vm.vfs_cache_pressure = 50`**  
The default is `100` — equal pressure on inode/dentry caches and page cache. Setting it to `50` makes the kernel favor keeping filesystem metadata in cache longer, benefiting workloads with frequent directory lookups and file access — typical for a general-purpose server.

### Scriptable Commands

```bash
# --- 10.1 Detect RAM size in MiB ---
RAM_MiB=$(free -m | awk '/^Mem:/{print $2}')
echo "Detected RAM: ${RAM_MiB} MiB — swapfile will be ${RAM_MiB}M"

# --- 10.2 Create, format, and activate swapfile ---
dd if=/dev/zero of=/swapfile bs=1M count=${RAM_MiB} status=progress
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

# Verify:
swapon --show
free -h

# --- 10.3 Persist swapfile in fstab ---
cp /etc/fstab /etc/fstab.bak
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Verify fstab entry:
grep swapfile /etc/fstab

# --- 10.4 to 10.6 Write performance sysctl parameters ---
cat > /etc/sysctl.d/99-performance.conf << 'EOF'
# ============================================================
# Memory management
# ============================================================

# 10.4 Reduce swap aggressiveness
vm.swappiness = 10

# 10.5 Dirty page flush thresholds
vm.dirty_background_ratio = 5
vm.dirty_ratio = 15

# 10.6 Favor keeping inode/dentry cache
vm.vfs_cache_pressure = 50
EOF

# --- 10.7 Apply parameters ---
sysctl --system

# Verify applied values:
sysctl vm.swappiness
sysctl vm.dirty_background_ratio
sysctl vm.dirty_ratio
sysctl vm.vfs_cache_pressure
```

### [Back to Top](#section-order)

---

## Section 11 — Intrusion Detection System

> Goal: Establish a cryptographic baseline of the filesystem after hardening is complete. Any unexpected file modification, addition, or deletion is detectable on subsequent checks. Configured conservatively to minimize resource impact on a low-resource VPS.

### Resource Profile

| Operation | Duration | RAM Usage | CPU | Disk I/O |
|-----------|----------|-----------|-----|----------|
| `aide --init` | 2–5 min | ~80–120MB | 100% (1 core) | Heavy read |
| `aide --check` | 1–3 min | ~60–90MB | 100% (1 core) | Heavy read |
| Idle | — | 0 | 0 | None |

All scans are run with `nice -n 19 ionice -c 3` to minimize impact on live services during scan windows. Schedule scans during your lowest-traffic window (e.g., 3AM).

### Checklist

- [ ] **11.1** Configure AIDE to monitor only high-value paths
- [ ] **11.2** Build the initial AIDE database (`--init`)
- [ ] **11.3** Move database to active location
- [ ] **11.4** Run a baseline check to confirm database integrity
- [ ] **11.5** Create a resource-conscious check script
- [ ] **11.6** Schedule periodic checks via `cron`

### Rationale

**11.1 — Targeted monitoring scope**  
The default AIDE configuration monitors an extremely broad set of paths, generating a large database and slow, CPU-intensive scans. For a low-resource VPS we narrow the scope to paths that are genuinely security-sensitive and unlikely to change during normal operation.

`database_attrs` explicitly lists the algorithms AIDE uses to verify its own database files. On AlmaLinux 10, GnuTLS does not include the GOST module, so AIDE produces warnings when it tries to use `stribog256` and `stribog512` on the database. Setting `database_attrs` to a list of available algorithms suppresses these warnings entirely. This does not affect how monitored files are checksummed — our `NORMAL` policy (sha256+sha512+...) is unaffected.

**Monitored paths (high value, low churn):**
- `/etc` — all configuration files
- `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` — system binaries
- `/boot` — kernel and bootloader
- `/root` — root home directory
- `/lib/modules` — kernel modules

**Excluded paths (high churn, low security value):**
- `/etc/mtab` — changes on every mount operation
- `/etc/resolv.conf` — recreated by cloud-init and NetworkManager on every boot; inode always changes; DNS config is managed externally and not meaningful for local integrity monitoring
- `/var/log` — constantly written by logging daemons
- `/var/spool` — mail and cron spool
- `/proc`, `/sys` — virtual filesystems
- `/tmp`, `/dev/shm` — intentionally volatile
- `/root/.lesshst`, `/root/.zsh_history`, `/root/.bash_history`, `/root/.zsh_sessions` — shell session files that change on every login; not security-relevant and would generate noise on every check

**Two attribute policies are defined:**
- `NORMAL` — full integrity check including inode number (`i`). Used for all standard paths.
- `BOOT` — identical to NORMAL but without inode checking. Used for `/boot` because the EFI partition uses FAT32, which does not store inodes natively. The kernel generates synthetic inode numbers at mount time based on file cluster position — these numbers change on every remount or reboot regardless of file content. Monitoring inodes on FAT32 produces guaranteed false positives. File content (checksums), permissions, and ownership are still fully monitored under the `BOOT` policy.

**11.2 — Initial database build**  
`aide --init` must be run **after all hardening steps are complete**. The database captures the current state as the trusted baseline. If built before hardening, every subsequent change made during hardening will appear as a false alert.

**11.3 — Database placement**  
AIDE writes the new database to `/var/lib/aide/aide.db.new.gz`. It will not use it for checks until renamed to `/var/lib/aide/aide.db.gz`. This two-step process prevents AIDE from automatically trusting an unreviewed database.

**11.4 — Baseline check**  
Immediately after building and activating the database, run one check. On a freshly hardened system with no changes since `--init`, this should produce zero alerts.

**11.5 — Resource-conscious check script**  
Wraps `aide --check` with `nice` and `ionice` priority reduction, timestamps the output, and appends results to a dedicated log file for a persistent audit trail.

**11.6 — Scheduled checks**  
Weekly is the right cadence for a low-resource VPS. Daily checks are too aggressive for a single vCPU. Weekly balances detection latency against system impact.

### Scriptable Commands

```bash
# --- 11.1 Configure AIDE monitoring scope ---
cp /etc/aide.conf /etc/aide.conf.bak

cat > /etc/aide.conf << 'EOF'
# AIDE configuration — resource-conscious, high-value paths only

# Database locations
database_in=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz
database_new=file:/var/lib/aide/aide.db.new.gz
gzip_dbout=yes

# Database self-verification algorithms
# Explicitly listed to suppress stribog (GOST) warnings from GnuTLS
# which are unavailable on AlmaLinux 10
database_attrs=sha256+sha512+md5+sha1+rmd160

# Report output
report_url=file:/var/log/aide/aide.log
report_url=stdout

# ============================================================
# Attribute policies
# ============================================================

# Standard policy — full integrity check including inode
NORMAL = sha256+sha512+ftype+p+i+n+u+g+s+acl+selinux

# Boot policy — no inode checking
# /boot/efi uses FAT32 which generates synthetic inode numbers at mount time
# Inodes change on every remount/reboot regardless of file content
# Content integrity (checksums) is still fully monitored
BOOT = sha256+sha512+ftype+p+n+u+g+s+acl+selinux

# ============================================================
# Monitored paths
# ============================================================
/boot                   BOOT
/bin                    NORMAL
/sbin                   NORMAL
/usr/bin                NORMAL
/usr/sbin               NORMAL
/lib/modules            NORMAL
/root                   NORMAL
/etc                    NORMAL

# ============================================================
# Explicit exclusions within monitored paths
# ============================================================
!/etc/mtab
!/etc/aide.conf
!/etc/resolv.conf
!/var/log
!/var/spool
!/var/cache
!/proc
!/sys
!/tmp
!/dev/shm
!/run

# Volatile root home files — change on every session, not security-relevant
!/root/.lesshst
!/root/.zsh_history
!/root/.bash_history
!/root/.zsh_sessions
EOF

mkdir -p /var/log/aide
chmod 700 /var/log/aide

# --- 11.2 Build initial database ---
# ⚠️  Run ONLY after ALL hardening sections are complete
# ⚠️  If aide.conf is modified after this step, --init must be re-run
nice -n 19 ionice -c 3 aide --init
# Takes 2–5 minutes with pegged vCPU — expected behaviour

# --- 11.3 Activate the database ---
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# --- 11.4 Baseline integrity check ---
nice -n 19 ionice -c 3 aide --check
# Expected: AIDE found no differences between database and filesystem.
# Any output beyond this should be investigated before proceeding.

# --- 11.5 Create resource-conscious check script ---
cat > /usr/local/bin/aide-check.sh << 'EOF'
#!/bin/bash
# AIDE integrity check — resource-conscious wrapper

LOG=/var/log/aide/aide-check.log
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "========================================" >> "$LOG"
echo "AIDE check started: $TIMESTAMP"          >> "$LOG"
echo "========================================" >> "$LOG"

nice -n 19 ionice -c 3 aide --check >> "$LOG" 2>&1
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
  echo "RESULT: CLEAN — no changes detected"                             >> "$LOG"
elif [ $((EXIT_CODE & 8)) -ne 0 ] || [ $EXIT_CODE -ge 16 ]; then
  echo "RESULT: ERROR — AIDE encountered a problem (exit code: $EXIT_CODE)" >> "$LOG"
else
  echo "RESULT: CHANGES DETECTED — review log (exit code: $EXIT_CODE)"  >> "$LOG"
fi
EOF

chmod 700 /usr/local/bin/aide-check.sh
chown root:root /usr/local/bin/aide-check.sh

# --- 11.6 Schedule weekly check via cron ---
# Every Monday at 3:00 AM
echo '0 3 * * 1 root /usr/local/bin/aide-check.sh' \
  > /etc/cron.d/aide-check

chmod 644 /etc/cron.d/aide-check

# Verify:
cat /etc/cron.d/aide-check

# Run the check script once manually to verify it works
# and to create the initial aide-check.log before the first cron fires:
bash /usr/local/bin/aide-check.sh

# Review result:
tail -5 /var/log/aide/aide-check.log
# Expected last line: RESULT: CLEAN — no changes detected
```

> **Updating the database after intentional changes:** Any time you deliberately modify a monitored file, rebuild the AIDE database afterward:
> ```bash
> nice -n 19 ionice -c 3 aide --update
> mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
> ```
> Habit: **change → verify → update database**.

> **Reviewing check logs:**
> ```bash
> tail -50 /var/log/aide/aide-check.log   # wrapper script log (cron/manual runs)
> tail -50 /var/log/aide/aide.log          # AIDE native log (all operations)
> ```

### [Back to Top](#section-order)

---

## Section 12 — Maintenance Hygiene

> Goal: Establish the operational habits that keep the hardened system hardened over time. A well-configured VPS degrades without a consistent maintenance rhythm.

### Checklist

- [ ] **12.1** Define snapshot discipline — before every significant change
- [ ] **12.2** Establish a weekly review routine
- [ ] **12.3** Establish a monthly review routine
- [ ] **12.4** Create a periodic hardening health-check script
- [ ] **12.5** Document your rollback procedure

### Rationale

**12.1 — Snapshot before changes**  
A snapshot taken before any significant change gives you a clean rollback point that requires no manual recovery steps. Make it a non-negotiable reflex: **snapshot first, change second**.

Recommended triggers:
- Before any `dnf update` that includes kernel packages
- Before installing any new service
- Before modifying any hardening configuration
- Before running `aide --update`

**12.2 — Weekly review**  
Short, focused checks that catch active threats and anomalies quickly. Covers `fail2ban` ban activity, AIDE check results, and a brief auth log scan. Should take under 10 minutes.

**12.3 — Monthly review**  
Deeper checks that catch configuration drift. Covers open ports, running services, `auditd` summary, disk usage, and a manual review of updates `dnf-automatic` may have held back.

**12.4 — Health-check script**  
Runs the key verification commands from every hardening section and produces a concise status report. Particularly useful after a reboot or provider maintenance window.

**12.5 — Rollback procedure**  
Document the exact steps to restore from a snapshot for your specific provider. Write it down while calm, not during an incident.

### Scriptable Commands

```bash
# --- 12.1 Snapshot discipline ---
# Manual step at your VPS provider's control panel.
# Label snapshots with date and reason:
# e.g., "2025-05-01 pre-kernel-update"

# --- 12.2 Weekly review commands ---
echo "=== fail2ban: banned IPs ==="
fail2ban-client status sshd

echo "=== AIDE: last check result ==="
# aide-check.log is written by the weekly cron or manual script run
# aide.log is written directly by AIDE and always present after any aide operation
tail -20 /var/log/aide/aide-check.log 2>/dev/null || \
  tail -20 /var/log/aide/aide.log

echo "=== Auth log: recent sudo and SSH events ==="
ausearch -k privilege_escalation -ts today 2>/dev/null | aureport --summary
journalctl _COMM=sshd --since "7 days ago" | grep -i 'failed\|accepted\|invalid'

echo "=== SELinux: any new denials ==="
ausearch -m avc -ts "last week" 2>/dev/null | grep 'denied' | head -20

# --- 12.3 Monthly review commands ---
echo "=== Open ports ==="
ss -tlnp

echo "=== Firewall state ==="
firewall-cmd --zone=public --list-all

echo "=== Running services ==="
systemctl list-units --type=service --state=running

echo "=== Auditd monthly summary ==="
aureport --summary \
  --start "$(date -d '1 month ago' '+%m/%d/%Y')" \
  --end   "$(date '+%m/%d/%Y')"

echo "=== Disk usage ==="
df -h
du -sh /var/log/audit/
du -sh /var/log/journal/

echo "=== Pending non-security updates ==="
dnf check-update 2>/dev/null | head -20

echo "=== World-writable files drift check ==="
find / -xdev \
  -not \( -path '/tmp'     -prune \) \
  -not \( -path '/dev/shm' -prune \) \
  -not \( -path '/proc'    -prune \) \
  -not \( -path '/sys'     -prune \) \
  -perm -0002 -type f 2>/dev/null

echo "=== New SUID/SGID binaries since baseline ==="
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
  | diff /root/suid-sgid-baseline.txt - 2>/dev/null \
  | grep '^>'

# --- 12.4 Hardening health-check script ---
cat > /usr/local/bin/harden-check.sh << 'EOF'
#!/bin/bash
# Hardening posture health check — covers all 12 sections

PASS="\e[32mPASS\e[0m"
FAIL="\e[31mFAIL\e[0m"

check() {
  local label="$1"
  local result="$2"
  local expected="$3"
  if echo "$result" | grep -q "$expected"; then
    echo -e "[$PASS] $label"
  else
    echo -e "[$FAIL] $label"
    echo "       Got: $result"
  fi
}

echo "================================================"
echo " Hardening Health Check — $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================"

# Section 1 — OS Baseline
check "chrony synced"            "$(chronyc tracking | grep 'System time')"        "seconds"
check "dnf-automatic enabled"   "$(systemctl is-enabled dnf-automatic-install.timer)" "enabled"

# Section 2 — User & Auth
check "root account locked"     "$(passwd -S root | awk '{print $2}')"             "L"
check "dan in wheel group"      "$(groups dan)"                                     "wheel"

# Section 3 — SSH
check "sshd running"            "$(systemctl is-active sshd)"                      "active"
check "sshd on port 32022"      "$(ss -tlnp | grep sshd)"                          "32022"
check "PasswordAuth off"        "$(sshd -T | grep passwordauthentication)"          "no"
check "fail2ban running"        "$(systemctl is-active fail2ban)"                   "active"

# Section 4 — Firewall
check "firewalld running"       "$(systemctl is-active firewalld)"                  "active"
check "port 32022 open"         "$(firewall-cmd --zone=public --list-ports)"        "32022"

# Section 6 — SELinux
check "SELinux enforcing"       "$(getenforce)"                                     "Enforcing"
check "SSH port in SELinux"     "$(semanage port -l | grep ssh_port_t)"             "32022"

# Section 7 — Audit & Logging
check "auditd running"          "$(systemctl is-active auditd)"                     "active"
check "auditd rules loaded"     "$(auditctl -l | wc -l)"                             "[1-9]"
check "journald persistent"     "$(journalctl --disk-usage | grep 'Archived')"      "M\|G"

# Section 8 — Kernel hardening
check "ip_forward disabled"     "$(sysctl -n net.ipv4.ip_forward)"                 "0"
check "SYN cookies enabled"     "$(sysctl -n net.ipv4.tcp_syncookies)"              "1"
check "ASLR enabled"            "$(sysctl -n kernel.randomize_va_space)"            "2"
check "dmesg restricted"        "$(sysctl -n kernel.dmesg_restrict)"                "1"

# Section 9 — Filesystem Hardening
check "/tmp noexec"             "$(findmnt /tmp    | grep noexec)"                  "noexec"
check "/dev/shm noexec"         "$(findmnt /dev/shm | grep noexec)"                 "noexec"

# Section 10 — Performance
check "swap active"             "$(swapon --show | grep swapfile)"                  "swapfile"
check "swappiness at 10"        "$(sysctl -n vm.swappiness)"                        "10"

# Section 11 — AIDE
check "AIDE database exists"    "$(ls /var/lib/aide/aide.db.gz 2>/dev/null)"        "aide.db.gz"
check "AIDE cron scheduled"     "$(cat /etc/cron.d/aide-check 2>/dev/null)"         "aide-check.sh"

echo "================================================"
echo " Check complete"
echo "================================================"
EOF

chmod 700 /usr/local/bin/harden-check.sh
chown root:root /usr/local/bin/harden-check.sh

# Run immediately to confirm baseline passes:
bash /usr/local/bin/harden-check.sh

# --- 12.5 Rollback procedure template ---
cat > /root/ROLLBACK.md << 'EOF'
# VPS Rollback Procedure

## Provider snapshot restore
1. Log in to provider control panel
2. Navigate to: [your VPS > Snapshots]
3. Select snapshot labeled with date and reason
4. Click Restore — confirm when prompted
5. Wait for restore to complete (typically 2–5 minutes)
6. SSH in to verify: ssh -p 32022 -i ~/.ssh/id_ed25519 dan@<ip>

## After restore — verify hardening posture
bash /usr/local/bin/harden-check.sh

## If SSH is unreachable after restore
1. Use provider console (web-based VNC/serial)
2. Log in as dan
3. Check sshd:    systemctl status sshd
4. Check firewall: firewall-cmd --list-ports
5. Check SELinux:  getenforce

## Emergency: if locked out completely
1. Provider console → log in as dan
2. sudo systemctl restart sshd
3. If sshd fails: sudo setenforce 0 → restart sshd → diagnose → re-enforce
EOF

chmod 600 /root/ROLLBACK.md
echo "Rollback procedure written to /root/ROLLBACK.md"

# ROLLBACK.md was created after AIDE --init — update the database:
nice -n 19 ionice -c 3 aide --update
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "AIDE database updated to include ROLLBACK.md"
```

### [Back to Top](#section-order)

---

## Quick Reference — Section Execution Order

Run sections in this exact order. Do not skip ahead.

```
1  → OS Baseline           (updates, EPEL, essentials)
2  → User & Auth           (create dan, lock root)
3  → SSH Hardening         (keys, sshd_config, SELinux port, fail2ban)
4  → Firewall              (firewalld baseline rules)
5  → Package Integrity     (GPG re-audit, rpm verify)
6  → SELinux               (confirm Enforcing, audit denials)
7  → Audit & Logging       (auditd rules, journald persistent)
8  → Kernel Hardening      (sysctl security)
9  → Filesystem Hardening  (tmp/shm/proc, SUID sweep, chattr)
10 → Performance           (swapfile, sysctl performance)
11 → AIDE                  (init database LAST — after all changes)
12 → Maintenance Hygiene   (scripts, cron, rollback doc)
```

> ⚠️ **AIDE `--init` must be the final hardening action.** The database captures the trusted baseline state — any change made after `--init` will appear as a false alert on the next check.

### [Back to Top](#section-order)