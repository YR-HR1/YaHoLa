# YaHoLa

Python-based collection tool designed for **IR**

It gathers a wide range of system artifacts into a single, timestamped `.tar.gz` bundle for offline analysis.

---

## ✨ Features

* **System State & Process Info**

  * Creates `/proc` snapshot (key files, network/sysctl trees, per-PID basics).
  * Optionally walks the entire `/proc` (`--include-all-proc`).
  * Captures loaded kernel modules and flags **foreign/unsigned LKMs**.

* **Systemd & Persistence**

  * Collects all `systemd` unit files, configs, timers, and volatile state.
  * Grabs binary **journald** logs (`/var/log/journal` & `/run/log/journal`).
  * Covers all persistence techniques covered in https://digitalwhisper.co.il/files/Zines/0xAB/DW171-5-LinuxPersistanceTechniques.pdf (article in hebrew)

* **User & Auth Artifacts**

  * Startup/login/logout data: `wtmp`, `btmp`, `utmp`, `lastlog`, and optional more data like 'last'.
  * System and user **shell configs** for the 3 most common shells (bash, zsh, fish).
  * Root and user **shell histories** and `~/.ssh` keys/configs (when accessible).
  * User home directory scraping with optional time-based filtering.

* **Sensitive & Config Files**

  * `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/skel`.
  * XDG configs (`/etc/xdg`, `~/.config`, `~/.local/share`, `~/.cache`).
  * SSH server configs (`/etc/ssh`).
  * Networking & system configs: `sysctl.conf`, `/etc/modprobe.d/`, `NetworkManager`, `nsswitch.conf`, hosts.allow/deny, sudoers, cron jobs.
  * Again, all from the article I've mentioned above.

* **Logs**

  * Core logs: `syslog`, `messages`, `kern.log`, `boot.log`, `dmesg`, `cron`.
  * Auth & security: `auth.log`, `secure`, `faillog`, `sudo.log`, audit logs.
  * Package managers: APT, dpkg, Yum/DNF, Zypper, Pacman.
  * SSSD & PAM logs.
  * Journald NDJSON export (`--export-journal`).

* **Environment & Metadata**

  * Per-process environment variables (`/proc/*/environ`).
  * Host/kernel metadata & time-window filters (`--from/--to`).
  * File size capping (default 200 MB, adjustable with `--max-mb`).

* **Output**

  * All files preserved in original paths under a single **tar.gz**.
  * Optional **parsed human-readable timelines** for logins & journal.

---

## 🛠️ Usage

```bash
sudo python3 linux_artifacts_scraper.py
sudo python3 linux_artifacts_scraper.py --from "2025-09-01 00:00" --to "2025-10-03 23:59"
sudo python3 linux_artifacts_scraper.py --user alice --export-logins --export-journal
sudo python3 linux_artifacts_scraper.py --include-all-proc --max-mb 500
```

Key options:

* `--from / --to` – filter by modification time.
* `--include-all-proc` – collect almost everything in `/proc`.
* `--user` / `--home` – target a user’s home directory and configs.
* `--export-logins` – create human-readable login timelines.
* `--export-journal` – dump `journalctl` logs as text & NDJSON.
* `--max-mb` – per-file size limit (default: 200 MB).


## 🚀 Future Updates

I'm gonna include more features, such as:

* Kernel crash logs (kdump, vmcore) 
* Automatic **iptables/nftables** and firewall state collection.
* Integrity chain: hashing & signing of all collected files.
* Userspace service states
* Deeper **container runtime** inspection (Docker/K8s).

  **The main focus is going to be the first 3 for now.**

