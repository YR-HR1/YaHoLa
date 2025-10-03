#!/usr/bin/env python3
# YaHoLa.py
#
# lightweight Linux Artifact collector. made by YR-HR
# Collects common IR artifacts on Linux into a tar.gz.
# Python 3.7+. Optional external tools: modinfo, uname, last/lastb/lastlog, utmpdump, journalctl.
#
# Usage examples:
#   sudo python3 linux_artifacts_scraper.py
#   sudo python3 linux_artifacts_scraper.py --from "2025-09-01 00:00" --to "2025-10-03 23:59"
#   sudo python3 linux_artifacts_scraper.py --user alice --export-logins --export-journal
#   sudo python3 linux_artifacts_scraper.py --home /home/bob --out /tmp/forensics_bundle.tar.gz
#
# Notes:
# - Time filtering uses mtime (modification time) as a practical proxy.
# - /proc is virtual; we snapshot key files/dirs and per-PID basics.
# - “Foreign” LKMs are modules outside /lib/modules/$(uname -r) and/or unsigned/unknown signer.


import argparse
import datetime
import os
import re
import shutil
import stat
import subprocess as sp
import sys
import tarfile
from glob import glob
from pathlib import Path
from typing import Iterable, Optional, Tuple

# Path Configuation

PROC_SNAPSHOT_FILES = [
    "/proc/cmdline",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/uptime",
    "/proc/loadavg",
    "/proc/mounts",
    "/proc/swaps",
    "/proc/partitions",
    "/proc/version",
    "/proc/modules",
    "/proc/kallsyms",          
    "/proc/sys/kernel/random/boot_id",
]

PROC_SNAPSHOT_DIRS = [
    "/proc/net",     
    "/proc/sys",     
]

SYSTEMD_DIRS = [
    "/etc/systemd",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/run/systemd",           
]
SYSTEMD_JOURNAL_DIRS = [
    "/var/log/journal",
    "/run/log/journal",
]

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/subuid",
    "/etc/subgid",
    "/etc/skel",  
]

SSH_DIR = "/etc/ssh"
ETC_XDG = "/etc/xdg"

STARTUP_LOGIN_LOGS = [
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/run/utmp",
    "/var/log/auth.log",
    "/var/log/auth.log.1",
    "/var/log/secure",
    "/var/log/secure.1",
]

TOP_SHELLS = ["bash", "zsh", "fish"]  # 3 Most popular shells

EXT_LOG_GLOBS = [
    # Core
    "/var/log/syslog", "/var/log/syslog.*",
    "/var/log/messages", "/var/log/messages.*",
    "/var/log/kern.log", "/var/log/kern.log.*",
    "/var/log/boot.log", "/var/log/boot.log.*",
    "/var/log/dmesg", "/var/log/dmesg.*",
    "/var/log/cron", "/var/log/cron.*",

    # Auth / sudo / audit
    "/var/log/faillog",
    "/var/log/sudo/sudo.log", "/var/log/sudo/sudo.log.*",
    "/var/log/sudo-io/**",
    "/var/log/audit/audit.log", "/var/log/audit/audit.log.*",

    # Package managers
    "/var/log/apt/history.log", "/var/log/apt/history.log.*",
    "/var/log/apt/term.log", "/var/log/apt/term.log.*",
    "/var/log/dpkg.log", "/var/log/dpkg.log.*",
    "/var/log/yum.log", "/var/log/dnf.log", "/var/log/zypper.log",
    "/var/log/pacman.log",

    # Journald metadata (in addition to raw dirs above)
    "/var/log/journal/**",

    # SSSD/PAM (enterprise)
    "/var/log/sssd/**",

    # Web/ssh extras
    "/var/log/ssh*", "/var/log/secure*",
]

# Optional: root & target-user histories (when you aren't scraping whole home)
HISTORY_PATHS_ROOT = [
    "/root/.bash_history", "/root/.zsh_history",
    "/root/.local/share/fish/fish_history",
]
# Relative to user home
HISTORY_REL_USER = [
    ".bash_history", ".zsh_history", ".local/share/fish/fish_history",
    ".ssh/authorized_keys", ".ssh/known_hosts", ".ssh/config",
]

DEFAULT_MAX_FILE_SIZE_MB = 200  # size cap unless otherwise noted
NOW_STR =  datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

# Helpers

def parse_dt(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%Y/%m/%d",
    ]
    for f in fmts:
        try:
            return datetime.datetime.strptime(s, f).timestamp()
        except ValueError:
            continue
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:
        raise SystemExit(f"Unrecognized datetime format: {s}")

def within_time_window(p: Path, tmin: Optional[float], tmax: Optional[float]) -> bool:
    try:
        st = p.stat()
    except Exception:
        return False
    mt = st.st_mtime
    if tmin and mt < tmin:
        return False
    if tmax and mt > tmax:
        return False
    return True

def is_readable_file(p: Path) -> bool:
    try:
        return p.is_file() and os.access(p, os.R_OK)
    except Exception:
        return False

def safe_rel(dest_root: Path, src: Path) -> Path:
    rel = str(src).lstrip(os.sep)
    return dest_root / rel

def run_cmd(cmd: list[str]) -> Tuple[int, str, str]:
    try:
        p = sp.run(cmd, stdout=sp.PIPE, stderr=sp.PIPE, text=True, check=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except Exception as e:
        return 1, "", str(e)

def uname_r() -> str:
    rc, out, _ = run_cmd(["uname", "-r"])
    return out.strip() if rc == 0 else ""

def modinfo_path(module: str) -> Optional[str]:
    rc, out, _ = run_cmd(["modinfo", "-n", module])
    if rc == 0:
        return out.strip()
    return None

def modinfo_signer(module: str) -> Optional[str]:
    rc, out, _ = run_cmd(["modinfo", "-F", "signer", module])
    if rc == 0:
        return out.strip()
    return None

def add_path_to_staging(src: Path, staging_root: Path, tmin: Optional[float], tmax: Optional[float],
                        max_mb: int, follow_symlinks: bool = False) -> None:
    try:
        if not src.exists():
            return
        if src.is_symlink() and not follow_symlinks:
            out = safe_rel(staging_root, src)
            out.parent.mkdir(parents=True, exist_ok=True)
            try:
                target = os.readlink(src)
                out.write_text(f"SYMLINK -> {target}\n", encoding="utf-8", errors="ignore")
            except Exception as e:
                out.write_text(f"SYMLINK (unreadable): {e}\n", encoding="utf-8", errors="ignore")
            return
        if src.is_dir():
            add_tree(src, staging_root, tmin, tmax, max_mb, follow_symlinks=follow_symlinks)
            return
        if tmin or tmax:
            if not within_time_window(src, tmin, tmax):
                return
        try:
            size_mb = src.stat().st_size / (1024 * 1024)
            if size_mb > max_mb:
                out = safe_rel(staging_root, src)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(f"[Skipped: {size_mb:.1f} MB exceeds {max_mb} MB limit]\n", encoding="utf-8", errors="ignore")
                return
        except Exception:
            pass
        out = safe_rel(staging_root, src)
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, out)
        except PermissionError:
            out.write_text("[Permission denied]\n", encoding="utf-8", errors="ignore")
        except IsADirectoryError:
            pass
        except Exception as e:
            out.write_text(f"[Copy error: {e}]\n", encoding="utf-8", errors="ignore")
    except Exception:
        pass

def add_tree(root: Path, staging_root: Path, tmin: Optional[float], tmax: Optional[float],
             max_mb: int, follow_symlinks: bool = False, depth_limit: Optional[int] = None) -> None:
    try:
        if not root.exists():
            return
        if root.is_file():
            add_path_to_staging(root, staging_root, tmin, tmax, max_mb, follow_symlinks)
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
            if depth_limit is not None:
                rel_depth = Path(dirpath).relative_to(root).parts
                if len(rel_depth) > depth_limit:
                    dirnames[:] = []
            for name in filenames:
                add_path_to_staging(Path(dirpath) / name, staging_root, tmin, tmax, max_mb, follow_symlinks)
    except Exception:
        pass

def dump_envs(staging_root: Path) -> None:
    env_dir = staging_root / "environment"
    env_dir.mkdir(parents=True, exist_ok=True)
    (env_dir / "current_process_env.txt").write_text(
        "\n".join([f"{k}={v}" for k, v in os.environ.items()]),
        encoding="utf-8", errors="ignore"
    )
    proc_dir = Path("/proc")
    for pid_dir in proc_dir.iterdir():
        if not pid_dir.is_dir() or not pid_dir.name.isdigit():
            continue
        environ_path = pid_dir / "environ"
        try:
            data = environ_path.read_bytes()
            kv = data.decode(errors="ignore").replace("\x00", "\n").strip()
            out = env_dir / f"pid_{pid_dir.name}_environ.txt"
            out.write_text(kv + "\n", encoding="utf-8", errors="ignore")
        except Exception:
            continue

def detect_foreign_lkms(report_path: Path) -> None:
    modules_file = Path("/proc/modules")
    kernel_root = f"/lib/modules/{uname_r()}" if uname_r() else "/lib/modules"
    lines = []
    try:
        mods = modules_file.read_text(errors="ignore").splitlines()
    except Exception as e:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(f"Unable to read /proc/modules: {e}\n", encoding="utf-8", errors="ignore")
        return

    lines.append(f"Kernel root considered: {kernel_root}")
    lines.append("Name\tState\tSize\tPath\tSigner\tForeign?")
    for m in mods:
        parts = m.split()
        if not parts:
            continue
        name = parts[0]
        size = parts[1] if len(parts) > 1 else "?"
        state = parts[2] if len(parts) > 2 else "?"
        path = modinfo_path(name) or ""
        signer = (modinfo_signer(name) or "").strip()
        foreign = False
        if not path or not path.startswith(kernel_root):
            foreign = True
        if signer == "" or signer.lower() in {"", "unsigned", "unknown", "n/a"}:
            foreign = True
        lines.append(f"{name}\t{state}\t{size}\t{path or 'N/A'}\t{signer or 'N/A'}\t{foreign}")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="ignore")

def discover_user_home(args) -> Tuple[Optional[str], Optional[Path]]:
    if args.home:
        return None, Path(args.home).expanduser().resolve()
    if args.user:
        try:
            import pwd
            pw = pwd.getpwnam(args.user)
            return args.user, Path(pw.pw_dir)
        except Exception:
            print(f"[!] Could not find home for user {args.user}", file=sys.stderr)
            return args.user, None
    return None, None

def detect_shells() -> list[str]:
    shells = []
    try:
        if Path("/etc/shells").exists():
            for line in Path("/etc/shells").read_text(errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("#") or not line.startswith("/"):
                    continue
                sh = Path(line).name
                shells.append(sh)
    except Exception:
        pass
    prioritized = [s for s in TOP_SHELLS if s in shells]
    for s in shells:
        if s not in prioritized:
            prioritized.append(s)
    return prioritized[:3] if prioritized else TOP_SHELLS

def collect_shell_configs(staging_root: Path, user_home: Optional[Path], shells: list[str],
                          tmin: Optional[float], tmax: Optional[float], max_mb: int):
    global_targets = [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshrc",
        "/etc/zsh/zprofile",
        "/etc/fish/config.fish",
        "/etc/fish/conf.d",
    ]
    for p in global_targets:
        add_path_to_staging(Path(p), staging_root, tmin, tmax, max_mb)
    if user_home and user_home.exists():
        per_shell = {
            "bash": [".bashrc", ".bash_profile", ".bash_login", ".profile"],
            "zsh": [".zshrc", ".zprofile", ".zlogin", ".zshenv"],
            "fish": [".config/fish/config.fish", ".config/fish/conf.d"],
        }
        for sh in shells:
            for rel in per_shell.get(sh, []):
                add_path_to_staging(user_home / rel, staging_root, tmin, tmax, max_mb)

def add_globs(globs: Iterable[str], staging_root: Path, tmin: Optional[float], tmax: Optional[float], max_mb: int):
    for pattern in globs:
        for p in glob(pattern, recursive=True):
            add_path_to_staging(Path(p), staging_root, tmin, tmax, max_mb)

def snapshot_proc(staging_root: Path, tmin: Optional[float], tmax: Optional[float], max_mb: int):
    for f in PROC_SNAPSHOT_FILES:
        add_path_to_staging(Path(f), staging_root, tmin, tmax, max_mb)
    for d in PROC_SNAPSHOT_DIRS:
        add_tree(Path(d), staging_root, tmin, tmax, max_mb, follow_symlinks=False, depth_limit=4)
    pids_root = staging_root / "proc_snapshot" / "pids"
    pids_root.mkdir(parents=True, exist_ok=True)
    for pid_dir in Path("/proc").iterdir():
        if not (pid_dir.is_dir() and pid_dir.name.isdigit()):
            continue
        for name in ["cmdline", "status", "cwd", "root", "exe", "maps", "mountinfo"]:
            src = pid_dir / name
            out = pids_root / pid_dir.name / name
            out.parent.mkdir(parents=True, exist_ok=True)
            try:
                if name in {"cwd", "root", "exe"} and src.is_symlink():
                    target = os.readlink(src)
                    out.write_text(f"SYMLINK -> {target}\n", encoding="utf-8", errors="ignore")
                elif src.is_file():
                    if tmin or tmax:
                        try:
                            st = src.stat()
                            mt = st.st_mtime
                            if (tmin and mt < tmin) or (tmax and mt > tmax):
                                continue
                        except Exception:
                            pass
                    data = src.read_bytes()
                    out.write_bytes(data)
            except Exception:
                continue

def collect_extended_logs(staging_root: Path, tmin, tmax, max_mb):
    add_globs(EXT_LOG_GLOBS, staging_root, tmin, tmax, max_mb=max(4096, max_mb))

def collect_histories(staging_root: Path, user_home: Optional[Path], tmin, tmax, max_mb):
    for p in HISTORY_PATHS_ROOT:
        add_path_to_staging(Path(p), staging_root, tmin, tmax, max_mb)
    if user_home and user_home.exists():
        for rel in HISTORY_REL_USER:
            add_path_to_staging(user_home / rel, staging_root, tmin, tmax, max_mb)

def export_logins_human_readable(staging_root: Path, tmin: Optional[float], tmax: Optional[float]):
    """
    Best-effort exports for login activity:
      - last / last -F -w -i
      - lastb (if available)
      - lastlog
      - utmpdump for raw wtmp/btmp (if available)
    Also writes a lightweight TSV by collapsing whitespace.
    """
    exp_dir = staging_root / "parsed" / "logins"
    exp_dir.mkdir(parents=True, exist_ok=True)

    def write_out(name: str, text: str):
        (exp_dir / f"{name}.txt").write_text(text, encoding="utf-8", errors="ignore")
        # naive TSV: collapse 2+ spaces to a single tab
        tsv = re.sub(r"[ ]{2,}", "\t", text)
        (exp_dir / f"{name}.tsv").write_text(tsv, encoding="utf-8", errors="ignore")

    # Build time args for last/lastb where supported (not all builds support --since/--until)
    since_arg = until_arg = None
    def fmt(dt: float) -> str:
        return datetime.datetime.fromtimestamp(dt).strftime("%Y-%m-%d %H:%M:%S")
    if tmin:
        since_arg = ["--since", fmt(tmin)]
    if tmax:
        until_arg = ["--until", fmt(tmax)]

    # last
    cmd = ["last", "-F", "-w", "-i"]
    if since_arg: cmd += since_arg
    if until_arg: cmd += until_arg
    rc, out, err = run_cmd(cmd)
    write_out("last", (out if out else "") + (("\n[stderr]\n"+err) if err else "")) if rc != 127 else None

    # lastb (failed logins)
    cmdb = ["lastb", "-F", "-w", "-i"]
    if since_arg: cmdb += since_arg
    if until_arg: cmdb += until_arg
    rcb, outb, errb = run_cmd(cmdb)
    if rcb != 127:
        write_out("lastb", (outb if outb else "") + (("\n[stderr]\n"+errb) if errb else ""))

    # lastlog (per-account last login)
    rcl, outl, errl = run_cmd(["lastlog"])
    if rcl != 127:
        write_out("lastlog", (outl if outl else "") + (("\n[stderr]\n"+errl) if errl else ""))

    # utmpdump for raw binary files if available
    for label, path in [("wtmp", "/var/log/wtmp"), ("btmp", "/var/log/btmp")]:
        if Path(path).exists():
            rcu, outu, erru = run_cmd(["utmpdump", path])
            if rcu != 127:
                write_out(f"utmpdump_{label}", (outu if outu else "") + (("\n[stderr]\n"+erru) if erru else ""))

def export_journal(staging_root: Path, tmin: Optional[float], tmax: Optional[float]):
    """
    Export systemd journal in text and NDJSON (one object per line) if journalctl exists.
    Honors time window when provided.
    """
    rc, _, _ = run_cmd(["journalctl", "--version"])
    if rc == 127:
        return
    exp_dir = staging_root / "parsed" / "journal"
    exp_dir.mkdir(parents=True, exist_ok=True)

    args_time = []
    def fmt(dt: float) -> str:
        return datetime.datetime.fromtimestamp(dt).strftime("%Y-%m-%d %H:%M:%S")
    if tmin:
        args_time += ["--since", fmt(tmin)]
    if tmax:
        args_time += ["--until", fmt(tmax)]

    # Text export
    rc1, out1, err1 = run_cmd(["journalctl", "-a"] + args_time)
    (exp_dir / "journal.txt").write_text((out1 if out1 else "") + (("\n[stderr]\n"+err1) if err1 else ""), encoding="utf-8", errors="ignore")

    # NDJSON (machine-parsable)
    rc2, out2, err2 = run_cmd(["journalctl", "-a", "-o", "json"] + args_time)
    (exp_dir / "journal.ndjson").write_text((out2 if out2 else "") + (("\n[stderr]\n"+err2) if err2 else ""), encoding="utf-8", errors="ignore")

def bundle_tar_gz(staging_root: Path, out_path: Path):
    out_path = out_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out_path, "w:gz") as tar:
        tar.add(staging_root, arcname=staging_root.name)

# ---------------------------- Main ----------------------------

def main():
    ap = argparse.ArgumentParser(description="Linux artifacts scraper (for IR/forensics).")
    ap.add_argument("--from", dest="time_from", help="Start of mtime window (e.g. '2025-09-01 00:00')", default=None)
    ap.add_argument("--to", dest="time_to", help="End of mtime window (e.g. '2025-10-03 23:59')", default=None)
    ap.add_argument("--user", help="Username whose home and shell files to scrape", default=None)
    ap.add_argument("--home", help="Explicit home directory path (overrides --user)", default=None)
    ap.add_argument("--out", help="Output tar.gz path", default=f"./linux_artifacts_{NOW_STR}.tar.gz")
    ap.add_argument("--max-mb", type=int, default=DEFAULT_MAX_FILE_SIZE_MB, help="Per-file size cap in MB")
    ap.add_argument("--no-time-filter", action="store_true", help="Ignore time window, collect all")
    ap.add_argument("--include-all-proc", action="store_true",
                    help="Aggressive: walk most of /proc (may be huge/noisy). By default we snapshot a curated subset.")
    # Optional parsers/exports
    ap.add_argument("--export-logins", action="store_true", help="Export human-readable login timelines (last/lastb/lastlog/utmpdump).")
    ap.add_argument("--export-journal", action="store_true", help="Export journalctl text + NDJSON (honors --from/--to).")

    args = ap.parse_args()

    tmin = parse_dt(args.time_from) if (args.time_from and not args.no_time_filter) else None
    tmax = parse_dt(args.time_to) if (args.time_to and not args.no_time_filter) else None

    staging_root = Path(f"./_artifacts_staging_{NOW_STR}").resolve()
    if staging_root.exists():
        shutil.rmtree(staging_root)
    staging_root.mkdir(parents=True, exist_ok=True)

    meta = {
        "utc_now": NOW_STR,
        "host": os.uname().nodename if hasattr(os, "uname") else "",
        "kernel": uname_r(),
        "time_window": {
            "from": args.time_from if tmin else None,
            "to": args.time_to if tmax else None,
            "mode": "mtime"
        },
        "max_mb_per_file": args.max_mb,
        "run_as_euid": os.geteuid() if hasattr(os, "geteuid") else "n/a",
        "include_all_proc": bool(args.include_all_proc),
        "export_logins": bool(args.export_logins),
        "export_journal": bool(args.export_journal),
    }
    (staging_root / "SCRAPE_METADATA.txt").write_text(
        "\n".join(f"{k}: {v}" for k, v in meta.items()),
        encoding="utf-8", errors="ignore"
    )

    # 1. /proc snapshot
    if args.include_all_proc:
        add_tree(Path("/proc"), staging_root, tmin, tmax, args.max_mb, follow_symlinks=False, depth_limit=5)
    else:
        snapshot_proc(staging_root, tmin, tmax, args.max_mb)

    # 2. systemd units/config & journals
    for d in SYSTEMD_DIRS:
        add_path_to_staging(Path(d), staging_root, tmin, tmax, args.max_mb)
    for d in SYSTEMD_JOURNAL_DIRS:
        add_path_to_staging(Path(d), staging_root, tmin, tmax, max_mb=max(4096, args.max_mb))

    # 3. Sensitive files
    for s in SENSITIVE_FILES:
        add_path_to_staging(Path(s), staging_root, tmin, tmax, args.max_mb)

    # 4. Startup/login/logout logs
    for s in STARTUP_LOGIN_LOGS:
        add_path_to_staging(Path(s), staging_root, tmin, tmax, max_mb=max(2048, args.max_mb))

    # 5. Extended logs (syslog/kern/messages/audit/pm etc.)
    collect_extended_logs(staging_root, tmin, tmax, args.max_mb)

    # 6. Shell files: detect top 3 shells; collect global + per-user
    shells = detect_shells()
    (staging_root / "shells_detected.txt").write_text("\n".join(shells) + "\n", encoding="utf-8", errors="ignore")

    user_name, user_home = discover_user_home(args)
    collect_shell_configs(staging_root, user_home, shells, tmin, tmax, args.max_mb)

    # 7. Histories/SSH 
    collect_histories(staging_root, user_home, tmin, tmax, args.max_mb)

    # 8. Optionally scrape *all* files from a user's home
    if user_home and user_home.exists():
        add_tree(user_home, staging_root, tmin, tmax, args.max_mb, follow_symlinks=False)

    # 9. XDG locations
    add_path_to_staging(Path(ETC_XDG), staging_root, tmin, tmax, args.max_mb)
    if user_home:
        for d in [user_home / ".config", user_home / ".local/share", user_home / ".cache"]:
            add_path_to_staging(d, staging_root, tmin, tmax, args.max_mb)

    # 10. /etc/ssh
    add_path_to_staging(Path(SSH_DIR), staging_root, tmin, tmax, args.max_mb)

    # 11. Environment variables (current + per-process where readable)
    dump_envs(staging_root)

    # 12. Foreign LKMs report
    detect_foreign_lkms(staging_root / "kernel" / "foreign_lkms_report.tsv")

    # 13. Extra small goodies
    extras = [
        "/etc/os-release",
        "/etc/issue",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/etc/fstab",
        "/etc/mtab",
        "/etc/cron.d",
        "/etc/crontab",
        "/var/spool/cron",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/sysctl.conf",
        "/etc/sysctl.d",
        "/etc/modprobe.d",
        "/etc/NetworkManager",
        "/etc/nsswitch.conf",
        "/etc/hosts.allow",
        "/etc/hosts.deny",
        "/var/lib/systemd/coredump",
        "/var/lib/systemd/timers",
        "/var/lib/dpkg/status",
        "/var/lib/rpm",
        "/var/lib/pacman/local",
        "/var/lib/containers",
        "/etc/containers",
        "/var/lib/docker/containers",
        "/etc/docker/daemon.json",
        "/var/lib/machines",
    ]
    for e in extras:
        add_path_to_staging(Path(e), staging_root, tmin, tmax, args.max_mb)

    # 13. Optional exports/parsers
    if args.export_logins:
        export_logins_human_readable(staging_root, tmin, tmax)
    if args.export_journal:
        export_journal(staging_root, tmin, tmax)

    # Bundle
    out_path = Path(args.out)
    bundle_tar_gz(staging_root, out_path)
    print(f"[+] Artifacts bundled to: {out_path}")
    print(f"[i] Staging folder kept for inspection: {staging_root}")

if __name__ == "__main__":
    main()

