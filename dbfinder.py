#!/usr/bin/env python3
"""DBFinder v1.0 — find a forgotten MySQL database name and location.

Run this on the PC that hosts the database. It is READ-ONLY: it never
modifies, deletes, or writes into any database folder. The only file it
ever writes is the report you explicitly export.

What it does:
  1. Lists MySQL / MariaDB Windows services (name, state, ImagePath).
  2. Finds mysqld.exe / mysql.exe, my.ini / my.cnf files, and reads the
     datadir / port out of them.
  3. Lists every database folder inside each datadir, with size, file
     counts (.frm / .ibd / .myd / .myi) and last-modified date.
  4. "Connection String Hunter": scans .config / .ini / .cs / .vb and
     similar files for server= / database= / user= details. Passwords
     are ALWAYS masked (shown as ***) and never saved.
  5. Optional "Live Check": runs SHOW DATABASES through mysql.exe with
     credentials you type (never stored, never written to disk).
  6. Bonus: lists SQL Server services and .mdf / .ldf files, in case the
     "SQL" on the PC is actually SQL Server (common with VS2010 apps).

Usage:
  GUI:      py dbfinder.py            (double-click, or run the .exe)
  CLI scan: py dbfinder.py --scan
  CLI + report file: py dbfinder.py --scan --report report.txt
  CLI + hunt a folder: py dbfinder.py --scan --hunt "C:\\Users\\Me\\Documents"

Stdlib only — no pip dependencies. No network access except a localhost
check on port 3306. No multiprocessing.
"""

import argparse
import datetime
import fnmatch
import glob
import os
import platform
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading

APP_NAME = "DBFinder"
APP_VERSION = "1.0.0"

IS_WINDOWS = platform.system() == "Windows"

try:
    import winreg  # Windows only; None everywhere else.
except ImportError:  # pragma: no cover - non-Windows
    winreg = None

# On Windows the app is built --windowed (no console of its own), so every
# child console program (sc, where) would pop up its OWN visible terminal
# window. CREATE_NO_WINDOW keeps them all hidden.
_NO_WINDOW = (
    {"creationflags": subprocess.CREATE_NO_WINDOW}
    if IS_WINDOWS else {}
)

# Databases MySQL ships with — everything else is a user database.
SYSTEM_DBS = {"mysql", "information_schema", "performance_schema", "sys"}

# File types that live inside a MySQL database folder.
DB_EXTENSIONS = (".frm", ".ibd", ".myd", ".myi")

# File types the Connection String Hunter reads (plain text only).
HUNT_EXTENSIONS = {
    ".config", ".ini", ".txt", ".xml", ".cs", ".vb",
    ".sln", ".csproj", ".vbproj", ".properties", ".env",
}

# Safety caps so a scan of a big drive always finishes quickly.
_MAX_HUNT_FILES = 5000       # max files read per hunt folder
_MAX_HUNT_BYTES = 2 * 1024 * 1024  # skip files bigger than 2 MB
_MAX_STRAY_HITS = 50         # max stray .frm/.ibd files reported
_MAX_STRAY_DIRS = 3000       # max directories walked in a stray search


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _run_hidden(cmd, timeout=20):
    """Run a child program with no visible console window (Windows).

    Returns (returncode, stdout_text). Never raises: failures come back
    as (-1, "") so one broken helper cannot kill the whole scan.
    """
    try:
        out = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, text=True, errors="ignore", **_NO_WINDOW,
        )
        return out.returncode, out.stdout or ""
    except Exception:
        return -1, ""


def _fmt_size(num_bytes):
    """Human-readable size, e.g. 1536 -> '1.5 KB'."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024.0:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.1f} PB"


def _fmt_time(epoch):
    """Epoch seconds -> 'YYYY-MM-DD HH:MM' (local time), or '-'."""
    if not epoch:
        return "-"
    try:
        return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return "-"


def _env(name, default=""):
    return os.environ.get(name, default) or default


def _program_files():
    return _env("ProgramFiles", r"C:\Program Files")


def _program_files_x86():
    return _env("ProgramFiles(x86)", r"C:\Program Files (x86)")


def _program_data():
    return _env("ProgramData", r"C:\ProgramData")


def _windows_dir():
    return _env("SystemRoot", r"C:\Windows")


# ---------------------------------------------------------------------------
# Password masking — passwords must NEVER be displayed or saved.
# ---------------------------------------------------------------------------

# Matches: password=secret / pwd="secret" / passwd: secret / "password": "x"
# The optional quote in group 2 covers the JSON form ("password": "x").
_PASSWORD_RE = re.compile(
    r"(password|pwd|passwd)([\"']?\s*[=:]\s*[\"']?)([^;\"'\s]+)",
    re.IGNORECASE,
)


def mask_passwords(text):
    """Replace every password value in `text` with ***.

    Applied to connection strings AND as a final safety net over the
    whole exported report, so a password can never leak into a file.
    """
    if not text:
        return text
    return _PASSWORD_RE.sub(lambda m: m.group(1) + m.group(2) + "***", text)


# ---------------------------------------------------------------------------
# my.ini / my.cnf parsing
# ---------------------------------------------------------------------------

# A setting line looks like:  datadir=C:/ProgramData/MySQL/.../Data
# Keys are case-insensitive; quotes and trailing comments are stripped.
_INI_KEY_RE = re.compile(r"^\s*([A-Za-z_][\w-]*)\s*=\s*(.*?)\s*$")


def parse_my_ini(path):
    """Parse one my.ini / my.cnf file.

    Returns {"path":..., "datadir":...|None, "port":...|None,
    "basedir":...|None}. Only the [mysqld] section is read — a datadir
    anywhere else would be misleading. Never raises.
    """
    result = {"path": path, "datadir": None, "port": None, "basedir": None}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            in_mysqld = False
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("["):
                    # A new [section] — only [mysqld] counts from here.
                    in_mysqld = line.lower().startswith("[mysqld]")
                    continue
                if not in_mysqld:
                    continue
                m = _INI_KEY_RE.match(line)
                if not m:
                    continue
                key, value = m.group(1).lower(), m.group(2)
                # Strip inline comments and surrounding quotes.
                value = re.split(r"\s*[#;]", value, maxsplit=1)[0].strip()
                value = value.strip("\"'")
                if key in ("datadir", "port", "basedir") and value:
                    result[key] = value
    except OSError:
        pass
    return result


def _ini_search_roots(extra_roots=None):
    """Directories that may hold a my.ini / my.cnf (Windows layout)."""
    roots = [
        os.path.join(_program_data(), "MySQL"),
        os.path.join(_program_files(), "MySQL"),
        os.path.join(_program_files_x86(), "MySQL"),
        _windows_dir(),
        r"C:\MySQL",
        r"C:\xampp\mysql",
    ]
    # WAMP keeps one MySQL install per version: C:\wamp64\bin\mysql\mysql8.x
    roots.extend(glob.glob(r"C:\wamp*\bin\mysql"))
    roots.extend(glob.glob(r"C:\wamp*\bin\mariadb"))
    if extra_roots:
        roots.extend(extra_roots)
    return roots


def find_my_ini_files(extra_roots=None):
    """Find my.ini / my.cnf files and parse each one.

    Returns a list of parse_my_ini() dicts, de-duplicated by path.
    `extra_roots` lets tests point the search at a fake layout.
    """
    found = {}
    for root in _ini_search_roots(extra_roots):
        if not root or not os.path.isdir(root):
            continue
        # my.ini sits either directly in the root or one level down
        # (e.g. ProgramData\MySQL\MySQL Server 5.7\my.ini).
        candidates = glob.glob(os.path.join(root, "my.ini"))
        candidates += glob.glob(os.path.join(root, "my.cnf"))
        candidates += glob.glob(os.path.join(root, "*", "my.ini"))
        candidates += glob.glob(os.path.join(root, "*", "my.cnf"))
        # XAMPP / WAMP also keep it in bin/.
        candidates += glob.glob(os.path.join(root, "bin", "my.ini"))
        candidates += glob.glob(os.path.join(root, "*", "bin", "my.ini"))
        for path in candidates:
            key = os.path.normcase(os.path.abspath(path))
            if key not in found:
                found[key] = parse_my_ini(path)
    return sorted(found.values(), key=lambda d: d["path"])


# ---------------------------------------------------------------------------
# Datadir inspection (read-only: only os.scandir / stat, never writes)
# ---------------------------------------------------------------------------

def list_databases(datadir):
    """List the databases inside one MySQL datadir.

    Every subfolder is one database. Returns a list of dicts:
    name, path, size_bytes, counts {frm, ibd, myd, myi}, files (total),
    modified (epoch of newest file), system (True for built-in DBs).
    Missing/unreadable datadirs return [].
    """
    databases = []
    if not datadir or not os.path.isdir(datadir):
        return databases
    try:
        entries = list(os.scandir(datadir))
    except OSError:
        return databases
    for entry in entries:
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        counts = {ext: 0 for ext in DB_EXTENSIONS}
        total_files = 0
        total_size = 0
        newest = 0
        # A database folder is normally flat, but walk it anyway — some
        # installs nest table files one level down.
        for dirpath, _dirnames, filenames in os.walk(entry.path):
            for fname in filenames:
                total_files += 1
                fpath = os.path.join(dirpath, fname)
                try:
                    st = os.stat(fpath)
                except OSError:
                    continue
                total_size += st.st_size
                if st.st_mtime > newest:
                    newest = st.st_mtime
                ext = os.path.splitext(fname)[1].lower()
                if ext in counts:
                    counts[ext] += 1
        databases.append({
            "name": entry.name,
            "path": entry.path,
            "size_bytes": total_size,
            "counts": counts,
            "files": total_files,
            "modified": newest,
            "system": entry.name.lower() in SYSTEM_DBS,
        })
    databases.sort(key=lambda d: (d["system"], d["name"].lower()))
    return databases


def inspect_datadir(datadir):
    """Describe one datadir: its databases plus InnoDB markers.

    ibdata1 / ib_logfile* at the datadir root confirm this is a real,
    live MySQL data folder and not an old copy.
    """
    dbs = list_databases(datadir)
    has_ibdata = os.path.isfile(os.path.join(datadir, "ibdata1"))
    ib_logs = sorted(
        f for f in ("ib_logfile0", "ib_logfile1", "ib_logfile2")
        if os.path.isfile(os.path.join(datadir, f))
    )
    return {
        "path": datadir,
        "databases": dbs,
        "ibdata1": has_ibdata,
        "ib_logfiles": ib_logs,
    }


def search_stray_db_files(roots, max_hits=_MAX_STRAY_HITS,
                          max_dirs=_MAX_STRAY_DIRS):
    """Bounded search for stray .frm / .ibd files (no datadir found).

    Only used as a fallback. Walks `roots` to a limited depth/dir count
    and returns the parent folders that hold table files — each one is
    a possible database folder. Skips Windows/system dirs for speed.
    """
    skip = {"windows", "$recycle.bin", "system volume information"}
    hits = []
    seen = set()
    dirs_walked = 0
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirs_walked += 1
            if dirs_walked > max_dirs or len(hits) >= max_hits:
                return hits
            # Prune system dirs and don't descend deeper than 6 levels.
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in skip and not d.startswith(".")
            ]
            if dirpath.count(os.sep) - root.count(os.sep) > 6:
                dirnames[:] = []
                continue
            for fname in filenames:
                if fname.lower().endswith((".frm", ".ibd")):
                    key = os.path.normcase(dirpath)
                    if key not in seen:
                        seen.add(key)
                        hits.append(dirpath)
                    break
    return hits


# ---------------------------------------------------------------------------
# Windows services (MySQL/MariaDB + SQL Server)
# ---------------------------------------------------------------------------

def _service_image_path(service_name):
    """Read a service's ImagePath from the registry (Windows only)."""
    if winreg is None:
        return ""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\%s" % service_name,
        )
        value, _kind = winreg.QueryValueEx(key, "ImagePath")
        winreg.CloseKey(key)
        return value or ""
    except OSError:
        return ""


def list_windows_services(keywords):
    """List Windows services whose name mentions any of `keywords`.

    Uses `sc query state= all` (one hidden call) and enriches each match
    with its ImagePath from the registry. Returns a list of dicts:
    name, display, state, image_path. Returns [] off Windows.
    """
    if not IS_WINDOWS:
        return []
    _rc, out = _run_hidden(["sc", "query", "state=", "all"], timeout=30)
    services = []
    current = None
    # `sc query` prints one block per service: SERVICE_NAME, DISPLAY_NAME,
    # then a STATE line like "STATE : 4  RUNNING".
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("SERVICE_NAME:"):
            if current is not None:
                services.append(current)
            current = {
                "name": stripped.split(":", 1)[1].strip(),
                "display": "", "state": "", "image_path": "",
            }
        elif current is not None and stripped.startswith("DISPLAY_NAME:"):
            current["display"] = stripped.split(":", 1)[1].strip()
        elif current is not None and stripped.startswith("STATE"):
            parts = stripped.split(":", 1)[1].strip().split()
            current["state"] = parts[-1] if parts else ""
    if current is not None:
        services.append(current)
    keywords = [k.lower() for k in keywords]
    matches = [
        s for s in services
        if any(k in s["name"].lower() or k in s["display"].lower()
               for k in keywords)
    ]
    for svc in matches:
        svc["image_path"] = _service_image_path(svc["name"])
    return matches


def find_mysql_services():
    return list_windows_services(["mysql", "mariadb"])


def find_sqlserver_services():
    return list_windows_services(["mssql", "sql server", "sqlexpress"])


# ---------------------------------------------------------------------------
# Binaries, host info, port check, SQL Server files
# ---------------------------------------------------------------------------

def find_mysql_binaries():
    """Find mysqld.exe / mysql.exe via PATH and common install dirs."""
    found = {}
    for exe in ("mysqld", "mysql", "mariadbd"):
        path = shutil.which(exe + (".exe" if IS_WINDOWS else ""))
        if path:
            found[os.path.normcase(os.path.abspath(path))] = path
    patterns = [
        os.path.join(_program_files(), "MySQL", "*", "bin", "mysqld.exe"),
        os.path.join(_program_files(), "MySQL", "*", "bin", "mysql.exe"),
        os.path.join(_program_files_x86(), "MySQL", "*", "bin", "mysqld.exe"),
        os.path.join(_program_files_x86(), "MySQL", "*", "bin", "mysql.exe"),
        os.path.join(_program_data(), "MySQL", "*", "bin", "mysqld.exe"),
        r"C:\MySQL\bin\mysqld.exe",
        r"C:\MySQL\bin\mysql.exe",
        r"C:\xampp\mysql\bin\mysqld.exe",
        r"C:\xampp\mysql\bin\mysql.exe",
        r"C:\wamp*\bin\mysql\*\bin\mysqld.exe",
        r"C:\wamp*\bin\mysql\*\bin\mysql.exe",
        r"C:\wamp*\bin\mariadb\*\bin\mariadbd.exe",
    ]
    for pattern in patterns:
        for path in glob.glob(pattern):
            found[os.path.normcase(os.path.abspath(path))] = path
    return sorted(found.values())


def get_host_info():
    """Hostname + local LAN IP (UDP trick: opens no real connection)."""
    hostname = socket.gethostname()
    lan_ip = ""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # No packet is ever sent; connect() just picks the route.
            probe.connect(("8.8.8.8", 80))
            lan_ip = probe.getsockname()[0]
        finally:
            probe.close()
    except OSError:
        pass
    if not lan_ip:
        try:
            lan_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            lan_ip = ""
    return {"hostname": hostname, "lan_ip": lan_ip}


def check_port_3306(timeout=2):
    """True if something answers on localhost:3306 (MySQL default)."""
    try:
        with socket.create_connection(("127.0.0.1", 3306), timeout=timeout):
            return True
    except OSError:
        return False


def find_sqlserver_data_files():
    """Find .mdf / .ldf files under SQL Server DATA dirs (top level).

    Returns a list of {"path", "size_bytes", "kind"} — kind is DATA
    (.mdf) or LOG (.ldf). Only the standard DATA folders are checked,
    so this stays fast even on a full drive.
    """
    found = []
    patterns = [
        os.path.join(_program_files(), "Microsoft SQL Server",
                     "MSSQL*", "MSSQL", "DATA"),
        os.path.join(_program_files_x86(), "Microsoft SQL Server",
                     "MSSQL*", "MSSQL", "DATA"),
    ]
    for pattern in patterns:
        for data_dir in glob.glob(pattern):
            if not os.path.isdir(data_dir):
                continue
            try:
                entries = list(os.scandir(data_dir))
            except OSError:
                continue
            for entry in entries:
                lower = entry.name.lower()
                if not (lower.endswith(".mdf") or lower.endswith(".ldf")):
                    continue
                try:
                    size = entry.stat().st_size
                except OSError:
                    size = 0
                found.append({
                    "path": entry.path,
                    "size_bytes": size,
                    "kind": "LOG" if lower.endswith(".ldf") else "DATA",
                })
    return sorted(found, key=lambda f: f["path"])


# ---------------------------------------------------------------------------
# Connection String Hunter
# ---------------------------------------------------------------------------

# Keys we care about in a connection string, normalised to one name each.
_CONN_KEY_ALIASES = {
    "server": "server", "data source": "server", "host": "server",
    "datasource": "server", "address": "server", "network address": "server",
    "database": "database", "initial catalog": "database",
    "db": "database", "dbname": "database",
    "uid": "user", "user id": "user", "user": "user", "username": "user",
    "port": "port",
}

# A connection string looks like key=value;key=value — grab the whole
# run of such pairs so one .config line yields one result, not five.
_CONN_RUN_RE = re.compile(
    r"(?:[A-Za-z][\w ]{0,20}\s*=\s*[^;\"'\n]{1,120}\s*;\s*){1,}"
    r"[A-Za-z][\w ]{0,20}\s*=\s*[^;\"'\n]{1,120}",
)
_PAIR_RE = re.compile(r"([A-Za-z][\w ]{0,20})\s*=\s*([^;]+)")


def parse_connection_string(text):
    """Parse one connection-string run into {server, database, user, port}.

    Returns None unless it has at least a server-ish key AND a
    database-ish key — that keeps random 'key=value' lines out.
    """
    pairs = {}
    for raw_key, raw_value in _PAIR_RE.findall(text):
        key = raw_key.strip().lower()
        norm = _CONN_KEY_ALIASES.get(key)
        if norm and norm not in pairs:
            pairs[norm] = raw_value.strip().strip("\"'")
    if "server" not in pairs or "database" not in pairs:
        return None
    return {
        "server": pairs.get("server", ""),
        "database": pairs.get("database", ""),
        "user": pairs.get("user", ""),
        "port": pairs.get("port", ""),
    }


def scan_text_for_connection_strings(text):
    """Yield (parsed_dict, masked_string) for each string in `text`."""
    for match in _CONN_RUN_RE.finditer(text):
        run = match.group(0).strip()
        parsed = parse_connection_string(run)
        if parsed:
            yield parsed, mask_passwords(run)


def scan_folder_for_connection_strings(folder, max_files=_MAX_HUNT_FILES):
    """Recursively hunt connection strings under `folder`.

    Only reads small plain-text files with a known extension. Returns a
    list of dicts: file, line, server, database, user, port, masked.
    Passwords are masked before anything is stored or shown.
    """
    results = []
    if not folder or not os.path.isdir(folder):
        return results
    files_read = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        # Skip bulky / irrelevant trees: build output, packages, .git.
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in {
                "bin", "obj", "node_modules", ".git", ".vs", "packages",
                "__pycache__",
            } and not d.startswith(".")
        ]
        for fname in filenames:
            if files_read >= max_files:
                return results
            if os.path.splitext(fname)[1].lower() not in HUNT_EXTENSIONS:
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(fpath) > _MAX_HUNT_BYTES:
                    continue
            except OSError:
                continue
            files_read += 1
            try:
                with open(fpath, "r", encoding="utf-8",
                          errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for parsed, masked in scan_text_for_connection_strings(text):
                # Line number: first line holding the database name.
                line_no = 1
                for i, line in enumerate(text.splitlines(), 1):
                    if parsed["database"] and parsed["database"] in line:
                        line_no = i
                        break
                results.append({
                    "file": fpath, "line": line_no,
                    "server": parsed["server"],
                    "database": parsed["database"],
                    "user": parsed["user"],
                    "port": parsed["port"],
                    "masked": masked,
                })
    return results


def suggested_hunt_folders():
    """Likely places for a VS2010 project / app folder (Windows)."""
    user_profile = _env("USERPROFILE", "")
    docs = os.path.join(user_profile, "Documents") if user_profile else ""
    suggestions = []
    if docs:
        suggestions.append(
            os.path.join(docs, "Visual Studio 2010", "Projects"))
        suggestions.append(docs)
    if user_profile:
        suggestions.append(os.path.join(user_profile, "Desktop"))
    suggestions.append(os.getcwd())
    return [s for s in suggestions if s]


# ---------------------------------------------------------------------------
# Live Check — SHOW DATABASES through mysql.exe (credentials never stored)
# ---------------------------------------------------------------------------

def run_live_check(host, port, user, password, mysql_exe):
    """Run SHOW DATABASES via mysql.exe.

    The password travels only in the child process ENVIRONMENT
    (MYSQL_PWD), never on the command line and never to disk.
    Returns (ok, databases_or_error_message).
    """
    if not mysql_exe or not os.path.isfile(mysql_exe):
        return False, "mysql.exe not found — cannot run a live check."
    env = dict(os.environ)
    env["MYSQL_PWD"] = password  # mysql.exe reads this; argv stays clean.
    cmd = [mysql_exe, "-h", host, "-P", str(port), "-u", user,
           "-N", "-e", "SHOW DATABASES;"]
    try:
        out = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=20, text=True, errors="ignore", env=env, **_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        return False, "Timed out talking to the MySQL server."
    except OSError as exc:
        return False, f"Could not start mysql.exe: {exc}"
    text = (out.stdout or "").strip()
    if out.returncode != 0:
        # mysql.exe prints its own error (e.g. Access denied) — pass it
        # through, but masked, in case it ever echoes the password back.
        return False, mask_passwords(text or "mysql.exe failed.")
    dbs = [line.strip() for line in text.splitlines() if line.strip()]
    return True, dbs


# ---------------------------------------------------------------------------
# Full scan + report
# ---------------------------------------------------------------------------

def run_scan(hunt_folder=None, extra_myini_roots=None):
    """Run every read-only check and return one findings dict.

    `hunt_folder` (optional) is also scanned for connection strings.
    `extra_myini_roots` is for tests — it adds my.ini search roots.
    """
    host = get_host_info()
    findings = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": host["hostname"],
        "lan_ip": host["lan_ip"],
        "port_3306_open": check_port_3306(),
        "mysql_services": find_mysql_services(),
        "sqlserver_services": find_sqlserver_services(),
        "binaries": find_mysql_binaries(),
        "ini_files": find_my_ini_files(extra_myini_roots),
        "datadirs": [],
        "stray_db_folders": [],
        "sqlserver_files": find_sqlserver_data_files(),
        "conn_strings": [],
    }

    # Every datadir from every my.ini, plus the well-known defaults.
    datadir_paths = []
    for ini in findings["ini_files"]:
        if ini.get("datadir"):
            datadir_paths.append(ini["datadir"])
    datadir_paths.append(
        os.path.join(_program_data(), "MySQL", "MySQL Server 5.7", "Data"))
    datadir_paths.append(
        os.path.join(_program_data(), "MySQL", "MySQL Server 5.6", "Data"))
    datadir_paths.append(
        os.path.join(_program_data(), "MySQL", "MySQL Server 5.5", "Data"))
    datadir_paths.append(os.path.join(_program_data(), "MySQL", "Data"))
    datadir_paths.append(r"C:\xampp\mysql\data")
    datadir_paths.append(r"C:\MySQL\data")

    seen = set()
    for path in datadir_paths:
        if not path:
            continue
        key = os.path.normcase(os.path.abspath(path))
        if key in seen or not os.path.isdir(path):
            continue
        seen.add(key)
        findings["datadirs"].append(inspect_datadir(path))

    # No datadir at all? Fall back to a bounded search for stray tables.
    if not findings["datadirs"]:
        roots = [
            _program_data(), _program_files(), _program_files_x86(),
            r"C:\xampp", r"C:\wamp64", r"C:\wamp", r"C:\MySQL",
        ]
        findings["stray_db_folders"] = search_stray_db_files(roots)

    if hunt_folder:
        findings["conn_strings"] = \
            scan_folder_for_connection_strings(hunt_folder)
    return findings


def build_report(findings):
    """Render findings as plain text. Passwords are masked throughout."""
    lines = []
    add = lines.append
    add(f"{APP_NAME} {APP_VERSION} — Database Finder Report")
    add(f"Generated: {findings.get('generated_at', '-')}")
    add(f"Computer:  {findings.get('hostname', '-')}")
    add(f"LAN IP:    {findings.get('lan_ip', '-') or '-'}")
    add("")

    add("== MySQL server ==")
    if findings.get("port_3306_open"):
        add("Port 3306 (MySQL): LISTENING — a MySQL server is running.")
    else:
        add("Port 3306 (MySQL): not listening — no server on this PC, "
            "or it uses another port.")
    add("")

    add("== MySQL / MariaDB services ==")
    for svc in findings.get("mysql_services", []):
        add(f"  {svc['name']} ({svc.get('display') or '-'}) — "
            f"{svc.get('state') or '?'}")
        if svc.get("image_path"):
            add(f"      ImagePath: {svc['image_path']}")
    if not findings.get("mysql_services"):
        add("  (none found)")
    add("")

    add("== MySQL binaries ==")
    for path in findings.get("binaries", []):
        add(f"  {path}")
    if not findings.get("binaries"):
        add("  (mysqld.exe / mysql.exe not found)")
    add("")

    add("== my.ini / my.cnf files ==")
    for ini in findings.get("ini_files", []):
        add(f"  {ini['path']}")
        add(f"      datadir: {ini.get('datadir') or '-'}")
        add(f"      port:    {ini.get('port') or '-'}")
        add(f"      basedir: {ini.get('basedir') or '-'}")
    if not findings.get("ini_files"):
        add("  (none found)")
    add("")

    add("== Data folders and databases ==")
    for dd in findings.get("datadirs", []):
        add(f"  Data folder: {dd['path']}")
        markers = []
        if dd.get("ibdata1"):
            markers.append("ibdata1 present")
        if dd.get("ib_logfiles"):
            markers.append("log files: " + ", ".join(dd["ib_logfiles"]))
        add("      " + ("; ".join(markers) if markers
                        else "(no ibdata1 — may be an old copy)"))
        for db in dd.get("databases", []):
            kind = "SYSTEM" if db["system"] else "USER"
            c = db["counts"]
            add(f"      [{kind}] {db['name']} — "
                f"{_fmt_size(db['size_bytes'])}, {db['files']} files "
                f"(.frm {c['.frm']}, .ibd {c['.ibd']}, "
                f".myd {c['.myd']}, .myi {c['.myi']}), "
                f"modified {_fmt_time(db['modified'])}")
        if not dd.get("databases"):
            add("      (no database folders inside)")
    if not findings.get("datadirs"):
        add("  (no datadir found)")
        for folder in findings.get("stray_db_folders", []):
            add(f"  Possible database folder (stray .frm/.ibd): {folder}")
        if not findings.get("stray_db_folders"):
            add("  (no stray .frm/.ibd files found either)")
    add("")

    add("== SQL Server (bonus check) ==")
    for svc in findings.get("sqlserver_services", []):
        add(f"  Service: {svc['name']} "
            f"({svc.get('display') or '-'}) — {svc.get('state') or '?'}")
    for f in findings.get("sqlserver_files", []):
        add(f"  [{f['kind']}] {f['path']} — {_fmt_size(f['size_bytes'])}")
    if not findings.get("sqlserver_services") \
            and not findings.get("sqlserver_files"):
        add("  (no SQL Server services or .mdf/.ldf files found)")
    add("")

    add("== Connection strings found ==")
    for cs in findings.get("conn_strings", []):
        add(f"  File: {cs['file']} (line {cs['line']})")
        add(f"      server={cs['server']}; database={cs['database']}; "
            f"user={cs['user']}; port={cs['port'] or '(default)'}")
        add(f"      {cs['masked']}")
    if not findings.get("conn_strings"):
        add("  (none — use the Connection String Hunter tab, or "
            "--hunt <folder>)")
    add("")
    add("NOTE: This report never contains passwords (they are masked).")
    add("DBFinder is read-only: it never modifies a database folder.")
    # Final safety net: mask anything that slipped through.
    return mask_passwords("\n".join(lines)) + "\n"


# ---------------------------------------------------------------------------
# CLI mode (headless — no GUI, no display needed)
# ---------------------------------------------------------------------------

def cli_main(args):
    """--scan mode: print findings, optionally write a report file."""
    findings = run_scan(hunt_folder=args.hunt)
    report = build_report(findings)
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                fh.write(report)
            print(f"Report written to: {args.report}")
        except OSError as exc:
            print(f"ERROR: could not write report: {exc}", file=sys.stderr)
            return 1
    print(report)
    return 0


# ---------------------------------------------------------------------------
# GUI mode (tkinter is imported lazily so CLI works without a display)
# ---------------------------------------------------------------------------

def _mysql_exe_from_binaries(binaries):
    for path in binaries:
        if os.path.basename(path).lower() == "mysql.exe":
            return path
    return ""


class DBFinderApp:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        self.tk = tk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.ttk = ttk
        self.root = root
        self.findings = None
        self.scanning = False
        # Workers NEVER touch tkinter directly (only the main thread may).
        # They drop results in this queue; the main thread polls it with
        # after() — the same pattern ipcam-scanner uses.
        self.events = queue.Queue()

        root.title(f"{APP_NAME} {APP_VERSION} — Find a forgotten MySQL database")
        root.geometry("900x620")
        root.minsize(760, 480)

        top = ttk.Frame(root, padding=8)
        top.pack(fill="x")
        ttk.Button(top, text="Scan Now", command=self.start_scan).pack(
            side="left")
        ttk.Button(top, text="Export Report",
                   command=self.export_report).pack(side="left", padx=6)
        ttk.Button(top, text="Copy Summary",
                   command=self.copy_summary).pack(side="left")
        self.status = ttk.Label(top, text="Ready.")
        self.status.pack(side="left", padx=12)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._build_databases_tab()
        self._build_details_tab()
        self._build_hunter_tab()
        self._build_live_tab()

        # Auto-scan shortly after launch so results are already there.
        root.after(100, self._poll_events)
        root.after(300, self.start_scan)

    def _poll_events(self):
        """Main-thread pump: apply finished worker results to the UI."""
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "scan":
                    self._scan_done(event[1])
                elif kind == "hunt":
                    self._hunt_done(event[1])
                elif kind == "live":
                    self._live_done(event[1], event[2])
        except queue.Empty:
            pass
        # Keep polling while the window lives; after() on a dead root
        # raises TclError, which mainloop swallows on shutdown anyway.
        try:
            self.root.after(100, self._poll_events)
        except Exception:
            pass

    # -- tabs ---------------------------------------------------------------
    def _build_databases_tab(self):
        ttk = self.ttk
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Databases")
        hint = ttk.Label(
            tab, text="Each row is one database folder inside a MySQL "
                     "data folder. USER databases are yours; SYSTEM ones "
                     "ship with MySQL.")
        hint.pack(anchor="w", pady=(0, 6))
        cols = ("database", "type", "size", "files", "modified", "location")
        self.db_tree = ttk.Treeview(tab, columns=cols, show="headings")
        for col, width in (("database", 180), ("type", 70), ("size", 90),
                           ("files", 180), ("modified", 130),
                           ("location", 260)):
            self.db_tree.heading(col, text=col.replace("_", " ").title())
            self.db_tree.column(col, width=width)
        scroll = ttk.Scrollbar(tab, orient="vertical",
                               command=self.db_tree.yview)
        self.db_tree.configure(yscrollcommand=scroll.set)
        self.db_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        btns = ttk.Frame(tab)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="Open Data Folder",
                   command=self.open_datadir).pack(side="left")
        ttk.Label(btns, text="Opens the selected database's data folder "
                             "in Explorer.").pack(side="left", padx=8)

    def _build_details_tab(self):
        ttk = self.ttk
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Services & Files")
        self.details_text = self.tk.Text(tab, wrap="word", state="disabled")
        scroll = ttk.Scrollbar(tab, orient="vertical",
                               command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=scroll.set)
        self.details_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_hunter_tab(self):
        ttk = self.ttk
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Connection String Hunter")
        ttk.Label(tab, text="Scans .config / .ini / .cs / .vb files for "
                            "server= and database= details. Passwords are "
                            "always shown as ***.").pack(anchor="w")
        row = ttk.Frame(tab)
        row.pack(fill="x", pady=6)
        self.hunt_entry = ttk.Entry(row)
        self.hunt_entry.pack(side="left", fill="x", expand=True)
        suggestions = suggested_hunt_folders()
        if suggestions:
            self.hunt_entry.insert(0, suggestions[0])
        ttk.Button(row, text="Browse…",
                   command=self.browse_hunt_folder).pack(side="left", padx=6)
        ttk.Button(row, text="Hunt",
                   command=self.start_hunt).pack(side="left")
        cols = ("file", "server", "database", "user", "port")
        self.hunt_tree = ttk.Treeview(tab, columns=cols, show="headings")
        for col, width in (("file", 320), ("server", 150), ("database", 150),
                           ("user", 110), ("port", 60)):
            self.hunt_tree.heading(col, text=col.title())
            self.hunt_tree.column(col, width=width)
        scroll = ttk.Scrollbar(tab, orient="vertical",
                               command=self.hunt_tree.yview)
        self.hunt_tree.configure(yscrollcommand=scroll.set)
        self.hunt_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_live_tab(self):
        ttk = self.ttk
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Live Check")
        ttk.Label(tab, text="Runs SHOW DATABASES through mysql.exe. "
                            "Credentials are used once and never stored "
                            "or written to disk.").pack(anchor="w")
        form = ttk.Frame(tab)
        form.pack(fill="x", pady=8)
        self.live_host = ttk.Entry(form, width=22)
        self.live_host.insert(0, "127.0.0.1")
        self.live_port = ttk.Entry(form, width=8)
        self.live_port.insert(0, "3306")
        self.live_user = ttk.Entry(form, width=18)
        self.live_user.insert(0, "root")
        self.live_pass = ttk.Entry(form, width=22, show="*")
        for label, widget in (("Host:", self.live_host),
                              ("Port:", self.live_port),
                              ("User:", self.live_user),
                              ("Password:", self.live_pass)):
            ttk.Label(form, text=label).pack(side="left")
            widget.pack(side="left", padx=(2, 10))
        ttk.Button(form, text="Run Live Check",
                   command=self.start_live_check).pack(side="left")
        self.live_text = self.tk.Text(tab, wrap="word", state="disabled",
                                      height=12)
        self.live_text.pack(fill="both", expand=True)

    # -- scan ---------------------------------------------------------------
    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.status.config(text="Scanning… (services, my.ini, data folders)")
        self.db_tree.delete(*self.db_tree.get_children())
        thread = threading.Thread(target=self._scan_worker, daemon=True)
        thread.start()

    def _scan_worker(self):
        findings = run_scan()
        self.events.put(("scan", findings))

    def _scan_done(self, findings):
        self.findings = findings
        self.scanning = False
        user_dbs = 0
        for dd in findings["datadirs"]:
            for db in dd["databases"]:
                if not db["system"]:
                    user_dbs += 1
                c = db["counts"]
                self.db_tree.insert("", "end", values=(
                    db["name"], "SYSTEM" if db["system"] else "USER",
                    _fmt_size(db["size_bytes"]),
                    f".frm {c['.frm']}, .ibd {c['.ibd']}, "
                    f".myd {c['.myd']}, .myi {c['.myi']} "
                    f"({db['files']} files)",
                    _fmt_time(db["modified"]), dd["path"]))
        self._set_text(self.details_text, build_report(findings))
        if findings["datadirs"]:
            self.status.config(
                text=f"Found {len(findings['datadirs'])} data folder(s), "
                     f"{user_dbs} user database(s).")
        else:
            self.status.config(
                text="No datadir found — check the Services & Files tab "
                     "for stray folders and the Hunter tab.")
        # Keep the live-check port in sync with what my.ini said.
        for ini in findings["ini_files"]:
            if ini.get("port"):
                self.live_port.delete(0, "end")
                self.live_port.insert(0, ini["port"])
                break

    # -- hunter -------------------------------------------------------------
    def browse_hunt_folder(self):
        folder = self.filedialog.askdirectory(
            title="Pick a folder to hunt for connection strings")
        if folder:
            self.hunt_entry.delete(0, "end")
            self.hunt_entry.insert(0, folder)

    def start_hunt(self):
        folder = self.hunt_entry.get().strip()
        if not folder or not os.path.isdir(folder):
            self.messagebox.showwarning(
                "Pick a folder", "That folder does not exist.")
            return
        self.status.config(text=f"Hunting connection strings in {folder}…")
        thread = threading.Thread(target=self._hunt_worker, args=(folder,),
                                  daemon=True)
        thread.start()

    def _hunt_worker(self, folder):
        results = scan_folder_for_connection_strings(folder)
        self.events.put(("hunt", results))

    def _hunt_done(self, results):
        self.hunt_tree.delete(*self.hunt_tree.get_children())
        for cs in results:
            self.hunt_tree.insert("", "end", values=(
                f"{cs['file']} (line {cs['line']})", cs["server"],
                cs["database"], cs["user"], cs["port"]))
        if self.findings is not None:
            self.findings["conn_strings"] = results
            self._set_text(self.details_text, build_report(self.findings))
        self.status.config(
            text=f"Hunt done: {len(results)} connection string(s) found.")

    # -- live check ---------------------------------------------------------
    def start_live_check(self):
        if not self.findings:
            self.messagebox.showinfo("Wait for the scan",
                                     "Let the first scan finish, then try.")
            return
        mysql_exe = _mysql_exe_from_binaries(self.findings["binaries"])
        if not mysql_exe:
            self.messagebox.showwarning(
                "mysql.exe not found",
                "No mysql.exe was found on this PC, so a live check is "
                "not possible. The file-based results above are still valid.")
            return
        host = self.live_host.get().strip() or "127.0.0.1"
        try:
            port = int(self.live_port.get().strip() or "3306")
        except ValueError:
            self.messagebox.showwarning("Bad port", "Port must be a number.")
            return
        user = self.live_user.get().strip() or "root"
        password = self.live_pass.get()
        self._set_text(self.live_text, "Contacting MySQL…\n")
        thread = threading.Thread(
            target=self._live_worker,
            args=(host, port, user, password, mysql_exe), daemon=True)
        thread.start()

    def _live_worker(self, host, port, user, password, mysql_exe):
        ok, result = run_live_check(host, port, user, password, mysql_exe)
        self.events.put(("live", ok, result))

    def _live_done(self, ok, result):
        if ok:
            lines = ["Live databases (SHOW DATABASES):\n"]
            lines += [f"  - {name}" for name in result] or ["  (none)"]
            if self.findings:
                file_names = {
                    db["name"]
                    for dd in self.findings["datadirs"]
                    for db in dd["databases"]
                }
                live_only = [n for n in result if n not in file_names]
                file_only = [n for n in file_names if n not in result]
                if live_only:
                    lines.append("\nOnly live (not in the folders scanned): "
                                 + ", ".join(live_only))
                if file_only:
                    lines.append("\nOnly in folders (not live — maybe "
                                 "another datadir): " + ", ".join(file_only))
            self._set_text(self.live_text, "\n".join(lines) + "\n")
            self.status.config(text="Live check OK.")
        else:
            self._set_text(self.live_text, f"Live check failed:\n{result}\n")
            self.status.config(text="Live check failed — see the tab.")

    # -- actions ------------------------------------------------------------
    def open_datadir(self):
        selected = self.db_tree.selection()
        if not selected:
            self.messagebox.showinfo("Select a database",
                                     "Click a database row first.")
            return
        location = self.db_tree.item(selected[0], "values")[5]
        if not os.path.isdir(location):
            self.messagebox.showwarning("Folder missing",
                                        f"Not found: {location}")
            return
        try:
            if IS_WINDOWS:
                os.startfile(location)  # noqa: S606 — user-chosen folder
            elif sys.platform == "darwin":
                subprocess.run(["open", location], **_NO_WINDOW)
            else:
                subprocess.run(["xdg-open", location], **_NO_WINDOW)
        except OSError as exc:
            self.messagebox.showwarning("Could not open", str(exc))

    def export_report(self):
        if not self.findings:
            self.messagebox.showinfo("Nothing yet",
                                     "Wait for the scan to finish first.")
            return
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
        path = self.filedialog.asksaveasfilename(
            title="Export report",
            defaultextension=".txt",
            initialfile=f"dbfinder-report-{stamp}.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(build_report(self.findings))
        except OSError as exc:
            self.messagebox.showerror("Could not save", str(exc))
            return
        self.status.config(text=f"Report saved to {path}")

    def copy_summary(self):
        if not self.findings:
            self.messagebox.showinfo("Nothing yet",
                                     "Wait for the scan to finish first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(build_report(self.findings))
        self.status.config(text="Summary copied to clipboard.")

    def _set_text(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")


def gui_main():
    """Start the Tkinter GUI. Returns an exit code."""
    try:
        import tkinter as tk
    except ImportError as exc:
        print(f"GUI needs tkinter, which is not installed here ({exc}).")
        print("Use the terminal scan instead:")
        print("  python dbfinder.py --scan --report report.txt")
        return 1
    try:
        root = tk.Tk()
    except Exception as exc:
        print(f"Could not open a window ({exc}).")
        print("Use the terminal scan instead:")
        print("  python dbfinder.py --scan --report report.txt")
        return 1
    DBFinderApp(root)
    root.mainloop()
    return 0


# ---------------------------------------------------------------------------
# Entry point — everything runs from inside this guard so a frozen exe
# never re-runs startup work in a child process.
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dbfinder",
        description="Find a forgotten MySQL database name and location.",
    )
    parser.add_argument("--scan", action="store_true",
                        help="run a headless scan and print the report")
    parser.add_argument("--report", metavar="FILE",
                        help="with --scan, also write the report to FILE")
    parser.add_argument("--hunt", metavar="FOLDER",
                        help="with --scan, also hunt FOLDER for "
                             "connection strings")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")
    args = parser.parse_args(argv)
    if args.scan or args.report or args.hunt:
        return cli_main(args)
    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
