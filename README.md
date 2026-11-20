# DBFinder v1.0.1 — Find a forgotten MySQL database

You have a PC with your own software and a MySQL database, other computers
reach it over the LAN, and after 2 years you have forgotten the database
**name** and **location**. DBFinder finds both for you.

**Read-only by design:** it never modifies, deletes, or writes into any
database folder. The only file it ever writes is the report you explicitly
export. Passwords are always masked (`***`) and never stored or saved.

## What it finds

1. **MySQL / MariaDB services** — name, running state, and ImagePath.
2. **mysqld.exe / mysql.exe** — in Program Files, ProgramData, XAMPP,
   WAMP, `C:\MySQL`, and PATH. Renamed variants count too
   (`vlmysqld.exe`, ...), including binaries named in a service's
   ImagePath.
3. **my.ini / my.cnf** — reads the `datadir` and `port` from each one,
   including a `my.ini` a service points at with `--defaults-file`
   (bundled installs such as PVMS keep their config outside the
   standard locations).
4. **Databases** — every folder inside each datadir, with size, file
   counts (`.frm` / `.ibd` / `.myd` / `.myi`), last-modified date, and
   USER vs SYSTEM marking. Also flags `ibdata1` / `ib_logfile*`.
5. **Connection String Hunter** — scans `.config` / `.ini` / `.cs` /
   `.vb` / `.xml` files (e.g. your VS2010 project) for `server=` and
   `database=` details. Passwords masked.
6. **Live Check (optional)** — runs `SHOW DATABASES` through `mysql.exe`
   with credentials you type. They are used once, never stored, never
   written to disk.
7. **SQL Server bonus** — lists SQL Server services and `.mdf` / `.ldf`
   files, in case the "SQL" on the PC is actually SQL Server (common
   with VS2010 apps).

It also shows the PC name, LAN IP, and per-instance port checks: port
3306 plus every port a `my.ini` names (e.g. `Port 34174 (IVMS320MYSQL):
listening`).

## Run it (no build needed)

Needs Python 3.10+ on the PC that hosts the database:

```bat
py dbfinder.py
```

That opens the window and auto-scans. Click **Scan Now** to re-scan,
**Open Data Folder** to open a datadir in Explorer, and **Export Report**
to save a `.txt` report.

## Run it from the terminal (no window)

```bat
py dbfinder.py --scan
py dbfinder.py --scan --report report.txt
py dbfinder.py --scan --hunt "C:\Users\Me\Documents\Visual Studio 2010\Projects"
py dbfinder.py --scan --hunt "C:\Users\Me\Documents" --report report.txt
```

## Build the .exe (Windows)

Double-click `build_exe.bat` (uses the `py` launcher). It builds two
exes in `dist\`:

- `DBFinder-console.exe` — console **test** build. Run this first: if
  anything goes wrong, the error stays visible in the console.
- `DBFinder.exe` — windowed **release** build (no console window).

Or push to GitHub: `.github/workflows/build-exe.yml` runs the tests and
builds both exes on `windows-latest` (Python 3.12); download them from
Actions > Artifacts > DBFinder-Windows.

## Tests

```bat
py -m unittest test_dbfinder.py -v
```

The tests build a fake MySQL layout in a temp dir (fake datadir, fake
`my.ini`, fake `app.config` with a password) and verify my.ini parsing,
database listing with file counts, connection-string extraction, and
password masking in the report. A second fake layout mimics a bundled
PVMS-style install (service `IVMS320MYSQL`, renamed `vlmysqld.exe`,
`--defaults-file`, port 34174) and verifies the service config is
followed end to end.

## Files

| File | What it is |
|---|---|
| `dbfinder.py` | The whole app — single file, stdlib only |
| `test_dbfinder.py` | Unit tests |
| `build_exe.bat` | Local PyInstaller build (console + windowed) |
| `.github/workflows/build-exe.yml` | Cloud build on GitHub Actions |
