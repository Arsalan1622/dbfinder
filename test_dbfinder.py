#!/usr/bin/env python3
"""Unit tests for DBFinder — run with:  python3 test_dbfinder.py

Builds a fake MySQL layout in a temp dir (fake datadir with two fake
database folders, a fake my.ini, a fake app.config with a connection
string including a password) and verifies parsing, listing, hunting
and password masking. Nothing here touches a real database.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dbfinder

FAKE_PASSWORD = "S3cret-P4ssw0rd-DoNotLeak"


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


class FakeLayoutTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        # Fake datadir: two user DBs + one system DB.
        self.datadir = os.path.join(root, "data")
        self.shop_db = os.path.join(self.datadir, "shopdb")
        self.old_db = os.path.join(self.datadir, "oldstock")
        self.sys_db = os.path.join(self.datadir, "mysql")
        for folder in (self.shop_db, self.old_db, self.sys_db):
            os.makedirs(folder)
        _write(os.path.join(self.shop_db, "customers.frm"), "fake")
        _write(os.path.join(self.shop_db, "customers.ibd"), "fake-ibd")
        _write(os.path.join(self.shop_db, "orders.frm"), "fake")
        _write(os.path.join(self.shop_db, "orders.ibd"), "fake-ibd")
        _write(os.path.join(self.old_db, "items.myd"), "fake")
        _write(os.path.join(self.old_db, "items.myi"), "fake")
        _write(os.path.join(self.sys_db, "user.frm"), "fake")
        _write(os.path.join(self.datadir, "ibdata1"), "fake-innodb")
        _write(os.path.join(self.datadir, "ib_logfile0"), "fake-log")
        # Fake my.ini pointing at the fake datadir.
        self.ini_dir = os.path.join(root, "MySQL Server 5.7")
        os.makedirs(self.ini_dir)
        self.ini_path = os.path.join(self.ini_dir, "my.ini")
        _write(self.ini_path,
               "[mysqld]\n"
               f"datadir={self.datadir}\n"
               "port=3307\n"
               f"basedir={root}\n"
               "\n[client]\nport=9999\n")
        # Fake VS2010 project with a connection string (with password).
        self.proj_dir = os.path.join(root, "Projects", "ShopApp")
        os.makedirs(self.proj_dir)
        self.config_path = os.path.join(self.proj_dir, "app.config")
        _write(self.config_path,
               '<?xml version="1.0"?>\n<configuration>\n'
               '  <connectionStrings>\n'
               '    <add name="ShopDb" connectionString="'
               'server=192.168.1.50;database=shopdb;uid=admin;'
               f'pwd={FAKE_PASSWORD};port=3307" />\n'
               '  </connectionStrings>\n</configuration>\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_my_ini(self):
        parsed = dbfinder.parse_my_ini(self.ini_path)
        self.assertEqual(parsed["datadir"], self.datadir)
        self.assertEqual(parsed["port"], "3307")
        # The [client] port (9999) must NOT win over [mysqld].
        self.assertNotEqual(parsed["port"], "9999")
        self.assertTrue(parsed["basedir"])

    def test_parse_my_ini_missing_file(self):
        parsed = dbfinder.parse_my_ini(os.path.join(self.tmp.name, "no.ini"))
        self.assertIsNone(parsed["datadir"])
        self.assertIsNone(parsed["port"])

    def test_find_my_ini_files(self):
        found = dbfinder.find_my_ini_files(
            extra_roots=[os.path.dirname(self.ini_dir)])
        paths = [f["path"] for f in found]
        self.assertIn(self.ini_path, paths)
        hit = [f for f in found if f["path"] == self.ini_path][0]
        self.assertEqual(hit["datadir"], self.datadir)

    def test_list_databases(self):
        dbs = dbfinder.list_databases(self.datadir)
        names = {d["name"] for d in dbs}
        self.assertEqual(names, {"shopdb", "oldstock", "mysql"})
        shop = [d for d in dbs if d["name"] == "shopdb"][0]
        self.assertEqual(shop["counts"][".frm"], 2)
        self.assertEqual(shop["counts"][".ibd"], 2)
        self.assertEqual(shop["files"], 4)
        self.assertFalse(shop["system"])
        self.assertGreater(shop["size_bytes"], 0)
        self.assertNotEqual(shop["modified"], 0)
        old = [d for d in dbs if d["name"] == "oldstock"][0]
        self.assertEqual(old["counts"][".myd"], 1)
        self.assertEqual(old["counts"][".myi"], 1)
        sysdb = [d for d in dbs if d["name"] == "mysql"][0]
        self.assertTrue(sysdb["system"])

    def test_list_databases_missing_dir(self):
        self.assertEqual(
            dbfinder.list_databases(os.path.join(self.tmp.name, "nope")), [])

    def test_inspect_datadir(self):
        info = dbfinder.inspect_datadir(self.datadir)
        self.assertTrue(info["ibdata1"])
        self.assertIn("ib_logfile0", info["ib_logfiles"])
        self.assertEqual(len(info["databases"]), 3)

    def test_connection_string_hunt(self):
        results = dbfinder.scan_folder_for_connection_strings(self.proj_dir)
        self.assertEqual(len(results), 1)
        hit = results[0]
        self.assertEqual(hit["server"], "192.168.1.50")
        self.assertEqual(hit["database"], "shopdb")
        self.assertEqual(hit["user"], "admin")
        self.assertEqual(hit["port"], "3307")
        self.assertEqual(hit["file"], self.config_path)
        # The stored/masked string must never contain the real password.
        self.assertNotIn(FAKE_PASSWORD, hit["masked"])
        self.assertIn("***", hit["masked"])

    def test_parse_connection_string_dotnet_style(self):
        parsed = dbfinder.parse_connection_string(
            "Data Source=192.168.1.9;Initial Catalog=accounts;"
            "User ID=sa;Password=hunter2")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["server"], "192.168.1.9")
        self.assertEqual(parsed["database"], "accounts")
        self.assertEqual(parsed["user"], "sa")

    def test_parse_connection_string_needs_server_and_db(self):
        self.assertIsNone(
            dbfinder.parse_connection_string("server=localhost;uid=root"))
        self.assertIsNone(
            dbfinder.parse_connection_string("database=shopdb;uid=root"))

    def test_mask_passwords(self):
        masked = dbfinder.mask_passwords(
            f"server=x;database=y;pwd={FAKE_PASSWORD};uid=admin")
        self.assertNotIn(FAKE_PASSWORD, masked)
        self.assertIn("pwd=***", masked)
        self.assertIn("database=y", masked)  # non-secrets stay readable
        masked2 = dbfinder.mask_passwords(
            f'"password": "{FAKE_PASSWORD}"')
        self.assertNotIn(FAKE_PASSWORD, masked2)

    def test_report_masks_passwords(self):
        findings = {
            "generated_at": "2026-11-20 12:00:00",
            "hostname": "TEST-PC", "lan_ip": "192.168.1.50",
            "port_3306_open": True,
            "mysql_services": [], "sqlserver_services": [],
            "binaries": [], "ini_files": [],
            "datadirs": [{
                "path": self.datadir, "ibdata1": True, "ib_logfiles": [],
                "databases": dbfinder.list_databases(self.datadir),
            }],
            "stray_db_folders": [], "sqlserver_files": [],
            # Deliberately plant an UNMASKED password to prove the
            # report's final safety net catches it.
            "conn_strings": [{
                "file": self.config_path, "line": 4,
                "server": "192.168.1.50", "database": "shopdb",
                "user": "admin", "port": "3307",
                "masked": f"server=192.168.1.50;pwd={FAKE_PASSWORD}",
            }],
        }
        report = dbfinder.build_report(findings)
        self.assertNotIn(FAKE_PASSWORD, report)
        self.assertIn("***", report)
        self.assertIn("shopdb", report)
        self.assertIn("TEST-PC", report)

    def test_stray_search_finds_db_folders(self):
        hits = dbfinder.search_stray_db_files([self.tmp.name])
        self.assertIn(self.shop_db, hits)
        self.assertNotIn(self.old_db, hits)  # .myd/.myi are not searched


class ServiceDefaultsFileTestCase(unittest.TestCase):
    """Mimics the real laptop miss: a PVMS-style bundled MySQL.

    Service IVMS320MYSQL runs a renamed binary (vlmysqld) with
    --defaults-file pointing at a my.ini outside the standard
    locations, on port 34174. v1.0.0 found the service but none of
    the rest; v1.0.1 must find it all.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        # Fake bundled install: <root>/PVMS 2020/Database/
        self.db_home = os.path.join(root, "PVMS 2020", "Database")
        self.bin_dir = os.path.join(self.db_home, "bin")
        os.makedirs(self.bin_dir)
        self.vlmysqld = os.path.join(self.bin_dir, "vlmysqld.exe")
        _write(self.vlmysqld, "fake-binary")
        # Fake datadir with two DBs.
        self.datadir = os.path.join(self.db_home, "data")
        self.surv_db = os.path.join(self.datadir, "surveillancesystem")
        self.other_db = os.path.join(self.datadir, "configdb")
        os.makedirs(self.surv_db)
        os.makedirs(self.other_db)
        for name in ("cameras", "events", "users"):
            _write(os.path.join(self.surv_db, name + ".frm"), "fake")
        for name in ("cameras", "events"):
            _write(os.path.join(self.surv_db, name + ".ibd"), "fake-ibd")
        _write(os.path.join(self.other_db, "settings.frm"), "fake")
        _write(os.path.join(self.datadir, "ibdata1"), "fake-innodb")
        # Fake my.ini: non-standard port, datadir, basedir.
        self.ini_path = os.path.join(self.db_home, "my.ini")
        _write(self.ini_path,
               "[mysqld]\n"
               "port=34174\n"
               f"basedir={self.db_home}\n"
               f"datadir={self.datadir}\n")
        # Fake service ImagePath, mirroring the real laptop one
        # (binary path has NO .exe suffix, like the real service).
        self.image_path = (
            f'"{os.path.join(self.bin_dir, "vlmysqld")}" '
            f'--defaults-file="{self.ini_path}" IVMS320MYSQL')
        self.service = {
            "name": "IVMS320MYSQL",
            "display": "IVMS320MYSQL",
            "state": "RUNNING",
            "image_path": self.image_path,
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_version_is_1_0_1(self):
        self.assertEqual(dbfinder.APP_VERSION, "1.0.1")

    def test_extract_defaults_file_quoted(self):
        self.assertEqual(
            dbfinder.extract_defaults_file(self.image_path), self.ini_path)

    def test_extract_defaults_file_unquoted(self):
        image = ("C:\\Somewhere\\mysqld "
                 "--defaults-file=C:\\Data\\my.ini MYSQL57")
        self.assertEqual(dbfinder.extract_defaults_file(image),
                         r"C:\Data\my.ini")

    def test_extract_defaults_file_missing(self):
        self.assertEqual(
            dbfinder.extract_defaults_file(
                '"C:\\MySQL\\bin\\mysqld.exe" MySQL'), "")
        self.assertEqual(dbfinder.extract_defaults_file(""), "")
        self.assertEqual(dbfinder.extract_defaults_file(None), "")

    def test_binary_from_image_path(self):
        self.assertEqual(
            dbfinder.binary_from_image_path(self.image_path),
            os.path.join(self.bin_dir, "vlmysqld"))
        self.assertEqual(
            dbfinder.binary_from_image_path(
                "C:\\MySQL\\bin\\mysqld.exe --defaults-file=x MySQL"),
            "C:\\MySQL\\bin\\mysqld.exe")

    def test_service_defaults_file_ini_parsed(self):
        found = dbfinder.find_my_ini_files(services=[self.service])
        paths = [f["path"] for f in found]
        self.assertIn(self.ini_path, paths)
        hit = [f for f in found if f["path"] == self.ini_path][0]
        self.assertEqual(hit["datadir"], self.datadir)
        self.assertEqual(hit["port"], "34174")
        self.assertEqual(hit["basedir"], self.db_home)
        self.assertEqual(hit["service"], "IVMS320MYSQL")
        self.assertIn("IVMS320MYSQL", hit["source"])
        self.assertIn("--defaults-file", hit["source"])

    def test_service_datadir_databases_listed(self):
        found = dbfinder.find_my_ini_files(services=[self.service])
        hit = [f for f in found if f["path"] == self.ini_path][0]
        dbs = dbfinder.list_databases(hit["datadir"])
        names = {d["name"] for d in dbs}
        self.assertEqual(names, {"surveillancesystem", "configdb"})
        surv = [d for d in dbs if d["name"] == "surveillancesystem"][0]
        self.assertEqual(surv["counts"][".frm"], 3)
        self.assertEqual(surv["counts"][".ibd"], 2)
        self.assertEqual(surv["files"], 5)
        self.assertFalse(surv["system"])

    def test_vlmysqld_detected_as_binary(self):
        # Direct path (no .exe suffix, like the real ImagePath).
        found = dbfinder.find_mysql_binaries(
            extra_paths=[os.path.join(self.bin_dir, "vlmysqld")])
        self.assertIn(self.vlmysqld, found)
        # Via the bin dir scan.
        found2 = dbfinder.find_mysql_binaries(extra_bin_dirs=[self.bin_dir])
        self.assertIn(self.vlmysqld, found2)
        # Name rules.
        self.assertTrue(dbfinder._is_mysql_server_binary("vlmysqld.exe"))
        self.assertTrue(dbfinder._is_mysql_server_binary("mysqld.exe"))
        self.assertTrue(dbfinder._is_mysql_client_binary("mysql.exe"))
        self.assertFalse(dbfinder._is_mysql_server_binary("notepad.exe"))
        self.assertFalse(dbfinder._is_mysql_client_binary("notepad.exe"))

    def test_full_scan_finds_service_instance(self):
        findings = dbfinder.run_scan(services=[self.service])
        # The service my.ini is parsed...
        inis = [i for i in findings["ini_files"]
                if i["path"] == self.ini_path]
        self.assertEqual(len(inis), 1)
        self.assertEqual(inis[0]["port"], "34174")
        # ...its datadir's databases are listed...
        all_dbs = [db["name"] for dd in findings["datadirs"]
                   for db in dd["databases"]]
        self.assertIn("surveillancesystem", all_dbs)
        # ...the renamed binary is found...
        self.assertIn(self.vlmysqld, findings["binaries"])
        # ...and port 34174 is checked alongside 3306.
        ports = {pc["port"]: pc for pc in findings["port_checks"]}
        self.assertIn(3306, ports)
        self.assertIn(34174, ports)
        self.assertEqual(ports[34174]["label"], "IVMS320MYSQL")
        # The report shows where it all came from.
        report = dbfinder.build_report(findings)
        self.assertIn("surveillancesystem", report)
        self.assertIn("from service IVMS320MYSQL --defaults-file", report)
        self.assertIn("Port 34174 (IVMS320MYSQL)", report)
        self.assertIn("Port 3306", report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
