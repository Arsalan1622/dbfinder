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


if __name__ == "__main__":
    unittest.main(verbosity=2)
