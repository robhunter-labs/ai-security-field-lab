"""Run every fixture and assert its expected verdict, plus unit checks on the
claim key, grouping, the retest card and the catalog.

  python3 -m unittest discover -s tests -v
Standard library only. No network.
"""
import glob
import ipaddress
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "replay"))
import check_package as cp  # noqa: E402
import make_card  # noqa: E402

FIXTURE_DIR = os.path.join(ROOT, "fixtures")
FIXTURES = sorted(glob.glob(os.path.join(FIXTURE_DIR, "*.json")))
BASE = os.path.join(FIXTURE_DIR, "_base", "package_high_idor.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class FixtureVerdicts(unittest.TestCase):
    """One test per fixture file (added below)."""

    def test_fixture_count(self):
        self.assertGreaterEqual(len(FIXTURES), 14)


def _make_fixture_test(path):
    def test(self):
        fx = load(path)
        actual = cp.run_fixture(fx, FIXTURE_DIR)
        mismatches = cp.compare_fixture(fx, actual)
        self.assertEqual(mismatches, [], f"{os.path.basename(path)}: {mismatches}\nactual={json.dumps(actual, default=str)[:1500]}")
    return test


for _p in FIXTURES:
    _name = "test_" + re.sub(r"\W", "_", os.path.basename(_p)[:-5])
    setattr(FixtureVerdicts, _name, _make_fixture_test(_p))


class FixtureHygiene(unittest.TestCase):
    def setUp(self):
        self.catalog = load(os.path.join(ROOT, "catalog", "classes.json"))
        self.ids = {c["id"] for f in self.catalog["families"] for c in f["classes"]} | \
                   {c["id"] for c in self.catalog["addenda"]["classes"]}

    def test_fixtures_are_marked_synthetic_and_reference_known_classes(self):
        for p in FIXTURES:
            fx = load(p)
            self.assertTrue(fx.get("synthetic"), p)
            self.assertIn("expected", fx, p)
            for cid in fx.get("classes", []):
                self.assertIn(cid, self.ids, f"{p}: unknown class {cid}")

    def test_fixtures_use_reserved_names_and_documentation_addresses(self):
        docs = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
        for p in FIXTURES + [BASE]:
            with open(p, encoding="utf-8") as f:
                text = f.read()
            for host in re.findall(r"https?://([A-Za-z0-9.-]+)", text):
                self.assertTrue(host.lower().endswith(".test"), f"{p}: host {host} is not under .test")
            for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
                self.assertTrue(any(ipaddress.ip_address(ip) in n for n in docs), f"{p}: {ip} is not a documentation address")


class ClaimKey(unittest.TestCase):
    def key(self, url, **kw):
        return cp.claim_key({"url": url, "method": kw.get("method", "GET"), "auth_context": kw.get("auth", "user"),
                             "sink_class": kw.get("sink", "sql"), "parameter": kw.get("param", "query:q")})

    def test_numeric_and_uuid_segments_become_placeholders(self):
        self.assertEqual(cp.route_template("https://a.example.test/v2/orders/123/items/550e8400-e29b-41d4-a716-446655440000"),
                         "https://a.example.test/v2/orders/{int}/items/{uuid}")

    def test_host_case_default_port_param_order_and_dot_segments(self):
        a = self.key("HTTPS://API.Example.TEST:443/v2/./x/../orders/7/?b=2&a=1")
        b = self.key("https://api.example.test/v2/orders/9?a=5&b=6")
        self.assertEqual(a["string"], b["string"])
        self.assertEqual(a["id"], b["id"])

    def test_path_case_and_parameter_names_are_kept(self):
        self.assertNotEqual(self.key("https://a.example.test/Admin")["id"], self.key("https://a.example.test/admin")["id"])
        self.assertNotEqual(self.key("https://a.example.test/s?q=1")["id"], self.key("https://a.example.test/s?r=1")["id"])

    def test_method_auth_and_sink_are_part_of_the_key(self):
        base = self.key("https://a.example.test/s?q=1")
        for kw in ({"method": "POST"}, {"auth": "anonymous"}, {"sink": "html-reflection"}):
            self.assertNotEqual(base["id"], self.key("https://a.example.test/s?q=1", **kw)["id"], kw)

    def test_percent_encoding_normalized(self):
        self.assertEqual(cp.route_template("https://a.example.test/%7euser/a%2fb"),
                         "https://a.example.test/~user/a%2Fb")


class Grouping(unittest.TestCase):
    def test_lineage_keeps_every_member_once(self):
        fx = load(os.path.join(FIXTURE_DIR, "17_vended_product_grouped_by_version.json"))
        groups = cp.group_candidates(fx["candidates"], "component", fx["context"])
        members = [m for g in groups for m in g["members"]]
        self.assertEqual(sorted(members), sorted(c["id"] for c in fx["candidates"]))
        big = next(g for g in groups if len(g["members"]) == 3)
        self.assertEqual({l["reachability"] for l in big["lineage"]}, {"reached from internet", "internal segment only"})

    def test_in_scope_redirect_is_an_alias_out_of_scope_is_not(self):
        c = {"id": "r1", "url": "https://old.example.test/", "observations": [
            {"id": "o", "url": "https://old.example.test/", "status": 301, "headers": {"Location": "https://www.example.test/"}}]}
        aliases, _ = cp.derive_aliases([c], {"scope_hosts": ["old.example.test", "www.example.test"]})
        self.assertEqual(aliases, {"old.example.test": "www.example.test"})
        aliases, _ = cp.derive_aliases([c], {"scope_hosts": ["old.example.test"]})
        self.assertEqual(aliases, {})

    def test_chain_steps_survive_grouping(self):
        a = {"id": "a", "url": "https://x.example.test/o/1", "auth_context": "user", "sink_class": "s", "parameter": "p"}
        b = dict(a, id="b", url="https://x.example.test/o/2", chain_steps=[{"chain_id": "CH-1", "step": 3}])
        groups = cp.group_candidates([a, b])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["chain_steps"], [{"chain_id": "CH-1", "step": 3}])


class Schemas(unittest.TestCase):
    def test_base_package_validates(self):
        self.assertEqual(cp.validate(load(BASE), cp.load_schema("package.schema.json")), [])

    def test_not_vulnerable_is_not_a_state(self):
        res = cp.check_transition({"id": "c", "url": "https://x.example.test/"}, {"state": "not_vulnerable"})
        self.assertEqual([r["code"] for r in res.reasons], ["UNKNOWN_STATE"])

    def test_cvss_nomenclature(self):
        self.assertEqual(cp.parse_cvss4("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")[1], "CVSS-B")
        self.assertEqual(cp.parse_cvss4("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/CR:H")[1], "CVSS-BTE")
        self.assertFalse(cp.parse_cvss4("CVSS:4.0/AV:N/AC:L")[0])


class RetestCard(unittest.TestCase):
    def test_card_forms_env_tokens_and_safety(self):
        card = make_card.make_card(load(BASE))
        for needle in ("curl.exe", "Invoke-RestMethod", "urllib.request", "$env:VP_TOKEN_READER",
                       "os.environ['VP_TOKEN_READER']", "Safety class: read-only", "Negative control", "Decision rule"):
            self.assertIn(needle, card)
        self.assertNotIn("{{identity:", card)
        self.assertNotIn("TESTER-ASSISTED", card)

    def test_python_form_compiles(self):
        pkg = load(BASE)
        roles = {i["role"]: make_card.env_name(i) for i in pkg["replay"]["identities"]}
        compile(make_card.py(pkg["replay"]["request"], roles), "<card>", "exec")

    def test_retest_code_keeps_package_body_literal_and_redirects_bounded(self):
        req = dict(load(BASE)["replay"]["request"])
        req["body"] = "first\n'@\nWrite-Output INJECTED\n@'\nlast"
        req["method"] = "POST; Write-Output INJECTED"
        powershell = make_card.curl_ps(req, {})
        self.assertIn("''@", powershell)
        self.assertNotIn("\n'@\nWrite-Output INJECTED\n", powershell)
        self.assertIn("-X 'POST; Write-Output INJECTED'", powershell)
        self.assertIn("-MaximumRedirection 0", make_card.irm(req, {}))
        python = make_card.py(req, {})
        compile(python, "<card>", "exec")
        self.assertIn("opener.open(req", python)
        self.assertIn("return None", python)

    def test_tester_assisted_marker_when_oracle_does_not_travel(self):
        pkg = cp.merge_patch(load(BASE), {"oracle": {"type": "out-of-band"},
                                          "replay": {"handoff": {"tester_assisted": True, "requires_tester_tooling": ["callback listener"]}}})
        self.assertIn("TESTER-ASSISTED RETEST", make_card.make_card(pkg))

    def test_example_card_is_current(self):
        with open(os.path.join(ROOT, "replay", "examples", "RETEST_CARD_VP-0001.md"), encoding="utf-8") as f:
            self.assertEqual(f.read(), make_card.make_card(load(BASE)))


class Catalog(unittest.TestCase):
    def test_markdown_in_sync_and_counts(self):
        out = subprocess.run([sys.executable, os.path.join(ROOT, "catalog", "build_catalog.py"), "--check"],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        data = load(os.path.join(ROOT, "catalog", "classes.json"))
        self.assertEqual(sum(len(f["classes"]) for f in data["families"]), 103)
        self.assertEqual(len(data["families"]), 16)
        self.assertEqual(len(data["panel_picks"]), 7)

    def test_reason_codes_map_to_known_classes(self):
        data = load(os.path.join(ROOT, "catalog", "classes.json"))
        ids = {c["id"] for f in data["families"] for c in f["classes"]}
        enum = cp.load_schema("candidate_state.schema.json")["$defs"]["_reason_code"]["enum"]
        self.assertEqual(sorted(enum), sorted(cp.REASON_CLASSES))
        for code, classes in cp.REASON_CLASSES.items():
            self.assertTrue(set(classes) <= ids, code)


if __name__ == "__main__":
    unittest.main()
