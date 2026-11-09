#!/usr/bin/env python3
"""check_package.py - validation-package and candidate-state checker (v1 prototype).

Status: Built, not exercised. Synthetic fixtures only. It decides nothing:
it refuses records that break the rules below and says why.

Core rule: a filter may lower a candidate's rank or change where it goes,
but only an oracle may close it.

Standard library only. No network.

Usage:
  python3 check_package.py FILE [FILE ...] [--json]
      FILE may be a fixture (has "fixture_id"), a package (has "package_id")
      or a bare candidate state (has "state").
  python3 check_package.py --claim-key URL [--method GET] [--auth user]
                           [--sink object-read] [--param path:id]
"""
import argparse
import copy
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import statistics
import sys
from urllib.parse import parse_qsl, urljoin, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_DIR = os.path.join(HERE, "schema")

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

SEVERITY_RANK = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
ORACLE_TYPES = ("identity-differential", "out-of-band", "timing-distribution",
                "browser-execution", "live-effective-permission",
                "version-or-reachability", "none")
# A "direct" oracle observes the effect itself. Timing is statistical and
# version/reachability is inference, so neither counts for the Critical gate.
DIRECT_ORACLES = {"identity-differential", "out-of-band", "browser-execution",
                  "live-effective-permission"}
# Oracles that do not travel to a developer laptop without tester tooling.
NON_TRAVELLING_ORACLES = {"out-of-band", "timing-distribution", "browser-execution"}
CLOSING_DISPOSITIONS = {"confirmed", "dismissed"}
NEVER_MERGE_AXES = ("auth_context", "route", "middleware", "parameter")
QUESTIONS = ("unique", "true", "actionable", "new")

# Demotion reason codes -> catalog classes (catalog/NON_UNIQUE_CLASSES.md).
REASON_CLASSES = {
    "SOFT_404": ["D1", "D2"], "CATCH_ALL_200": ["D1", "D3"],
    "LOGIN_BOUNCE": ["F2", "A1"], "CACHE_ARTIFACT": ["C6"],
    "TESTER_PATH_ARTIFACT": ["C1", "C2", "C11"], "RATE_LIMITED": ["C5"],
    "EGRESS_UNVERIFIED": ["C3"], "DNS_ONLY_CALLBACK": ["C10"],
    "INTERMEDIARY_CALLBACK": ["C10"], "TIMING_INCONCLUSIVE": ["E1", "E2", "E4"],
    "STOCHASTIC_LOW_RATE": ["E7", "N6"], "VERSION_ONLY_EVIDENCE": ["H1", "H2", "H3"],
    "NOT_SHOWN_REACHABLE": ["I1", "I3"], "INTENTIONALLY_PUBLIC_IDENTIFIER": ["G4", "J3"],
    "UNVERIFIED_SECRET": ["J1"], "REQUIRES_PRIVILEGE": ["F4"], "INTERNAL_ONLY": ["I6"],
    "VENDOR_OWNED_LAYER": ["G1", "G2", "G3"], "WEAKNESS_NOT_VULNERABILITY": ["G7"],
    "KNOWN_OR_ACCEPTED": ["G5"],
}
# Reason codes a detector can back. A demotion citing one of these is refused
# unless that detector actually fired on the candidate's observations.
EVIDENCE_BACKED_REASONS = {
    "SOFT_404": "SOFT_404", "LOGIN_BOUNCE": "LOGIN_BOUNCE",
    "TESTER_PATH_ARTIFACT": "TESTER_CHAIN_HEADER", "CACHE_ARTIFACT": "CACHE_HIT",
    "RATE_LIMITED": "RATE_LIMITED",
}
# Demotions that are chain links: allowed, but flagged (re-rank, never drop).
CHAIN_LINK_REASONS = {"REQUIRES_PRIVILEGE", "INTERNAL_ONLY",
                      "WEAKNESS_NOT_VULNERABILITY", "NOT_SHOWN_REACHABLE"}

EDGE_WORDS = re.compile(r"\b(waf|cdn|edge|blocked|challenge|captcha|bot ?manager)\b", re.I)
LOGIN_PATH = re.compile(r"(^|/)(login|signin|sign-in|logon|sso|authorize|oauth2?)(/|$)", re.I)
LOGIN_TITLE = re.compile(r"\b(log ?in|sign ?in)\b", re.I)
SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "api-key",
                  "x-auth-token", "proxy-authorization"}
PLACEHOLDER = re.compile(r"\{\{identity:([a-z0-9_-]+)\}\}")
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
DEFAULT_PORTS = {"http": 80, "https": 443}
NUM_SEG = re.compile(r"\d+")
UUID_SEG = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
DEFAULT_RECHECK_HORIZON_DAYS = 90
EDGE_RECHECK_DAYS = 14

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def parse_time(value):
    """Parse an ISO date or date-time into an aware UTC datetime (None passes through)."""
    if value is None or isinstance(value, dt.datetime):
        return value
    s = str(value)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        d = dt.date.fromisoformat(s)
        return dt.datetime(d.year, d.month, d.day, tzinfo=dt.timezone.utc)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    t = dt.datetime.fromisoformat(s)
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def safe_time(value):
    try:
        return parse_time(value)
    except (TypeError, ValueError):
        return None


def g(obj, dotted, default=None):
    """Safe deep get: g(pkg, 'replay.handoff.tester_assisted')."""
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def gs(obj, dotted):
    """Deep get that returns only a string (wrong types become None)."""
    v = g(obj, dotted)
    return v if isinstance(v, str) else None


def _as_list(v):
    return v if isinstance(v, list) else []


def gd(obj, dotted):
    """Deep get that returns only a dict (wrong types become {})."""
    v = g(obj, dotted)
    return v if isinstance(v, dict) else {}


def merge_patch(target, patch):
    """RFC 7386 JSON merge patch (null deletes a key)."""
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    out = copy.deepcopy(target) if isinstance(target, dict) else {}
    for k, v in patch.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = merge_patch(out.get(k), v)
    return out


def _headers(obs):
    return {str(k).lower(): str(v) for k, v in (obs.get("headers") or {}).items()}


def _host(url):
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def _origin(url):
    p = urlsplit(url)
    scheme = p.scheme.lower()
    try:
        port = p.port
    except ValueError:
        port = None
    return scheme, (p.hostname or "").lower(), port or DEFAULT_PORTS.get(scheme)


class Result:
    """What the checker says. It never says 'vulnerable' or 'safe'."""

    def __init__(self):
        self.reasons, self.labels, self.warnings = [], [], []
        self.suggested_state = None
        self.severity_cap = None
        self.route_to = None
        self.notes = {}

    def refuse(self, code, message):
        if not any(r["code"] == code and r["message"] == message for r in self.reasons):
            self.reasons.append({"code": code, "message": message})

    def label(self, name):
        if name not in self.labels:
            self.labels.append(name)

    def warn(self, message):
        if message not in self.warnings:
            self.warnings.append(message)

    def suggest(self, state):
        if self.suggested_state is None:  # first (most specific) suggestion wins
            self.suggested_state = state

    def absorb(self, other):
        for r in other.reasons:
            self.refuse(r["code"], r["message"])
        for lab in other.labels:
            self.label(lab)
        for w in other.warnings:
            self.warn(w)
        self.suggest(other.suggested_state) if other.suggested_state else None
        self.severity_cap = self.severity_cap or other.severity_cap
        self.route_to = self.route_to or other.route_to
        self.notes.update(other.notes)

    @property
    def verdict(self):
        return "REFUSE" if self.reasons else "ACCEPT"

    def to_dict(self):
        return {"verdict": self.verdict, "reasons": self.reasons, "labels": self.labels,
                "warnings": self.warnings, "suggested_state": self.suggested_state,
                "severity_cap": self.severity_cap, "route_to": self.route_to,
                "notes": self.notes}


# ---------------------------------------------------------------------------
# Minimal JSON Schema validator (the subset these schemas use)
# ---------------------------------------------------------------------------

_SCHEMAS = {}


def load_schema(name):
    if name not in _SCHEMAS:
        with open(os.path.join(SCHEMA_DIR, name), encoding="utf-8") as f:
            _SCHEMAS[name] = json.load(f)
    return _SCHEMAS[name]


def _type_ok(value, t):
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "null": value is None,
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
    }[t]


def validate(inst, schema, root=None, path="$"):
    """Validate against a subset of JSON Schema 2020-12. Returns [(path, message)].

    Supported: $ref (local), type, const, enum, minLength, pattern, format
    (date, date-time), minimum, maximum, minItems, items, required,
    properties, additionalProperties:false, oneOf, anyOf.
    """
    root = schema if root is None else root
    if "$ref" in schema:
        node = root
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node[part]
        return validate(inst, node, root, path)
    errs = []
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(inst, t) for t in types):
            return [(path, f"expected {' or '.join(types)}, got {type(inst).__name__}")]
    if "const" in schema and inst != schema["const"]:
        errs.append((path, f"must be {schema['const']!r}"))
    if "enum" in schema and inst not in schema["enum"]:
        errs.append((path, f"{inst!r} is not one of {schema['enum']}"))
    if isinstance(inst, str):
        if len(inst) < schema.get("minLength", 0):
            errs.append((path, "must not be empty"))
        if "pattern" in schema and not re.search(schema["pattern"], inst):
            errs.append((path, f"does not match {schema['pattern']}"))
        if schema.get("format") in ("date", "date-time") and safe_time(inst) is None:
            errs.append((path, f"is not a valid {schema['format']}"))
    if isinstance(inst, (int, float)) and not isinstance(inst, bool):
        if "minimum" in schema and inst < schema["minimum"]:
            errs.append((path, f"must be >= {schema['minimum']}"))
        if "maximum" in schema and inst > schema["maximum"]:
            errs.append((path, f"must be <= {schema['maximum']}"))
    if isinstance(inst, list):
        if len(inst) < schema.get("minItems", 0):
            errs.append((path, f"needs at least {schema['minItems']} item(s)"))
        if "items" in schema:
            for i, item in enumerate(inst):
                errs += validate(item, schema["items"], root, f"{path}[{i}]")
    if isinstance(inst, dict):
        for req in schema.get("required", []):
            if req not in inst:
                errs.append((f"{path}.{req}", "is required"))
        props = schema.get("properties", {})
        for k, v in inst.items():
            if k in props:
                errs += validate(v, props[k], root, f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                errs.append((f"{path}.{k}", "is not an allowed property"))
    if "oneOf" in schema:
        n = sum(1 for s in schema["oneOf"] if not validate(inst, s, root, path))
        if n != 1:
            errs.append((path, f"must match exactly one alternative (matched {n})"))
    if "anyOf" in schema and not any(not validate(inst, s, root, path) for s in schema["anyOf"]):
        errs.append((path, "matches none of the allowed alternatives"))
    return errs


def state_names():
    schema = load_schema("candidate_state.schema.json")
    return [ref["$ref"].split("/")[-1] for ref in schema["oneOf"]]


# ---------------------------------------------------------------------------
# Claim key and grouping
# ---------------------------------------------------------------------------


def _normalize_pct(segment):
    """Uppercase percent triplets; decode unreserved characters (RFC 3986 6.2.2)."""
    def fix(m):
        ch = chr(int(m.group(1), 16))
        return ch if re.fullmatch(r"[A-Za-z0-9\-._~]", ch) else "%" + m.group(1).upper()
    return re.sub(r"%([0-9A-Fa-f]{2})", fix, segment)


def _remove_dot_segments(path):
    out = []
    for seg in path.split("/"):
        if seg == ".":
            continue
        if seg == "..":
            if len(out) > 1:
                out.pop()
            continue
        out.append(seg)
    p = "/".join(out)
    if path.endswith(("/.", "/..")):
        p += "/"
    return p if p.startswith("/") else "/" + p


def route_template(url, aliases=None):
    """Canonical route: lowercase scheme and host (aliases folded), default port
    dropped, dot segments removed, numeric and UUID segments replaced with
    placeholders, trailing slash dropped, query reduced to sorted parameter names.
    Path case is kept: paths can be case-sensitive (catalog A5)."""
    p = urlsplit(url)
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower().rstrip(".")
    if aliases:
        host = aliases.get(host, host)
    try:
        port = p.port
    except ValueError:
        port = None
    netloc = host if port in (None, DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    path = _remove_dot_segments(_normalize_pct(p.path or "/"))
    segs = []
    for s in path.split("/"):
        if NUM_SEG.fullmatch(s):
            segs.append("{int}")
        elif UUID_SEG.fullmatch(s):
            segs.append("{uuid}")
        else:
            segs.append(s)
    path = "/".join(segs)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    names = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    return f"{scheme}://{netloc}{path}" + (("?" + "&".join(names)) if names else "")


def claim_key(candidate, aliases=None):
    """Claim key: route template + method + auth context + sink class + parameter
    (+ middleware when recorded). Returns the parts, a readable string and an id."""
    route = route_template(candidate["url"], aliases)
    key = {
        "method": (candidate.get("method") or "GET").upper(),
        "route": route,
        "auth_context": candidate.get("auth_context"),
        "sink_class": candidate.get("sink_class"),
        "parameter": candidate.get("parameter"),
        "middleware": candidate.get("middleware"),
    }
    parts = [key["method"], route, f"auth={key['auth_context']}",
             f"sink={key['sink_class']}", f"param={key['parameter']}"]
    if key["middleware"]:
        parts.append(f"mw={key['middleware']}")
    key["string"] = " | ".join(parts)
    key["id"] = "ck-" + hashlib.sha256(key["string"].encode("utf-8")).hexdigest()[:16]
    return key


def observation_key(candidate):
    """Exact observation key: method, raw URL, status, body hash of the first
    candidate/oracle observation. Kept in lineage, never used to merge."""
    obs = next((o for o in candidate.get("observations", [])
                if o.get("role") in ("candidate", "oracle")), {})
    raw = json.dumps([candidate.get("method", "GET"), candidate.get("url"),
                      obs.get("status"), obs.get("body_sha256")], sort_keys=True)
    return "ok-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def derive_aliases(candidates, ctx=None):
    """Host aliases from evidence, never from shared IPs.
    1. An in-scope host that redirects to another in-scope host.
    2. Hosts serving the same path with the same back-end fingerprint (and the
       same certificate SAN set where both are recorded)."""
    ctx = ctx or {}
    scope = {h.lower() for h in ctx.get("scope_hosts", [])}
    aliases, why = {}, {}
    for c in candidates:
        for o in c.get("observations", []):
            loc = _headers(o).get("location")
            if o.get("status") in REDIRECT_STATUSES and loc:
                src, dst = _host(o["url"]), _host(urljoin(o["url"], loc))
                if src != dst and src in scope and dst in scope:
                    aliases[src] = dst
                    why[src] = f"redirect {src} -> {dst}"
    by_fp = {}
    for c in candidates:
        fp = c.get("backend_fingerprint")
        if fp:
            path = urlsplit(route_template(c["url"])).path
            by_fp.setdefault((fp, c.get("cert_san_sha256"), path), set()).add(_host(c["url"]))
    for (fp, _san, _path), hosts in by_fp.items():
        if len(hosts) > 1:
            canon = sorted(hosts, key=lambda h: (len(h), h))[0]
            for h in hosts:
                if h != canon and h not in aliases:
                    aliases[h] = canon
                    why[h] = f"same back-end fingerprint {fp} as {canon}"

    def resolve(h, seen=()):
        nxt = aliases.get(h)
        return h if nxt is None or nxt in seen else resolve(nxt, seen + (h,))
    return {h: resolve(h) for h in aliases}, why


STRENGTH_RANK = {"strong": 3, "moderate": 2, "weak": 1}


def group_candidates(candidates, mode="claim", ctx=None):
    """Group candidates without losing any. mode='claim' groups on the claim key
    (aliases folded); mode='component' groups vended products on product,
    version and advisory, and pre-stages the vendor-relationship owner.
    Every candidate lands in exactly one group, with lineage."""
    ctx = ctx or {}
    aliases, why = derive_aliases(candidates, ctx)
    owners = {k.lower(): v for k, v in ctx.get("vendor_owners", {}).items()}
    groups, order = {}, []
    for c in candidates:
        if mode == "component":
            comp = c.get("component") or {}
            key = f"{str(comp.get('product', '?')).lower()}@{comp.get('version', '?')}#{comp.get('advisory', '?')}"
        else:
            key = claim_key(c, aliases)["string"]
        if key not in groups:
            groups[key] = {"key": key, "members": [], "lineage": [], "chain_steps": []}
            if mode == "component":
                product = str((c.get("component") or {}).get("product", "")).lower()
                groups[key]["owner"] = owners.get(product, "UNOWNED: route to the default owner queue (O1), never to suppression")
            order.append(key)
        grp = groups[key]
        host = _host(c["url"])
        reasons = []
        if host in aliases:
            reasons.append(f"ALIAS_HOST({why.get(host)})")
        reasons.append("SAME_COMPONENT_VERSION" if mode == "component" else "SAME_CLAIM_KEY")
        grp["members"].append(c["id"])
        grp["lineage"].append({
            "id": c["id"], "url": c.get("url"), "observation_key": observation_key(c),
            "reason": reasons if grp["members"][0] != c["id"] else ["FIRST_SEEN"],
            "reachability": c.get("reachability"),
            "evidence_strength": c.get("evidence_strength"),
        })
        for step in c.get("chain_steps", []):
            if step not in grp["chain_steps"]:
                grp["chain_steps"].append(step)
    out = []
    for key in order:
        grp = groups[key]
        # Canonical = strongest evidence, not earliest (catalog B1 trap).
        best = max(grp["lineage"], key=lambda m: STRENGTH_RANK.get(m.get("evidence_strength"), 0))
        grp["canonical_id"] = best["id"]
        out.append(grp)
    seen = [m for grp in out for m in grp["members"]]
    assert sorted(seen) == sorted(c["id"] for c in candidates), "grouping lost or duplicated a candidate"
    return out


# ---------------------------------------------------------------------------
# Lint-stage detectors (deterministic, heuristic)
# ---------------------------------------------------------------------------


def lint_observation(obs, ctx):
    """Labels for one response, plus its provenance: edge, origin or unknown."""
    h = _headers(obs)
    labels = []
    prov = obs.get("provenance", "unknown")
    if h.get("cf-mitigated", "").lower() == "challenge" or \
            h.get("x-amzn-waf-action", "").lower() in ("challenge", "captcha", "block"):
        labels.append("EDGE_CHALLENGE")
        prov = "edge"
    if obs.get("body_sha256") and obs["body_sha256"] in set(ctx.get("edge_block_page_hashes", [])):
        labels.append("EDGE_BLOCK_PAGE")
        prov = "edge"
    expected = (obs.get("expected_content_type") or "").lower()
    got = (obs.get("content_type") or h.get("content-type", "")).lower()
    if "json" in expected and "text/html" in got:
        labels.append("CONTENT_TYPE_SWAP")  # suspicious, not proof of an edge
    cache_status = h.get("cf-cache-status", "").upper()
    age = h.get("age", "").strip()
    if cache_status in ("HIT", "STALE", "UPDATING", "REVALIDATED") or "HIT" in h.get("x-cache", "").upper() \
            or (age.isdigit() and int(age) > 0):
        labels.append("CACHE_HIT")
        if not obs.get("cache_buster"):
            labels.append("CACHE_UNCONTROLLED")
    status = obs.get("status")
    if status in REDIRECT_STATUSES and h.get("location"):
        dest = urljoin(obs["url"], h["location"])
        labels.append("SAME_ORIGIN_REDIRECT" if _origin(dest) == _origin(obs["url"]) else "OFF_ORIGIN_REDIRECT")
        if LOGIN_PATH.search(urlsplit(dest).path):
            labels.append("LOGIN_BOUNCE")
    elif status == 200 and obs.get("role") != "calibration" and LOGIN_TITLE.search(obs.get("title") or ""):
        labels.append("LOGIN_BOUNCE")
    if status == 429 or "retry-after" in h:
        labels.append("RATE_LIMITED")
    return labels, prov


def _matches_calibration(obs, cal):
    if obs.get("status") != cal.get("status"):
        return False
    if obs.get("body_sha256") and obs.get("body_sha256") == cal.get("body_sha256"):
        return True
    bl, cl = obs.get("body_len"), cal.get("body_len")
    if bl is None or cl is None:
        return False
    near = abs(bl - cl) <= max(16, 0.02 * cl)
    return near and obs.get("words") == cal.get("words") and obs.get("lines") == cal.get("lines") \
        and (obs.get("title") or "") == (cal.get("title") or "")


def lint_candidate(cand, ctx):
    by_obs, prov = {}, {}
    observations = cand.get("observations", [])
    for o in observations:
        labels, p = lint_observation(o, ctx)
        by_obs[o["id"]] = labels
        prov[o["id"]] = p
    # Soft 404: candidate response matches at least two calibration probes.
    cals = [o for o in observations if o.get("role") == "calibration"]
    for o in observations:
        if o.get("role") != "candidate":
            continue
        if len(cals) >= 2:
            if all(_matches_calibration(o, c) for c in cals):
                by_obs[o["id"]].append("SOFT_404")
            elif not all(_matches_calibration(cals[0], c) for c in cals[1:]):
                by_obs[o["id"]].append("CALIBRATION_UNSTABLE")
        elif cals:
            by_obs[o["id"]].append("CALIBRATION_THIN")
    # Tester-chain header: present through the proxy, absent on a clean-egress replay.
    for o in observations:
        if o.get("path") != "proxy":
            continue
        h = _headers(o)
        for sig in ctx.get("tester_chain_signatures", []):
            name = sig["header"].lower()
            if name not in h or sig.get("contains", "").lower() not in h[name].lower():
                continue
            directs = [d for d in observations if d.get("path") == "direct" and d.get("url") == o.get("url")]
            if not directs:
                by_obs[o["id"]].append("TESTER_CHAIN_UNVERIFIED")
            elif any(name in _headers(d) for d in directs):
                by_obs[o["id"]].append("TARGET_ALSO_SENDS_HEADER")
            else:
                by_obs[o["id"]].append("TESTER_CHAIN_HEADER")
    labels = []
    for o in observations:
        for lab in by_obs[o["id"]]:
            if lab not in labels:
                labels.append(lab)
    return {"labels": labels, "by_obs": by_obs, "provenance": prov}


def fingerprint_diff(captured, observed):
    if not captured or not observed:
        return []
    return sorted(k for k in set(captured) & set(observed) if captured[k] != observed[k])


def analyze_callbacks(ev, ctx):
    """Classify out-of-band interactions by token and source."""
    token, decoy = ev.get("probe_token"), ev.get("decoy_token")
    nets = [ipaddress.ip_network(n) for n in ctx.get("target_egress_cidrs", [])]
    intermediaries = {s.lower() for s in ctx.get("intermediary_asn_orgs", [])}
    callbacks = ev.get("callbacks", [])
    labels = []
    if decoy and any(c.get("token") == decoy for c in callbacks):
        labels.append("DECOY_FIRED")
    mine = [c for c in callbacks if c.get("token") == token]
    if not mine:
        return labels + ["NO_CALLBACK"]

    def in_target(ip):
        try:
            addr = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return False
        return any(addr in n for n in nets)
    http = [c for c in mine if c.get("protocol") in ("http", "https")]
    via_inter = [c for c in http if (c.get("asn_org") or "").lower() in intermediaries]
    from_target = [c for c in http if c not in via_inter and in_target(c.get("source_ip"))]
    if from_target:
        labels.append("CALLBACK_HTTP_FROM_TARGET")
    if via_inter:
        labels.append("CALLBACK_FROM_INTERMEDIARY")
    if http and not from_target and not via_inter:
        labels.append("CALLBACK_HTTP_UNATTRIBUTED")
    if not http:
        labels.append("CALLBACK_DNS_ONLY")
    return labels


def _strip_upper_outliers(xs):
    if len(xs) < 4:
        return list(xs)
    q1, _, q3 = statistics.quantiles(xs, n=4)
    cut = q3 + 1.5 * (q3 - q1)
    return [x for x in xs if x <= cut]


def analyze_timing(ev, min_baseline=30, min_levels=2, min_per_level=3, min_controls=3):
    """Timing as a statistical oracle. A trial counts as delayed only at
    observed >= max(0.5 s, mean + 7*sd) of the baseline after an upper-outlier
    strip (after sqlmap's rule; the IQR strip is this prototype's own choice).
    Also needs interleaved zero-delay controls and dose-response."""
    base = [float(x) for x in ev.get("baseline_s", [])]
    problems = []
    if len(base) < min_baseline:
        problems.append(f"baseline has {len(base)} samples; need at least {min_baseline}")
    stripped = _strip_upper_outliers(base)
    mean = statistics.fmean(stripped) if stripped else 0.0
    sd = statistics.pstdev(stripped) if len(stripped) > 1 else 0.0
    threshold = max(0.5, mean + 7 * sd)
    levels = {}
    for t in ev.get("trials", []):
        levels.setdefault(float(t["requested_delay_s"]), []).append(float(t["observed_s"]))
    nonzero = {k: v for k, v in levels.items() if k > 0}
    controls = levels.get(0.0, [])
    if len(nonzero) < min_levels:
        problems.append(f"{len(nonzero)} non-zero delay level(s); need at least {min_levels} for dose-response")
    thin = sorted(k for k, v in nonzero.items() if len(v) < min_per_level)
    if thin:
        problems.append(f"delay level(s) {thin} have fewer than {min_per_level} trials")
    if len(controls) < min_controls:
        problems.append(f"{len(controls)} zero-delay control(s); need at least {min_controls}")
    if not ev.get("interleaved"):
        problems.append("trials were not interleaved with the controls")
    hot = [x for x in controls if x >= threshold]
    if hot:
        problems.append(f"{len(hot)} zero-delay control(s) crossed the {threshold:.2f} s threshold")
    missed = [x for v in nonzero.values() for x in v if x < threshold]
    if missed:
        problems.append(f"{len(missed)} delayed trial(s) fell under the {threshold:.2f} s threshold")
    ks = sorted(nonzero)
    means = [statistics.fmean(nonzero[k]) for k in ks]
    if len(ks) >= 2 and any(b <= a for a, b in zip(means, means[1:])):
        problems.append("observed delay does not rise with the requested delay (no dose-response)")
    model = {"baseline_n": len(base), "baseline_n_after_strip": len(stripped),
             "mean_s": round(mean, 4), "sd_s": round(sd, 4), "threshold_s": round(threshold, 4),
             "rule": "delayed iff observed >= max(0.5 s, mean + 7*sd) after upper-outlier strip"}
    return ("delayed" if not problems else "inconclusive"), problems, model


# ---------------------------------------------------------------------------
# CVSS v4 vector (format and nomenclature only; no scoring)
# ---------------------------------------------------------------------------

CVSS4_BASE = {"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
              "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN"}
CVSS4_THREAT = {"E": "XAPU"}
CVSS4_ENV = {"CR": "XHML", "IR": "XHML", "AR": "XHML", "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP",
             "MPR": "XNLH", "MUI": "XNPA", "MVC": "XHLN", "MVI": "XHLN", "MVA": "XHLN",
             "MSC": "XHLN", "MSI": "XSHLN", "MSA": "XSHLN"}
CVSS4_SUPP = {"S": "XNP", "AU": "XNY", "R": "XAUI", "V": "XDC", "RE": "XLMH"}
CVSS4_U = {"X", "Clear", "Green", "Amber", "Red"}


def parse_cvss4(vector):
    """Return (ok, nomenclature, message). Checks metric names, values, required
    base metrics and duplicates. Does not check metric order or compute a score."""
    if not vector.startswith("CVSS:4.0/"):
        return False, None, "vector must start with CVSS:4.0/"
    seen = {}
    for part in vector[len("CVSS:4.0/"):].split("/"):
        if ":" not in part:
            return False, None, f"malformed metric {part!r}"
        k, v = part.split(":", 1)
        if k in seen:
            return False, None, f"duplicate metric {k}"
        allowed = {**CVSS4_BASE, **CVSS4_THREAT, **CVSS4_ENV, **CVSS4_SUPP}.get(k)
        if k == "U":
            if v not in CVSS4_U:
                return False, None, f"bad value {v!r} for U"
        elif allowed is None:
            return False, None, f"unknown metric {k}"
        elif len(v) != 1 or v not in allowed:
            return False, None, f"bad value {v!r} for {k}"
        seen[k] = v
    missing = [k for k in CVSS4_BASE if k not in seen]
    if missing:
        return False, None, f"missing base metric(s) {', '.join(missing)}"
    threat = any(seen.get(k, "X") != "X" for k in CVSS4_THREAT)
    env = any(seen.get(k, "X") != "X" for k in CVSS4_ENV)
    nom = "CVSS-B" + ("T" if threat else "") + ("E" if env else "")
    return True, nom, "ok"


# ---------------------------------------------------------------------------
# Shared rule pieces
# ---------------------------------------------------------------------------


def check_positive_control(pc, res, where):
    if not isinstance(pc, dict) or not pc.get("ran"):
        res.refuse("CLOSE_WITHOUT_POSITIVE_CONTROL",
                   f"{where}: a close needs a positive control showing the oracle could have fired here; none was run.")
        return False
    if not pc.get("fired"):
        res.refuse("POSITIVE_CONTROL_DID_NOT_FIRE",
                   f"{where}: the positive control ran but did not fire, so the oracle could not have fired either "
                   "(for example egress is blocked or the edge ate the payload). Its silence proves nothing.")
        return False
    return True


def _check_recheck(tr, res, now, covered, horizon_days):
    rb = tr.get("recheck_by")
    if not rb:
        res.refuse("DEMOTION_WITHOUT_RECHECK",
                   "a demoted state needs a recheck_by date; without one a demotion becomes a quiet close.")
        covered.add("recheck_by")
        return
    when = safe_time(rb)
    if when is None:
        return  # schema reports the format error
    if when <= now:
        res.refuse("DEMOTION_RECHECK_IN_PAST", f"recheck_by {rb} is not in the future.")
    elif when > now + dt.timedelta(days=horizon_days):
        res.refuse("DEMOTION_RECHECK_TOO_FAR",
                   f"recheck_by {rb} is more than {horizon_days} days out; demoted items are aged and sampled, not parked.")


# ---------------------------------------------------------------------------
# Candidate state transitions
# ---------------------------------------------------------------------------


def _t_closed(cand, tr, ctx, res, lint, now):
    outcome = tr.get("outcome")
    oracle = tr.get("oracle") if isinstance(tr.get("oracle"), dict) else {}
    otype = oracle.get("type") if isinstance(oracle.get("type"), str) else None

    changed = fingerprint_diff(cand.get("captured_fingerprint"), tr.get("validation_fingerprint"))
    if changed:
        res.label("TARGET_CHANGED")
        res.refuse("TARGET_CHANGED",
                   f"the target fingerprint changed between capture and validation ({', '.join(changed)}). "
                   "'Fixed since' or 'moved since' is not a false positive: re-baseline against the current target, "
                   "then re-run the oracle.")
        res.suggest({"state": "rebaseline_required", "reason": "TARGET_CHANGED",
                     "observed_fingerprint": tr.get("validation_fingerprint")})

    if not otype or otype == "none":
        res.refuse("CLOSE_WITHOUT_ORACLE",
                   "only an oracle may close a candidate, and the oracle type is 'none' or missing. "
                   "Record what would settle it and leave the candidate open or demoted.")
        pc_ok = False
    else:
        pc_ok = check_positive_control(oracle.get("positive_control"), res, "transition")

    refs = oracle.get("observation_refs")
    obs_ids = refs if refs is not None else [o["id"] for o in cand.get("observations", [])
                                             if o.get("role") in ("candidate", "oracle")]
    edge_ids = [i for i in obs_ids if lint["provenance"].get(i) == "edge"]
    if outcome == "refuted" and (edge_ids or EDGE_WORDS.search(tr.get("reason", ""))):
        res.refuse("EDGE_RECORDED_AS_NOT_VULNERABLE",
                   "the response the oracle read came from the edge (or the reason cites a WAF/CDN block). "
                   "Blocked at the edge says nothing about the origin; record blocked_at_edge_origin_unknown "
                   "with the bypass search open.")
        res.suggest({"state": "blocked_at_edge_origin_unknown",
                     "edge_evidence_ref": (edge_ids or obs_ids or ["?"])[0], "bypass_search": "open",
                     "recheck_by": (now + dt.timedelta(days=EDGE_RECHECK_DAYS)).date().isoformat()})
    elif outcome == "confirmed" and edge_ids:
        res.refuse("ORACLE_OBSERVATION_FROM_EDGE",
                   f"observation(s) {edge_ids} came from the edge, not the target; an edge page is not target behavior.")

    uncontrolled = [i for i in obs_ids if "CACHE_UNCONTROLLED" in lint["by_obs"].get(i, [])]
    if uncontrolled:
        res.refuse("CACHE_ARTIFACT_UNCONTROLLED",
                   f"observation(s) {uncontrolled} were served from a cache with no cache buster; "
                   "replay with a cache buster and read Age and the cache-status header before any close.")
        res.suggest({"state": "demoted", "reason_code": "CACHE_ARTIFACT",
                     "recheck_by": (now + dt.timedelta(days=7)).date().isoformat()})
        res.warn("If the cached body holds another user's data, route it to a person: it may be cache deception "
                 "with real-user impact (catalog C6).")

    ev = oracle.get("evidence") if isinstance(oracle.get("evidence"), dict) else {}
    if otype == "out-of-band":
        cb = analyze_callbacks(ev, ctx)
        for lab in cb:
            res.label(lab)
        if outcome == "confirmed":
            if "DECOY_FIRED" in cb:
                res.refuse("DECOY_FIRED", "the decoy token fired, so callbacks cannot be attributed to this probe.")
            if "CALLBACK_HTTP_FROM_TARGET" not in cb:
                if "CALLBACK_FROM_INTERMEDIARY" in cb:
                    res.refuse("CALLBACK_FROM_INTERMEDIARY",
                               "the HTTP callback came from an intermediary (CDN, mail scanner, IPS), not the "
                               "application. Classify by source: an intermediary that fetches attacker URLs may be "
                               "its own in-scope finding, but it does not confirm this one.")
                elif "CALLBACK_DNS_ONLY" in cb:
                    res.refuse("CALLBACK_DNS_ONLY",
                               "only a DNS lookup arrived. A resolver lookup is indirect: it is weaker than an HTTP "
                               "callback from the application and cannot confirm on its own.")
                elif "CALLBACK_HTTP_UNATTRIBUTED" in cb:
                    res.refuse("CALLBACK_UNATTRIBUTED",
                               "an HTTP callback arrived from a source outside the target's recorded egress ranges.")
                else:
                    res.refuse("NO_CALLBACK", "no callback carried this probe's token.")
        elif outcome == "refuted":
            if "NO_CALLBACK" not in cb:
                res.refuse("CALLBACK_CONTRADICTS_REFUTATION", "a callback carrying the probe token arrived.")
            if not pc_ok:
                res.label("EGRESS_UNVERIFIED")
                res.suggest({"state": "demoted", "reason_code": "EGRESS_UNVERIFIED",
                             "recheck_by": (now + dt.timedelta(days=14)).date().isoformat()})
    elif otype == "timing-distribution":
        verdict, problems, model = analyze_timing(ev)
        res.notes["timing_model"] = model
        if outcome == "confirmed" and verdict != "delayed":
            res.refuse("TIMING_INSUFFICIENT", "timing oracle is inconclusive: " + "; ".join(problems) + ".")
            res.suggest({"state": "demoted", "reason_code": "TIMING_INCONCLUSIVE",
                         "recheck_by": (now + dt.timedelta(days=14)).date().isoformat()})
        elif outcome == "refuted":
            if model["baseline_n"] < 30 or not ev.get("trials"):
                res.refuse("TIMING_INSUFFICIENT", "a timing refutation needs at least 30 baseline samples and trials.")
            elif verdict == "delayed":
                res.refuse("TIMING_CONTRADICTS_REFUTATION", "the trials meet the delay rule.")

    if isinstance(tr.get("package"), dict):
        res.absorb(check_package(tr["package"], ctx))
    return set()


def _t_demoted(cand, tr, ctx, res, lint, now):
    covered = set()
    code = tr.get("reason_code")
    if not code:
        res.refuse("DEMOTION_WITHOUT_REASON",
                   "a demotion needs a reason code (a filter may lower rank, but it must say why).")
        covered.add("reason_code")
    _check_recheck(tr, res, now, covered, ctx.get("recheck_horizon_days", DEFAULT_RECHECK_HORIZON_DAYS))
    needed = EVIDENCE_BACKED_REASONS.get(code)
    if needed and needed not in lint["labels"]:
        if code == "TESTER_PATH_ARTIFACT" and "TARGET_ALSO_SENDS_HEADER" in lint["labels"]:
            msg = ("the clean-egress replay shows the target sends this header too; the tester's proxy may be "
                   "masking a real header. Not a tester-path artifact.")
        elif code == "TESTER_PATH_ARTIFACT":
            msg = "no clean-egress replay shows the header is absent without the tester's proxy chain."
        elif code == "SOFT_404":
            msg = ("the candidate response does not match the calibration probes on status, hash, size, words, "
                   "lines and title; a real resource may sit behind the catch-all.")
        else:
            msg = f"reason {code} needs detector {needed}, which did not fire on this candidate's observations."
        res.refuse("REASON_NOT_SUPPORTED_BY_EVIDENCE", msg)
    if code in CHAIN_LINK_REASONS:
        res.warn(f"{code} is a chain link: it changes rank and route, never truth. Keep it visible to chain-finding.")
    if code:
        res.notes["classes"] = REASON_CLASSES.get(code, [])
    return covered


def _t_blocked_at_edge(cand, tr, ctx, res, lint, now):
    covered = set()
    if not ({"EDGE_CHALLENGE", "EDGE_BLOCK_PAGE"} & set(lint["labels"])):
        res.refuse("REASON_NOT_SUPPORTED_BY_EVIDENCE",
                   "no observation carries an edge marker (challenge header or known block page).")
    _check_recheck(tr, res, now, covered, ctx.get("recheck_horizon_days", DEFAULT_RECHECK_HORIZON_DAYS))
    return covered


def _t_merged(cand, tr, ctx, res, lint, now):
    pool = {c["id"]: c for c in ctx.get("candidates", [])}
    into = pool.get(tr.get("into"))
    if into is None:
        res.refuse("MERGE_TARGET_UNKNOWN", f"merge target {tr.get('into')!r} is not among the known candidates.")
        return set()
    if "OFF_ORIGIN_REDIRECT" in lint["labels"]:
        dests = [urljoin(o["url"], _headers(o).get("location", "")) for o in cand.get("observations", [])
                 if "OFF_ORIGIN_REDIRECT" in lint["by_obs"].get(o["id"], [])]
        res.refuse("OFF_ORIGIN_REDIRECT_IS_SCOPE_QUESTION",
                   f"the candidate redirects off origin ({', '.join(sorted({_host(d) for d in dests}))}). "
                   "That is a scope question, not a duplicate.")
        res.suggest({"state": "scope_hold", "reason": "off-origin redirect: " + ", ".join(sorted(set(dests)))})
    aliases, _ = derive_aliases([cand, into], ctx)
    ka, kb = claim_key(cand, aliases), claim_key(into, aliases)
    axis_failed = False
    for axis in NEVER_MERGE_AXES:
        a, b = ka[axis], kb[axis]
        if a == b:
            continue
        axis_failed = True
        if a is None or b is None:
            res.refuse("NEVER_MERGE_AXIS",
                       f"{axis} is recorded on one side only ({a!r} vs {b!r}); an unknown axis cannot be shown "
                       "equal. A missed merge leaves a visible duplicate; a false merge can hide a real vulnerability.")
        else:
            res.refuse("NEVER_MERGE_AXIS",
                       f"{axis} differs ({a!r} vs {b!r}); one exploitation attempt cannot settle both, so they "
                       "stay separate.")
    if not axis_failed:
        for part in ("method", "sink_class"):
            if ka[part] != kb[part]:
                res.refuse("CLAIM_KEY_MISMATCH", f"{part} differs ({ka[part]!r} vs {kb[part]!r}).")
    declared = tr.get("claim_key")
    if declared and declared not in (kb["string"], kb["id"]):
        res.refuse("CLAIM_KEY_DECLARED_MISMATCH",
                   f"declared claim_key {declared!r} does not match the computed key {kb['string']!r} ({kb['id']}).")
    src_steps = {(s.get("chain_id"), s.get("step")) for s in cand.get("chain_steps", [])}
    result = tr.get("result_chain_steps")
    if result is None:
        result = into.get("chain_steps", [])
    kept = {(s.get("chain_id"), s.get("step")) for s in result}
    dropped = sorted(src_steps - kept)
    if dropped:
        res.refuse("MERGE_DROPS_CHAIN_STEP",
                   f"the merge would drop chain step(s) {[f'{c} step {s}' for c, s in dropped]}. Carry them in "
                   "result_chain_steps, or do not merge.")
    res.notes["claim_key"] = kb["string"]
    return set()


def _t_rebaseline(cand, tr, ctx, res, lint, now):
    if not fingerprint_diff(cand.get("captured_fingerprint"), tr.get("observed_fingerprint")):
        res.refuse("REASON_NOT_SUPPORTED_BY_EVIDENCE",
                   "observed_fingerprint does not differ from the captured fingerprint.")
    return set()


def _t_noop(cand, tr, ctx, res, lint, now):
    return set()


TRANSITIONS = {
    "open": _t_noop, "merged": _t_merged, "demoted": _t_demoted, "scope_hold": _t_noop,
    "blocked_at_edge_origin_unknown": _t_blocked_at_edge, "rebaseline_required": _t_rebaseline,
    "not_reviewed_no_capacity": _t_noop, "closed_by_oracle": _t_closed,
}


def check_transition(candidate, transition, ctx=None):
    """Check a proposed state for a candidate. Returns a Result."""
    ctx = ctx or {}
    res = Result()
    now = safe_time(ctx.get("now")) or dt.datetime.now(dt.timezone.utc)
    lint = lint_candidate(candidate, ctx)
    for lab in lint["labels"]:
        res.label(lab)
    state = transition.get("state")
    if state not in state_names():
        res.refuse("UNKNOWN_STATE",
                   f"{state!r} is not a candidate state (allowed: {', '.join(state_names())}). "
                   "A label such as 'not_vulnerable' is not a state; only closed_by_oracle closes.")
        return res
    covered = TRANSITIONS[state](candidate, transition, ctx, res, lint, now) or set()
    schema = load_schema("candidate_state.schema.json")
    for path, msg in validate(transition, schema["$defs"][state], root=schema):
        if path.split(".")[-1] in covered:
            continue
        res.refuse("STATE_SCHEMA", f"{path} {msg}")
    return res


# ---------------------------------------------------------------------------
# Validation packages
# ---------------------------------------------------------------------------


def check_package(pkg, ctx=None):
    """Check a validation package against the schema and the rules. Returns a Result."""
    ctx = ctx or {}
    res = Result()
    for path, msg in validate(pkg, load_schema("package.schema.json")):
        res.refuse("PACKAGE_SCHEMA", f"{path} {msg}")

    # Credentials are referenced by role, never inlined.
    headers = gd(pkg, "replay.request.headers")
    roles = {i.get("role") for i in _as_list(g(pkg, "replay.identities")) if isinstance(i, dict)}
    for name, value in headers.items():
        value = str(value)
        if name.lower() in SECRET_HEADERS and not PLACEHOLDER.search(value):
            res.refuse("INLINE_CREDENTIAL",
                       f"replay.request.headers.{name} carries a literal value. Use {{{{identity:<role>}}}} and keep "
                       "the secret in an environment variable or vault.")
        for role in PLACEHOLDER.findall(value):
            if role not in roles:
                res.refuse("UNKNOWN_IDENTITY_ROLE", f"header {name} references role {role!r}, which has no identity.")

    vector = g(pkg, "severity.cvss_v4_vector")
    if isinstance(vector, str):
        ok, nom, msg = parse_cvss4(vector)
        if not ok:
            res.refuse("CVSS_VECTOR_INVALID", f"cvss_v4_vector: {msg}.")
        elif nom != g(pkg, "severity.cvss_v4_nomenclature"):
            res.refuse("CVSS_NOMENCLATURE_MISMATCH",
                       f"the vector's metric groups make it {nom}, but the package says "
                       f"{g(pkg, 'severity.cvss_v4_nomenclature')}.")

    start, end = safe_time(g(pkg, "authorization.window.start")), safe_time(g(pkg, "authorization.window.end"))
    executed = safe_time(g(pkg, "replay.executed_at"))
    if start and end and executed and not (start <= executed <= end):
        res.refuse("OUTSIDE_AUTHORIZED_WINDOW", "replay.executed_at falls outside the authorized test window.")

    disposition = gs(pkg, "review.disposition")
    otype = gs(pkg, "oracle.type")
    if disposition in CLOSING_DISPOSITIONS:
        if otype in (None, "none"):
            res.refuse("CLOSE_WITHOUT_ORACLE",
                       f"disposition '{disposition}' closes the candidate, but the oracle type is 'none'. "
                       "Only an oracle may close.")
        else:
            check_positive_control(g(pkg, "oracle.positive_control"), res, "package")
    if disposition == "dismissed":
        text = " ".join(str(g(pkg, f"review.questions.{q}.reason") or "") for q in QUESTIONS)
        if "C4" in _as_list(g(pkg, "claim.non_unique_classes")) or EDGE_WORDS.search(text):
            res.refuse("EDGE_RECORDED_AS_NOT_VULNERABLE",
                       "a dismissal that rests on an edge block says nothing about the origin; "
                       "use disposition blocked_at_edge_origin_unknown.")

    tool, validated = gs(pkg, "severity.tool_rating"), gs(pkg, "severity.validated_rating")
    if tool in SEVERITY_RANK and validated in SEVERITY_RANK and SEVERITY_RANK[validated] < SEVERITY_RANK[tool]:
        downs = [e for e in _as_list(g(pkg, "severity.change_log")) if isinstance(e, dict)
                 and SEVERITY_RANK.get(e.get("to"), 9) < SEVERITY_RANK.get(e.get("from"), -1)]
        if not downs:
            res.refuse("SEVERITY_CHANGE_NOT_LOGGED", f"severity fell from {tool} to {validated} with no change-log entry.")
        signer = g(pkg, "severity.signed_by")
        authors = {e.get("by") for e in downs}
        if not signer or signer in authors:
            res.refuse("SELF_SIGNED_DOWNGRADE",
                       f"the downgrade from {tool} to {validated} is signed by its own author ({signer}). "
                       "Downgrades route up to a second signer.")
            res.route_to = "lead signer (a second person)"

    if validated == "Critical":
        missing = []
        if otype not in DIRECT_ORACLES:
            missing.append(f"a direct oracle (have '{otype}')")
        ir = gd(pkg, "replay.independent_replay")
        if ir.get("result") != "reproduced" or not ir.get("by") or ir.get("by") == g(pkg, "replay.executed_by"):
            missing.append("an independent replay by a second person")
        if g(pkg, "severity.evidence.reachability") != "proven":
            missing.append("reachability from where the threat is (inferred)")
        if g(pkg, "severity.evidence.impact") != "proven":
            missing.append("proven impact (inferred)")
        if missing:
            res.refuse("CRITICAL_GATE",
                       "Critical needs a direct oracle, an independent replay, reachability from the threat "
                       f"position and proven impact. Missing: {'; '.join(missing)}. Capped at 'High, pending'; send a "
                       "provisional notice to the owner and the security lead with a validation deadline in hours.")
            res.severity_cap = "High, pending"

    if validated in ("High", "Critical"):
        recorded = safe_time(g(pkg, "controls.expected_difference.recorded_at"))
        if recorded is None:
            res.refuse("PREREG_MISSING", "High and Critical need the expected difference recorded before replay.")
        elif executed and recorded >= executed:
            res.refuse("PREREG_AFTER_REPLAY",
                       f"the expected difference was recorded at {g(pkg, 'controls.expected_difference.recorded_at')}, "
                       f"at or after the replay ({g(pkg, 'replay.executed_at')}). For High and Critical it must be "
                       "written down first.")

    handoff = gd(pkg, "replay.handoff")
    needs = handoff.get("requires_tester_tooling") if isinstance(handoff.get("requires_tester_tooling"), list) else []
    if not handoff.get("tester_assisted"):
        if needs:
            res.refuse("HANDOFF_NEEDS_TESTER_MARK",
                       f"the replay needs tester tooling ({', '.join(map(str, needs))}) but is not marked tester-assisted.")
        elif otype in NON_TRAVELLING_ORACLES and not handoff.get("self_check"):
            res.refuse("HANDOFF_NEEDS_TESTER_MARK",
                       f"a '{otype}' oracle does not travel to a developer laptop; give a self-check or mark the "
                       "retest tester-assisted.")

    proven, of = g(pkg, "review.scope.proven"), g(pkg, "review.scope.of")
    if isinstance(proven, int) and isinstance(of, int) and proven > of:
        res.refuse("SCOPE_STATEMENT_INVALID", f"scope says {proven} proven of {of}.")

    if g(pkg, "retest.at"):
        if g(pkg, "retest.expected_refusal_observed") is None or g(pkg, "retest.controls_still_behaving") is None:
            res.refuse("RETEST_INCOMPLETE",
                       "a retest needs the expected refusal observed and the controls still behaving, recorded.")
        elif g(pkg, "retest.expected_refusal_observed") is False:
            res.label("RETEST_FAILED")
    return res


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def load_fixture_package(fx, fixtures_dir):
    if "package" in fx:
        return fx["package"]
    with open(os.path.join(fixtures_dir, fx["package_base"]), encoding="utf-8") as f:
        base = json.load(f)
    return merge_patch(base, fx.get("package_patch", {}))


def run_fixture(fx, fixtures_dir):
    ctx = fx.get("context", {})
    kind = fx["kind"]
    if kind == "package":
        return check_package(load_fixture_package(fx, fixtures_dir), ctx).to_dict()
    if kind == "transition":
        return check_transition(fx["candidate"], fx["transition"], ctx).to_dict()
    if kind == "group":
        groups = group_candidates(fx["candidates"], fx.get("group_by", "claim"), ctx)
        return {"verdict": "GROUPED", "groups": groups}
    raise ValueError(f"unknown fixture kind {kind!r}")


def compare_fixture(fx, actual):
    """Return a list of mismatches between a fixture's expected block and the result."""
    exp, out = fx["expected"], []
    if exp.get("verdict") != actual.get("verdict"):
        out.append(f"verdict: expected {exp.get('verdict')}, got {actual.get('verdict')}")
    if "reason_codes" in exp:
        got = sorted({r["code"] for r in actual.get("reasons", [])})
        if sorted(set(exp["reason_codes"])) != got:
            out.append(f"reason codes: expected {sorted(set(exp['reason_codes']))}, got {got}")
    for lab in exp.get("labels", []):
        if lab not in actual.get("labels", []):
            out.append(f"label {lab} missing (got {actual.get('labels')})")
    if "suggested_state" in exp:
        got = (actual.get("suggested_state") or {}).get("state")
        if got != exp["suggested_state"]:
            out.append(f"suggested_state: expected {exp['suggested_state']}, got {got}")
    for k in ("severity_cap", "route_to"):
        if k in exp and exp[k] != actual.get(k):
            out.append(f"{k}: expected {exp[k]!r}, got {actual.get(k)!r}")
    if "groups" in exp:
        want = sorted(sorted(grp) for grp in exp["groups"])
        got = sorted(sorted(grp["members"]) for grp in actual.get("groups", []))
        if want != got:
            out.append(f"groups: expected {want}, got {got}")
        for spec in exp.get("group_owners", []):
            match = [grp for grp in actual.get("groups", []) if sorted(grp["members"]) == sorted(spec["members"])]
            if not match or not str(match[0].get("owner", "")).startswith(spec["owner_prefix"]):
                out.append(f"owner for {spec['members']}: expected prefix {spec['owner_prefix']!r}")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_result(name, d):
    print(f"{name}: {d['verdict']}")
    for r in d.get("reasons", []):
        print(f"  - {r['code']}: {r['message']}")
    if d.get("labels"):
        print(f"  labels: {', '.join(d['labels'])}")
    for w in d.get("warnings", []):
        print(f"  warning: {w}")
    if d.get("suggested_state"):
        print(f"  suggested state: {json.dumps(d['suggested_state'])}")
    if d.get("severity_cap"):
        print(f"  severity cap: {d['severity_cap']}")
    if d.get("route_to"):
        print(f"  route to: {d['route_to']}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check validation packages, candidate states and fixtures (prototype).")
    ap.add_argument("files", nargs="*")
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    ap.add_argument("--claim-key", metavar="URL", help="print the claim key for a URL and exit")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--auth", default=None)
    ap.add_argument("--sink", default=None)
    ap.add_argument("--param", default=None)
    args = ap.parse_args(argv)

    if args.claim_key:
        print(json.dumps(claim_key({"url": args.claim_key, "method": args.method, "auth_context": args.auth,
                                    "sink_class": args.sink, "parameter": args.param}), indent=2))
        return 0
    if not args.files:
        ap.print_help()
        return 2
    rc = 0
    for path in args.files:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        name = os.path.relpath(path)
        if "fixture_id" in doc:
            actual = run_fixture(doc, os.path.dirname(os.path.abspath(path)))
            mismatches = compare_fixture(doc, actual)
            if args.json:
                print(json.dumps({"fixture": name, "pass": not mismatches, "mismatches": mismatches,
                                  "actual": actual}, indent=2, default=str))
            else:
                print(f"{'PASS' if not mismatches else 'FAIL'} {name}: {doc.get('title', '')}")
                for m in mismatches:
                    print(f"  - {m}")
            rc |= 1 if mismatches else 0
            continue
        if "package_id" in doc:
            d = check_package(doc).to_dict()
        elif "state" in doc:
            schema = load_schema("candidate_state.schema.json")
            errs = validate(doc, schema)
            d = Result().to_dict()
            d["verdict"] = "REFUSE" if errs else "ACCEPT"
            d["reasons"] = [{"code": "STATE_SCHEMA", "message": f"{p} {m}"} for p, m in errs]
        else:
            print(f"{name}: not a fixture, package or state", file=sys.stderr)
            rc |= 2
            continue
        if args.json:
            print(json.dumps(d, indent=2, default=str))
        else:
            _print_result(name, d)
        rc |= 1 if d["verdict"] == "REFUSE" else 0
    return rc


if __name__ == "__main__":
    sys.exit(main())
