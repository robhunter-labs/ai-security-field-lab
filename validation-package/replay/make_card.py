#!/usr/bin/env python3
"""make_card.py - one-page Markdown retest card for a developer, from a validation package.

The card gives the same replay three ways (curl.exe, PowerShell Invoke-RestMethod,
standard-library Python), reads tokens from environment variables, states the
expected result and the negative control in plain words, shows the replay-safety
class first, and marks the retest "tester-assisted" when the oracle does not travel.

  python3 replay/make_card.py PACKAGE.json [-o CARD.md]
  python3 replay/make_card.py FIXTURE.json       # a package fixture (base + patch) also works

Standard library only. The card decides nothing; the decision rule and a person do.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import check_package as cp  # noqa: E402

TOOL_HINTS = {
    "out-of-band": "a callback listener the tester controls (the developer laptop cannot see the callback)",
    "timing-distribution": "a timing loop with a saved baseline (40+ samples) and interleaved controls",
    "browser-execution": "a headless browser with a print() hook, or two browser profiles as two identities",
}


def env_name(identity):
    scheme, _, name = identity["credential_ref"].partition(":")
    if scheme == "env":
        return name
    return "VP_TOKEN_" + re.sub(r"[^A-Z0-9]", "_", identity["role"].upper())


def _split(value, roles):
    """Split a header value into literal and env-var parts around {{identity:role}}."""
    parts, pos = [], 0
    for m in cp.PLACEHOLDER.finditer(value):
        if m.start() > pos:
            parts.append(("lit", value[pos:m.start()]))
        parts.append(("env", roles.get(m.group(1), "VP_TOKEN_" + m.group(1).upper())))
        pos = m.end()
    if pos < len(value):
        parts.append(("lit", value[pos:]))
    return parts


def _ps_dq(parts):
    """PowerShell double-quoted string with $env: interpolation and escaped literals."""
    out = []
    for kind, text in parts:
        if kind == "env":
            out.append(f"$env:{text}")
        else:
            out.append(text.replace("`", "``").replace('"', '`"').replace("$", "`$"))
    return '"' + "".join(out) + '"'


def _ps_sq(text):
    return "'" + text.replace("'", "''") + "'"


def curl_ps(req, roles):
    lines = [f"curl.exe -s -i -X {_ps_sq(req['method'])} `"]
    for name, value in req.get("headers", {}).items():
        lines.append(f"  -H {_ps_dq(_split(f'{name}: {value}', roles))} `")
    if req.get("body"):
        lines.append("  --data-binary '@body.txt' `")
    lines.append(f"  {_ps_dq([('lit', req['url'])])}")
    pre = ""
    if req.get("body"):
        pre = f"{_ps_sq(req['body'])} | Set-Content -NoNewline -Encoding utf8 body.txt\n"
    return pre + "\n".join(lines)


def irm(req, roles):
    hdrs = "; ".join(f"{_ps_sq(n)} = {_ps_dq(_split(str(v), roles))}" for n, v in req.get("headers", {}).items())
    call = f"Invoke-RestMethod -MaximumRedirection 0 -Method {_ps_sq(req['method'].title())} -Uri {_ps_sq(req['url'])} -Headers $headers"
    if req.get("body"):
        call += f" -Body {_ps_sq(req['body'])}"
    return ("$headers = @{ " + hdrs + " }\n"
            "try {\n"
            f"  $r = {call}\n"
            "  'HTTP 2xx'; $r | ConvertTo-Json -Depth 6\n"
            "} catch {\n"
            "  'HTTP ' + [int]$_.Exception.Response.StatusCode\n"
            "}")


def py(req, roles):
    hl = []
    for name, value in req.get("headers", {}).items():
        expr = " + ".join(repr(t) if k == "lit" else f"os.environ[{t!r}]" for k, t in _split(str(value), roles)) or "''"
        hl.append(f"    {name!r}: {expr},")
    body = f"{req['body']!r}.encode('utf-8')" if req.get("body") else "None"
    return ("import os, urllib.request, urllib.error\n"
            "class NoRedirect(urllib.request.HTTPRedirectHandler):\n"
            "    def redirect_request(self, req, fp, code, msg, headers, newurl):\n"
            "        return None\n"
            "opener = urllib.request.build_opener(NoRedirect)\n"
            f"req = urllib.request.Request({req['url']!r}, method={req['method']!r}, data={body}, headers={{\n"
            + "\n".join(hl) + "\n})\n"
            "try:\n"
            "    with opener.open(req, timeout=15) as resp:\n"
            "        print('HTTP', resp.status)\n"
            "        print(resp.read(2000).decode('utf-8', 'replace'))\n"
            "except urllib.error.HTTPError as e:\n"
            "    print('HTTP', e.code)")


def safety_line(rs):
    cls = rs.get("class", "unknown")
    yn = lambda b: "yes" if b else "no"  # noqa: E731
    line = (f"**Safety class: {cls}** | changes state: {yn(rs.get('state_changing'))} | "
            f"safe to run against production: {yn(rs.get('production_safe'))}")
    if cls == "destructive-do-not-replay":
        line += "\n\n**DO NOT REPLAY.** This retest is tester-assisted only."
    return line


def tester_assisted(pkg):
    ho = cp.g(pkg, "replay.handoff") or {}
    otype = cp.g(pkg, "oracle.type")
    return bool(ho.get("tester_assisted") or ho.get("requires_tester_tooling") or otype in cp.NON_TRAVELLING_ORACLES), otype, ho


def make_card(pkg):
    claim, replay, controls = pkg["claim"], pkg["replay"], pkg["controls"]
    req = replay["request"]
    roles = {i["role"]: env_name(i) for i in replay["identities"]}
    used = [r for r in roles if any(f"{{{{identity:{r}}}}}" in str(v) for v in req.get("headers", {}).values())]
    assisted, otype, ho = tester_assisted(pkg)
    out = [f"# Retest card: {claim['claim_id']}", "",
           safety_line(pkg["authorization"]["replay_safety"]), ""]
    if assisted:
        needs = ho.get("requires_tester_tooling") or [TOOL_HINTS.get(otype, "tester tooling")]
        out += ["> **TESTER-ASSISTED RETEST.** The oracle for this finding "
                f"({otype}) does not travel to a developer laptop. Run the replay below to check the request is now "
                f"refused, then ask the tester to confirm with: {'; '.join(needs)}.", ""]
        if ho.get("self_check"):
            out += [f"> **Self-check you can do:** {ho['self_check']}", ""]
    out += [f"**What this checks.** {claim['statement']}", "",
            f"**Target.** {claim['asset']} (build at capture: {replay['environment']['build']}). "
            f"Package {pkg['package_id']}, tested {replay['executed_at']}.", "",
            "## 1. Set your identities", "",
            "Use your own test accounts for these roles. The commands read tokens from environment variables; "
            "never paste a token into a command or a ticket.", "",
            "| Role | Environment variable | What it is |", "|---|---|---|"]
    for i in replay["identities"]:
        out.append(f"| {i['role']} | `{roles[i['role']]}` | {i.get('description', '')} |")
    first = roles[used[0]] if used else next(iter(roles.values()))
    out += ["", f"PowerShell: `$env:{first} = '<token>'` (this session only). "
            f"bash: `export {first}='<token>'`.", "",
            "## 2. Run the replay (pick one)", "",
            "**curl.exe** (Windows PowerShell or pwsh; from cmd.exe use `%VAR%` instead of `$env:VAR`)", "",
            "```powershell", curl_ps(req, roles), "```", "",
            "**PowerShell Invoke-RestMethod**", "", "```powershell", irm(req, roles), "```", "",
            "**Python 3, standard library only**", "", "```python", py(req, roles), "```", "",
            "## 3. What you should see", "",
            f"- **Expected difference:** {controls['expected_difference']['statement']}",
            f"- **Decision rule:** {controls['expected_difference']['decision_rule']}"]
    if pkg["review"].get("verify_replay"):
        out.append(f"- **After the fix:** {pkg['review']['verify_replay']}")
    out += ["", "## 4. Negative control", "", controls["negative"]["description"]]
    if controls["negative"].get("request"):
        out += ["", "```powershell", curl_ps(controls["negative"]["request"], roles), "```"]
    out += ["", "If the negative control does not behave as described, stop: the replay is not measuring what it claims.", ""]
    inv = ho.get("investigation") or {}
    if inv:
        out += ["## 5. To dig further", ""]
        for k in ("route", "source", "config"):
            if inv.get(k):
                out.append(f"- **{k.title()}:** {inv[k]}")
        out.append("")
    out += ["---", f"Generated by `replay/make_card.py` from package {pkg['package_id']} (prototype). "
            "The card decides nothing; the decision rule and a person do.", ""]
    return "\n".join(out)


def load_package(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if "fixture_id" in doc:
        return cp.load_fixture_package(doc, os.path.dirname(os.path.abspath(path)))
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description="Make a one-page retest card from a validation package.")
    ap.add_argument("package")
    ap.add_argument("-o", "--out")
    args = ap.parse_args(argv)
    pkg = load_package(args.package)
    res = cp.check_package(pkg)
    card = make_card(pkg)
    if res.verdict == "REFUSE":
        codes = ", ".join(r["code"] for r in res.reasons)
        card = (f"> **DRAFT: the package does not pass check_package.py ({codes}).** Do not hand this card "
                "to a developer until it does.\n\n") + card
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(card)
        print(f"wrote {args.out}")
    else:
        print(card)
    return 0


if __name__ == "__main__":
    sys.exit(main())
