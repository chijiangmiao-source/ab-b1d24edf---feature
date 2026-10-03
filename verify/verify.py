#!/usr/bin/env python3
"""End-to-end acceptance verifier for the audit service.

Runs against a healthy ``app`` container (or a locally started server):

1.  API/HTTP smoke checks,
2.  version-shadowing scenario (earlier-loaded compatible object wins),
3.  parsing-rule unit tests (interleaved),
4.  weak-symbol scenario (weak references may stay unbound),
5.  corrupted dynamic-table scenarios (rejection with first error),
6.  frozen-verdict replay / conflict semantics,
7.  replacement-review scenarios (reference diffing, replay/conflict,
    locatable failure conclusions, base-audit isolation).

Exits 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for extra in (os.path.join(REPO, "app", "src"), os.path.join(REPO, "tools")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from elfbuilder import ElfBuilder, dynamic_value, patch_dynamic  # noqa: E402
from elfaudit.elf import DT_SYMTAB, DT_VERSYM  # noqa: E402

APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:8000").rstrip("/")

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {name}"
    if detail and not ok:
        line += f"\n       {detail}"
    print(line, flush=True)


def http(method: str, path: str, payload=None, raw: bytes | None = None):
    """Return ``(status, body_bytes)`` for one HTTP call."""
    data = raw
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(APP_URL + path, data=data, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def post_audit(audit_id: str, target_name: str, target: bytes,
               deps: list[tuple[str, bytes]]):
    payload = {
        "audit_id": audit_id,
        "target_name": target_name,
        "target": b64(target),
        "dependencies": [{"name": n, "data": b64(d)} for n, d in deps],
    }
    return http("POST", "/audits", payload)


def post_review(review_id: str, audit_id: str, object_name: str,
                candidate: bytes):
    payload = {
        "review_id": review_id,
        "audit_id": audit_id,
        "object_name": object_name,
        "candidate": b64(candidate),
    }
    return http("POST", "/reviews", payload)


def wait_for_app(timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = http("GET", "/healthz")
            if status == 200:
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    check("app becomes healthy", False, f"no /healthz 200 within {timeout}s")
    summary_and_exit()


def summary_and_exit() -> None:
    failed = [r for r in RESULTS if not r[1]]
    print("-" * 60)
    print(f"acceptance: {len(RESULTS) - len(failed)} passed, "
          f"{len(failed)} failed")
    for name, _, detail in failed:
        print(f"  FAILED: {name} {detail}")
    sys.exit(1 if failed else 0)


# ----------------------------------------------------------------------
# fixtures
# ----------------------------------------------------------------------
def shadowing_fixtures():
    """Target + two providers of nav_update@FC_2.0 (libb impersonates liba)."""
    liba = (ElfBuilder(soname="liba.so")
            .verdef("FC_2.0")
            .symbol("nav_update", version="FC_2.0", value=0xA000)
            .symbol("log_emit", value=0xA100)
            .build())
    libb = (ElfBuilder(soname="liba.so")  # replaced library, same SONAME
            .verdef("FC_2.0")
            .symbol("nav_update", version="FC_2.0", value=0xB000)
            .symbol("log_emit", value=0xB100)
            .build())
    target = (ElfBuilder(soname="fc_core.so")
              .need("liba.so")
              .need("libb.so")
              .symbol("nav_update", defined=False, version="FC_2.0",
                      version_file="liba.so")
              .symbol("log_emit", defined=False)
              .build())
    return target, [("liba.so", liba), ("libb.so", libb)]


def weak_fixtures():
    liba = (ElfBuilder(soname="liba.so")
            .symbol("required_op", value=0x4000)
            .symbol("weak_choice", bind="WEAK", value=0x4100)
            .build())
    target = (ElfBuilder(soname="fc_core.so")
              .need("liba.so")
              .symbol("required_op", defined=False)
              .symbol("optional_trace", defined=False, bind="WEAK")
              .symbol("weak_choice", defined=False, bind="WEAK")
              .build())
    return target, [("liba.so", liba)]


def review_fixtures():
    """Base scope for replacement reviews: two providers plus a weak ref.

    liba provides nav_update@FC_2.0 and log_emit; libb impersonates liba
    via SONAME and also provides nav_update@FC_2.0.  The weak reference
    optional_trace has no definition anywhere.
    """
    liba = (ElfBuilder(soname="liba.so")
            .verdef("FC_2.0")
            .symbol("nav_update", version="FC_2.0", value=0xA000)
            .symbol("log_emit", value=0xA100)
            .build())
    libb = (ElfBuilder(soname="liba.so")  # shadow provider, same SONAME
            .verdef("FC_2.0")
            .symbol("nav_update", version="FC_2.0", value=0xB000)
            .build())
    target = (ElfBuilder(soname="fc_core.so")
              .need("liba.so")
              .need("libb.so")
              .symbol("nav_update", defined=False, version="FC_2.0",
                      version_file="liba.so")
              .symbol("log_emit", defined=False)
              .symbol("optional_trace", defined=False, bind="WEAK")
              .build())
    return target, [("liba.so", liba), ("libb.so", libb)]


# ----------------------------------------------------------------------
# scenario steps
# ----------------------------------------------------------------------
def step_smoke() -> None:
    print("== API/HTTP smoke ==", flush=True)
    status, body = http("GET", "/healthz")
    check("GET /healthz -> 200", status == 200, f"got {status}: {body!r}")

    status, _ = http("GET", "/audits/never-seen")
    check("GET unknown audit -> 404", status == 404, f"got {status}")

    status, _ = http("GET", "/")
    check("GET / -> 404", status == 404, f"got {status}")

    status, _ = http("POST", "/audits", raw=b"{not json")
    check("POST malformed JSON -> 400", status == 400, f"got {status}")

    status, _ = http("POST", "/audits", {"audit_id": "x", "target_name": "t"})
    check("POST missing target -> 400", status == 400, f"got {status}")

    status, _ = http("POST", "/audits", {
        "audit_id": "bad-b64", "target_name": "t", "target": "!!!notb64!!!"})
    check("POST invalid Base64 -> 400", status == 400, f"got {status}")

    too_many = [{"name": f"lib{i}.so", "data": b64(b"x")} for i in range(9)]
    status, _ = http("POST", "/audits", {
        "audit_id": "too-many", "target_name": "t", "target": b64(b"x"),
        "dependencies": too_many})
    check("POST nine dependencies -> 400", status == 400, f"got {status}")

    status, _ = http("POST", "/elsewhere", {})
    check("POST unknown path -> 404", status == 404, f"got {status}")


def step_version_shadowing() -> dict:
    print("== version shadowing scenario ==", flush=True)
    target, deps = shadowing_fixtures()
    status, body = post_audit("shadow-1", "fc_core.so", target, deps)
    check("shadow-1 audit created", status == 201, f"got {status}: {body!r}")
    verdict = json.loads(body) if status in (200, 201) else {}

    ok = verdict.get("status") == "passed"
    check("shadow-1 verdict passed", ok, json.dumps(verdict)[:400])

    by_symbol = {r["symbol"]: r for r in verdict.get("references", [])}
    nav = by_symbol.get("nav_update", {})
    res = nav.get("resolution", {})
    check("versioned ref binds to earlier-loaded compatible object",
          res.get("object") == "liba.so",
          f"resolution={res!r}")
    check("version basis records verdef FC_2.0",
          res.get("version_basis") == {"kind": "verdef", "version": "FC_2.0",
                                       "index": 2},
          f"basis={res.get('version_basis')!r}")
    check("requirement echoes version and file",
          nav.get("requirement") == {"version": "FC_2.0", "file": "liba.so"},
          f"requirement={nav.get('requirement')!r}")
    log = by_symbol.get("log_emit", {})
    check("unversioned shadowed ref binds to first loaded object",
          log.get("resolution", {}).get("object") == "liba.so",
          f"resolution={log.get('resolution')!r}")
    check("load order is BFS first-discovery",
          verdict.get("load_order") == ["fc_core.so", "liba.so", "libb.so"],
          f"load_order={verdict.get('load_order')!r}")

    # Reversed DT_NEEDED order: the impostor now loads first and wins,
    # which is exactly what the audit is meant to make visible.
    reversed_target = (ElfBuilder(soname="fc_core.so")
                       .need("libb.so")
                       .need("liba.so")
                       .symbol("nav_update", defined=False, version="FC_2.0",
                               version_file="liba.so")
                       .build())
    status, body = post_audit("shadow-2", "fc_core.so", reversed_target, deps)
    verdict2 = json.loads(body) if status in (200, 201) else {}
    nav2 = {r["symbol"]: r for r in verdict2.get("references", [])}.get(
        "nav_update", {})
    check("reversed load order shadows to the impostor",
          nav2.get("resolution", {}).get("object") == "libb.so",
          f"resolution={nav2.get('resolution')!r}")
    return verdict


def step_unit_tests() -> None:
    print("== parsing-rule unit tests (interleaved) ==", flush=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [os.path.join(REPO, "app", "src"), os.path.join(REPO, "tools")]
        + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s",
         os.path.join(REPO, "tests"), "-v"],
        capture_output=True, text=True, env=env)
    tail = "\n".join((proc.stderr or proc.stdout).splitlines()[-6:])
    check("parsing-rule unit tests pass", proc.returncode == 0, tail)


def step_weak_symbols() -> None:
    print("== weak symbol scenario ==", flush=True)
    target, deps = weak_fixtures()
    status, body = post_audit("weak-1", "fc_core.so", target, deps)
    check("weak-1 audit created", status == 201, f"got {status}: {body!r}")
    verdict = json.loads(body) if status in (200, 201) else {}
    check("weak-1 verdict passed despite unbound weak ref",
          verdict.get("status") == "passed", json.dumps(verdict)[:400])
    by_symbol = {r["symbol"]: r for r in verdict.get("references", [])}
    weak = by_symbol.get("optional_trace", {})
    check("weak ref stays unbound with reason",
          weak.get("status") == "unbound"
          and "no visible definition" in weak.get("reason", ""),
          f"ref={weak!r}")
    check("no first_unresolved for weak-only misses",
          verdict.get("first_unresolved") is None,
          f"first_unresolved={verdict.get('first_unresolved')!r}")
    check("strong ref bound to provider",
          by_symbol.get("required_op", {}).get("resolution", {}).get("object")
          == "liba.so", f"ref={by_symbol.get('required_op')!r}")
    check("weak ref with definition is bound",
          by_symbol.get("weak_choice", {}).get("status") == "bound",
          f"ref={by_symbol.get('weak_choice')!r}")

    # Strong reference without any definition must fail the verdict.
    bad_target = (ElfBuilder(soname="fc_core.so")
                  .need("liba.so")
                  .symbol("missing_op", defined=False)
                  .build())
    status, body = post_audit("weak-2", "fc_core.so", bad_target, deps)
    verdict2 = json.loads(body) if status in (200, 201) else {}
    first = verdict2.get("first_unresolved") or {}
    check("strong unbound ref fails the verdict",
          verdict2.get("status") == "failed"
          and first.get("symbol") == "missing_op"
          and "no visible definition" in first.get("reason", ""),
          json.dumps(verdict2)[:400])


def step_corrupted_tables() -> None:
    print("== corrupted dynamic table scenarios ==", flush=True)
    target, deps = shadowing_fixtures()

    # Unmappable DT_SYMTAB (virtual address outside every PT_LOAD).
    broken = patch_dynamic(target, DT_SYMTAB, 0x00DEAD0000)
    status, body = post_audit("corrupt-1", "fc_core.so", broken, deps)
    verdict = json.loads(body) if status in (200, 201) else {}
    err = verdict.get("error") or {}
    check("unmappable symbol table rejected with first error located",
          verdict.get("status") == "rejected"
          and err.get("field") == "DT_SYMTAB"
          and err.get("object") == "fc_core.so",
          json.dumps(verdict)[:400])

    # Truncated object.
    status, body = post_audit("corrupt-2", "fc_core.so", target[:100], deps)
    verdict = json.loads(body) if status in (200, 201) else {}
    check("truncated object rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") in ("e_phoff", "e_ident"),
          json.dumps(verdict)[:400])

    # Contradictory version reference: hidden version on an undefined
    # symbol (versym of symbol index 1 gets the hidden bit).
    versym_off = dynamic_value(target, DT_VERSYM)
    raw = bytearray(target)
    raw[versym_off + 3] |= 0x80  # hidden bit (0x8000) of versym[1], LE high byte
    status, body = post_audit("corrupt-3", "fc_core.so", bytes(raw), deps)
    verdict = json.loads(body) if status in (200, 201) else {}
    check("contradictory version reference rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_VERSYM",
          json.dumps(verdict)[:400])

    # Missing dependency object.
    status, body = post_audit("corrupt-4", "fc_core.so", target, deps[:1])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("missing dependency rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_NEEDED"
          and "libb.so" in verdict.get("error", {}).get("message", ""),
          json.dumps(verdict)[:400])

    # Duplicate object names in the request.
    status, body = post_audit("corrupt-5", "fc_core.so", target,
                              [deps[0], deps[0]])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("duplicate object names rejected",
          verdict.get("status") == "rejected"
          and "duplicate" in verdict.get("error", {}).get("message", ""),
          json.dumps(verdict)[:400])


def step_replay_and_conflict(frozen: dict) -> None:
    print("== frozen verdict replay / conflict ==", flush=True)
    target, deps = shadowing_fixtures()

    status, body = post_audit("shadow-1", "fc_core.so", target, deps)
    check("identical replay returns 200 with frozen verdict",
          status == 200 and json.loads(body) == frozen,
          f"got {status}: {body!r}")

    status, body = http("GET", "/audits/shadow-1")
    check("GET replays the same frozen verdict",
          status == 200 and json.loads(body) == frozen,
          f"got {status}: {body!r}")

    tampered = deps[1][1][:-1] + bytes([deps[1][1][-1] ^ 0x01])
    status, _ = post_audit("shadow-1", "fc_core.so", target,
                           [("liba.so", deps[0][1]), ("libb.so", tampered)])
    check("replaced dependency object conflicts (409)", status == 409,
          f"got {status}")

    status, _ = post_audit("shadow-1", "fc_renamed.so", target, deps)
    check("renamed target conflicts (409)", status == 409, f"got {status}")

    status, body = http("GET", "/audits/shadow-1")
    check("original verdict still readable after conflicts",
          status == 200 and json.loads(body) == frozen,
          f"got {status}: {body!r}")

    status, body = post_audit("shadow-3", "fc_core.so", target, deps)
    check("same request under a new audit id is independent",
          status == 201 and json.loads(body)["audit_id"] == "shadow-3",
          f"got {status}")


def step_replacement_reviews() -> None:
    print("== replacement review scenarios ==", flush=True)
    target, deps = review_fixtures()
    status, body = post_audit("review-base", "fc_core.so", target, deps)
    check("review-base audit created", status == 201, f"got {status}: {body!r}")
    base_verdict = json.loads(body) if status in (200, 201) else {}

    # -- request-level validation --------------------------------
    status, _ = http("GET", "/reviews/never-seen")
    check("GET unknown review -> 404", status == 404, f"got {status}")

    status, _ = post_review("rev-x", "no-such-audit", "liba.so", deps[0][1])
    check("review against unknown audit -> 404", status == 404,
          f"got {status}")

    status, _ = http("POST", "/reviews", {"review_id": "rev-x",
                                          "audit_id": "review-base",
                                          "object_name": "liba.so"})
    check("review missing candidate -> 400", status == 400, f"got {status}")

    status, _ = http("POST", "/reviews", {"review_id": "rev-x",
                                          "audit_id": "review-base",
                                          "object_name": "liba.so",
                                          "candidate": "!!!notb64!!!"})
    check("review invalid Base64 -> 400", status == 400, f"got {status}")

    # -- identical candidate: every reference unchanged -----------
    status, body = post_review("rev-same", "review-base", "liba.so",
                               deps[0][1])
    same = json.loads(body) if status in (200, 201) else {}
    check("identical candidate review created", status == 201,
          f"got {status}: {body!r}")
    check("identical candidate leaves every reference unchanged",
          same.get("status") == "passed"
          and same.get("changes")
          and all(c["change"] == "unchanged" for c in same["changes"])
          and same.get("first_unresolved") is None,
          json.dumps(same)[:400])

    # -- full diff: rebound + newly unbound + newly bound ---------
    candidate = (ElfBuilder(soname="liba.so")
                 .verdef("FC_1.0")
                 .symbol("nav_update", version="FC_1.0", value=0xA000)
                 .symbol("optional_trace", value=0xA200)
                 .build())
    status, body = post_review("rev-diff", "review-base", "liba.so", candidate)
    diff = json.loads(body) if status in (200, 201) else {}
    check("replacement diff review created", status == 201,
          f"got {status}: {body!r}")
    by_symbol = {c["symbol"]: c for c in diff.get("changes", [])}
    nav = by_symbol.get("nav_update", {})
    log = by_symbol.get("log_emit", {})
    weak = by_symbol.get("optional_trace", {})
    check("versioned ref rebounds to the shadow provider",
          nav.get("change") == "rebound"
          and nav.get("original", {}).get("resolution", {}).get("object")
          == "liba.so"
          and nav.get("replacement", {}).get("resolution", {}).get("object")
          == "libb.so",
          f"change={nav!r}")
    check("strong ref losing its only definition is newly unbound",
          log.get("change") == "newly_unbound"
          and log.get("replacement", {}).get("status") == "unbound",
          f"change={log!r}")
    check("weak ref gaining a definition is newly bound",
          weak.get("change") == "newly_bound"
          and weak.get("replacement", {}).get("resolution", {}).get("object")
          == "liba.so",
          f"change={weak!r}")
    first = diff.get("first_unresolved") or {}
    check("review fails with first unresolved basis located",
          diff.get("status") == "failed"
          and first.get("symbol") == "log_emit"
          and "no visible definition" in first.get("reason", ""),
          json.dumps(diff)[:400])

    # -- replay / conflict matrix for the review id ---------------
    status, body = post_review("rev-diff", "review-base", "liba.so", candidate)
    check("identical review replay returns 200 with frozen review",
          status == 200 and json.loads(body) == diff,
          f"got {status}: {body!r}")

    status, body = http("GET", "/reviews/rev-diff")
    check("GET replays the same frozen review",
          status == 200 and json.loads(body) == diff,
          f"got {status}: {body!r}")

    tampered = candidate[:-1] + bytes([candidate[-1] ^ 0x01])
    status, _ = post_review("rev-diff", "review-base", "liba.so", tampered)
    check("changed candidate bytes conflict (409)", status == 409,
          f"got {status}")

    status, _ = post_review("rev-diff", "review-base", "libb.so", candidate)
    check("changed object name conflicts (409)", status == 409,
          f"got {status}")

    status, _ = post_review("rev-diff", "shadow-1", "liba.so", candidate)
    check("changed base audit conflicts (409)", status == 409,
          f"got {status}")

    status, body = http("GET", "/reviews/rev-diff")
    check("original review still readable after conflicts",
          status == 200 and json.loads(body) == diff,
          f"got {status}: {body!r}")

    # -- locatable failure conclusions -----------------------------
    status, body = post_review("rev-nope", "review-base", "libnope.so",
                               candidate)
    verdict = json.loads(body) if status in (200, 201) else {}
    check("object outside load scope rejected with location",
          status == 201
          and verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "object_name"
          and verdict.get("error", {}).get("object") == "libnope.so",
          f"got {status}: {body!r}")

    status, body = post_review("rev-tgt", "review-base", "fc_core.so",
                               candidate)
    verdict = json.loads(body) if status in (200, 201) else {}
    check("replacing the target itself rejected",
          status == 201
          and verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "object_name",
          f"got {status}: {body!r}")

    status, body = post_review("rev-garbage", "review-base", "liba.so",
                               b"\x7fELFgarbage")
    verdict = json.loads(body) if status in (200, 201) else {}
    check("malformed candidate rejected with object located",
          status == 201
          and verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("object") == "liba.so"
          and verdict.get("error", {}).get("field") == "e_ident",
          f"got {status}: {body!r}")

    needy = (ElfBuilder(soname="liba.so")
             .need("libz.so")
             .symbol("log_emit", value=0xA100)
             .build())
    status, body = post_review("rev-needy", "review-base", "liba.so", needy)
    verdict = json.loads(body) if status in (200, 201) else {}
    check("candidate introducing missing dependency rejected",
          status == 201
          and verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_NEEDED"
          and "libz.so" in verdict.get("error", {}).get("message", ""),
          f"got {status}: {body!r}")

    # Incompatible version in a single-provider scope.
    solo_target = (ElfBuilder(soname="fc_core.so")
                   .need("liba.so")
                   .symbol("nav_update", defined=False, version="FC_2.0",
                           version_file="liba.so")
                   .build())
    solo_lib = (ElfBuilder(soname="liba.so")
                .verdef("FC_2.0")
                .symbol("nav_update", version="FC_2.0")
                .build())
    status, body = post_audit("review-solo", "fc_core.so", solo_target,
                              [("liba.so", solo_lib)])
    check("review-solo audit created", status == 201,
          f"got {status}: {body!r}")
    wrong_ver = (ElfBuilder(soname="liba.so")
                 .verdef("FC_3.0")
                 .symbol("nav_update", version="FC_3.0")
                 .build())
    status, body = post_review("rev-version", "review-solo", "liba.so",
                               wrong_ver)
    verdict = json.loads(body) if status in (200, 201) else {}
    first = verdict.get("first_unresolved") or {}
    check("incompatible version fails with located basis",
          status == 201
          and verdict.get("status") == "failed"
          and first.get("symbol") == "nav_update"
          and "FC_2.0" in first.get("reason", ""),
          f"got {status}: {body!r}")

    # A structurally rejected base audit cannot be rehearsed.
    status, body = post_audit("review-broken", "fc_core.so", target[:100],
                              deps)
    check("review-broken rejected base created", status == 201,
          f"got {status}: {body!r}")
    status, body = post_review("rev-broken", "review-broken", "liba.so",
                               deps[0][1])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("rejected base audit yields locatable failure",
          status == 201
          and verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "audit_id",
          f"got {status}: {body!r}")

    # -- reviews never pollute the base audit or other reviews ----
    status, body = http("GET", "/audits/review-base")
    check("base audit verdict unchanged by reviews",
          status == 200 and json.loads(body) == base_verdict,
          f"got {status}: {body!r}")
    status, body = http("GET", "/reviews/rev-same")
    check("other reviews unchanged by later reviews",
          status == 200 and json.loads(body) == same,
          f"got {status}: {body!r}")


def main() -> None:
    wait_for_app()
    step_smoke()
    frozen = step_version_shadowing()
    step_unit_tests()
    step_weak_symbols()
    step_corrupted_tables()
    step_replay_and_conflict(frozen)
    step_replacement_reviews()
    summary_and_exit()


if __name__ == "__main__":
    main()
