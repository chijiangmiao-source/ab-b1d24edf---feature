#!/usr/bin/env python3
"""End-to-end acceptance verifier for the audit service.

Runs against a healthy ``app`` container (or a locally started server):

1.  API/HTTP smoke checks,
2.  version-shadowing scenario (earlier-loaded compatible object wins),
3.  parsing-rule unit tests (interleaved),
4.  weak-symbol scenario (weak references may stay unbound),
5.  corrupted dynamic-table scenarios (rejection with first error),
6.  frozen-verdict replay / conflict semantics,
7.  replacement-review scenarios (reference diffs, rejection preconditions,
    replay/conflict matrix, isolation from the frozen audits).

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


def post_review(audit_id: str, review_id: str, object_name: str,
                candidate: bytes):
    payload = {"review_id": review_id, "object_name": object_name,
               "candidate": b64(candidate)}
    return http("POST", f"/audits/{audit_id}/replacement-reviews", payload)


def get_review(audit_id: str, review_id: str):
    return http("GET", f"/audits/{audit_id}/replacement-reviews/{review_id}")


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


def step_replacement_reviews(frozen: dict) -> None:
    print("== replacement review scenarios ==", flush=True)
    # Dedicated base audit: libb impersonates file liba.so (same SONAME)
    # and defines nav_update@FC_2.0, but only liba provides log_emit.
    # Swapping liba can therefore produce both a rebound (nav_update
    # falls through to libb) and an unbound strong reference (log_emit).
    rv_liba = (ElfBuilder(soname="liba.so")
               .verdef("FC_2.0")
               .symbol("nav_update", version="FC_2.0", value=0xA000)
               .symbol("log_emit", value=0xA100)
               .build())
    rv_libb = (ElfBuilder(soname="liba.so")
               .verdef("FC_2.0")
               .symbol("nav_update", version="FC_2.0", value=0xB000)
               .build())
    rv_target = (ElfBuilder(soname="fc_core.so")
                 .need("liba.so")
                 .need("libb.so")
                 .symbol("nav_update", defined=False, version="FC_2.0",
                         version_file="liba.so")
                 .symbol("log_emit", defined=False)
                 .build())
    rv_deps = [("liba.so", rv_liba), ("libb.so", rv_libb)]
    status, body = post_audit("rv-base", "fc_core.so", rv_target, rv_deps)
    check("rv-base audit created", status == 201, f"got {status}: {body!r}")
    base_rv = json.loads(body) if status in (200, 201) else {}
    check("rv-base binds both references to liba",
          {r["symbol"]: r["resolution"]["object"]
           for r in base_rv.get("references", [])}
          == {"nav_update": "liba.so", "log_emit": "liba.so"},
          json.dumps(base_rv.get("references"))[:300])

    # 1. Byte-identical candidate: every target reference is unchanged.
    status, body = post_review("rv-base", "rv-same", "liba.so", rv_liba)
    check("identical-candidate review created (201)",
          status == 201, f"got {status}: {body!r}")
    rv_same = json.loads(body) if status in (200, 201) else {}
    check("identical candidate leaves every reference unchanged",
          rv_same.get("status") == "passed"
          and all(d["change"] == "unchanged"
                  for d in rv_same.get("diffs", []))
          and rv_same.get("diff_summary", {}).get("unchanged") == 2,
          json.dumps(rv_same)[:500])

    # Replay with the exact same base audit / object / bytes -> 200,
    # and GET returns the identical frozen review.
    status, body = post_review("rv-base", "rv-same", "liba.so", rv_liba)
    check("identical review replay returns 200",
          status == 200 and json.loads(body) == rv_same,
          f"got {status}: {body!r}")
    status, body = get_review("rv-base", "rv-same")
    check("GET review returns the frozen record",
          status == 200 and json.loads(body) == rv_same,
          f"got {status}: {body!r}")

    # 2. Stripped candidate: libb impersonates file liba.so via SONAME
    #    and still provides nav_update@FC_2.0 -> rebound; the
    #    unversioned log_emit disappears from the whole scope -> unbound.
    stripped = (ElfBuilder(soname="liba.so").build())
    status, body = post_review("rv-base", "rv-strip", "liba.so", stripped)
    rv_strip = json.loads(body) if status in (200, 201) else {}
    d = {x["symbol"]: x for x in rv_strip.get("diffs", [])}
    check("stripped candidate fails the replay",
          rv_strip.get("status") == "failed"
          and rv_strip.get("error") is None,
          json.dumps(rv_strip)[:400])
    check("versioned reference rebounds to later SONAME match",
          d.get("nav_update", {}).get("change") == "rebound"
          and d["nav_update"]["before"]["resolution"]["object"] == "liba.so"
          and d["nav_update"]["after"]["resolution"]["object"] == "libb.so",
          json.dumps(d.get("nav_update"))[:300])
    check("lost unversioned reference is unbound with first basis",
          d.get("log_emit", {}).get("change") == "unbound"
          and d["log_emit"]["after"]["status"] == "unbound"
          and "no visible definition" in d["log_emit"]["after"].get("reason", "")
          and rv_strip.get("first_unresolved", {}).get("symbol") == "log_emit",
          json.dumps(d.get("log_emit"))[:300])

    # 3. Incompatible version: a lone candidate downgrading FC_2.0 to
    #    FC_1.0 cannot satisfy the versioned strong reference.
    ver_target = (ElfBuilder(soname="fc_core.so")
                  .need("liba.so")
                  .symbol("nav_update", defined=False, version="FC_2.0",
                          version_file="liba.so")
                  .build())
    ver_liba = (ElfBuilder(soname="liba.so")
                .verdef("FC_2.0")
                .symbol("nav_update", version="FC_2.0", value=0xA000)
                .build())
    status, body = post_audit("rv-ver", "fc_core.so", ver_target,
                              [("liba.so", ver_liba)])
    check("rv-ver base audit created", status == 201, f"got {status}")
    downgraded = (ElfBuilder(soname="liba.so")
                  .verdef("FC_1.0")
                  .symbol("nav_update", version="FC_1.0", value=0xC000)
                  .build())
    status, body = post_review("rv-ver", "rv-badver", "liba.so", downgraded)
    rv_badver = json.loads(body) if status in (200, 201) else {}
    dv = {x["symbol"]: x for x in rv_badver.get("diffs", [])}
    check("incompatible version fails with locatable reason",
          rv_badver.get("status") == "failed"
          and rv_badver.get("error") is None
          and dv.get("nav_update", {}).get("change") == "unbound"
          and "FC_2.0" in dv["nav_update"]["after"].get("reason", ""),
          json.dumps(rv_badver)[:500])

    # 4. Candidate introduces a missing dependency -> structural reject.
    needy = (ElfBuilder(soname="liba.so")
             .need("libghost.so")
             .build())
    status, body = post_review("rv-base", "rv-ghost", "liba.so", needy)
    rv_ghost = json.loads(body) if status in (200, 201) else {}
    check("candidate with missing dependency rejected",
          rv_ghost.get("status") == "rejected"
          and rv_ghost["error"]["field"] == "DT_NEEDED"
          and rv_ghost["error"]["object"] == "liba.so"
          and "libghost.so" in rv_ghost["error"]["message"]
          and all(x["change"] == "structural_rejected"
                  for x in rv_ghost.get("diffs", [])),
          json.dumps(rv_ghost)[:400])

    # 5. Structurally malformed candidate -> first error located on it.
    status, body = post_review("rv-base", "rv-malformed", "liba.so",
                               b"\x7fELFgarbage")
    rv_bad = json.loads(body) if status in (200, 201) else {}
    check("malformed candidate rejected under its object name",
          rv_bad.get("status") == "rejected"
          and rv_bad.get("error", {}).get("object") == "liba.so"
          and rv_bad.get("error", {}).get("field"),
          json.dumps(rv_bad)[:400])

    # 6. Pre-condition failures: unknown name, target name, and an
    #    object submitted but never actually loaded.
    status, body = post_review("rv-base", "rv-outscope", "libghost.so",
                               rv_liba)
    rv_out = json.loads(body) if status in (200, 201) else {}
    check("object name outside actual load scope rejected",
          rv_out.get("status") == "rejected"
          and rv_out["error"]["field"] == "object_name"
          and "libghost.so" in rv_out["error"]["message"],
          json.dumps(rv_out)[:400])

    status, body = post_review("rv-base", "rv-target", "fc_core.so",
                               rv_target)
    rv_tgt = json.loads(body) if status in (200, 201) else {}
    check("replacing the target itself is rejected",
          rv_tgt.get("status") == "rejected"
          and rv_tgt["error"]["field"] == "object_name",
          json.dumps(rv_tgt)[:300])

    target, deps = shadowing_fixtures()
    libextra = ElfBuilder(soname="libextra.so").build()
    status, body = post_audit("base-extra", "fc_core.so", target,
                              [deps[0], deps[1], ("libextra.so", libextra)])
    check("base-extra audit created", status == 201, f"got {status}")
    status, body = post_review("base-extra", "rv-unused", "libextra.so",
                               libextra)
    rv_unused = json.loads(body) if status in (200, 201) else {}
    check("unloaded dependency cannot be reviewed",
          rv_unused.get("status") == "rejected"
          and rv_unused["error"]["field"] == "object_name"
          and "actual load scope" in rv_unused["error"]["message"],
          json.dumps(rv_unused)[:300])

    # 7. A review cannot be based on a structurally rejected audit.
    status, body = post_review("corrupt-1", "rv-base-reject",
                               "fc_core.so", target)
    rv_base = json.loads(body) if status in (200, 201) else {}
    check("review over rejected base audit is refused",
          rv_base.get("status") == "rejected"
          and rv_base["error"]["field"] == "base_audit"
          and rv_base.get("diffs") == [],
          json.dumps(rv_base)[:300])

    # 8. Conflict matrix: the same review id only replays the exact
    #    (base audit, object name, candidate bytes) triple.
    tampered = stripped[:-1] + bytes([stripped[-1] ^ 0x01])
    status, _ = post_review("rv-base", "rv-same", "liba.so", tampered)
    check("changed candidate bytes conflict (409)", status == 409,
          f"got {status}")
    status, _ = post_review("rv-base", "rv-same", "libb.so", rv_liba)
    check("changed object name conflicts (409)", status == 409,
          f"got {status}")
    status, body = get_review("rv-base", "rv-same")
    check("original review still frozen after conflicts",
          status == 200 and json.loads(body) == rv_same,
          f"got {status}: {body!r}")

    # Reusing a review id under a different base audit also conflicts.
    status, _ = post_review("shadow-1", "rv-same", "liba.so", deps[0][1])
    check("review id reused under another base audit conflicts (409)",
          status == 409, f"got {status}")
    status, _ = get_review("shadow-1", "rv-same")
    check("review is not readable through another audit path",
          status == 404, f"got {status}")

    # 9. Isolation: the base audits and other reviews are untouched, and
    #    replaying an audit still yields its original verdict.
    status, body = http("GET", "/audits/rv-base")
    check("base audit verdict is not polluted by reviews",
          status == 200 and json.loads(body) == base_rv,
          f"got {status}: {body!r}")
    status, body = http("GET", "/audits/shadow-1")
    check("shadow-1 verdict remains byte-identical",
          status == 200 and json.loads(body) == frozen,
          f"got {status}: {body!r}")
    status, body = post_audit("shadow-1", "fc_core.so", target, deps)
    check("base audit replay semantics unchanged",
          status == 200 and json.loads(body) == frozen,
          f"got {status}")
    status, body = get_review("rv-base", "rv-strip")
    check("other review remains independently readable",
          status == 200 and json.loads(body) == rv_strip,
          f"got {status}")

    # 10. HTTP surface: unknown ids, wrong method, malformed requests.
    status, _ = post_review("never-seen", "rv-x", "liba.so", rv_liba)
    check("review on unknown base audit -> 404", status == 404,
          f"got {status}")
    status, _ = get_review("rv-base", "never-seen-review")
    check("GET unknown review -> 404", status == 404, f"got {status}")
    status, _ = http("GET", "/audits/rv-base/replacement-reviews")
    check("GET review collection -> 405", status == 405, f"got {status}")
    status, _ = http("POST", "/audits/rv-base/replacement-reviews",
                     raw=b"{bad json")
    check("malformed review JSON -> 400", status == 400, f"got {status}")
    status, _ = http("POST", "/audits/rv-base/replacement-reviews",
                     {"review_id": "rv-nocand", "object_name": "liba.so"})
    check("review missing candidate -> 400", status == 400, f"got {status}")
    status, _ = http("POST", "/audits/rv-base/replacement-reviews",
                     {"review_id": "rv!", "object_name": "liba.so",
                      "candidate": b64(rv_liba)})
    check("malformed review id -> 400", status == 400, f"got {status}")

    # 11. Weak reference newly bound after the swap (non-fatal before
    #     and after).
    weak_lib = (ElfBuilder(soname="liba.so").build())
    weak_target = (ElfBuilder(soname="fc_core.so")
                   .need("liba.so")
                   .symbol("optional_trace", defined=False, bind="WEAK")
                   .build())
    status, body = post_audit("weak-rev", "fc_core.so", weak_target,
                              [("liba.so", weak_lib)])
    check("weak-review base audit created", status == 201, f"got {status}")
    weak_candidate = (ElfBuilder(soname="liba.so")
                      .symbol("optional_trace", bind="WEAK", value=0x7000)
                      .build())
    status, body = post_review("weak-rev", "rv-weak", "liba.so",
                               weak_candidate)
    rv_weak = json.loads(body) if status in (200, 201) else {}
    dw = {x["symbol"]: x for x in rv_weak.get("diffs", [])}
    check("weak reference newly bound by replacement",
          rv_weak.get("status") == "passed"
          and dw.get("optional_trace", {}).get("change") == "newly_bound"
          and dw["optional_trace"]["before"]["status"] == "unbound"
          and dw["optional_trace"]["after"]["status"] == "bound",
          json.dumps(rv_weak)[:400])


def main() -> None:
    wait_for_app()
    step_smoke()
    frozen = step_version_shadowing()
    step_unit_tests()
    step_weak_symbols()
    step_corrupted_tables()
    step_replay_and_conflict(frozen)
    step_replacement_reviews(frozen)
    summary_and_exit()


if __name__ == "__main__":
    main()
