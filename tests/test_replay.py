"""Replacement-review engine tests.

Covers the stable per-reference diff (unchanged / rebound / unbound /
newly_bound / structural_rejected), replay through the same BFS and
version-binding rules, locatable rejection conclusions, and isolation
from the frozen base audit.
"""
import copy
import unittest

from elfaudit.audit import run_audit
from elfaudit.replay import review_fingerprint, run_replacement_review
from elfbuilder import ElfBuilder


def lib(name, soname=None, needed=(), symbols=(), verdefs=()):
    b = ElfBuilder(soname=soname or name)
    for n in needed:
        b.need(n)
    for v in verdefs:
        b.verdef(v)
    for kw in symbols:
        b.symbol(**kw)
    return b.build()


def make_base(audit_id, target_name, target, deps):
    verdict = run_audit(target_name, target, deps)
    record = {"audit_id": audit_id,
              "request_sha256": "frozen-fp",
              **verdict}
    inputs = {"target_name": target_name, "target": target,
              "dependencies": list(deps)}
    return record, inputs


def review(record, inputs, object_name, candidate, review_id="rv-1"):
    fp = review_fingerprint(record["audit_id"], record["request_sha256"],
                            object_name, candidate)
    return run_replacement_review(record, inputs, review_id, fp,
                                  object_name, candidate)


def diffs_by_symbol(rv):
    return {d["symbol"]: d for d in rv["diffs"]}


class HappyPath(unittest.TestCase):
    def _fixture(self):
        target = lib("fc.so", needed=("liba.so", "libb.so"),
                     symbols=(dict(name="nav_update", defined=False,
                                   version="FC_2.0", version_file="liba.so"),
                              dict(name="log_emit", defined=False)))
        liba = lib("liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),
                            dict(name="log_emit")))
        libb = lib("libb.so", soname="liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),))
        return target, [("liba.so", liba), ("libb.so", libb)]

    def test_identical_candidate_leaves_everything_unchanged(self):
        target, deps = self._fixture()
        record, inputs = make_base("a1", "fc.so", target, deps)
        rv = review(record, inputs, "liba.so", deps[0][1])
        self.assertEqual(rv["status"], "passed")
        self.assertEqual(rv["load_order"],
                         ["fc.so", "liba.so", "libb.so"])
        self.assertEqual({d["change"] for d in rv["diffs"]}, {"unchanged"})
        self.assertEqual(rv["diff_summary"]["unchanged"], 2)
        self.assertIsNone(rv["error"])
        self.assertIsNone(rv["first_unresolved"])
        nav = diffs_by_symbol(rv)["nav_update"]
        self.assertEqual(nav["before"]["resolution"]["object"], "liba.so")
        self.assertEqual(nav["after"]["resolution"]["object"], "liba.so")

    def test_candidate_dropping_symbols_rebinds_and_unbinds(self):
        target, deps = self._fixture()
        record, inputs = make_base("a1", "fc.so", target, deps)
        # Replacement liba keeps its SONAME but provides neither symbol:
        # nav_update's FC_2.0 requirement still matches libb (which
        # impersonates file liba.so via SONAME) -> rebound; the
        # unversioned log_emit has no provider anywhere -> unbound.
        candidate = lib("liba.so", soname="liba.so")
        rv = review(record, inputs, "liba.so", candidate)
        self.assertEqual(rv["status"], "failed")
        d = diffs_by_symbol(rv)
        self.assertEqual(d["log_emit"]["change"], "unbound")
        self.assertEqual(d["log_emit"]["before"]["status"], "bound")
        self.assertEqual(d["log_emit"]["after"]["status"], "unbound")
        self.assertIn("no visible definition", d["log_emit"]["after"]["reason"])
        self.assertEqual(d["nav_update"]["change"], "rebound")
        self.assertEqual(d["nav_update"]["before"]["resolution"]["object"],
                         "liba.so")
        self.assertEqual(d["nav_update"]["after"]["resolution"]["object"],
                         "libb.so")
        self.assertEqual(rv["first_unresolved"]["symbol"], "log_emit")

    def test_candidate_lets_later_object_win(self):
        target, deps = self._fixture()
        record, inputs = make_base("a1", "fc.so", target, deps)
        # Replacement liba provides log_emit at a different definition;
        # nav_update stays FC_2.0-bound in liba; log_emit still in liba.
        # Instead drop only nav_update FC_2.0 from liba: the versioned
        # requirement names file liba.so, so libb (SONAME liba.so) wins.
        candidate = lib("liba.so", soname="liba.so",
                        symbols=(dict(name="log_emit"),))
        rv = review(record, inputs, "liba.so", candidate)
        d = diffs_by_symbol(rv)
        self.assertEqual(d["nav_update"]["change"], "rebound")
        self.assertEqual(d["nav_update"]["before"]["resolution"]["object"],
                         "liba.so")
        self.assertEqual(d["nav_update"]["after"]["resolution"]["object"],
                         "libb.so")
        self.assertEqual(d["log_emit"]["change"], "unchanged")

    def test_candidate_version_downgrade_is_failure_not_rejection(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="nav_update", defined=False,
                                   version="FC_2.0", version_file="liba.so"),))
        liba = lib("liba.so", symbols=(dict(name="nav_update",
                                            version="FC_2.0"),))
        record, inputs = make_base("a1", "fc.so", target,
                                   [("liba.so", liba)])
        candidate = lib("liba.so", verdefs=("FC_1.0",),
                        symbols=(dict(name="nav_update",
                                      version="FC_1.0"),))
        rv = review(record, inputs, "liba.so", candidate)
        self.assertEqual(rv["status"], "failed")
        self.assertIsNone(rv["error"])
        d = diffs_by_symbol(rv)["nav_update"]
        self.assertEqual(d["change"], "unbound")
        self.assertIn("FC_2.0", d["after"]["reason"])


class LoadDiscovery(unittest.TestCase):
    def test_candidate_pulls_new_dependency_into_load_order(self):
        # libc is submitted but unused by the frozen graph; the original
        # load scope is [fc, liba].  The replacement liba NEEDs libc, so
        # discovery re-runs and libc enters the scope; its definition of
        # 'svc' then wins over the removed one.
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="svc", defined=False),))
        liba = lib("liba.so", symbols=(dict(name="svc", value=0x1111),))
        libc = lib("libc.so", symbols=(dict(name="svc", value=0x3333),))
        deps = [("liba.so", liba), ("libc.so", libc)]
        record, inputs = make_base("a1", "fc.so", target, deps)
        self.assertEqual(record["load_order"], ["fc.so", "liba.so"])

        candidate = lib("liba.so", needed=("libc.so",))
        rv = review(record, inputs, "liba.so", candidate)
        self.assertEqual(rv["status"], "passed")
        self.assertEqual(rv["load_order"],
                         ["fc.so", "liba.so", "libc.so"])
        d = diffs_by_symbol(rv)["svc"]
        self.assertEqual(d["change"], "rebound")
        self.assertEqual(d["after"]["resolution"]["object"], "libc.so")

    def test_candidate_introduces_missing_dependency_is_rejected(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="svc", defined=False),))
        liba = lib("liba.so", symbols=(dict(name="svc"),))
        record, inputs = make_base("a1", "fc.so", target,
                                   [("liba.so", liba)])
        candidate = lib("liba.so", needed=("libghost.so",))
        rv = review(record, inputs, "liba.so", candidate)
        self.assertEqual(rv["status"], "rejected")
        self.assertEqual(rv["error"]["field"], "DT_NEEDED")
        self.assertEqual(rv["error"]["object"], "liba.so")
        self.assertIn("libghost.so", rv["error"]["message"])
        (d,) = rv["diffs"]
        self.assertEqual(d["change"], "structural_rejected")
        self.assertEqual(d["before"]["status"], "bound")
        self.assertIsNone(d["after"])

    def test_malformed_candidate_is_rejected_under_its_name(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="svc", defined=False),))
        liba = lib("liba.so", symbols=(dict(name="svc"),))
        record, inputs = make_base("a1", "fc.so", target,
                                   [("liba.so", liba)])
        rv = review(record, inputs, "liba.so", b"\x7fELFxxxx")
        self.assertEqual(rv["status"], "rejected")
        self.assertEqual(rv["error"]["object"], "liba.so")
        (d,) = rv["diffs"]
        self.assertEqual(d["change"], "structural_rejected")


class WeakTransitions(unittest.TestCase):
    def test_newly_bound_weak_reference(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="opt", defined=False, bind="WEAK"),))
        liba = lib("liba.so")
        record, inputs = make_base("a1", "fc.so", target,
                                   [("liba.so", liba)])
        self.assertEqual(record["status"], "passed")
        candidate = lib("liba.so", symbols=(dict(name="opt", bind="WEAK"),))
        rv = review(record, inputs, "liba.so", candidate)
        self.assertEqual(rv["status"], "passed")
        d = diffs_by_symbol(rv)["opt"]
        self.assertEqual(d["change"], "newly_bound")
        self.assertEqual(d["before"]["status"], "unbound")
        self.assertEqual(d["after"]["status"], "bound")
        self.assertEqual(d["after"]["resolution"]["object"], "liba.so")

    def test_weak_becomes_unbound_is_not_failure(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="opt", defined=False, bind="WEAK"),))
        liba = lib("liba.so", symbols=(dict(name="opt"),))
        record, inputs = make_base("a1", "fc.so", target,
                                   [("liba.so", liba)])
        rv = review(record, inputs, "liba.so", lib("liba.so"))
        self.assertEqual(rv["status"], "passed")
        self.assertIsNone(rv["first_unresolved"])
        d = diffs_by_symbol(rv)["opt"]
        self.assertEqual(d["change"], "unbound")


class Preconditions(unittest.TestCase):
    def test_base_audit_rejected(self):
        target = lib("fc.so", needed=("liba.so",))
        verdict = run_audit("fc.so", target, [])
        self.assertEqual(verdict["status"], "rejected")
        record = {"audit_id": "a1", "request_sha256": "fp", **verdict}
        inputs = {"target_name": "fc.so", "target": target,
                  "dependencies": []}
        rv = review(record, inputs, "liba.so", lib("liba.so"))
        self.assertEqual(rv["status"], "rejected")
        self.assertEqual(rv["error"]["field"], "base_audit")
        self.assertEqual(rv["diffs"], [])

    def test_object_name_outside_load_scope_unknown(self):
        target = lib("fc.so", needed=("liba.so",))
        liba = lib("liba.so")
        record, inputs = make_base("a1", "fc.so", target,
                                   [("liba.so", liba)])
        rv = review(record, inputs, "libz.so", b"anything")
        self.assertEqual(rv["status"], "rejected")
        self.assertEqual(rv["error"]["field"], "object_name")
        self.assertIn("libz.so", rv["error"]["message"])

    def test_object_name_unused_dependency_out_of_scope(self):
        target = lib("fc.so", needed=("liba.so",))
        liba = lib("liba.so")
        extra = lib("libextra.so")
        record, inputs = make_base("a1", "fc.so", target,
                                   [("liba.so", liba),
                                    ("libextra.so", extra)])
        rv = review(record, inputs, "libextra.so", extra)
        self.assertEqual(rv["status"], "rejected")
        self.assertEqual(rv["error"]["field"], "object_name")
        self.assertIn("actual load scope", rv["error"]["message"])

    def test_cannot_replace_target(self):
        target = lib("fc.so", needed=("liba.so",))
        liba = lib("liba.so")
        record, inputs = make_base("a1", "fc.so", target,
                                   [("liba.so", liba)])
        rv = review(record, inputs, "fc.so", target)
        self.assertEqual(rv["status"], "rejected")
        self.assertEqual(rv["error"]["field"], "object_name")


class Isolation(unittest.TestCase):
    def test_review_does_not_mutate_base_verdict_or_inputs(self):
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="svc", defined=False),))
        liba = lib("liba.so", symbols=(dict(name="svc"),))
        deps = [("liba.so", liba)]
        record, inputs = make_base("a1", "fc.so", target, deps)
        record_before = copy.deepcopy(record)
        inputs_before = copy.deepcopy(inputs)
        candidate = lib("liba.so")
        rv = review(record, inputs, "liba.so", candidate)
        self.assertEqual(rv["status"], "failed")
        self.assertEqual(record, record_before)
        self.assertEqual(inputs, inputs_before)

    def test_fingerprint_changes_with_any_component(self):
        c1 = b"candidate-one"
        fp = review_fingerprint("a1", "basefp", "liba.so", c1)
        self.assertNotEqual(fp,
                            review_fingerprint("a2", "basefp", "liba.so", c1))
        self.assertNotEqual(fp,
                            review_fingerprint("a1", "otherfp", "liba.so", c1))
        self.assertNotEqual(fp,
                            review_fingerprint("a1", "basefp", "libb.so", c1))
        self.assertNotEqual(fp,
                            review_fingerprint("a1", "basefp", "liba.so",
                                               b"candidate-two"))
        self.assertEqual(fp,
                         review_fingerprint("a1", "basefp", "liba.so", c1))


if __name__ == "__main__":
    unittest.main()
