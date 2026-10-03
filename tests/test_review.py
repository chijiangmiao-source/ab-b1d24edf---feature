"""Replacement-review tests: diffing target references against the base."""
import json
import unittest

from elfaudit.audit import run_audit
from elfaudit.review import run_review
from elfbuilder import ElfBuilder


def lib(name, soname=None, needed=(), symbols=()):
    b = ElfBuilder(soname=soname or name)
    for n in needed:
        b.need(n)
    for kw in symbols:
        b.symbol(**kw)
    return b.build()


def base_scope():
    """Target with versioned/unversioned/weak refs and two providers.

    liba provides nav_update@FC_2.0 and log_emit; libb impersonates
    liba via SONAME and also provides nav_update@FC_2.0.  The weak ref
    optional_trace has no definition anywhere.
    """
    target = lib("fc_core.so", needed=("liba.so", "libb.so"), symbols=(
        dict(name="nav_update", defined=False, version="FC_2.0",
             version_file="liba.so"),
        dict(name="log_emit", defined=False),
        dict(name="optional_trace", defined=False, bind="WEAK"),
    ))
    liba = lib("liba.so", symbols=(
        dict(name="nav_update", version="FC_2.0", value=0xA000),
        dict(name="log_emit", value=0xA100),
    ))
    libb = lib("libb.so", soname="liba.so", symbols=(
        dict(name="nav_update", version="FC_2.0", value=0xB000),
    ))
    deps = [("liba.so", liba), ("libb.so", libb)]
    base = run_audit("fc_core.so", target, deps)
    assert base["status"] == "passed"
    return "fc_core.so", target, deps, base


def review(base, target_name, target, deps, object_name, candidate):
    return run_review("base-1", base, target_name, target, deps,
                      object_name, candidate)


def changes_by_symbol(verdict):
    return {c["symbol"]: c for c in verdict["changes"]}


class LoadScopeRules(unittest.TestCase):
    def test_target_object_cannot_be_replaced(self):
        name, target, deps, base = base_scope()
        verdict = review(base, name, target, deps, name, deps[0][1])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["field"], "object_name")
        self.assertEqual(verdict["error"]["object"], "fc_core.so")
        self.assertIn("target", verdict["error"]["message"])

    def test_unknown_object_rejected_with_load_scope(self):
        name, target, deps, base = base_scope()
        verdict = review(base, name, target, deps, "libnope.so", deps[0][1])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["field"], "object_name")
        self.assertEqual(verdict["error"]["object"], "libnope.so")
        self.assertIn("liba.so", verdict["error"]["message"])
        self.assertEqual(verdict["changes"], [])

    def test_unused_object_is_outside_load_scope(self):
        name, target, deps, base = base_scope()
        extra = lib("libextra.so")
        deps = deps + [("libextra.so", extra)]
        base = run_audit(name, target, deps)
        self.assertEqual(base["unused_objects"], ["libextra.so"])
        verdict = review(base, name, target, deps, "libextra.so", extra)
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["field"], "object_name")
        self.assertIn("never loaded", verdict["error"]["message"])

    def test_rejected_base_audit_cannot_be_reviewed(self):
        name, target, deps, base = base_scope()
        broken_target = target[:100]
        bad_base = run_audit(name, broken_target, deps)
        self.assertEqual(bad_base["status"], "rejected")
        verdict = review(bad_base, name, broken_target, deps,
                         "liba.so", deps[0][1])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["field"], "audit_id")
        self.assertEqual(verdict["error"]["object"], "base-1")
        self.assertIn("base-1", verdict["error"]["message"])

    def test_failed_base_audit_can_still_be_reviewed(self):
        # A failed (not rejected) base froze a full load scope; the
        # review may show the candidate fixing the failure.
        target = lib("fc.so", needed=("liba.so",),
                     symbols=(dict(name="missing_op", defined=False),))
        liba = lib("liba.so")
        deps = [("liba.so", liba)]
        base = run_audit("fc.so", target, deps)
        self.assertEqual(base["status"], "failed")
        candidate = lib("liba.so", symbols=(dict(name="missing_op"),))
        verdict = review(base, "fc.so", target, deps, "liba.so", candidate)
        self.assertEqual(verdict["status"], "passed")
        (change,) = verdict["changes"]
        self.assertEqual(change["change"], "newly_bound")
        self.assertIsNone(verdict["first_unresolved"])


class CandidateStructure(unittest.TestCase):
    def test_malformed_candidate_rejected_with_location(self):
        name, target, deps, base = base_scope()
        verdict = review(base, name, target, deps, "liba.so",
                         b"\x7fELFgarbage")
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["object"], "liba.so")
        self.assertEqual(verdict["error"]["field"], "e_ident")
        self.assertEqual(verdict["changes"], [])
        self.assertIsNone(verdict["first_unresolved"])

    def test_candidate_introducing_missing_dependency_rejected(self):
        name, target, deps, base = base_scope()
        candidate = lib("liba.so", needed=("libz.so",),
                        symbols=(dict(name="log_emit"),))
        verdict = review(base, name, target, deps, "liba.so", candidate)
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["field"], "DT_NEEDED")
        self.assertEqual(verdict["error"]["object"], "liba.so")
        self.assertIn("libz.so", verdict["error"]["message"])

    def test_candidate_may_use_previously_unused_frozen_object(self):
        # libextra was provided to the base audit but never loaded; the
        # candidate's DT_NEEDED may still resolve against it because it
        # is part of the frozen dependency inputs.
        name, target, deps, base = base_scope()
        extra = lib("libextra.so", symbols=(dict(name="bonus_op"),))
        deps = deps + [("libextra.so", extra)]
        base = run_audit(name, target, deps)
        self.assertEqual(base["unused_objects"], ["libextra.so"])
        candidate = lib("liba.so", needed=("libextra.so",), symbols=(
            dict(name="nav_update", version="FC_2.0", value=0xA000),
            dict(name="log_emit", value=0xA100),
            dict(name="bonus_op", defined=False),
        ))
        verdict = review(base, name, target, deps, "liba.so", candidate)
        self.assertEqual(verdict["status"], "passed")
        self.assertEqual(verdict["load_order"],
                         ["fc_core.so", "liba.so", "libb.so", "libextra.so"])


class BindingDiff(unittest.TestCase):
    def test_identical_candidate_leaves_everything_unchanged(self):
        name, target, deps, base = base_scope()
        verdict = review(base, name, target, deps, "liba.so", deps[0][1])
        self.assertEqual(verdict["status"], "passed")
        self.assertEqual(verdict["load_order"], base["load_order"])
        self.assertEqual(len(verdict["changes"]), 3)
        for change in verdict["changes"]:
            self.assertEqual(change["change"], "unchanged")
        self.assertIsNone(verdict["first_unresolved"])
        self.assertIsNone(verdict["error"])

    def test_rebound_to_earlier_compatible_shadow_provider(self):
        name, target, deps, base = base_scope()
        # Candidate liba provides only FC_1.0; libb (SONAME liba.so)
        # still provides the required FC_2.0 and must win.
        candidate = lib("liba.so", symbols=(
            dict(name="nav_update", version="FC_1.0", value=0xA000),
            dict(name="log_emit", value=0xA100),
        ))
        verdict = review(base, name, target, deps, "liba.so", candidate)
        self.assertEqual(verdict["status"], "passed")
        by_symbol = changes_by_symbol(verdict)
        nav = by_symbol["nav_update"]
        self.assertEqual(nav["change"], "rebound")
        self.assertEqual(nav["requirement"],
                         {"version": "FC_2.0", "file": "liba.so"})
        self.assertEqual(nav["original"]["resolution"]["object"], "liba.so")
        self.assertEqual(nav["replacement"]["resolution"]["object"], "libb.so")
        self.assertEqual(nav["replacement"]["resolution"]["version_basis"],
                         {"kind": "verdef", "version": "FC_2.0", "index": 2})
        self.assertEqual(by_symbol["log_emit"]["change"], "unchanged")
        self.assertEqual(by_symbol["optional_trace"]["change"], "unchanged")

    def test_full_diff_rebound_unbound_and_newly_bound(self):
        name, target, deps, base = base_scope()
        # Candidate drops log_emit and FC_2.0 but defines the weak ref.
        candidate = lib("liba.so", symbols=(
            dict(name="nav_update", version="FC_1.0", value=0xA000),
            dict(name="optional_trace", value=0xA200),
        ))
        verdict = review(base, name, target, deps, "liba.so", candidate)
        self.assertEqual(verdict["status"], "failed")
        by_symbol = changes_by_symbol(verdict)
        # nav_update rebounds to the shadow provider libb.
        self.assertEqual(by_symbol["nav_update"]["change"], "rebound")
        self.assertEqual(
            by_symbol["nav_update"]["replacement"]["resolution"]["object"],
            "libb.so")
        # log_emit loses its only definition.
        log = by_symbol["log_emit"]
        self.assertEqual(log["change"], "newly_unbound")
        self.assertEqual(log["original"]["status"], "bound")
        self.assertEqual(log["replacement"]["status"], "unbound")
        self.assertIn("no visible definition",
                      log["replacement"]["reason"])
        # The weak ref gains a definition from the candidate.
        weak = by_symbol["optional_trace"]
        self.assertEqual(weak["change"], "newly_bound")
        self.assertEqual(weak["original"]["status"], "unbound")
        self.assertEqual(weak["replacement"]["resolution"]["object"],
                         "liba.so")
        # The first unresolved basis points at the strong miss.
        first = verdict["first_unresolved"]
        self.assertEqual(first["symbol"], "log_emit")
        self.assertEqual(first["object"], "fc_core.so")
        self.assertIn("no visible definition", first["reason"])

    def test_incompatible_version_failure_is_locatable(self):
        target = lib("fc_core.so", needed=("liba.so",), symbols=(
            dict(name="nav_update", defined=False, version="FC_2.0",
                 version_file="liba.so"),))
        liba = lib("liba.so",
                   symbols=(dict(name="nav_update", version="FC_2.0"),))
        deps = [("liba.so", liba)]
        base = run_audit("fc_core.so", target, deps)
        self.assertEqual(base["status"], "passed")
        candidate = lib("liba.so",
                        symbols=(dict(name="nav_update", version="FC_3.0"),))
        verdict = review(base, "fc_core.so", target, deps, "liba.so",
                         candidate)
        self.assertEqual(verdict["status"], "failed")
        first = verdict["first_unresolved"]
        self.assertEqual(first["symbol"], "nav_update")
        self.assertIn("FC_2.0", first["reason"])
        nav = changes_by_symbol(verdict)["nav_update"]
        self.assertEqual(nav["change"], "newly_unbound")
        self.assertEqual(nav["original"]["resolution"]["object"], "liba.so")

    def test_reason_changed_while_staying_unbound(self):
        name, target, deps, base = base_scope()
        # The candidate adds only a hidden-version definition of the
        # weak ref: still unbound, but for a different reason.
        candidate = lib("liba.so", symbols=(
            dict(name="nav_update", version="FC_2.0", value=0xA000),
            dict(name="log_emit", value=0xA100),
            dict(name="optional_trace", version="V1", hidden_version=True),
        ))
        verdict = review(base, name, target, deps, "liba.so", candidate)
        self.assertEqual(verdict["status"], "passed")
        weak = changes_by_symbol(verdict)["optional_trace"]
        self.assertEqual(weak["change"], "reason_changed")
        self.assertEqual(weak["original"]["status"], "unbound")
        self.assertEqual(weak["replacement"]["status"], "unbound")
        self.assertIn("hidden", weak["replacement"]["reason"])

    def test_change_entries_follow_symbol_order(self):
        name, target, deps, base = base_scope()
        verdict = review(base, name, target, deps, "liba.so", deps[0][1])
        self.assertEqual(
            [c["symbol"] for c in verdict["changes"]],
            ["nav_update", "log_emit", "optional_trace"])
        self.assertEqual(
            [c["symbol_index"] for c in verdict["changes"]], [1, 2, 3])


class Isolation(unittest.TestCase):
    def test_review_does_not_pollute_base_verdict(self):
        name, target, deps, base = base_scope()
        frozen = json.loads(json.dumps(base))
        candidate = lib("liba.so",
                        symbols=(dict(name="nav_update", version="FC_1.0"),))
        review(base, name, target, deps, "liba.so", candidate)
        self.assertEqual(base, frozen)
        # Re-running the original audit still yields the frozen verdict.
        self.assertEqual(run_audit(name, target, deps), base)

    def test_reviews_are_independent_of_each_other(self):
        name, target, deps, base = base_scope()
        candidate_a = lib("liba.so", symbols=(
            dict(name="nav_update", version="FC_1.0", value=0xA000),
            dict(name="log_emit", value=0xA100),
        ))
        candidate_b = lib("libb.so", soname="liba.so", symbols=(
            dict(name="nav_update", version="FC_3.0", value=0xB000),
        ))
        verdict_a = review(base, name, target, deps, "liba.so", candidate_a)
        verdict_b = review(base, name, target, deps, "libb.so", candidate_b)
        # Replacing liba rebounds nav_update to libb; replacing libb
        # leaves every target reference bound to liba as before.
        self.assertEqual(changes_by_symbol(verdict_a)["nav_update"]["change"],
                         "rebound")
        self.assertEqual(changes_by_symbol(verdict_b)["nav_update"]["change"],
                         "unchanged")
        # And the first review is still what it was.
        self.assertEqual(changes_by_symbol(verdict_a)["nav_update"]
                         ["replacement"]["resolution"]["object"], "libb.so")


if __name__ == "__main__":
    unittest.main()
