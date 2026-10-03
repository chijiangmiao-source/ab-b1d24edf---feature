"""Replacement review: rehearse swapping one loaded dependency object.

A replacement review is anchored to a frozen base audit.  It replaces
exactly one actually loaded dependency object with candidate ELF64
bytes, re-runs the full dependency-discovery and version-binding rules
of :func:`elfaudit.audit.run_audit` against the frozen original inputs,
and diffs the target object's undefined GLOBAL/WEAK references against
the frozen base verdict.

Every failure conclusion is locatable: the review verdict either carries
an ``error`` pinpointing the cause (base audit structurally rejected,
object name outside the actual load scope, candidate structurally
invalid, candidate introducing a missing dependency) or a
``first_unresolved`` reference when the candidate leaves a strong
reference unbound (incompatible versions).  Reviews only read the frozen
base audit; they never mutate it or other reviews.
"""
from __future__ import annotations

from .audit import run_audit

# Per-reference change categories between the base verdict and the
# replacement run.
UNCHANGED = "unchanged"            # identical binding outcome
REBOUND = "rebound"                # bound to a different definition
NEWLY_BOUND = "newly_bound"        # was unbound, now bound
NEWLY_UNBOUND = "newly_unbound"    # was bound, now unbound
REASON_CHANGED = "reason_changed"  # still unbound, different basis


def run_review(audit_id: str, base: dict, target_name: str,
               target_bytes: bytes, dependencies: list, object_name: str,
               candidate_bytes: bytes) -> dict:
    """Rehearse replacing one loaded dependency and diff the target's refs.

    ``base`` is the frozen base verdict and ``dependencies`` the frozen
    ``(name, raw_bytes)`` pairs of the base audit.  Malformed input never
    raises: every failure becomes a locatable ``rejected`` or ``failed``
    review verdict.
    """
    # A structurally rejected base audit froze no load scope to
    # rehearse against.
    if base["status"] == "rejected":
        base_error = base.get("error") or {}
        return _rejected(
            target_name, object_name, "audit_id",
            f"base audit '{audit_id}' is frozen as structurally rejected "
            f"({base_error.get('field')}: {base_error.get('message')}); "
            f"no frozen load scope to rehearse against",
            audit_id)

    load_scope = list(base["load_order"])

    # Only actually loaded dependency objects may be replaced: neither
    # the target itself nor merely provided (never loaded) objects are
    # part of the replaceable load scope.
    if object_name == target_name:
        return _rejected(
            target_name, object_name, "object_name",
            f"'{object_name}' is the audit target; only actually loaded "
            f"dependency objects can be replaced")
    if object_name not in load_scope:
        if object_name in base.get("unused_objects", []):
            message = (f"object '{object_name}' was provided to audit "
                       f"'{audit_id}' but never loaded; it is outside the "
                       f"actual load scope")
        else:
            message = (f"object '{object_name}' is not in the actual load "
                       f"scope of audit '{audit_id}' (loaded dependencies: "
                       f"{', '.join(load_scope[1:]) or 'none'})")
        return _rejected(target_name, object_name, "object_name", message)

    # Swap the candidate bytes in for the same-named object and re-run
    # the full dependency-discovery and version-binding rules against
    # the frozen original inputs.
    replacement = [(name, candidate_bytes if name == object_name else data)
                   for name, data in dependencies]
    verdict = run_audit(target_name, target_bytes, replacement)

    # Candidate structural errors and missing dependencies it introduces
    # are reported exactly where the re-run located them.
    if verdict["status"] == "rejected":
        return _review(target_name, object_name, "rejected", [], [],
                       None, verdict["error"])

    # Diff the target object's undefined GLOBAL/WEAK references against
    # the frozen base verdict.  The target bytes are unchanged, so its
    # references line up by symbol index in both runs.
    base_refs = {ref["symbol_index"]: ref for ref in base["references"]
                 if ref["object"] == target_name}
    changes = []
    for ref in verdict["references"]:
        if ref["object"] != target_name:
            continue
        base_ref = base_refs[ref["symbol_index"]]
        changes.append({
            "symbol_index": ref["symbol_index"],
            "symbol": ref["symbol"],
            "bind": ref["bind"],
            "requirement": ref["requirement"],
            "change": _classify(base_ref, ref),
            "original": _outcome(base_ref),
            "replacement": _outcome(ref),
        })

    return _review(target_name, object_name, verdict["status"],
                   verdict["load_order"], changes,
                   verdict["first_unresolved"], None)


def _outcome(ref: dict) -> dict:
    """The binding outcome of one reference, bound or unbound."""
    if ref["status"] == "bound":
        return {"status": "bound", "resolution": ref["resolution"]}
    return {"status": "unbound", "reason": ref["reason"]}


def _classify(base_ref: dict, ref: dict) -> str:
    if base_ref["status"] == "bound":
        if ref["status"] == "bound":
            if base_ref["resolution"] == ref["resolution"]:
                return UNCHANGED
            return REBOUND
        return NEWLY_UNBOUND
    if ref["status"] == "bound":
        return NEWLY_BOUND
    if base_ref["reason"] == ref["reason"]:
        return UNCHANGED
    return REASON_CHANGED


def _review(target_name: str, object_name: str, status: str,
            load_order: list, changes: list, first_unresolved: dict | None,
            error: dict | None) -> dict:
    return {
        "status": status,
        "target": target_name,
        "object_name": object_name,
        "load_order": load_order,
        "changes": changes,
        "first_unresolved": first_unresolved,
        "error": error,
    }


def _rejected(target_name: str, object_name: str, field: str, message: str,
              obj: str | None = None) -> dict:
    return _review(target_name, object_name, "rejected", [], [], None, {
        "object": obj if obj is not None else object_name,
        "field": field,
        "message": message,
        "offset": None,
    })
