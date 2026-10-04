"""Replacement review: replay a frozen audit with one loaded object swapped.

A replacement review never re-derives anything from the caller: it only
references the frozen target bytes and frozen dependency inputs of an
existing audit.  The candidate bytes replace the dependency object that
was actually loaded under ``object_name``; the exact same dependency
discovery (BFS, ring de-duplication, missing-dependency rejection) and
version-aware binding rules as :func:`elfaudit.audit.run_audit` are then
re-applied.

For every undefined GLOBAL/WEAK reference *of the target object* the
review records a stable, order-preserving comparison against the frozen
adjudication:

* ``unchanged``           - bound to the same definition, or still unbound
* ``rebound``             - was bound, now bound to a different definition
* ``unbound``             - was bound, now has no compatible definition
* ``newly_bound``         - was unbound (typically a weak reference), now bound
* ``structural_rejected`` - the replay itself was structurally rejected

Pre-conditions that make a replay impossible (the base audit itself is
rejected, the named object is outside the base audit's actual load
scope, or the caller tries to replace the target object) are locatable
``rejected`` review conclusions rather than HTTP errors, mirroring the
audit verdict semantics.
"""
from __future__ import annotations

import hashlib

from .audit import run_audit

_CHANGES = ("unchanged", "rebound", "unbound", "newly_bound", "structural_rejected")


def review_fingerprint(base_audit_id: str, base_request_sha256: str,
                       object_name: str, candidate_bytes: bytes) -> str:
    """Byte-exact identity of a replacement review request."""
    h = hashlib.sha256()
    h.update(base_audit_id.encode("utf-8"))
    h.update(b"\0")
    h.update(base_request_sha256.encode("ascii"))
    h.update(b"\0")
    h.update(object_name.encode("utf-8"))
    h.update(b"\0")
    h.update(candidate_bytes)
    h.update(b"\0")
    return h.hexdigest()


def run_replacement_review(base_record: dict, base_inputs: dict,
                           review_id: str, review_fp: str,
                           object_name: str, candidate_bytes: bytes) -> dict:
    """Compute a replacement review verdict as a JSON-ready dict.

    ``base_record`` is the frozen audit verdict; ``base_inputs`` holds
    the frozen ``target_name`` / ``target`` bytes / ``dependencies``
    list the audit was created from.  Malformed candidates and violated
    pre-conditions never raise: they become ``rejected`` conclusions
    pinpointing the object and field involved.
    """
    target_name = base_inputs["target_name"]
    target_bytes = base_inputs["target"]
    dependencies = list(base_inputs["dependencies"])
    candidate_fp = hashlib.sha256(candidate_bytes).hexdigest()

    def envelope(status, *, load_order=None, diffs=(), error=None,
                 first_unresolved=None):
        summary = {change: 0 for change in _CHANGES}
        for diff in diffs:
            summary[diff["change"]] += 1
        return {
            "review_id": review_id,
            "base_audit_id": base_record["audit_id"],
            "review_sha256": review_fp,
            "candidate_sha256": candidate_fp,
            "status": status,
            "target": target_name,
            "replaced_object": object_name,
            "load_order": load_order or [],
            "diffs": list(diffs),
            "diff_summary": summary,
            "first_unresolved": first_unresolved,
            "error": error,
        }

    def reject(field, message, *, obj=None, offset=None):
        return envelope(
            "rejected",
            error={"object": obj if obj is not None else object_name,
                   "field": field, "message": message, "offset": offset},
        )

    # A structurally rejected audit has no frozen adjudications and its
    # input graph was never fully discovered; nothing can be replayed.
    if base_record["status"] == "rejected":
        base_error = base_record.get("error") or {}
        return reject(
            "base_audit",
            f"base audit '{base_record['audit_id']}' is structurally rejected "
            f"({base_error.get('field', 'unknown')}: "
            f"{base_error.get('message', '')}); a replacement review cannot "
            f"be replayed against it",
            obj=base_error.get("object", target_name),
            offset=base_error.get("offset"),
        )

    # The review diffs the target object's own references, so the target
    # itself must stay byte-identical; only a loaded dependency may be
    # swapped.
    if object_name == target_name:
        return reject(
            "object_name",
            f"cannot replace the target object '{object_name}': a replacement "
            f"review swaps one actually loaded dependency, not the target",
        )

    # Only objects that were part of the frozen *actual load scope* may
    # be replaced; merely submitted but unloaded dependencies are out of
    # scope, as is any unknown name.
    if object_name not in base_record["load_order"]:
        scope = ", ".join(base_record["load_order"]) or "(empty)"
        return reject(
            "object_name",
            f"object '{object_name}' is not in the base audit's actual load "
            f"scope [{scope}]",
        )

    # Substitute the candidate bytes in the frozen dependency slot,
    # touching nothing else.
    replaced = False
    new_dependencies: list[tuple[str, bytes]] = []
    for name, data in dependencies:
        if name == object_name:
            new_dependencies.append((name, candidate_bytes))
            replaced = True
        else:
            new_dependencies.append((name, data))
    if not replaced:  # defensive: load_scope guarantees a matching slot
        return reject(
            "object_name",
            f"object '{object_name}' was loaded but is absent from the frozen "
            f"dependency inputs",
        )

    # Re-walk the exact same discovery and binding rules with no inputs
    # other than the frozen ones (the candidate may only reference names
    # already present among them).
    new_verdict = run_audit(target_name, target_bytes, new_dependencies)

    base_refs = [ref for ref in base_record["references"]
                 if ref["object"] == target_name]

    if new_verdict["status"] == "rejected":
        diffs = [_diff(ref, None) for ref in base_refs]
        return envelope("rejected",
                        load_order=new_verdict["load_order"],
                        diffs=diffs,
                        error=new_verdict["error"])

    after_by_index = {
        ref["symbol_index"]: ref
        for ref in new_verdict["references"] if ref["object"] == target_name
    }
    diffs = []
    for ref in base_refs:
        after = after_by_index.get(ref["symbol_index"])
        diffs.append(_diff(ref, after))

    return envelope(new_verdict["status"],
                    load_order=new_verdict["load_order"],
                    diffs=diffs,
                    first_unresolved=new_verdict["first_unresolved"])


def _snapshot(ref: dict | None) -> dict | None:
    """The adjudication portion of one reference entry."""
    if ref is None:
        return None
    snap = {"status": ref["status"]}
    if ref["status"] == "bound":
        snap["resolution"] = ref["resolution"]
    else:
        snap["reason"] = ref.get("reason")
    return snap


def _resolution_key(resolution: dict) -> tuple:
    """Stable identity of a binding.

    The defining object plus the version basis (kind/version) identifies
    the bound implementation; the dynsym/verdef indexes are deliberately
    excluded because swapping an object legitimately re-numbers its
    internal tables even when the same named, same-version definition is
    picked.  The full resolution (indexes included) is still shown in the
    before/after snapshots.
    """
    basis = resolution.get("version_basis") or {}
    return (resolution.get("object"), basis.get("kind"), basis.get("version"))


def _diff(before_ref: dict, after_ref: dict | None) -> dict:
    before = _snapshot(before_ref)
    after = _snapshot(after_ref)
    if after_ref is None:
        change = "structural_rejected"
    elif before_ref["status"] == "bound" and after_ref["status"] == "bound":
        change = ("unchanged"
                  if _resolution_key(before_ref["resolution"])
                  == _resolution_key(after_ref["resolution"])
                  else "rebound")
    elif before_ref["status"] == "bound" and after_ref["status"] == "unbound":
        change = "unbound"
    elif before_ref["status"] == "unbound" and after_ref["status"] == "bound":
        change = "newly_bound"
    else:
        change = "unchanged"
    return {
        "object": before_ref["object"],
        "symbol_index": before_ref["symbol_index"],
        "symbol": before_ref["symbol"],
        "bind": before_ref["bind"],
        "requirement": before_ref.get("requirement"),
        "change": change,
        "before": before,
        "after": after,
    }
