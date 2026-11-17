"""Phase 4: one policy per tenant on top of a shared base."""

from __future__ import annotations

import os

import pytest

from backend.policy.loader import PolicyError, PolicyStore
from backend.policy.tenants import TenantPolicies, parse_tenant_rules, tenant_of

BASE = """
version: 1
default_effect: deny
rules:
  - id: base-no-shell
    match: {tool: "shell.*"}
    effect: deny
  - id: base-read
    match: {tool: "fs.read"}
    effect: allow
"""

PAYMENTS = """
version: 1
rules:
  - id: payments-refund
    match: {tool: "payments.refund"}
    effect: require_approval
  - id: payments-shell
    match: {tool: "shell.*"}
    effect: allow
"""


@pytest.fixture
def setup(tmp_path):
    base = tmp_path / "base.yaml"
    base.write_text(BASE)
    tenants = tmp_path / "tenants"
    tenants.mkdir()
    (tenants / "payments.yaml").write_text(PAYMENTS)

    def make(**kwargs) -> TenantPolicies:
        return TenantPolicies(PolicyStore(base, recheck_seconds=0), tenants, recheck_seconds=0, **kwargs)

    return base, tenants, make


def _ids(loaded) -> list[str]:
    return [r.id for r in loaded.policy.rules]


@pytest.mark.parametrize("principal,expected", [
    ("payments.checkout-agent", "payments"), ("payments", "payments"), ("a.b.c", "a"),
    (None, None), ("", None), ("../etc.agent", None),
])
def test_the_tenant_is_the_key_name_before_the_first_dot(principal, expected):
    assert tenant_of(principal) == expected


def test_a_tenant_gets_the_base_rules_first_then_its_own(setup):
    _, _, make = setup
    policies = make()
    assert _ids(policies.get("payments")) == ["base-no-shell", "base-read", "payments-refund", "payments-shell"]
    assert policies.tenants() == ["payments"]


def test_a_tenant_without_a_file_and_no_tenant_get_the_base(setup):
    _, _, make = setup
    policies = make()
    base = policies.get(None)
    assert _ids(base) == ["base-no-shell", "base-read"]
    assert policies.get("search").sha256 == base.sha256
    assert policies.get("payments").sha256 != base.sha256


def test_a_tenant_cannot_override_a_base_deny(setup):
    """payments-shell allows shell.*, but base-no-shell comes first and decides."""
    from backend.guardian.schema import ToolCall
    from backend.policy import evaluate

    _, _, make = setup
    loaded = make().get("payments")
    decision = evaluate(loaded, ToolCall(name="shell.exec", arguments={"cmd": "ls"}), principal="payments.agent")
    assert decision.effect == "deny" and decision.rule_id == "base-no-shell"
    decision = evaluate(loaded, ToolCall(name="payments.refund", arguments={"amount": 5}),
                        principal="payments.agent")
    assert decision.effect == "require_approval" and decision.rule_id == "payments-refund"


def test_a_tenant_file_may_hold_only_version_and_rules(setup):
    with pytest.raises(PolicyError, match="mode"):
        parse_tenant_rules("version: 1\nmode: monitor\nrules: []\n")
    with pytest.raises(PolicyError, match="default_effect"):
        parse_tenant_rules("version: 1\ndefault_effect: allow\n")


def test_a_rule_id_used_by_the_base_is_refused_at_startup(setup):
    _, tenants, make = setup
    (tenants / "search.yaml").write_text(
        "version: 1\nrules:\n  - {id: base-read, match: {tool: x}, effect: allow}\n")
    with pytest.raises(PolicyError, match="already used by the base policy: base-read"):
        make()


def test_a_broken_tenant_file_stops_startup(setup):
    _, tenants, make = setup
    (tenants / "search.yaml").write_text("version: 1\nrules: [{id: x, effect: explode}]\n")
    with pytest.raises(PolicyError, match="search.yaml"):
        make()


def test_a_tenant_file_edit_is_picked_up_and_a_bad_edit_keeps_the_last_good_policy(setup):
    _, tenants, make = setup
    policies = make()
    before = policies.get("payments")
    path = tenants / "payments.yaml"
    path.write_text(PAYMENTS + "  - {id: payments-extra, match: {tool: x}, effect: allow}\n")
    os.utime(path, ns=(1, 1))
    after = policies.get("payments")
    assert "payments-extra" in _ids(after) and after.sha256 != before.sha256
    path.write_text("version: 1\nrules: [{id: x, effect: explode}]\n")
    assert policies.get("payments").sha256 == after.sha256
    assert "explode" in policies.last_error("payments") or "effect" in policies.last_error("payments")
    path.write_text(PAYMENTS)
    assert policies.get("payments").sha256 == before.sha256 and policies.last_error("payments") is None


def test_a_tenant_file_added_broken_refuses_that_tenant_only(setup):
    _, tenants, make = setup
    policies = make()
    (tenants / "search.yaml").write_text("not: [valid")
    with pytest.raises(PolicyError, match="tenant 'search' has no usable policy"):
        policies.get("search")
    assert _ids(policies.get("payments"))[-1] == "payments-shell"
    (tenants / "search.yaml").write_text("version: 1\nrules: []\n")
    assert _ids(policies.get("search")) == ["base-no-shell", "base-read"]


def test_a_base_edit_reaches_every_tenant(setup):
    base, _, make = setup
    policies = make()
    before = policies.get("payments").sha256
    base.write_text(BASE + "  - {id: base-extra, match: {tool: y}, effect: deny}\n")
    os.utime(base, ns=(2, 2))
    after = policies.get("payments")
    assert after.sha256 != before
    assert _ids(after) == ["base-no-shell", "base-read", "base-extra", "payments-refund", "payments-shell"]


def test_tenant_names_cannot_reach_outside_the_directory(setup):
    _, _, make = setup
    policies = make()
    assert policies.get("..").sha256 == policies.get(None).sha256


def test_without_a_directory_everyone_gets_the_base(setup):
    base, _, _ = setup
    policies = TenantPolicies(PolicyStore(base))
    assert policies.get("payments").sha256 == policies.get(None).sha256 and policies.tenants() == []
