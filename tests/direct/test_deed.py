"""Direct-mode tests for the Deed contract.

Every test that touches DNS mocks BOTH resolvers explicitly, because the
security model is "both independent resolvers must agree" and the tests
should prove each half of that, not assume it.
"""

import json

from tests.direct.conftest import to_hex

CONTRACT = "contracts/deed.py"

T0 = "2026-01-01T00:00:00Z"
T0_TS = 1767225600
T1 = "2026-01-01T06:00:00Z"
T1_TS = T0_TS + 6 * 3600

DOMAIN = "example.com"
QNAME = "_deed.example.com"
CF = r"^https://cloudflare-dns\.com/dns-query\?type=TXT&name=_deed\.example\.com$"
GG = r"^https://dns\.google/resolve\?type=TXT&name=_deed\.example\.com$"


# ---------------------------------------------------------------------------
# DoH response builders, matching each resolver's real JSON shape
# ---------------------------------------------------------------------------


def _cf_body(values, status=0, ad=False, extra_answers=None, tc=False):
    answers = [{"name": QNAME, "type": 16, "TTL": 300, "data": f'"{v}"'} for v in values]
    answers += extra_answers or []
    body = {"Status": status, "TC": tc, "RD": True, "RA": True, "AD": ad, "CD": False,
            "Question": [{"name": QNAME, "type": 16}]}
    if answers:
        body["Answer"] = answers
    return json.dumps(body)


def _gg_body(values, status=0, ad=False, extra_answers=None, tc=False):
    # Google returns names with a trailing dot and TXT data unquoted.
    answers = [{"name": QNAME + ".", "type": 16, "TTL": 300, "data": v} for v in values]
    answers += extra_answers or []
    body = {"Status": status, "TC": tc, "RD": True, "RA": True, "AD": ad, "CD": False,
            "Question": [{"name": QNAME + ".", "type": 16}]}
    if answers:
        body["Answer"] = answers
    return json.dumps(body)


def _mock(vm, cf_values=None, gg_values=None, *, cf_body=None, gg_body=None,
          cf_status_http=200, gg_status_http=200, ad=False):
    vm.clear_mocks()
    if cf_body is None:
        cf_body = _cf_body(cf_values or [], ad=ad)
    if gg_body is None:
        gg_body = _gg_body(gg_values or [], ad=ad)
    vm.mock_web(CF, {"status": cf_status_http, "body": cf_body})
    vm.mock_web(GG, {"status": gg_status_http, "body": gg_body})


def _record(contract, wallet):
    return contract.record_for(to_hex(wallet))


def _claimed(vm, contract, wallet, when=T0):
    vm.warp(when)
    rec = _record(contract, wallet)
    _mock(vm, [rec], [rec])
    vm.sender = wallet
    contract.claim(DOMAIN)
    return rec


# ---------------------------------------------------------------------------
# record helpers
# ---------------------------------------------------------------------------


def test_record_for_binds_version_contract_and_wallet(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    parts = rec.split(":")
    assert len(parts) == 3
    assert parts[0] == "deed-v1"
    assert parts[1].startswith("0x") and len(parts[1]) == 42 and parts[1] == parts[1].lower()
    assert parts[2] == to_hex(direct_alice).lower()


def test_record_for_rejects_malformed_wallet(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    for bad in ["", "0x123", "1234567890123456789012345678901234567890", "0x" + "g" * 40]:
        with direct_vm.expect_revert("0x-prefixed 40-hex"):
            contract.record_for(bad)


def test_wallet_inputs_accept_address_objects_as_sent_by_the_cli(direct_vm, direct_deploy, direct_alice):
    """The genlayer CLI converts any 40-hex argument to an Address before it
    reaches the contract. Views that take a wallet must not crash on that."""
    contract = direct_deploy(CONTRACT)
    from genlayer.py.types import Address

    as_obj = Address(to_hex(direct_alice))
    assert contract.record_for(as_obj) == _record(contract, direct_alice)
    _claimed(direct_vm, contract, direct_alice)
    assert contract.is_owner(DOMAIN, as_obj, 86400) is True
    assert contract.get_domains(as_obj) == [DOMAIN]


def test_record_name_is_underscore_label_on_normalized_domain(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    assert contract.record_name("Example.COM.") == "_deed.example.com"


# ---------------------------------------------------------------------------
# claim: happy paths
# ---------------------------------------------------------------------------


def test_claim_records_deed_when_both_resolvers_confirm(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    d = contract.get_deed(DOMAIN)
    assert d["domain"] == DOMAIN
    assert d["owner"] == to_hex(direct_alice).lower()
    assert d["claimed_at"] == T0_TS
    assert d["verified_at"] == T0_TS
    assert d["dnssec"] is False
    assert contract.owner_of(DOMAIN) == to_hex(direct_alice).lower()


def test_claim_records_dnssec_only_when_both_resolvers_validate(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    rec = _record(contract, direct_alice)
    direct_vm.sender = direct_alice

    _mock(direct_vm, cf_body=_cf_body([rec], ad=True), gg_body=_gg_body([rec], ad=False))
    contract.claim(DOMAIN)
    assert contract.get_deed(DOMAIN)["dnssec"] is False

    _mock(direct_vm, [rec], [rec], ad=True)
    contract.claim(DOMAIN)
    assert contract.get_deed(DOMAIN)["dnssec"] is True


def test_claim_normalizes_domain_case_and_trailing_dot(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    rec = _record(contract, direct_alice)
    _mock(direct_vm, [rec], [rec])
    direct_vm.sender = direct_alice

    contract.claim("  ExAmPle.COM. ")
    assert contract.owner_of("example.com") == to_hex(direct_alice).lower()


def test_claim_accepts_uppercase_record_and_multi_segment_txt(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    rec = _record(contract, direct_alice)
    upper = rec.upper().replace("DEED-V1", "deed-v1").replace("0X", "0x")
    # Cloudflare splits long TXT values into quoted character-strings.
    split_cf = {"name": QNAME, "type": 16, "TTL": 300, "data": f'"{upper[:20]}" "{upper[20:]}"'}
    cf = json.dumps({"Status": 0, "TC": False, "AD": False, "Answer": [split_cf]})
    _mock(direct_vm, cf_body=cf, gg_body=_gg_body([upper]))
    direct_vm.sender = direct_alice

    contract.claim(DOMAIN)
    assert contract.owner_of(DOMAIN) == to_hex(direct_alice).lower()


def test_claim_ignores_unrelated_txt_records(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.warp(T0)
    rec = _record(contract, direct_alice)
    noise = ["v=spf1 -all", "google-site-verification=abc", "deed-v1:garbage"]
    _mock(direct_vm, noise + [rec], [rec] + noise)
    direct_vm.sender = direct_alice

    contract.claim(DOMAIN)
    assert contract.owner_of(DOMAIN) == to_hex(direct_alice).lower()


# ---------------------------------------------------------------------------
# claim: both resolvers must agree
# ---------------------------------------------------------------------------


def test_claim_fails_when_only_cloudflare_has_record(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    _mock(direct_vm, [rec], [])
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("No matching deed record"):
        contract.claim(DOMAIN)
    assert contract.owner_of(DOMAIN) == ""


def test_claim_fails_when_only_google_has_record(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    _mock(direct_vm, [], [rec])
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("No matching deed record"):
        contract.claim(DOMAIN)


def test_claim_fails_on_nxdomain(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    _mock(direct_vm, cf_body=_cf_body([], status=3), gg_body=_gg_body([], status=3))
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("No matching deed record"):
        contract.claim(DOMAIN)


# ---------------------------------------------------------------------------
# claim: binding and replay protection
# ---------------------------------------------------------------------------


def test_claim_cannot_bind_a_record_published_for_another_wallet(direct_vm, direct_deploy, direct_alice, direct_bob):
    """Front-running protection: seeing Alice's record in DNS doesn't let
    Bob claim it, because the record names the wallet it authorizes."""
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    _mock(direct_vm, [rec], [rec])
    direct_vm.sender = direct_bob

    with direct_vm.expect_revert("No matching deed record"):
        contract.claim(DOMAIN)
    assert contract.owner_of(DOMAIN) == ""


def test_claim_rejects_records_with_extra_fields(direct_vm, direct_deploy, direct_alice):
    """Only the exact 3-part format counts, so a record can't carry
    extra fields that some other parser might read differently."""
    contract = direct_deploy(CONTRACT)
    v, addr, wallet = _record(contract, direct_alice).split(":")
    extended = f"{v}:{addr}:{wallet}:extra"
    _mock(direct_vm, [extended], [extended])
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("No matching deed record"):
        contract.claim(DOMAIN)


def test_claim_rejects_record_for_another_deed_contract(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    v, _addr, wallet = _record(contract, direct_alice).split(":")
    other_contract = f"{v}:0x{'ab' * 20}:{wallet}"
    _mock(direct_vm, [other_contract], [other_contract])
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("No matching deed record"):
        contract.claim(DOMAIN)


def test_claim_rejects_unknown_record_version(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    v2 = _record(contract, direct_alice).replace("deed-v1", "deed-v2")
    _mock(direct_vm, [v2], [v2])
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("No matching deed record"):
        contract.claim(DOMAIN)


# ---------------------------------------------------------------------------
# claim: CNAME and unusable answers
# ---------------------------------------------------------------------------


def test_claim_rejects_record_reached_through_cname(direct_vm, direct_deploy, direct_alice):
    """A dangling CNAME at _deed.<domain> pointing into a zone someone else
    took over must not let that someone claim the domain."""
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    target = "takeover.attacker.example"
    cname_cf = {"name": QNAME, "type": 5, "TTL": 300, "data": target + "."}
    txt_cf = {"name": target, "type": 16, "TTL": 300, "data": f'"{rec}"'}
    cname_gg = {"name": QNAME + ".", "type": 5, "TTL": 300, "data": target + "."}
    txt_gg = {"name": target + ".", "type": 16, "TTL": 300, "data": rec}
    _mock(
        direct_vm,
        cf_body=json.dumps({"Status": 0, "TC": False, "AD": False, "Answer": [cname_cf, txt_cf]}),
        gg_body=json.dumps({"Status": 0, "TC": False, "AD": False, "Answer": [cname_gg, txt_gg]}),
    )
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("not reached through a CNAME"):
        contract.claim(DOMAIN)


def test_claim_rejects_answer_for_a_different_name(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    wrong = {"name": "_deed.evil.com", "type": 16, "TTL": 300, "data": f'"{rec}"'}
    body = json.dumps({"Status": 0, "TC": False, "AD": False, "Answer": [wrong]})
    _mock(direct_vm, cf_body=body, gg_body=_gg_body([rec]))
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("not reached through a CNAME"):
        contract.claim(DOMAIN)


def test_claim_fails_on_servfail(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    _mock(direct_vm, cf_body=_cf_body([rec]), gg_body=_gg_body([], status=2))
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("DNS resolver returned an error"):
        contract.claim(DOMAIN)


def test_claim_fails_on_http_error(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    _mock(direct_vm, [rec], [rec], cf_status_http=503)
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("DNS resolver returned an error"):
        contract.claim(DOMAIN)


def test_claim_fails_on_malformed_json(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    _mock(direct_vm, cf_body="<html>rate limited</html>", gg_body=_gg_body([rec]))
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("DNS resolver returned an error"):
        contract.claim(DOMAIN)


def test_claim_fails_on_truncated_answer(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    _mock(direct_vm, cf_body=_cf_body([rec], tc=True), gg_body=_gg_body([rec]))
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("DNS resolver returned an error"):
        contract.claim(DOMAIN)


def test_claim_fails_when_a_resolver_is_unreachable(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _record(contract, direct_alice)
    direct_vm.clear_mocks()
    direct_vm.mock_web(CF, {"status": 200, "body": _cf_body([rec])})  # Google unmocked
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("DNS resolver returned an error"):
        contract.claim(DOMAIN)


# ---------------------------------------------------------------------------
# claim: input validation (nothing reaches a resolver URL unvalidated)
# ---------------------------------------------------------------------------


def test_claim_rejects_malformed_domains_before_any_dns_query(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.clear_mocks()  # any DNS query would hit no mock and look like an error
    direct_vm.sender = direct_alice
    cases = {
        "example.com&type=A": "may only contain",
        "example.com/../x": "may only contain",
        "example.com#frag": "may only contain",
        "exa mple.com": "may only contain",
        "ex%61mple.com": "may only contain",
        "_deed.example.com": "may only contain",
        "exämple.com": "may only contain",
        "localhost": "at least two labels",
        "a..com": "1-63 characters",
        "-bad.com": "cannot start or end with a hyphen",
        "bad-.com": "cannot start or end with a hyphen",
        "1.2.3.4": "top-level label must contain a letter",
        "ab": "must be 3-",
        ("a" * 63 + ".") * 4 + "com": "must be 3-",
        "a" * 64 + ".com": "1-63 characters",
    }
    for bad, msg in cases.items():
        with direct_vm.expect_revert(msg):
            contract.claim(bad)
    assert contract.get_all_domains() == []


# ---------------------------------------------------------------------------
# claim: ownership changes
# ---------------------------------------------------------------------------


def test_reclaim_by_same_owner_keeps_claimed_at_and_renews_verified_at(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _claimed(direct_vm, contract, direct_alice)

    direct_vm.warp(T1)
    _mock(direct_vm, [rec], [rec])
    contract.claim(DOMAIN)

    d = contract.get_deed(DOMAIN)
    assert d["claimed_at"] == T0_TS
    assert d["verified_at"] == T1_TS


def test_new_wallet_authorized_in_dns_takes_over_the_deed(direct_vm, direct_deploy, direct_alice, direct_bob):
    """DNS is the source of truth: if the domain's controller now authorizes
    Bob, Bob can claim even while Alice holds the deed."""
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    direct_vm.warp(T1)
    bob_rec = _record(contract, direct_bob)
    _mock(direct_vm, [bob_rec], [bob_rec])
    direct_vm.sender = direct_bob
    contract.claim(DOMAIN)

    d = contract.get_deed(DOMAIN)
    assert d["owner"] == to_hex(direct_bob).lower()
    assert d["claimed_at"] == T1_TS  # a new owner starts a new tenure
    assert contract.get_domains(to_hex(direct_alice)) == []
    assert contract.get_domains(to_hex(direct_bob)) == [DOMAIN]


# ---------------------------------------------------------------------------
# refresh: renew, revoke, or change nothing
# ---------------------------------------------------------------------------


def test_refresh_renews_when_both_resolvers_still_confirm(direct_vm, direct_deploy, direct_alice, direct_charlie):
    contract = direct_deploy(CONTRACT)
    rec = _claimed(direct_vm, contract, direct_alice)

    direct_vm.warp(T1)
    _mock(direct_vm, [rec], [rec], ad=True)
    direct_vm.sender = direct_charlie  # permissionless
    contract.refresh(DOMAIN)

    d = contract.get_deed(DOMAIN)
    assert d["owner"] == to_hex(direct_alice).lower()
    assert d["claimed_at"] == T0_TS
    assert d["verified_at"] == T1_TS
    assert d["dnssec"] is True


def test_refresh_revokes_when_both_resolvers_show_record_gone(direct_vm, direct_deploy, direct_alice, direct_charlie):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    _mock(direct_vm, [], [])
    direct_vm.sender = direct_charlie
    contract.refresh(DOMAIN)

    assert contract.owner_of(DOMAIN) == ""
    assert contract.get_all_domains() == []
    with direct_vm.expect_revert("No deed recorded"):
        contract.get_deed(DOMAIN)


def test_refresh_revokes_when_domain_now_authorizes_someone_else(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    bob_rec = _record(contract, direct_bob)
    _mock(direct_vm, [bob_rec], [bob_rec])
    contract.refresh(DOMAIN)

    assert contract.owner_of(DOMAIN) == ""  # revoked, not silently transferred


def test_refresh_revokes_on_nxdomain_from_both(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    _mock(direct_vm, cf_body=_cf_body([], status=3), gg_body=_gg_body([], status=3))
    contract.refresh(DOMAIN)
    assert contract.owner_of(DOMAIN) == ""


def test_refresh_changes_nothing_when_resolvers_disagree(direct_vm, direct_deploy, direct_alice):
    """One lying or lagging resolver can't revoke a deed..."""
    contract = direct_deploy(CONTRACT)
    rec = _claimed(direct_vm, contract, direct_alice)

    direct_vm.warp(T1)
    _mock(direct_vm, [rec], [])
    with direct_vm.expect_revert("Resolvers disagree"):
        contract.refresh(DOMAIN)

    d = contract.get_deed(DOMAIN)
    assert d["owner"] == to_hex(direct_alice).lower()
    assert d["verified_at"] == T0_TS  # ...and can't renew one either


def test_refresh_changes_nothing_on_resolver_error(direct_vm, direct_deploy, direct_alice):
    """An outage must never be read as "record removed"."""
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    direct_vm.warp(T1)
    _mock(direct_vm, cf_body=_cf_body([]), gg_body=_gg_body([], status=2))
    with direct_vm.expect_revert("DNS resolver returned an error"):
        contract.refresh(DOMAIN)
    assert contract.get_deed(DOMAIN)["verified_at"] == T0_TS


def test_refresh_revokes_when_record_moves_behind_a_cname(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _claimed(direct_vm, contract, direct_alice)

    cname = {"name": QNAME, "type": 5, "TTL": 300, "data": "elsewhere.example."}
    txt = {"name": "elsewhere.example", "type": 16, "TTL": 300, "data": f'"{rec}"'}
    body = json.dumps({"Status": 0, "TC": False, "AD": False, "Answer": [cname, txt]})
    _mock(direct_vm, cf_body=body, gg_body=body)
    contract.refresh(DOMAIN)
    assert contract.owner_of(DOMAIN) == ""


def test_refresh_unknown_domain_fails(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    with direct_vm.expect_revert("No deed recorded"):
        contract.refresh(DOMAIN)


def test_reclaim_after_revocation_works_and_does_not_duplicate_listing(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _claimed(direct_vm, contract, direct_alice)
    _mock(direct_vm, [], [])
    contract.refresh(DOMAIN)

    direct_vm.warp(T1)
    _mock(direct_vm, [rec], [rec])
    contract.claim(DOMAIN)

    assert contract.get_all_domains() == [DOMAIN]
    assert contract.get_deed(DOMAIN)["claimed_at"] == T1_TS


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------


def test_owner_can_release(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    contract.release(DOMAIN)
    assert contract.owner_of(DOMAIN) == ""


def test_non_owner_cannot_release(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("Only the current owner"):
        contract.release(DOMAIN)
    assert contract.owner_of(DOMAIN) == to_hex(direct_alice).lower()


def test_release_unknown_domain_fails(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("No deed recorded"):
        contract.release(DOMAIN)


# ---------------------------------------------------------------------------
# consumer-facing views
# ---------------------------------------------------------------------------


def test_is_owner_enforces_freshness(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)
    alice = to_hex(direct_alice)

    direct_vm.warp(T1)  # 6 hours later
    assert contract.is_owner(DOMAIN, alice, 6 * 3600) is True
    assert contract.is_owner(DOMAIN, alice, 6 * 3600 - 1) is False
    assert contract.is_owner(DOMAIN, alice.lower(), 86400) is True


def test_is_owner_false_for_other_wallets_and_bad_inputs(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)
    alice = to_hex(direct_alice)

    assert contract.is_owner(DOMAIN, to_hex(direct_bob), 86400) is False
    assert contract.is_owner(DOMAIN, alice, -1) is False
    assert contract.is_owner("not a domain", alice, 86400) is False
    assert contract.is_owner(DOMAIN, "0xnope", 86400) is False
    assert contract.is_owner("other.com", alice, 86400) is False


def test_owner_of_and_verified_at_never_revert(direct_vm, direct_deploy):
    contract = direct_deploy(CONTRACT)
    assert contract.owner_of("unclaimed.com") == ""
    assert contract.owner_of("bad domain!") == ""
    assert contract.verified_at("unclaimed.com") == 0
    assert contract.verified_at("bad domain!") == 0


def test_non_text_inputs_never_crash_views(direct_vm, direct_deploy, direct_alice):
    """The genlayer CLI sends numeric-looking arguments as numbers. Views
    that promise never to revert must answer "no" instead of crashing, and
    writes must refuse with a clear message."""
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)
    alice = to_hex(direct_alice)

    for bad in (123, None, ["example.com"]):  # floats can't be sent: calldata has no float type
        assert contract.owner_of(bad) == ""
        assert contract.verified_at(bad) == 0
        assert contract.is_owner(bad, alice, 86400) is False
    for bad_age in ("86400", None, True):
        assert contract.is_owner(DOMAIN, alice, bad_age) is False
    with direct_vm.expect_revert("domain must be a text string"):
        contract.claim(123)


def test_get_domains_lists_only_current_holdings(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)
    alice = to_hex(direct_alice)

    assert contract.get_domains(alice) == [DOMAIN]
    assert contract.get_domains(to_hex(direct_bob)) == []
    assert contract.get_domains("garbage") == []


# ---------------------------------------------------------------------------
# consensus: a leader cannot fabricate what DNS says
# ---------------------------------------------------------------------------


def test_validator_rejects_a_leader_that_invents_a_record(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)

    honest = {"ok": True, "direct": True, "owners": [to_hex(direct_alice).lower()], "ad": False}
    assert direct_vm.run_validator(leader_result={"r": [honest, honest]}) is True

    forged = dict(honest, owners=[to_hex(direct_bob).lower()])
    assert direct_vm.run_validator(leader_result={"r": [forged, forged]}) is False
    assert direct_vm.run_validator(leader_result={"r": [honest, forged]}) is False


def test_validator_rejects_a_leader_that_hides_a_resolver_error(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    rec = _claimed(direct_vm, contract, direct_alice)

    # The validator now sees Google erroring; a leader claiming both were fine must be rejected.
    _mock(direct_vm, cf_body=_cf_body([rec]), gg_body=_gg_body([], status=2))
    honest = {"ok": True, "direct": True, "owners": [to_hex(direct_alice).lower()], "ad": False}
    assert direct_vm.run_validator(leader_result={"r": [honest, honest]}) is False


def test_validator_rejects_a_leader_error(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy(CONTRACT)
    _claimed(direct_vm, contract, direct_alice)
    assert direct_vm.run_validator(leader_error=Exception("boom")) is False
