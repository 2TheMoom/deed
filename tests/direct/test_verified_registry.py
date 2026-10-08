"""Direct-mode tests for the VerifiedRegistry example consumer.

Direct mode can't run two contracts against each other, so these tests
install a cross-contract hook that answers the registry's calls to Deed
from a table the test controls. That isolates exactly what the registry is
responsible for: asking the right question, of the right state, at the
right times. Deed's own answers are covered by test_deed.py, and the real
cross-contract path is verified live on Bradbury (see README).
"""

from tests.direct.conftest import to_hex

CONTRACT = "contracts/verified_registry.py"
DEED_ADDR = "0x" + "de" * 20
OFFICIAL = "0x" + "12" * 20
LATEST_FINAL = 1
SEVEN_DAYS = 7 * 86400


class FakeDeed:
    """Stands in for a deployed Deed and records every call made to it."""

    def __init__(self):
        self.owners = {}  # (domain, wallet_lower) -> answer
        self.calls = []
        self.fail = False  # simulate Deed returning an error

    def install(self, vm):
        def hook(_vm, request):
            from genlayer.py import calldata  # the SDK is only importable once a contract is deployed

            if "CallContract" not in request:
                return None
            req = request["CallContract"]
            addr = req["address"]
            addr_hex = "0x" + (addr.as_bytes.hex() if hasattr(addr, "as_bytes") else bytes(addr).hex())
            cd = req["calldata"]
            self.calls.append({"address": addr_hex, "method": cd["method"], "args": list(cd["args"]),
                               "state": req.get("state")})
            if self.fail:
                return bytes([1]) + b"simulated Deed error"
            if addr_hex != DEED_ADDR or cd["method"] != "is_owner":
                return bytes([1]) + b"unexpected call"
            domain, wallet, max_age = cd["args"]
            return bytes([0]) + calldata.encode(self.owners.get((domain, wallet.lower()), False))

        vm._gl_call_hook = hook


def _setup(direct_vm, direct_deploy):
    fake = FakeDeed()
    fake.install(direct_vm)
    contract = direct_deploy(CONTRACT, DEED_ADDR)
    return contract, fake


def test_owner_with_fresh_finalized_deed_can_publish(direct_vm, direct_deploy, direct_alice):
    contract, fake = _setup(direct_vm, direct_deploy)
    alice = to_hex(direct_alice).lower()
    fake.owners[("example.com", alice)] = True
    direct_vm.sender = direct_alice

    contract.publish("Example.com.", OFFICIAL)

    assert contract.lookup("example.com") == OFFICIAL
    listing = contract.get_listing("example.com")
    assert listing == {"domain": "example.com", "official_address": OFFICIAL,
                       "publisher": alice, "currently_valid": True}


def test_registry_reads_deeds_finalized_state_with_a_freshness_bound(direct_vm, direct_deploy, direct_alice):
    """The security-relevant part of the integration: an accepted-but-still-
    appealable claim must not be enough to publish."""
    contract, fake = _setup(direct_vm, direct_deploy)
    alice = to_hex(direct_alice).lower()
    fake.owners[("example.com", alice)] = True
    direct_vm.sender = direct_alice

    contract.publish("example.com", OFFICIAL)

    call = fake.calls[-1]
    assert call["address"] == DEED_ADDR
    assert call["method"] == "is_owner"
    assert call["args"] == ["example.com", alice, SEVEN_DAYS]
    assert call["state"] == LATEST_FINAL


def test_non_owner_cannot_publish(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract, fake = _setup(direct_vm, direct_deploy)
    fake.owners[("example.com", to_hex(direct_alice).lower())] = True
    direct_vm.sender = direct_bob

    with direct_vm.expect_revert("does not hold a finalized"):
        contract.publish("example.com", OFFICIAL)
    assert contract.lookup("example.com") == ""


def test_publish_rejects_malformed_address(direct_vm, direct_deploy, direct_alice):
    contract, fake = _setup(direct_vm, direct_deploy)
    fake.owners[("example.com", to_hex(direct_alice).lower())] = True
    direct_vm.sender = direct_alice

    for bad in ["", "0x12", "12" * 21, "0x" + "zz" * 20]:
        with direct_vm.expect_revert("0x-prefixed 40-hex"):
            contract.publish("example.com", bad)


def test_lookup_stops_answering_once_the_deed_lapses(direct_vm, direct_deploy, direct_alice):
    """Domain sold, record removed, or deed gone stale: the listing must stop
    being served immediately, not linger until someone cleans it up."""
    contract, fake = _setup(direct_vm, direct_deploy)
    alice = to_hex(direct_alice).lower()
    fake.owners[("example.com", alice)] = True
    direct_vm.sender = direct_alice
    contract.publish("example.com", OFFICIAL)

    fake.owners[("example.com", alice)] = False
    assert contract.lookup("example.com") == ""
    assert contract.get_listing("example.com")["currently_valid"] is False


def test_new_domain_owner_can_replace_the_listing(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract, fake = _setup(direct_vm, direct_deploy)
    alice, bob = to_hex(direct_alice).lower(), to_hex(direct_bob).lower()
    fake.owners[("example.com", alice)] = True
    direct_vm.sender = direct_alice
    contract.publish("example.com", OFFICIAL)

    fake.owners[("example.com", alice)] = False
    fake.owners[("example.com", bob)] = True
    direct_vm.sender = direct_bob
    new_official = "0x" + "34" * 20
    contract.publish("example.com", new_official)

    assert contract.lookup("example.com") == new_official
    assert contract.get_listing("example.com")["publisher"] == bob


def test_lookup_unknown_domain_is_empty(direct_vm, direct_deploy):
    contract, _ = _setup(direct_vm, direct_deploy)
    assert contract.lookup("nothing.com") == ""
    with direct_vm.expect_revert("No listing"):
        contract.get_listing("nothing.com")


def test_deed_error_fails_closed(direct_vm, direct_deploy, direct_alice):
    """An error returned by Deed must mean "no", never trust and never a
    reverted lookup. (A Deed that doesn't exist in finalized state at all
    aborts the caller on real GenVM instead, also fail-closed; see README.)"""
    contract, fake = _setup(direct_vm, direct_deploy)
    alice = to_hex(direct_alice).lower()
    fake.owners[("example.com", alice)] = True
    direct_vm.sender = direct_alice
    contract.publish("example.com", OFFICIAL)

    fake.fail = True
    assert contract.lookup("example.com") == ""
    assert contract.get_listing("example.com")["currently_valid"] is False
    with direct_vm.expect_revert("does not hold a finalized"):
        contract.publish("example.com", OFFICIAL)


def test_only_a_literal_true_grants_trust(direct_vm, direct_deploy, direct_alice):
    contract, fake = _setup(direct_vm, direct_deploy)
    alice = to_hex(direct_alice).lower()
    direct_vm.sender = direct_alice
    for truthy_but_not_true in ["yes", 1, ["x"]]:
        fake.owners[("example.com", alice)] = truthy_but_not_true
        with direct_vm.expect_revert("does not hold a finalized"):
            contract.publish("example.com", OFFICIAL)
