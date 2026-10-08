# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *
from genlayer.py.public_abi import StorageType

# How recently DNS must have confirmed the publisher's deed. A listing is
# only as trustworthy as the deed behind it, so this is checked both when
# publishing and on every lookup.
MAX_DEED_AGE_SECONDS = 7 * 86400
HEX_CHARS = "0123456789abcdef"


def _canonical(domain: str) -> str:
    d = domain.strip().lower()
    return d[:-1] if d.endswith(".") else d


class VerifiedRegistry(gl.Contract):
    """Example consumer of Deed: a registry of each domain's official
    contract address, writable only by that domain's verified owner.

    Answers "which contract is the real one for example.com?" without
    trusting whoever happens to be sponsoring a search result or a token
    listing. It reads Deed's FINALIZED state, not the latest accepted one:
    a claim that is accepted but still inside its appeal window could be
    reversed, and a registry entry that outlives a reversed claim would be
    exactly the kind of impersonation this exists to prevent.
    """

    deed: Address
    listings: TreeMap[str, str]  # domain -> official contract address (lowercase hex)
    publishers: TreeMap[str, str]  # domain -> wallet that published it

    def __init__(self, deed_address: Address):
        # The CLI delivers an Address; direct-mode tests pass a hex string.
        self.deed = deed_address if isinstance(deed_address, Address) else Address(deed_address)

    def _holds_deed(self, domain: str, wallet: str) -> bool:
        # Fail closed: an error Deed returns, or any answer other than a
        # literal True, means "no". One failure can't be caught here: if
        # Deed doesn't exist in finalized state yet (its own deployment
        # isn't final), GenVM aborts this whole call. That is still fail
        # closed (nothing is granted), and it only applies until Deed's
        # deployment finalizes.
        try:
            return (
                gl.get_contract_at(self.deed)
                .view(state=StorageType.LATEST_FINAL)
                .is_owner(domain, wallet, MAX_DEED_AGE_SECONDS)
            ) is True
        except Exception:
            return False

    @gl.public.write
    def publish(self, domain: str, official_address: str) -> None:
        d = _canonical(domain)
        if isinstance(official_address, Address):
            official_address = official_address.as_hex
        a = str(official_address).strip().lower()
        if len(a) != 42 or not a.startswith("0x") or any(ch not in HEX_CHARS for ch in a[2:]):
            raise gl.vm.UserError("official_address must be a 0x-prefixed 40-hex-character address")

        sender = gl.message.sender_address.as_hex.lower()
        if not self._holds_deed(d, sender):
            raise gl.vm.UserError(
                "Sender does not hold a finalized, recently verified Deed for this domain"
            )
        self.listings[d] = a
        self.publishers[d] = sender

    @gl.public.view
    def lookup(self, domain: str) -> str:
        """The listed address, or "" if there is none or the publisher no
        longer holds a fresh deed (domain sold, record removed, deed gone stale)."""
        d = _canonical(domain)
        if d not in self.listings:
            return ""
        if not self._holds_deed(d, self.publishers[d]):
            return ""
        return self.listings[d]

    @gl.public.view
    def get_listing(self, domain: str) -> dict:
        d = _canonical(domain)
        if d not in self.listings:
            raise gl.vm.UserError("No listing for this domain")
        return {
            "domain": d,
            "official_address": self.listings[d],
            "publisher": self.publishers[d],
            "currently_valid": self._holds_deed(d, self.publishers[d]),
        }
