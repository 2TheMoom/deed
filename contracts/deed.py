# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from genlayer import *

RECORD_LABEL = "_deed"
RECORD_VERSION = "deed-v1"

# Two independently operated DNS-over-HTTPS resolvers, fixed in code. A
# caller can never choose where the proof comes from, and a single lying,
# compromised or stale resolver can't create, keep or revoke a deed on its
# own: every state change needs both to agree.
RESOLVERS = (
    "https://cloudflare-dns.com/dns-query?type=TXT&name=",
    "https://dns.google/resolve?type=TXT&name=",
)
DOH_HEADERS = {"Accept": "application/dns-json"}

DNS_NOERROR = 0
DNS_NXDOMAIN = 3
TYPE_CNAME = 5
TYPE_TXT = 16

HEX_CHARS = "0123456789abcdef"
LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"
MAX_DOMAIN_LENGTH = 253 - len(RECORD_LABEL) - 1  # room for the "_deed." prefix


def _error_observation() -> dict:
    return {"ok": False, "direct": False, "owners": [], "ad": False}


def _normalize_domain(raw: str) -> str:
    """Strict hostname validation. Only [a-z0-9-] labels separated by dots
    are accepted, so the value can be interpolated into a resolver URL
    without any way to smuggle extra query parameters, paths or fragments."""
    d = raw.strip().lower()
    if d.endswith("."):
        d = d[:-1]
    if not (3 <= len(d) <= MAX_DOMAIN_LENGTH):
        raise gl.vm.UserError(f"domain must be 3-{MAX_DOMAIN_LENGTH} characters")
    labels = d.split(".")
    if len(labels) < 2:
        raise gl.vm.UserError("domain must have at least two labels, e.g. example.com")
    for label in labels:
        if not (1 <= len(label) <= 63):
            raise gl.vm.UserError("each domain label must be 1-63 characters")
        if label[0] == "-" or label[-1] == "-":
            raise gl.vm.UserError("domain labels cannot start or end with a hyphen")
        for ch in label:
            if ch not in LABEL_CHARS:
                raise gl.vm.UserError(
                    "domain may only contain a-z, 0-9, '-' and '.' (use the punycode form for IDNs)"
                )
    if not any(ch.isalpha() for ch in labels[-1]):
        raise gl.vm.UserError("top-level label must contain a letter (IP addresses are not domains)")
    return d


def _normalize_wallet(raw) -> str | None:
    # The genlayer CLI turns any 40-hex argument into an Address before it
    # reaches the contract, while typed SDK callers send a plain string.
    # Accept both rather than crash on one of them.
    if isinstance(raw, Address):
        return raw.as_hex.lower()
    if not isinstance(raw, str):
        return None
    w = raw.strip().lower()
    if len(w) != 42 or not w.startswith("0x"):
        return None
    for ch in w[2:]:
        if ch not in HEX_CHARS:
            return None
    return w


def _txt_value(data: str) -> str:
    """DoH resolvers present TXT data differently: Cloudflare wraps each
    character-string in quotes ("a" "b"), Google returns them concatenated
    and unquoted. Normalize both to the same plain string."""
    s = data.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1].replace('" "', "")
    return s.strip().lower()


def _query(base: str, qname: str, contract: str) -> dict:
    """One resolver's view of the deed records published at `qname`.

    Only an answer that is (a) HTTP 200, (b) valid DoH JSON, (c) not
    truncated, and (d) a definitive DNS result (NOERROR or NXDOMAIN) counts.
    Anything else is an error, never an "absent" record, so a resolver
    outage can't be mistaken for the owner removing their proof.
    """
    try:
        resp = gl.nondet.web.request(base + qname, method="GET", headers=DOH_HEADERS)
    except Exception:
        return _error_observation()
    if resp.status != 200:
        return _error_observation()
    try:
        data = json.loads((resp.body or b"").decode("utf-8"))
    except Exception:
        return _error_observation()
    if not isinstance(data, dict) or data.get("TC") is True:
        return _error_observation()

    status = data.get("Status")
    ad = data.get("AD") is True
    if status == DNS_NXDOMAIN:
        return {"ok": True, "direct": True, "owners": [], "ad": ad}
    if status != DNS_NOERROR:
        return _error_observation()

    answers = data.get("Answer") or []
    if not isinstance(answers, list):
        return _error_observation()

    owners = set()
    direct = True
    for a in answers:
        if not isinstance(a, dict):
            return _error_observation()
        name = str(a.get("name", "")).strip().lower().rstrip(".")
        rtype = a.get("type")
        # The proof must live at the name itself. A CNAME (for example a
        # dangling one pointing at a zone someone else now controls) means
        # the answer came from somewhere the domain owner may not control.
        if rtype == TYPE_CNAME or name != qname:
            direct = False
            continue
        if rtype != TYPE_TXT:
            continue
        parts = _txt_value(str(a.get("data", ""))).split(":")
        if len(parts) != 3 or parts[0] != RECORD_VERSION:
            continue
        # Records are scoped to this exact Deed contract, so a record
        # published for one deployment proves nothing to another.
        if parts[1] != contract:
            continue
        wallet = _normalize_wallet(parts[2])
        if wallet is not None:
            owners.add(wallet)

    if not direct:
        owners = set()
    return {"ok": True, "direct": direct, "owners": sorted(owners), "ad": ad}


@allow_storage
@dataclass
class DeedRecord:
    owner: str  # lowercase 0x-hex wallet
    claimed_at: u256  # when this owner first proved control
    verified_at: u256  # last time both resolvers confirmed the record
    dnssec: bool  # both resolvers returned DNSSEC-validated answers at last verification


class Deed(gl.Contract):
    """Proves, on-chain, that a wallet controls a DNS domain.

    The domain owner publishes a TXT record at `_deed.<domain>` whose value
    is exactly what `record_for(wallet)` returns:

        deed-v1:<this contract>:<wallet>

    `claim(domain)` then has every validator independently query two
    independent DNS-over-HTTPS resolvers (Cloudflare and Google). The deed
    is recorded only if both return that record, directly at the name, for
    the calling wallet. No LLM is involved and no value moves.

    Deeds age. `verified_at` is the last time DNS confirmed the record, and
    `is_owner(domain, wallet, max_age_seconds)` makes freshness part of
    every check. Anyone may call `refresh(domain)`: it renews the deed if
    both resolvers still show the record, deletes it if both show it gone,
    and changes nothing if they disagree or either errors. The owner can
    also `release(domain)` at any time.

    A deed proves control of exactly the name claimed: not its parent
    domain, not its subdomains, and not that the controller is who a user
    thinks they are.
    """

    deeds: TreeMap[str, DeedRecord]
    domains: DynArray[str]  # every domain ever claimed, append-only, for enumeration
    seen: TreeMap[str, bool]

    def __init__(self):
        pass

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _scope(self) -> str:
        # Deliberately not gl.message.chain_id: on Bradbury it reads 1 in
        # both writes and views (verified live), so it can't separate
        # networks, and if a runtime upgrade ever changed it, every
        # existing record would stop matching and refresh() would revoke
        # every deed. The contract address alone scopes a record to one
        # deployment.
        return gl.message.contract_address.as_hex.lower()

    def _observe(self, domain: str) -> list:
        qname = RECORD_LABEL + "." + domain
        contract = self._scope()

        def leader_fn() -> dict:
            return {"r": [_query(base, qname, contract) for base in RESOLVERS]}

        def validator_fn(leaders_res) -> bool:
            if not isinstance(leaders_res, gl.vm.Return):
                return False
            return leader_fn() == leaders_res.calldata

        return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)["r"]

    # -- writes --

    @gl.public.write
    def claim(self, domain: str) -> None:
        d = _normalize_domain(domain)
        me = gl.message.sender_address.as_hex.lower()

        obs = self._observe(d)
        if not all(r["ok"] for r in obs):
            raise gl.vm.UserError("A DNS resolver returned an error or unusable answer; nothing changed, try again")
        if not all(r["direct"] for r in obs):
            raise gl.vm.UserError("The _deed record must be a TXT record at the name itself, not reached through a CNAME")
        if not all(me in r["owners"] for r in obs):
            raise gl.vm.UserError(
                "No matching deed record for this wallet on every resolver; publish the exact value "
                "from record_for() at record_name() and wait for DNS to propagate"
            )

        now = self._now()
        claimed_at = now
        if d in self.deeds and self.deeds[d].owner == me:
            claimed_at = self.deeds[d].claimed_at
        self.deeds[d] = DeedRecord(
            owner=me,
            claimed_at=claimed_at,
            verified_at=now,
            dnssec=all(r["ad"] for r in obs),
        )
        if d not in self.seen:
            self.seen[d] = True
            self.domains.append(d)

    @gl.public.write
    def refresh(self, domain: str) -> None:
        d = _normalize_domain(domain)
        if d not in self.deeds:
            raise gl.vm.UserError("No deed recorded for this domain")
        deed = self.deeds[d]

        obs = self._observe(d)
        if not all(r["ok"] for r in obs):
            raise gl.vm.UserError("A DNS resolver returned an error or unusable answer; nothing changed, try again")

        present = [r["direct"] and deed.owner in r["owners"] for r in obs]
        if all(present):
            deed.verified_at = self._now()
            deed.dnssec = all(r["ad"] for r in obs)
            return
        if not any(present):
            del self.deeds[d]
            return
        raise gl.vm.UserError("Resolvers disagree about this record; nothing changed, try again once DNS has propagated")

    @gl.public.write
    def release(self, domain: str) -> None:
        d = _normalize_domain(domain)
        if d not in self.deeds:
            raise gl.vm.UserError("No deed recorded for this domain")
        if self.deeds[d].owner != gl.message.sender_address.as_hex.lower():
            raise gl.vm.UserError("Only the current owner can release this deed")
        del self.deeds[d]

    # -- views --

    @gl.public.view
    def record_name(self, domain: str) -> str:
        return RECORD_LABEL + "." + _normalize_domain(domain)

    @gl.public.view
    def record_for(self, wallet: str) -> str:
        w = _normalize_wallet(wallet)
        if w is None:
            raise gl.vm.UserError("wallet must be a 0x-prefixed 40-hex-character address")
        return f"{RECORD_VERSION}:{self._scope()}:{w}"

    @gl.public.view
    def get_deed(self, domain: str) -> dict:
        d = _normalize_domain(domain)
        if d not in self.deeds:
            raise gl.vm.UserError("No deed recorded for this domain")
        deed = self.deeds[d]
        return {
            "domain": d,
            "owner": deed.owner,
            "claimed_at": deed.claimed_at,
            "verified_at": deed.verified_at,
            "dnssec": deed.dnssec,
        }

    @gl.public.view
    def owner_of(self, domain: str) -> str:
        """"" when there is no deed (or the input isn't a valid domain), so a
        consumer contract never reverts just because a user typed a bad name."""
        try:
            d = _normalize_domain(domain)
        except gl.vm.UserError:
            return ""
        if d not in self.deeds:
            return ""
        return self.deeds[d].owner

    @gl.public.view
    def verified_at(self, domain: str) -> u256:
        try:
            d = _normalize_domain(domain)
        except gl.vm.UserError:
            return u256(0)
        if d not in self.deeds:
            return u256(0)
        return self.deeds[d].verified_at

    @gl.public.view
    def is_owner(self, domain: str, wallet: str, max_age_seconds: int) -> bool:
        """The check consumer contracts should use: true only if `wallet`
        holds the deed AND DNS confirmed it within `max_age_seconds`."""
        w = _normalize_wallet(wallet)
        if w is None or max_age_seconds < 0:
            return False
        try:
            d = _normalize_domain(domain)
        except gl.vm.UserError:
            return False
        if d not in self.deeds:
            return False
        deed = self.deeds[d]
        return deed.owner == w and self._now() - int(deed.verified_at) <= max_age_seconds

    @gl.public.view
    def get_domains(self, wallet: str) -> list:
        w = _normalize_wallet(wallet)
        if w is None:
            return []
        return [d for d in self.domains if d in self.deeds and self.deeds[d].owner == w]

    @gl.public.view
    def get_all_domains(self) -> list:
        return [d for d in self.domains if d in self.deeds]
