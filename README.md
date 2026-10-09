# Deed

Proof on GenLayer that a wallet controls a DNS domain, checked through two
independent DNS resolvers by every validator, with no LLM involved.

## The problem

Nothing on-chain links an address to the organization people think it
belongs to. That gap drives a large share of crypto losses: fake "official"
token contracts, cloned project contracts, phishing airdrops, impostor
treasury addresses. Off-chain, the internet already has an authority for
"who controls this name": DNS. Deed brings that answer on-chain in a form
any other Intelligent Contract can check before acting.

## How it works

1. The domain owner asks Deed what to publish:
   `record_for(wallet)` returns

   ```
   deed-v1:<deed contract address>:<wallet>
   ```

   and `record_name(domain)` returns `_deed.<domain>`.
2. They add that value as a TXT record at that name in their DNS.
3. The wallet calls `claim(domain)`. Every validator queries **both**
   Cloudflare (`cloudflare-dns.com`) and Google (`dns.google`) over
   DNS-over-HTTPS. The deed is recorded only if both return the record,
   directly at `_deed.<domain>`, naming the calling wallet.
4. Other contracts call `is_owner(domain, wallet, max_age_seconds)` and act
   only on a deed that DNS confirmed recently enough for their purpose.
5. Anyone can call `refresh(domain)`. It renews the deed if both resolvers
   still show the record, deletes it if both show it gone, and changes
   nothing if they disagree or either one errors. The owner can
   `release(domain)` at any time.

## Security model

Each rule below is enforced in code and has its own test in
`tests/direct/test_deed.py`.

**Where the proof comes from**
- **Fixed sources.** The two resolvers are constants in the contract. A
  caller can never supply the source the proof is checked against.
- **Two independent operators must agree.** One compromised, lying,
  lagging or cache-poisoned resolver can't create a deed, keep a revoked
  one alive, or revoke a valid one. Every state change needs both.
- **An outage is never an absence.** Only HTTP 200, valid DoH JSON, an
  untruncated answer and a definitive DNS result (`NOERROR` or `NXDOMAIN`)
  count. `SERVFAIL`, timeouts, rate-limit pages and truncated answers are
  errors, so an outage can't be read as "record removed".
- **Validators re-derive everything.** The leader's observation is accepted
  only if each validator's own queries produce exactly the same result. A
  leader can't invent a record, hide one, or hide a resolver error.

**What the record binds**
- **The record names the wallet it authorizes.** Seeing someone else's
  record in DNS doesn't let you claim it, so front-running a claim doesn't
  work.
- **Records are scoped to one Deed contract.** A record published for one
  deployment proves nothing to another (no replay). The chain ID is
  deliberately left out: on Bradbury `gl.message.chain_id` reads `1` in
  both writes and views (verified live with a probe contract), so it can't
  separate networks. Worse, if a runtime upgrade ever changed it, every
  existing record would stop matching and `refresh` would revoke every
  deed. Leaving it out also costs nothing: a record only authorizes the
  wallet it names, so replaying it elsewhere can only bind that same
  wallet.
- **No CNAME indirection.** The TXT record must be at `_deed.<domain>`
  itself. A dangling CNAME there, pointing into a zone someone else has
  since taken over, can't be used to claim the domain.
- **Strict input validation.** Domains must be plain `a-z0-9-` labels
  (punycode for IDNs). Nothing else is ever put into a resolver URL, so
  extra query parameters, paths or fragments can't be injected.

**How long a deed means anything**
- **Deeds age.** `verified_at` records the last time both resolvers
  confirmed the record. `is_owner` makes freshness part of every check:
  there's no "trust forever" option.
- **Revocation is permissionless and conservative.** Anyone can trigger a
  refresh, and only a conclusive answer from both resolvers changes state.
- **Deeds need upkeep, by design.** A deed only passes `is_owner` while its
  last confirmation is within the consumer's `max_age_seconds`, so someone
  has to call `refresh` periodically: the owner, a keeper, or any consumer
  that depends on it. A deed nobody refreshes stops being trusted on its
  own, which is the safe failure.
- **DNSSEC is reported, not required.** `dnssec` is true when both
  resolvers returned DNSSEC-validated answers. A high-value consumer can
  require it; most domains aren't signed, so Deed doesn't.

### What a deed does not prove

- **Exactly the name, nothing more.** A deed for `blog.example.com` says
  nothing about `example.com`, and the reverse is also true. Shared-suffix
  hosts (dynamic DNS providers, for example) are their own names.
- **Control, not identity.** It shows that whoever controls the domain's
  DNS authorized this wallet. Whether that domain is the organization a
  user has in mind is still the user's judgment.
- **Expired domains change hands.** Whoever re-registers a domain controls
  its DNS and can claim it. `claimed_at` shows when the current owner's
  tenure started, so consumers can treat a recent change of hands with
  suspicion.
- **Accepted is not final.** On GenLayer an accepted transaction can still
  be appealed during its finality window. Contracts making valuable
  decisions should read Deed's finalized state, as the example registry
  below does.

## Using Deed from another contract

`contracts/verified_registry.py` is a complete, tested consumer: a
registry of each domain's official contract address that only the
domain's verified owner can write:

```python
from genlayer.py.public_abi import StorageType

MAX_DEED_AGE_SECONDS = 7 * 86400

def _holds_deed(self, domain: str, wallet: str) -> bool:
    return bool(
        gl.get_contract_at(self.deed)
        .view(state=StorageType.LATEST_FINAL)   # not just accepted: final
        .is_owner(domain, wallet, MAX_DEED_AGE_SECONDS)
    )
```

It checks the deed when an address is published **and again on every
lookup**, so a listing stops being served the moment the domain's deed
lapses or changes hands. Nobody has to clean it up first.

Two things we learned on Bradbury that matter to any Deed consumer:

- **Finalized state lags.** Reading `LATEST_FINAL` means a fresh claim
  isn't visible to the registry until the claim transaction finalizes
  after its appeal window. That delay is the point: an accepted claim
  that later gets reversed never reaches the registry.
- **Before Deed's own deployment finalizes, calls to it abort the caller.**
  GenVM reports `invalid_contract absent_runner_comment` and stops the
  consumer's whole call, so a `try/except` in the consumer can't catch it.
  It is still fail-closed: nothing gets granted. It only happens in the
  window right after Deed is deployed.

## Interface

| Method | Kind | Purpose |
|---|---|---|
| `record_for(wallet)` | view | Exact TXT value a wallet should publish |
| `record_name(domain)` | view | Where to publish it (`_deed.<domain>`) |
| `claim(domain)` | write | Record a deed for the caller after both resolvers confirm |
| `refresh(domain)` | write | Anyone: renew, revoke, or (on disagreement) change nothing |
| `release(domain)` | write | Owner gives up the deed |
| `is_owner(domain, wallet, max_age_seconds)` | view | The consumer check: owner and fresh enough |
| `owner_of(domain)` / `verified_at(domain)` | view | Raw state; never revert, so consumers can't be griefed by bad input |
| `get_deed(domain)` | view | Full record: owner, claimed_at, verified_at, dnssec |
| `get_domains(wallet)` / `get_all_domains()` | view | Enumerate current deeds |

Methods that take a wallet accept either a hex string (typed SDK callers)
or an `Address` (what the `genlayer` CLI sends for any 40-hex argument).

## Live deployment

GenLayer Bradbury Testnet (chain 4221):

- **Deed:** [`0x726e2ee206b11ab5862D24D84654619be5C7e9fc`](https://explorer-bradbury.genlayer.com/address/0x726e2ee206b11ab5862D24D84654619be5C7e9fc)
- **VerifiedRegistry (example consumer):** [`0x76f51Bad89DF4d5a8F66283279dBE0490522AcE3`](https://explorer-bradbury.genlayer.com/address/0x76f51Bad89DF4d5a8F66283279dBE0490522AcE3)

The addresses above are the final deployment. A post-submission review
found that the never-revert views crashed on non-text input (the CLI
sends numeric-looking arguments as numbers); the fix needed a
redeploy. Every check below was re-run on it, except the three registry
rows marked *pending*: those need the new claim to finalize first, and
their results here are from the previous deployment.

**Live-verified against real DNS** with `usesalvage.xyz`, whose
`_deed.usesalvage.xyz` TXT record is published for this deployment:

| Check | Result |
|---|---|
| `claim` on a domain with no record (`olumi.xyz`) | Refused: "No matching deed record..." |
| `claim` after publishing the record | Deed recorded, 5/5 agree |
| `is_owner` for the owner / another wallet | `true` / `false` |
| Freshness in a view uses real time | 299s-old proof: rejected at `max_age=30`, accepted at `max_age=599` |
| `owner_of` with injection-style input (`x&type=A`) | `""`, no revert |
| `owner_of(123)` from the CLI (which sends it as a number) | `""`, no revert |
| `refresh` with the record still present | `verified_at` advanced, `claimed_at` kept, 5/5 agree |
| `refresh` after the record was removed from DNS (on the previous deployment, once its record was replaced) | Deed revoked, `owner_of` became `""`, 5/5 agree |
| Registry `publish` while the claim was accepted but not final *(pending)* | Refused by the registry's own check, through a real cross-contract read of Deed's finalized state |
| Same `publish` after the claim finalized *(pending)* | Accepted, 5/5 agree |
| Registry `lookup` (view calling Deed's view, finalized state) *(pending)* | Returns the published address; `get_listing` reports `currently_valid: true` |

## Development

```shell
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

genvm-lint check contracts/deed.py
genvm-lint check contracts/verified_registry.py
python -m pytest tests/direct/ -v
```

Direct-mode tests mock each resolver with its real response shape
(Cloudflare quotes TXT data and omits the trailing dot, Google does the
opposite). The registry tests install a cross-contract hook that records
every call the registry makes to Deed, including which state it reads.

## License

MIT
