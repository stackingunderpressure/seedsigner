import pytest

import base  # hardware-dependency mocking as an import side effect; must precede importing seedsigner.views.*

from embit import bip32, ec, hashes
from embit.descriptor import Descriptor
from embit.descriptor.taptree import _tweak_helper
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit.util import secp256k1

from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import psbt_views

from psbt_testing_util import PSBTTestData


# Same NUMS point and account-level path used across the other taproot test
# files (test_taproot_scriptpath.py, test_taproot_change_output.py).
NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
ACCOUNT_PATH = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0]  # m/86'/1'/0'
DERIVATION_PATH = ACCOUNT_PATH + [0, 0]  # .../0/0 -- the real signing child


def _account_key_str(root, account_path_str="86h/1h/0h"):
    """
    `[fp/86h/1h/0h]tpub.../0/0` -- an account-level xpub with a `/0/0`
    derivation SUFFIX in the descriptor text, exactly the real-world shape
    (DynastyTrust's `[fp/path]xpub/0/0`, Nunchuk's wildcard equivalent).
    This is deliberately NOT a bare pre-derived xonly pubkey with no
    further derivation possible -- that shape is what let the un-derived-
    vs-derived leaf-hash bug (get_signing_leaf_summary hashing the
    registered descriptor's leaves BEFORE deriving them) pass every
    existing test while being broken against every real registered
    wallet. See embit_utils.py's get_multisig_address taproot branch and
    psbt_parser.py's get_signing_leaf_summary docstring for the full
    story.
    """
    fp = root.my_fingerprint
    account_xpub = root.derive(ACCOUNT_PATH).to_public()
    return f"[{fp.hex()}/{account_path_str}]{account_xpub.to_base58()}/0/0"


def _build_founders_and_timelocked_recovery_psbt(seed_a: Seed, seed_b: Seed, seed_c: Seed,
                                                   signing_leaf: str, network: str = SettingsConstants.REGTEST,
                                                   timelock_expr: str = "after(500)"):
    """
    Builds a real 2-leaf taproot PSBT matching a DynastyTrust-shaped
    policy: `tr(NUMS, {multi_a(2,A,B,C), and_v(v:TIMELOCK,multi_a(2,A,B,C))})`
    -- a 2-of-3 founders-now leaf and a 2-of-3 recovery leaf gated by
    `timelock_expr` (default an absolute after(500); pass e.g.
    "older(4199366)" to model a real Nunchuk-shaped time-based relative
    lock, or reverse the and_v operand order via `quorum_first=True`).
    `signing_leaf` is "founders" or "recovery"; the returned PSBT's single
    input carries taproot_bip32_derivations AND taproot_scripts for
    signer A tied to whichever leaf was asked for, exactly as a real
    coordinator would populate PSBT_IN_TAP_BIP32_DERIVATION and
    PSBT_IN_TAP_LEAF_SCRIPT.

    Returns (psbt, descriptor) -- the descriptor is what a user would have
    registered on the device ahead of time, built with real account-level
    xpubs + a `/0/0` derivation suffix (see _account_key_str), not bare
    pre-derived keys -- this is the actual shape the critical
    derivation-mismatch bug was invisible against.
    """
    embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
    root_a = bip32.HDKey.from_seed(seed_a.seed_bytes, version=embit_network["xprv"])
    root_b = bip32.HDKey.from_seed(seed_b.seed_bytes, version=embit_network["xprv"])
    root_c = bip32.HDKey.from_seed(seed_c.seed_bytes, version=embit_network["xprv"])
    key_a = root_a.derive(DERIVATION_PATH)
    fp_a = root_a.my_fingerprint

    keys = f"{_account_key_str(root_a)},{_account_key_str(root_b)},{_account_key_str(root_c)}"
    desc_str = f"tr({NUMS_HEX},{{multi_a(2,{keys}),and_v(v:{timelock_expr},multi_a(2,{keys}))}})"
    descriptor = Descriptor.from_string(desc_str)

    # The registered descriptor is fixed (non-wildcard): derive() at any
    # index/branch is a proven no-op for it, same as DynastyTrust's real
    # vaults -- but the PSBT itself is built from the DERIVED tree, the
    # same way a real coordinator computes real leaf hashes from the real
    # on-chain script, which is the whole point of this fixture no longer
    # matching the un-derived tree by coincidence.
    derived_descriptor = descriptor.derive(0, branch_index=0)
    script_pubkey = derived_descriptor.script_pubkey()

    leaves_with_paths, merkle_root = _tweak_helper(derived_descriptor.taptree)
    internal_xonly = bytes.fromhex(NUMS_HEX)
    tweak = hashes.tagged_hash("TapTweak", internal_xonly + merkle_root)
    point = secp256k1.ec_pubkey_parse(b"\x02" + internal_xonly)
    secp256k1.ec_pubkey_tweak_add(point, bytes(tweak))
    _, parity = secp256k1.xonly_pubkey_from_pubkey(point)

    control_blocks = []
    for leaf, path in leaves_with_paths:
        # Raw (non-length-prefixed) script bytes -- the real BIP371
        # PSBT_IN_TAP_LEAF_SCRIPT wire value is <raw script><leaf
        # version>, NOT the length-prefixed form leaf.serialize() itself
        # produces (that prefix is only needed inside the TapLeaf HASH
        # preimage, via Script(...).serialize() below, matching embit's
        # own sign_input_with_tapkey exactly).
        raw_script_bytes = leaf.miniscript.compile()
        control_block = bytes([leaf.version | (1 if parity else 0)]) + internal_xonly + path
        leaf_hash = hashes.tagged_hash("TapLeaf", bytes([leaf.version]) + Script(raw_script_bytes).serialize())
        control_blocks.append((control_block, raw_script_bytes, leaf.version, leaf_hash, leaf))

    prevout = TransactionOutput(100_000_000, script_pubkey)
    tx_in = TransactionInput(bytes(32), 0)
    tx_out = TransactionOutput(99_990_000, script_pubkey)
    p = PSBT(Transaction(vin=[tx_in], vout=[tx_out]))
    inp = p.inputs[0]
    inp.witness_utxo = prevout
    inp.taproot_internal_key = ec.PublicKey.from_xonly(internal_xonly)
    inp.taproot_merkle_root = merkle_root

    is_timelocked = signing_leaf == "recovery"
    matches = [c for c in control_blocks if ("after" in str(c[4].miniscript) or "older" in str(c[4].miniscript)) == is_timelocked]
    cb, raw_script_bytes, v, leaf_hash, _leaf = matches[0]

    # A real coordinator only includes PSBT_IN_TAP_LEAF_SCRIPT (the
    # control block + script) for the leaf actually being spent on THIS
    # input -- not every leaf in the wallet's whole tree. Populating all
    # of them here (as an earlier version of this fixture did) made
    # signer A's key -- which legitimately appears in every leaf of this
    # policy -- match every leaf's real taproot_scripts entry, which is
    # accurate for what the fixture handed it, but not representative of
    # a real single-leaf spend.
    inp.taproot_scripts[cb] = raw_script_bytes + bytes([v])
    inp.taproot_bip32_derivations[key_a.to_public()] = ([leaf_hash], DerivationPath(fp_a, DERIVATION_PATH))

    return p, descriptor


class TestSigningLeafSummary:
    """
    2026-08-07: the last piece of the taproot confirm-screen work -- a
    human-readable (well, human-readable at the VIEW layer; this model
    returns raw facts) description of which spending path a seed is about
    to sign. Deliberately split into two honesty tiers: WITH a registered
    descriptor, the signing leaf is matched against the wallet's own real
    tap tree and its true position + quorum are reported, read from the
    descriptor's PARSED miniscript AST (never decompiled from raw script
    bytes -- get_signing_leaf_summary's own docstring explains why that
    matters). WITHOUT one, only what the PSBT's own metadata independently
    proves gets reported -- never a leaf position or quorum guess.
    """

    seed_a = PSBTTestData.seed
    seed_b = PSBTTestData.multisig_key_2
    seed_c = PSBTTestData.multisig_key_3

    def test_no_taproot_leaf_signing_returns_none(self):
        """A PSBT with no taproot input at all (or a key-path-only one)
        has nothing leaf-specific to say."""
        parser = PSBTParser.__new__(PSBTParser)
        parser.signing_leaf_hashes = set()
        assert parser.get_signing_leaf_summary() is None

    def test_timelocked_recovery_leaf_reported_correctly_with_registered_descriptor(self):
        psbt, descriptor = _build_founders_and_timelocked_recovery_psbt(
            self.seed_a, self.seed_b, self.seed_c, signing_leaf="recovery"
        )
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        summary = parser.get_signing_leaf_summary(registered_descriptor=descriptor)

        assert summary["num_eligible_keys"] == 1
        assert summary["leaf_count"] == 2
        assert summary["leaf_index"] in (1, 2)
        assert summary["quorum_k"] == 2
        assert summary["quorum_n"] == 3
        assert summary["timelock_kind"] == "after_height"
        assert summary["timelock_value"] == 500

    def test_plain_founders_leaf_reported_with_no_timelock(self):
        psbt, descriptor = _build_founders_and_timelocked_recovery_psbt(
            self.seed_a, self.seed_b, self.seed_c, signing_leaf="founders"
        )
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        summary = parser.get_signing_leaf_summary(registered_descriptor=descriptor)

        assert summary["quorum_k"] == 2
        assert summary["quorum_n"] == 3
        assert summary["timelock_kind"] is None
        assert summary["timelock_value"] is None

        # The two leaves must resolve to DIFFERENT positions -- if this
        # ever ties, the leaf-matching logic isn't actually distinguishing
        # them.
        other = PSBTParser(
            _build_founders_and_timelocked_recovery_psbt(self.seed_a, self.seed_b, self.seed_c, signing_leaf="recovery")[0],
            self.seed_a, network=SettingsConstants.REGTEST,
        ).get_signing_leaf_summary(registered_descriptor=descriptor)
        assert summary["leaf_index"] != other["leaf_index"]

    def test_without_registered_descriptor_only_the_provable_fact_is_reported(self):
        """Security-honesty regression guard: no leaf position, no
        quorum claim, without a registered wallet to prove them against --
        even though the PSBT itself carries a real, valid signing leaf."""
        psbt, _descriptor = _build_founders_and_timelocked_recovery_psbt(
            self.seed_a, self.seed_b, self.seed_c, signing_leaf="recovery"
        )
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        summary = parser.get_signing_leaf_summary(registered_descriptor=None)

        assert summary["num_eligible_keys"] == 1
        assert summary["leaf_index"] is None
        assert summary["leaf_count"] is None
        assert summary["quorum_k"] is None
        assert summary["quorum_n"] is None
        assert summary["timelock_kind"] is None

    def test_a_different_registered_wallet_does_not_falsely_claim_a_position(self):
        """The registered descriptor doesn't match THIS PSBT's leaf at
        all (different keys entirely) -- must fall back to the honest
        no-position tier, not a wrong match."""
        psbt, _real_descriptor = _build_founders_and_timelocked_recovery_psbt(
            self.seed_a, self.seed_b, self.seed_c, signing_leaf="recovery"
        )
        _, unrelated_descriptor = _build_founders_and_timelocked_recovery_psbt(
            PSBTTestData.multisig_key_3, self.seed_b, self.seed_a, signing_leaf="recovery"
        )
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        summary = parser.get_signing_leaf_summary(registered_descriptor=unrelated_descriptor)
        assert summary["leaf_index"] is None
        assert summary["quorum_k"] is None

    def test_parse_leaf_quorum_unrecognized_shape_returns_none_rather_than_guessing(self):
        """A shape this deliberately narrow recognizer doesn't handle
        (e.g. a nested or_d/or_i policy) must return all-None, not a
        best-effort guess."""
        from embit.descriptor.miniscript import Miniscript
        node = Miniscript.from_string(
            "or_d(pk(0245f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8),"
            "and_v(v:older(10),pk(0345f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8)))",
            taproot=True,
        )
        k, n, timelock_kind, timelock_value = PSBTParser._parse_leaf_quorum(node)
        assert (k, n, timelock_kind, timelock_value) == (None, None, None, None)

    def test_parse_leaf_quorum_bare_pk_leaf(self):
        from embit.descriptor.miniscript import Miniscript
        node = Miniscript.from_string(
            "pk(0245f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8)", taproot=True
        )
        assert PSBTParser._parse_leaf_quorum(node) == (1, 1, None, None)

    def test_parse_leaf_quorum_older_timelock(self):
        from embit.descriptor.miniscript import Miniscript
        node = Miniscript.from_string(
            "and_v(v:older(144),multi_a(1,0245f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8))",
            taproot=True,
        )
        assert PSBTParser._parse_leaf_quorum(node) == (1, 1, "older_blocks", 144)

    def test_parse_leaf_quorum_older_time_based_bip68(self):
        """The real Nunchuk-shaped value from a live wallet: older(4199366)
        has BIP68 bit 22 (0x400000) set, so the low 16 bits (5062) are
        512-second units, not a raw block count -- 5062 * 512 = 2,591,744
        seconds, exactly 30.0 days. Rendering this as "4199366 blocks of
        age" (as the pre-fix code did) would read as roughly 80 years
        instead of 30 days -- precisely backwards."""
        from embit.descriptor.miniscript import Miniscript
        node = Miniscript.from_string(
            "and_v(v:older(4199366),multi_a(1,0245f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8))",
            taproot=True,
        )
        k, n, timelock_kind, timelock_value = PSBTParser._parse_leaf_quorum(node)
        assert (k, n, timelock_kind) == (1, 1, "older_time")
        assert timelock_value == 2_591_744
        assert round(timelock_value / 86400, 1) == 30.0  # ~30 days

    def test_parse_leaf_quorum_after_time_based_bip65(self):
        """after(n) with n >= 500_000_000 is a UNIX timestamp (BIP65),
        not a block height -- rendering it as "After block 1767225600"
        (as the pre-fix code did) is a meaningless nine-digit "block"."""
        from embit.descriptor.miniscript import Miniscript
        node = Miniscript.from_string(
            "and_v(v:after(1767225600),multi_a(1,0245f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8))",
            taproot=True,
        )
        assert PSBTParser._parse_leaf_quorum(node) == (1, 1, "after_time", 1767225600)

    def test_parse_leaf_quorum_recognizes_both_and_v_operand_orders(self):
        """and_v(A,B) only requires ONE side to be V-wrapped -- different
        compilers pick different sides. A DynastyTrust-compiled leaf wraps
        the timelock first (and_v(v:TIMELOCK,QUORUM)); a real Nunchuk
        inheritance-plan export wraps the quorum first
        (and_v(v:QUORUM,TIMELOCK)) -- this used to silently return
        all-None (losing the quorum too, not just the timelock) for the
        reversed order."""
        from embit.descriptor.miniscript import Miniscript
        timelock_first = Miniscript.from_string(
            "and_v(v:older(144),multi_a(2,0245f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8,"
            "0345f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8))",
            taproot=True,
        )
        quorum_first = Miniscript.from_string(
            "and_v(v:multi_a(2,0245f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8,"
            "0345f16537edee0817820087c677725b21e744cec835a06fadfdf651544135e8),older(144))",
            taproot=True,
        )
        assert PSBTParser._parse_leaf_quorum(timelock_first) == (2, 2, "older_blocks", 144)
        assert PSBTParser._parse_leaf_quorum(quorum_first) == (2, 2, "older_blocks", 144)


class TestPSBTOverviewRoutingToSpendPathView:
    """
    The confirm-screen wiring: PSBTOverviewView routes through the new
    PSBTSpendPathView only when there's actually a taproot leaf being
    signed (get_signing_leaf_summary returns non-None); everything else
    -- single-key, legacy multisig -- must be completely unaffected and
    keep going straight to the existing PSBTMathView/warning routing.
    _next_destination is tested directly (a pure function of psbt_parser,
    no GUI/Controller/renderer needed) since this repo's own test suite
    doesn't unit-render Screens either (FlowTest mocks View.run_screen()
    entirely) -- matching, not falling short of, the existing convention.
    """
    seed_a = PSBTTestData.seed
    seed_b = PSBTTestData.multisig_key_2
    seed_c = PSBTTestData.multisig_key_3

    def test_taproot_script_path_spend_has_a_leaf_summary_to_show(self):
        psbt, descriptor = _build_founders_and_timelocked_recovery_psbt(
            self.seed_a, self.seed_b, self.seed_c, signing_leaf="founders"
        )
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.get_signing_leaf_summary(descriptor) is not None

    def test_next_destination_ignores_leaf_summary_entirely(self):
        """_next_destination is the routing PSBTOverviewView falls back to
        AFTER the leaf-summary check -- it must never re-derive or
        duplicate that check itself (single responsibility: the caller
        decides whether to detour through PSBTSpendPathView at all)."""
        psbt, _descriptor = _build_founders_and_timelocked_recovery_psbt(
            self.seed_a, self.seed_b, self.seed_c, signing_leaf="founders"
        )
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        dest = psbt_views.PSBTOverviewView._next_destination(parser)
        # This PSBT has no change output (single destination-shaped
        # output in the test builder) -> routes to the no-change warning,
        # exercising the real branch logic rather than a trivial default.
        assert dest.View_cls == psbt_views.PSBTNoChangeWarningView

    def test_legacy_multisig_psbt_is_unaffected_by_the_new_routing(self):
        """A completely ordinary legacy multisig PSBT (no taproot
        anywhere) must have no leaf summary and route exactly as it did
        before this feature existed."""
        from binascii import a2b_base64
        from embit.psbt import PSBT as EmbitPSBT
        raw = a2b_base64(PSBTTestData.MULTISIG_NATIVE_SEGWIT_1_INPUT)
        # No outputs on this base fixture -- just prove there's nothing
        # taproot-leaf-specific to show, which is the actual claim here.
        psbt = EmbitPSBT.parse(raw)
        parser = PSBTParser.__new__(PSBTParser)
        parser.psbt = psbt
        parser.seed = PSBTTestData.seed
        parser.network = SettingsConstants.REGTEST
        parser.policy = None
        parser.input_amount = 0
        parser.num_inputs = 0
        parser.signing_leaf_hashes = set()
        parser.root = None
        parser._set_root()
        parser._parse_inputs()
        assert parser.get_signing_leaf_summary() is None



def _build_keypath_spend_psbt_with_real_internal_key(seed_a: Seed, seed_b: Seed, network: str = SettingsConstants.REGTEST):
    """
    A taproot wallet whose INTERNAL key is a real, spendable key (signer
    A) -- not the NUMS point -- alongside a genuine script-path leaf
    (pk(B)). The single input is signed via the KEY PATH by signer A,
    bypassing the leaf entirely: exactly the shape some third-party
    coordinators (e.g. Nunchuk-style inheritance plans) produce, and
    exactly the case PSBTParser.signing_key_path exists to flag.
    """
    embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
    root_a = bip32.HDKey.from_seed(seed_a.seed_bytes, version=embit_network["xprv"])
    root_b = bip32.HDKey.from_seed(seed_b.seed_bytes, version=embit_network["xprv"])
    key_a = root_a.derive(DERIVATION_PATH)
    fp_a = root_a.my_fingerprint

    desc_str = f"tr({_account_key_str(root_a)},{{pk({_account_key_str(root_b)})}})"
    descriptor = Descriptor.from_string(desc_str)
    derived = descriptor.derive(0, branch_index=0)
    script_pubkey = derived.script_pubkey()

    _, merkle_root = _tweak_helper(derived.taptree)

    prevout = TransactionOutput(100_000_000, script_pubkey)
    tx_in = TransactionInput(bytes(32), 0)
    tx_out = TransactionOutput(99_990_000, script_pubkey)
    p = PSBT(Transaction(vin=[tx_in], vout=[tx_out]))
    inp = p.inputs[0]
    inp.witness_utxo = prevout
    inp.taproot_internal_key = key_a.to_public()
    inp.taproot_merkle_root = merkle_root
    # Key-path claim: EMPTY leaf_hashes -- exactly what a coordinator
    # populates for an internal-key derivation, as distinct from a
    # leaf-tied one.
    inp.taproot_bip32_derivations[key_a.to_public()] = ([], DerivationPath(fp_a, DERIVATION_PATH))

    return p


class TestKeyPathSpendDetection:
    """
    embit's own signing algorithm (PSBT.sign_input_with_tapkey) always
    tries a KEY-PATH spend first for every candidate key, regardless of
    any leaf_hashes claim -- so a taproot wallet with a real (non-NUMS)
    internal key can be spent via the key path even when a tap tree with
    real leaves exists, bypassing every leaf's quorum/timelock entirely.
    PSBTParser.signing_key_path exists to catch and flag exactly this,
    while leaving a plain single-key taproot wallet (no tree at all --
    the overwhelmingly common case) completely silent, since there's
    nothing to bypass there.
    """
    seed_a = PSBTTestData.seed
    seed_b = PSBTTestData.multisig_key_2

    def test_keypath_spend_with_real_internal_key_and_real_tree_is_flagged(self):
        psbt = _build_keypath_spend_psbt_with_real_internal_key(self.seed_a, self.seed_b)
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.signing_key_path is True
        assert parser.signing_leaf_hashes == set()  # no leaf is being signed at all
        assert parser.get_signing_leaf_summary() is None

    def test_plain_single_key_taproot_keypath_is_not_flagged(self):
        """A plain single-key tr(key) wallet (no tree at all, merkle_root
        empty) has nothing to bypass -- key-path is its only possible
        spend, not a dangerous escape hatch, and must stay silent exactly
        like it did before this feature existed."""
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(SettingsConstants.REGTEST)]
        root_a = bip32.HDKey.from_seed(self.seed_a.seed_bytes, version=embit_network["xprv"])
        key_a = root_a.derive(DERIVATION_PATH)
        fp_a = root_a.my_fingerprint

        # BIP341 always applies the tweak, even with an empty tree --
        # merkle_root=b"" is not "skip the tweak", it's "tweak against no
        # tree". A raw untweaked key here would silently fail to match
        # any real single-sig taproot output.
        tweaked_xonly = key_a.taproot_tweak(b"").xonly()
        script_pubkey = Script(b"\x51\x20" + tweaked_xonly)

        prevout = TransactionOutput(100_000_000, script_pubkey)
        tx_in = TransactionInput(bytes(32), 0)
        tx_out = TransactionOutput(99_990_000, script_pubkey)
        p = PSBT(Transaction(vin=[tx_in], vout=[tx_out]))
        inp = p.inputs[0]
        inp.witness_utxo = prevout
        inp.taproot_internal_key = key_a.to_public()
        inp.taproot_merkle_root = b""
        inp.taproot_bip32_derivations[key_a.to_public()] = ([], DerivationPath(fp_a, DERIVATION_PATH))

        parser = PSBTParser(p, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.signing_key_path is False


class TestMultipleLeavesAndEligibleKeyCounting:
    """
    Two related correctness properties of get_signing_leaf_summary:
    num_eligible_keys must count distinct KEYS (not leaves -- one key can
    legitimately be eligible on more than one leaf), and a PSBT that
    genuinely signs more than one distinct leaf must say so explicitly
    (multiple_leaves) rather than silently reporting only the first one
    found as if it were the whole story.
    """
    seed_a = PSBTTestData.seed
    seed_b = PSBTTestData.multisig_key_2
    seed_c = PSBTTestData.multisig_key_3

    def test_one_key_eligible_on_two_leaves_reports_multiple_leaves_not_two_keys(self):
        """Signer A appears in BOTH the founders leaf and the recovery
        leaf of this policy. A PSBT whose input's taproot_scripts
        genuinely includes both leaves' control blocks (e.g. a
        coordinator handing over full tree info) means signer A can
        really sign either -- that's a multi-path fact worth flagging,
        not a "two keys eligible" miscount."""
        psbt, descriptor = _build_founders_and_timelocked_recovery_psbt(
            self.seed_a, self.seed_b, self.seed_c, signing_leaf="recovery"
        )
        # Also wire in the founders leaf's control block for the SAME
        # input, so signer A's key genuinely matches two real leaves --
        # mirroring what _build_founders_and_timelocked_recovery_psbt's
        # own comment describes as the multi-leaf-eligible scenario.
        internal_xonly = bytes.fromhex(NUMS_HEX)
        derived = descriptor.derive(0, branch_index=0)
        leaves_with_paths, merkle_root = _tweak_helper(derived.taptree)
        tweak = hashes.tagged_hash("TapTweak", internal_xonly + merkle_root)
        point = secp256k1.ec_pubkey_parse(b"\x02" + internal_xonly)
        secp256k1.ec_pubkey_tweak_add(point, bytes(tweak))
        _, parity = secp256k1.xonly_pubkey_from_pubkey(point)
        for leaf, path in leaves_with_paths:
            raw_script_bytes = leaf.miniscript.compile()
            control_block = bytes([leaf.version | (1 if parity else 0)]) + internal_xonly + path
            psbt.inputs[0].taproot_scripts[control_block] = raw_script_bytes + bytes([leaf.version])

        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert len(parser.signing_leaf_pubkeys) == 1  # one distinct KEY
        assert len(parser.signing_leaf_hashes) == 2  # eligible on two distinct LEAVES

        summary = parser.get_signing_leaf_summary(registered_descriptor=descriptor)
        assert summary["num_eligible_keys"] == 1  # not 2 -- this is a key count, not a leaf count
        assert summary["multiple_leaves"] is True
        assert summary["leaf_index"] is None  # never arbitrarily pick one
        assert summary["leaf_count"] == 2
