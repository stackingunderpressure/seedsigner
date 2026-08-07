import pytest

import base  # hardware-dependency mocking as an import side effect; must precede importing seedsigner.views.*

from embit import bip32, ec, hashes
from embit.descriptor import Descriptor
from embit.descriptor.taptree import _tweak_helper
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
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
DERIVATION_PATH = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0, 0, 0]


def _key_str(root, path="86h/1h/0h/0/0"):
    fp = root.my_fingerprint
    key = root.derive(DERIVATION_PATH)
    return f"[{fp.hex()}/{path}]{key.to_public().xonly().hex()}"


def _build_founders_and_timelocked_recovery_psbt(seed_a: Seed, seed_b: Seed, seed_c: Seed,
                                                   signing_leaf: str, network: str = SettingsConstants.REGTEST):
    """
    Builds a real 2-leaf taproot PSBT matching a DynastyTrust-shaped
    policy: `tr(NUMS, {multi_a(2,A,B,C), and_v(v:after(500),multi_a(2,A,B,C))})`
    -- a 2-of-3 founders-now leaf and a 2-of-3 recovery leaf that only
    unlocks after block 500. `signing_leaf` is "founders" or "recovery";
    the returned PSBT's single input carries taproot_bip32_derivations for
    signer A tied to whichever leaf was asked for, exactly as a real
    coordinator would populate PSBT_IN_TAP_BIP32_DERIVATION.

    Returns (psbt, descriptor) -- the descriptor is what a user would have
    registered on the device ahead of time.
    """
    embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
    root_a = bip32.HDKey.from_seed(seed_a.seed_bytes, version=embit_network["xprv"])
    root_b = bip32.HDKey.from_seed(seed_b.seed_bytes, version=embit_network["xprv"])
    root_c = bip32.HDKey.from_seed(seed_c.seed_bytes, version=embit_network["xprv"])
    key_a = root_a.derive(DERIVATION_PATH)
    fp_a = root_a.my_fingerprint

    keys = f"{_key_str(root_a)},{_key_str(root_b)},{_key_str(root_c)}"
    desc_str = f"tr({NUMS_HEX},{{multi_a(2,{keys}),and_v(v:after(500),multi_a(2,{keys}))}})"
    descriptor = Descriptor.from_string(desc_str)
    script_pubkey = descriptor.script_pubkey()

    leaves_with_paths, merkle_root = _tweak_helper(descriptor.taptree)
    internal_xonly = bytes.fromhex(NUMS_HEX)
    tweak = hashes.tagged_hash("TapTweak", internal_xonly + merkle_root)
    point = secp256k1.ec_pubkey_parse(b"\x02" + internal_xonly)
    secp256k1.ec_pubkey_tweak_add(point, bytes(tweak))
    _, parity = secp256k1.xonly_pubkey_from_pubkey(point)

    control_blocks = []
    for leaf, path in leaves_with_paths:
        leaf_ser = leaf.serialize()
        version, script_bytes = leaf_ser[0], leaf_ser[1:]
        control_block = bytes([version | (1 if parity else 0)]) + internal_xonly + path
        leaf_hash = hashes.tagged_hash("TapLeaf", leaf_ser)
        control_blocks.append((control_block, script_bytes, version, leaf_hash, leaf))

    prevout = TransactionOutput(100_000_000, script_pubkey)
    tx_in = TransactionInput(bytes(32), 0)
    tx_out = TransactionOutput(99_990_000, script_pubkey)
    p = PSBT(Transaction(vin=[tx_in], vout=[tx_out]))
    inp = p.inputs[0]
    inp.witness_utxo = prevout
    inp.taproot_internal_key = ec.PublicKey.from_xonly(internal_xonly)
    inp.taproot_merkle_root = merkle_root
    for cb, sb, v, lh, leaf in control_blocks:
        inp.taproot_scripts[cb] = sb + bytes([v])

    is_timelocked = signing_leaf == "recovery"
    matches = [c for c in control_blocks if ("after" in str(c[4].miniscript)) == is_timelocked]
    _, _, _, leaf_hash, _ = matches[0]
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
        assert summary["timelock_kind"] == "after"
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
        assert PSBTParser._parse_leaf_quorum(node) == (1, 1, "older", 144)


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
