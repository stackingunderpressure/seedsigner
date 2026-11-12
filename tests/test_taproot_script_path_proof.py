"""
2026-11: this fork signs taproot script path spends (a vault's spending paths), which
stock SeedSigner refuses outright. Since the merge of upstream's psbt hardening, a leaf
is only signed, and only described on screen, once its control block PROVES it is part
of the address being spent (PSBTParser._proven_leaf_hash, BIP-341).

Without that proof a coordinator could attach any script holding our key and have the
device show that script's rules ("2 of 3, no timelock") while the coin obeys another.

These tests feed the parser honest and forged versions of the same two-path vault spend.
"""
import pytest

from embit import bip32, ec, hashes
from embit.descriptor import Descriptor
from embit.descriptor.taptree import _tweak_helper
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from base import FlowTest, FlowStep
from psbt_testing_util import PSBTTestData
from taproot_testing_util import control_block as taproot_control_block

from seedsigner.models.psbt_parser import (
    PSBTInputAmountVerificationError,
    PSBTNegativeFeeError,
    PSBTParser,
    PSBTUnprovenScriptPathError,
    PSBTUnsupportedScriptPathError,
)
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import psbt_views
from seedsigner.views.view import MainMenuView


NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
ACCOUNT_PATH = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0]
DERIVATION_PATH = ACCOUNT_PATH + [0, 0]
NETWORK = SettingsConstants.REGTEST
EMBIT_NETWORK = NETWORKS[SettingsConstants.map_network_to_embit(NETWORK)]

SEED_A = PSBTTestData.seed
SEED_B = PSBTTestData.multisig_key_2
SEED_C = PSBTTestData.multisig_key_3

COIN_VALUE = 100_000_000
SPEND_VALUE = 99_990_000


def _root(seed):
    return bip32.HDKey.from_seed(seed.seed_bytes, version=EMBIT_NETWORK["xprv"])


def _account_key_str(root):
    return f"[{root.my_fingerprint.hex()}/86h/1h/0h]{root.derive(ACCOUNT_PATH).to_public().to_base58()}/0/0"


def _vault_descriptor() -> Descriptor:
    """Two spending paths: A and B together now; A and C together after block 900000."""
    a, b, c = (_account_key_str(_root(s)) for s in (SEED_A, SEED_B, SEED_C))
    return Descriptor.from_string(
        f"tr({NUMS_HEX},{{multi_a(2,{a},{b}),and_v(v:multi_a(2,{a},{c}),after(900000))}})"
    )


def _leaves(descriptor: Descriptor):
    """[(raw_script_bytes, leaf_version, leaf_hash, control_block)], merkle_root, script_pubkey"""
    derived = descriptor.derive(0, branch_index=0)
    leaves_with_paths, merkle_root = _tweak_helper(derived.taptree)
    out = []
    for leaf, path in leaves_with_paths:
        raw = leaf.miniscript.compile()
        leaf_hash = hashes.tagged_hash("TapLeaf", bytes([leaf.version]) + Script(raw).serialize())
        out.append((raw, leaf.version, leaf_hash, taproot_control_block(leaf.version, bytes.fromhex(NUMS_HEX), merkle_root, path)))
    return out, merkle_root, derived.script_pubkey()


def _vault_spend(leaf_index: int = 0, attach_leaf_script: bool = True):
    """
    An honest spend of the vault through one path, as seed A sees it: the coin, the
    path's script with its control block, and A's key claimed on that path.
    """
    descriptor = _vault_descriptor()
    leaves, merkle_root, script_pubkey = _leaves(descriptor)
    raw, version, leaf_hash, control_block = leaves[leaf_index]

    root_a = _root(SEED_A)
    key_a = root_a.derive(DERIVATION_PATH)

    destination = Script(b"\x00\x14" + bytes(20))
    p = PSBT(Transaction(vin=[TransactionInput(bytes(32), 0)], vout=[TransactionOutput(SPEND_VALUE, destination)]))
    inp = p.inputs[0]
    inp.witness_utxo = TransactionOutput(COIN_VALUE, script_pubkey)
    inp.taproot_internal_key = ec.PublicKey.from_xonly(bytes.fromhex(NUMS_HEX))
    inp.taproot_merkle_root = merkle_root
    if attach_leaf_script:
        inp.taproot_scripts[control_block] = raw + bytes([version])
    inp.taproot_bip32_derivations[key_a.to_public()] = ([leaf_hash], DerivationPath(root_a.my_fingerprint, DERIVATION_PATH))
    return p, descriptor, leaves


def _replace_control_block(p: PSBT, new_control_block: bytes):
    inp = p.inputs[0]
    (_, leaf_script), = inp.taproot_scripts.items()
    inp.taproot_scripts.clear()
    inp.taproot_scripts[new_control_block] = leaf_script


def _only_control_block(p: PSBT) -> bytes:
    (control_block, _), = p.inputs[0].taproot_scripts.items()
    return control_block



class TestHonestScriptPathSpend:
    @pytest.mark.parametrize("leaf_index", [0, 1])
    def test_proven_path_is_recorded_described_and_signed(self, leaf_index):
        p, descriptor, leaves = _vault_spend(leaf_index)
        parser = PSBTParser(p, SEED_A, network=NETWORK)

        assert parser.signing_leaf_hashes == {leaves[leaf_index][2]}
        assert parser.signing_key_path is False
        assert parser.spend_amount == SPEND_VALUE
        assert parser.fee_amount == COIN_VALUE - SPEND_VALUE

        summary = parser.get_signing_leaf_summary(registered_descriptor=descriptor)
        assert summary["leaf_index"] == leaf_index + 1
        assert summary["leaf_count"] == 2
        assert (summary["quorum_k"], summary["quorum_n"]) == (2, 2)
        assert summary["timelock_value"] == (900000 if leaf_index == 1 else None)

        assert p.sign_with(parser.root) == 1
        assert len(p.inputs[0].taproot_sigs) == 1
        assert PSBTParser.sig_count(PSBTParser.trim(p)) == 1


    def test_seed_with_no_key_in_the_supplied_path_cannot_sign(self):
        """Seed C is in the vault, but not on the path this psbt spends through."""
        from seedsigner.models.psbt_parser import PSBTSeedCannotSignError
        p, _, _ = _vault_spend(0)
        with pytest.raises(PSBTSeedCannotSignError):
            PSBTParser(p, SEED_C, network=NETWORK)



class TestForgedScriptPath:
    """Every one of these must be refused before a single screen is shown."""

    def test_script_that_is_not_in_the_address(self):
        """
        The attack the proof exists for: a made-up path holding our key ("A alone, no
        waiting"), attached under a real path's control block.
        """
        p, _, _ = _vault_spend(0)
        key_a_xonly = _root(SEED_A).derive(DERIVATION_PATH).to_public().xonly()
        forged_script = b"\x20" + key_a_xonly + b"\xac"  # <A> OP_CHECKSIG

        inp = p.inputs[0]
        control_block = _only_control_block(p)
        inp.taproot_scripts[control_block] = forged_script + bytes([0xC0])

        with pytest.raises(PSBTUnprovenScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_real_path_shown_beside_an_unproven_one(self):
        """An honest leaf does not excuse a second, unproven leaf holding our key."""
        p, _, leaves = _vault_spend(0)
        key_a_xonly = _root(SEED_A).derive(DERIVATION_PATH).to_public().xonly()
        forged_script = b"\x20" + key_a_xonly + b"\xac"
        other_control_block = leaves[1][3]
        p.inputs[0].taproot_scripts[other_control_block] = forged_script + bytes([0xC0])

        with pytest.raises(PSBTUnprovenScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_real_script_from_another_address(self):
        """The right script, but the coin being spent sits at a different address."""
        p, _, _ = _vault_spend(0)
        p.inputs[0].witness_utxo = TransactionOutput(COIN_VALUE, Script(b"\x51\x20" + bytes([7]) * 32))
        with pytest.raises(PSBTUnprovenScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_tampered_merkle_path(self):
        p, _, _ = _vault_spend(0)
        control_block = bytearray(_only_control_block(p))
        assert len(control_block) == 65, "two paths: one sibling in the merkle path"
        control_block[40] ^= 0x01
        _replace_control_block(p, bytes(control_block))
        with pytest.raises(PSBTUnprovenScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_wrong_internal_key(self):
        p, _, _ = _vault_spend(0)
        control_block = _only_control_block(p)
        other_key = _root(SEED_B).derive(DERIVATION_PATH).to_public().xonly()
        _replace_control_block(p, control_block[:1] + other_key + control_block[33:])
        with pytest.raises(PSBTUnprovenScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_wrong_parity_bit(self):
        p, _, _ = _vault_spend(0)
        control_block = _only_control_block(p)
        _replace_control_block(p, bytes([control_block[0] ^ 0x01]) + control_block[1:])
        with pytest.raises(PSBTUnprovenScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_wrong_leaf_version(self):
        p, _, _ = _vault_spend(0)
        control_block = _only_control_block(p)
        _replace_control_block(p, bytes([control_block[0] ^ 0x02]) + control_block[1:])
        with pytest.raises(PSBTUnprovenScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)


    @pytest.mark.parametrize("length", [0, 1, 32, 34, 64, 66])
    def test_malformed_control_block_length(self, length):
        p, _, _ = _vault_spend(0)
        control_block = _only_control_block(p)
        _replace_control_block(p, (control_block + bytes(32))[:length])
        with pytest.raises(PSBTUnprovenScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_path_claimed_but_its_script_left_out(self):
        """Nothing to prove and nothing to sign: refused, at the milder level."""
        p, _, _ = _vault_spend(0, attach_leaf_script=False)
        with pytest.raises(PSBTUnsupportedScriptPathError):
            PSBTParser(p, SEED_A, network=NETWORK)



class TestForgedAmountOnAVaultSpend:
    def _with_previous_transaction(self, p: PSBT, real_value: int):
        """Attach the full transaction that created the coin, worth real_value."""
        script_pubkey = p.inputs[0].witness_utxo.script_pubkey
        previous_tx = Transaction(vin=[TransactionInput(bytes(32), 0)], vout=[TransactionOutput(real_value, script_pubkey)])
        p.inputs[0].txid = previous_tx.txid()
        p.inputs[0].vout = 0
        p.inputs[0].non_witness_utxo = previous_tx


    def test_matching_previous_transaction_is_accepted(self):
        p, _, _ = _vault_spend(0)
        self._with_previous_transaction(p, COIN_VALUE)
        parser = PSBTParser(p, SEED_A, network=NETWORK)
        assert parser.verified_input_amount == COIN_VALUE


    def test_stated_amount_contradicting_the_previous_transaction_is_refused(self):
        """The psbt says the coin is worth less than it is, hiding the rest as fee."""
        p, _, _ = _vault_spend(0)
        self._with_previous_transaction(p, COIN_VALUE * 5)
        with pytest.raises(PSBTInputAmountVerificationError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_previous_transaction_that_did_not_create_the_coin_is_refused(self):
        p, _, _ = _vault_spend(0)
        self._with_previous_transaction(p, COIN_VALUE)
        p.inputs[0].txid = bytes([9]) * 32
        with pytest.raises(PSBTInputAmountVerificationError):
            PSBTParser(p, SEED_A, network=NETWORK)


    def test_outputs_worth_more_than_the_coin_are_refused(self):
        p, _, _ = _vault_spend(0)
        p.inputs[0].witness_utxo = TransactionOutput(SPEND_VALUE - 1, p.inputs[0].witness_utxo.script_pubkey)
        with pytest.raises(PSBTNegativeFeeError):
            PSBTParser(p, SEED_A, network=NETWORK)



class TestScriptPathFlows(FlowTest):
    def _load_psbt_for_signing(self, psbt: PSBT):
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, NETWORK)
        self.controller.psbt = psbt
        self.controller.storage.set_pending_seed(SEED_A)
        self.controller.storage.finalize_pending_seed()


    def test_unproven_path_stops_the_flow_before_any_detail_is_shown(self):
        p, _, _ = _vault_spend(0)
        control_block = _only_control_block(p)
        _replace_control_block(p, bytes([control_block[0] ^ 0x01]) + control_block[1:])
        self._load_psbt_for_signing(p)

        self.run_sequence([
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
            FlowStep(psbt_views.PSBTUnprovenScriptPathView, button_data_selection=psbt_views.PSBTUnprovenScriptPathView.DISCARD),
            FlowStep(MainMenuView),
        ])


    def test_proven_path_reaches_the_overview(self):
        p, _, _ = _vault_spend(0)
        self._load_psbt_for_signing(p)

        self.run_sequence([
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView),
        ])
        assert self.controller.psbt_parser.signing_leaf_hashes
