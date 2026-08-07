import pytest

import base  # hardware-dependency mocking as an import side effect; must precede importing seedsigner.views.*

from unittest.mock import MagicMock, patch

from embit import bip32, ec, hashes
from embit.descriptor import Descriptor
from embit.descriptor.taptree import _tweak_helper
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.controller import Controller
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import psbt_views, seed_views

from psbt_testing_util import PSBTTestData


NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
ACCOUNT_PATH = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0]
DERIVATION_PATH = ACCOUNT_PATH + [0, 0]


def _account_key_str(root):
    fp = root.my_fingerprint.hex()
    account_xpub = root.derive(ACCOUNT_PATH).to_public()
    return f"[{fp}/86h/1h/0h]{account_xpub.to_base58()}/0/0"


def _build_leaf_signing_psbt_and_descriptor(seed_a: Seed, seed_b: Seed, network: str = SettingsConstants.REGTEST):
    """A real 2-of-2 taproot script-path PSBT + its matching descriptor -- enough to make get_signing_leaf_summary return a non-None enriched summary once the descriptor is registered."""
    embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
    root_a = bip32.HDKey.from_seed(seed_a.seed_bytes, version=embit_network["xprv"])
    root_b = bip32.HDKey.from_seed(seed_b.seed_bytes, version=embit_network["xprv"])
    key_a = root_a.derive(DERIVATION_PATH)
    fp_a = root_a.my_fingerprint

    keys = f"{_account_key_str(root_a)},{_account_key_str(root_b)}"
    descriptor = Descriptor.from_string(f"tr({NUMS_HEX},{{multi_a(2,{keys})}})")
    derived = descriptor.derive(0, branch_index=0)
    script_pubkey = derived.script_pubkey()
    leaves_with_paths, merkle_root = _tweak_helper(derived.taptree)
    leaf, path = leaves_with_paths[0]
    raw_script_bytes = leaf.miniscript.compile()
    leaf_hash = hashes.tagged_hash("TapLeaf", bytes([leaf.version]) + Script(raw_script_bytes).serialize())
    control_block = bytes([leaf.version]) + bytes.fromhex(NUMS_HEX) + path

    prevout = TransactionOutput(100_000_000, script_pubkey)
    tx_in = TransactionInput(bytes(32), 0)
    tx_out = TransactionOutput(99_990_000, script_pubkey)
    p = PSBT(Transaction(vin=[tx_in], vout=[tx_out]))
    inp = p.inputs[0]
    inp.witness_utxo = prevout
    inp.taproot_internal_key = ec.PublicKey.from_xonly(bytes.fromhex(NUMS_HEX))
    inp.taproot_merkle_root = merkle_root
    inp.taproot_scripts[control_block] = raw_script_bytes + bytes([leaf.version])
    inp.taproot_bip32_derivations[key_a.to_public()] = ([leaf_hash], DerivationPath(fp_a, DERIVATION_PATH))

    return p, descriptor


class TestMultisigWalletDescriptorViewReturnRouting:
    """
    Round-2 audit finding: MultisigWalletDescriptorView's RETURN branch
    (reached after registering a wallet descriptor mid-PSBT-review) used
    to jump straight to PSBTChangeDetailsView, bypassing the taproot
    key-path/leaf disclosure check PSBTOverviewView.run() makes right
    after its own screen closes. That meant the realistic journey --
    scan a PSBT with no descriptor registered yet, land in change
    verification, register a descriptor from there, return -- permanently
    skipped the enriched (leaf index / quorum / timelock) disclosure even
    though the device now holds exactly the data needed to show it. Fixed
    by routing RETURN through the same PSBTOverviewView._route_after_overview
    check instead of a bare jump.
    """

    seed_a = PSBTTestData.seed
    seed_b = PSBTTestData.multisig_key_2

    def test_return_after_registering_a_descriptor_routes_to_spend_path_disclosure(self):
        psbt, descriptor = _build_leaf_signing_psbt_and_descriptor(self.seed_a, self.seed_b)
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.get_signing_leaf_summary(descriptor) is not None, "sanity: this PSBT really does have a leaf to disclose"

        controller = Controller.get_instance()
        controller.psbt_parser = parser
        controller.multisig_wallet_descriptor = descriptor
        controller.resume_main_flow = Controller.FLOW__PSBT

        view = seed_views.MultisigWalletDescriptorView()
        view.screen = MagicMock()
        with patch.object(view, "run_screen", return_value=0):  # selects the single available button: RETURN
            destination = view.run()

        assert destination.View_cls == psbt_views.PSBTSpendPathView, "must show the enriched leaf disclosure, not jump straight past it to change verification"

    def test_return_with_nothing_to_disclose_still_reaches_change_details_eventually(self):
        """A completely ordinary legacy multisig PSBT (nothing taproot
        about it) has no key-path/leaf disclosure to show -- RETURN must
        still end up on the same math/change flow as before, just via
        the shared routing method instead of a bare jump."""
        from binascii import a2b_base64
        from embit.psbt import PSBT as EmbitPSBT

        raw = a2b_base64(PSBTTestData.MULTISIG_NATIVE_SEGWIT_1_INPUT)
        psbt = EmbitPSBT.parse(raw)
        parser = PSBTParser(psbt, PSBTTestData.seed, network=SettingsConstants.REGTEST)
        assert parser.get_signing_leaf_summary() is None

        # An ordinary registered legacy multisig descriptor -- unrelated
        # to this PSBT, but MultisigWalletDescriptorView.run() always
        # assumes a descriptor was just registered (that's the only way
        # to reach it), so this can't be None.
        legacy_descriptor = Descriptor.from_string(
            "wsh(sortedmulti(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,"
            "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,"
            "[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))#zw6cnrlk"
        )

        controller = Controller.get_instance()
        controller.psbt_parser = parser
        controller.multisig_wallet_descriptor = legacy_descriptor
        controller.resume_main_flow = Controller.FLOW__PSBT

        view = seed_views.MultisigWalletDescriptorView()
        view.screen = MagicMock()
        with patch.object(view, "run_screen", return_value=0):
            destination = view.run()

        assert destination.View_cls != psbt_views.PSBTSpendPathView
        assert destination.View_cls != psbt_views.PSBTKeyPathSpendView
