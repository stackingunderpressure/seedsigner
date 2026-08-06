import pytest

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

from psbt_testing_util import PSBTTestData


# Well-known NUMS point (BIP341 "point with unknown discrete log"), same
# constant DynastyTrust's own compiler uses as its unspendable internal key
# for every tr_multileaf policy.
NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
DERIVATION_PATH = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0, 0, 0]


def _build_two_leaf_taproot_psbt(seed_a: Seed, seed_b: Seed, network: str = SettingsConstants.REGTEST):
    """
    Builds a real 2-leaf Taproot PSBT -- `tr(NUMS,{pk(A),pk(B)})` -- the same
    shape as a DynastyTrust distribution-wallet tranche (a beneficiary leaf
    and a trustee leaf), with a NUMS internal key so there is no key-path
    spend, only two independent script-path leaves. Every BIP371 field is
    populated as a real coordinator would: tap_internal_key, the control
    block for each leaf (tap_scripts), and tap_key_origins for each leaf's
    key. Used to prove embit's sign_with() actually produces valid
    script-path signatures end to end, independent of any hand-crafted
    base64 fixture.
    """
    embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
    root_a = bip32.HDKey.from_seed(seed_a.seed_bytes, version=embit_network["xprv"])
    root_b = bip32.HDKey.from_seed(seed_b.seed_bytes, version=embit_network["xprv"])
    key_a = root_a.derive(DERIVATION_PATH)
    key_b = root_b.derive(DERIVATION_PATH)
    fp_a = root_a.my_fingerprint
    fp_b = root_b.my_fingerprint

    desc_str = (
        f"tr({NUMS_HEX},{{"
        f"pk([{fp_a.hex()}/86h/1h/0h/0/0]{key_a.to_public().xonly().hex()}),"
        f"pk([{fp_b.hex()}/86h/1h/0h/0/0]{key_b.to_public().xonly().hex()})"
        f"}})"
    )
    descriptor = Descriptor.from_string(desc_str)
    script_pubkey = descriptor.script_pubkey()

    leaves_with_paths, merkle_root = _tweak_helper(descriptor.taptree)
    internal_xonly = bytes.fromhex(NUMS_HEX)

    # Confirm our from-scratch tweak matches embit's own descriptor-derived
    # scriptPubkey before trusting any of the control blocks built from it.
    tweak = hashes.tagged_hash("TapTweak", internal_xonly + merkle_root)
    point = secp256k1.ec_pubkey_parse(b"\x02" + internal_xonly)
    secp256k1.ec_pubkey_tweak_add(point, bytes(tweak))
    output_xonly = ec.PublicKey(point).xonly()
    _, parity = secp256k1.xonly_pubkey_from_pubkey(point)
    assert script_pubkey.data[2:] == output_xonly

    control_blocks = []
    for leaf, path in leaves_with_paths:
        leaf_ser = leaf.serialize()
        version, script_bytes = leaf_ser[0], leaf_ser[1:]
        control_block = bytes([version | (1 if parity else 0)]) + internal_xonly + path
        leaf_hash = hashes.tagged_hash("TapLeaf", leaf_ser)
        control_blocks.append((control_block, script_bytes, version, leaf_hash))

    prevout = TransactionOutput(100_000_000, script_pubkey)
    tx_in = TransactionInput(bytes(32), 0)
    tx_out = TransactionOutput(99_990_000, script_pubkey)
    tx = Transaction(vin=[tx_in], vout=[tx_out])
    p = PSBT(tx)
    inp = p.inputs[0]
    inp.witness_utxo = prevout
    inp.taproot_internal_key = ec.PublicKey.from_xonly(internal_xonly)
    inp.taproot_merkle_root = merkle_root
    for control_block, script_bytes, version, leaf_hash in control_blocks:
        inp.taproot_scripts[control_block] = script_bytes + bytes([version])

    leaf_hash_a, leaf_hash_b = control_blocks[0][3], control_blocks[1][3]
    inp.taproot_bip32_derivations[key_a.to_public()] = ([leaf_hash_a], DerivationPath(fp_a, DERIVATION_PATH))
    inp.taproot_bip32_derivations[key_b.to_public()] = ([leaf_hash_b], DerivationPath(fp_b, DERIVATION_PATH))

    return p, root_a, root_b


class TestTaprootScriptPathSigning:
    """
    2026-08-06: embit (this repo's pinned 0.8.0) already implements real
    BIP340/341 script-path signing via sign_with() -> sign_input_with_tapkey().
    PSBTParser itself had two bugs blocking that capability from ever being
    usable: sig_count() and trim() only ever looked at final_scriptwitness
    (Taproot key-path) and partial_sigs (legacy/segwit), never at
    taproot_sigs (Taproot script-path) -- so a real signature would silently
    be miscounted as "signing failed" and dropped on export. A third,
    separate guard in get_input_fingerprints() hard-raised on any
    leaf-derived key on the stale assumption that embit had no script-path
    support at all; it's dead code today (nothing calls it), but left
    uncorrected it would mislead the next person who wires it up.
    """

    seed_beneficiary = PSBTTestData.seed
    seed_trustee = PSBTTestData.multisig_key_2

    def test_has_matching_input_fingerprint_for_a_leaf_derived_key(self):
        p, _, _ = _build_two_leaf_taproot_psbt(self.seed_beneficiary, self.seed_trustee)
        assert PSBTParser.has_matching_input_fingerprint(p, self.seed_beneficiary, SettingsConstants.REGTEST)
        assert PSBTParser.has_matching_input_fingerprint(p, self.seed_trustee, SettingsConstants.REGTEST)
        wrong_seed = Seed(["bacon"] * 24)
        assert not PSBTParser.has_matching_input_fingerprint(p, wrong_seed, SettingsConstants.REGTEST)

    def test_get_input_fingerprints_no_longer_raises_for_leaf_derivations(self):
        p, root_a, root_b = _build_two_leaf_taproot_psbt(self.seed_beneficiary, self.seed_trustee)
        fingerprints = PSBTParser.get_input_fingerprints(p)
        assert set(fingerprints) == {root_a.my_fingerprint.hex(), root_b.my_fingerprint.hex()}

    def test_sign_with_produces_a_valid_schnorr_signature_per_leaf(self):
        """The actual crypto: prove sign_with() produces a real, independently
        verifiable BIP340 signature over the correct BIP341 tapscript sighash
        for each leaf -- not just that no exception is raised."""
        p, root_a, root_b = _build_two_leaf_taproot_psbt(self.seed_beneficiary, self.seed_trustee)
        inp = p.inputs[0]

        assert p.sign_with(root_a) == 1
        assert p.sign_with(root_b) == 1
        assert len(inp.taproot_sigs) == 2

        for (pub, leaf), sigdata in inp.taproot_sigs.items():
            sig = ec.Signature(sigdata[:64])
            for ctrl, sc in inp.taproot_scripts.items():
                leaf_version, script = sc[-1], Script(sc[:-1])
                if hashes.tagged_hash("TapLeaf", bytes([leaf_version]) + script.serialize()) != leaf:
                    continue
                sighash = p.sighash(0, sighash=0, ext_flag=1, script=script, leaf_version=leaf_version)
                assert pub.schnorr_verify(sig, sighash), "signature must verify against the real tapscript sighash"

    def test_sig_count_and_trim_reflect_script_path_signatures(self):
        """This is the actual bug: before the fix, sig_count()/trim() never
        looked at taproot_sigs, so PSBTParser reported real signing as a
        no-op and the exported (trimmed) PSBT silently lost the signature."""
        p, root_a, root_b = _build_two_leaf_taproot_psbt(self.seed_beneficiary, self.seed_trustee)

        assert PSBTParser.sig_count(p) == 0
        p.sign_with(root_a)
        assert PSBTParser.sig_count(p) == 1, "one leaf signed -- must be counted, not silently dropped"
        p.sign_with(root_b)
        assert PSBTParser.sig_count(p) == 2, "both leaves signed"

        trimmed = PSBTParser.trim(p)
        assert PSBTParser.sig_count(trimmed) == 2, "trim() must preserve taproot_sigs, not discard them"
        assert len(trimmed.inputs[0].taproot_sigs) == 2
        # And it should be genuinely smaller than the untrimmed PSBT, since
        # that's the entire point of trimming before a QR-size-limited export.
        assert len(trimmed.serialize()) < len(p.serialize())
