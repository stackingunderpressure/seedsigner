import pytest

from embit import bip32, ec, hashes
from embit.descriptor import Descriptor
from embit.descriptor.taptree import _tweak_helper
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants

from psbt_testing_util import PSBTTestData


# Same NUMS point DynastyTrust's own compiler uses as its unspendable
# internal key for every tr_multileaf policy (see test_taproot_scriptpath.py).
NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
DERIVATION_PATH = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0, 0, 0]


def _serialize_tap_tree(entries) -> bytes:
    """BIP371 PSBT_OUT_TAP_TREE raw value: (depth, leaf_version, script) tuples."""
    buf = b""
    for depth, version, sc in entries:
        buf += bytes([depth, version]) + sc.serialize()
    return buf


def _build_psbt_with_multileaf_change(seed_a: Seed, seed_b: Seed, network: str = SettingsConstants.REGTEST):
    """
    Builds a real PSBT with one plain single-key p2tr input (unrelated
    scaffolding, just enough to set self.policy = {"type": "p2tr"}) and
    one output paying to a real `tr(NUMS,{pk(A),pk(B)})` address -- the
    same 2-leaf shape as a DynastyTrust distribution-wallet tranche --
    with the output carrying the exact BIP371 metadata the Rust fix
    (attach_tap_change_output_metadata) now attaches to real change:
    tap_internal_key, PSBT_OUT_TAP_TREE (key 0x06, raw, since embit's
    OutputScope doesn't parse it), and taproot_bip32_derivations for
    both signer keys.

    Returns (psbt, root_a, root_b, tap_tree_entries, real_merkle_root,
    real_output_script) so tests can both use the well-formed PSBT and
    tamper with specific pieces of it.
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
    change_script_pubkey = descriptor.script_pubkey()

    leaves_with_paths, merkle_root = _tweak_helper(descriptor.taptree)
    tap_tree_entries = []  # (depth, version, Script)
    leaf_hashes = {}       # xonly pubkey hex -> leaf hash, for convenience below
    for leaf, path in leaves_with_paths:
        depth = len(path) // 32
        leaf_script = Script(leaf.miniscript.compile())
        tap_tree_entries.append((depth, leaf.version, leaf_script))
        lh = hashes.tagged_hash("TapLeaf", leaf.serialize())
        for k in leaf.keys:
            leaf_hashes[k.key.xonly().hex()] = lh

    # Unrelated scaffolding input: a plain single-key p2tr, just enough
    # to give the parser a self.policy of {"type": "p2tr"} to compare
    # the output's policy against (see PSBTParser._get_policy -- for
    # p2tr this is always just {"type": "p2tr"}, no further detail).
    from embit import script as script_module
    scaffold_root = bip32.HDKey.from_seed(seed_a.seed_bytes, version=embit_network["xprv"])
    scaffold_key = scaffold_root.derive([0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0, 0, 0])
    scaffold_script = script_module.p2tr(scaffold_key.to_public())

    tx_in = TransactionInput(bytes(32), 0)
    tx_out = TransactionOutput(99_990_000, change_script_pubkey)
    tx = Transaction(vin=[tx_in], vout=[tx_out])
    p = PSBT(tx)

    inp = p.inputs[0]
    inp.witness_utxo = TransactionOutput(100_000_000, scaffold_script)

    out = p.outputs[0]
    out.taproot_internal_key = ec.PublicKey.from_xonly(bytes.fromhex(NUMS_HEX))
    # Reassign (not mutate-in-place): embit 0.8.0's OutputScope.__init__
    # has a mutable-default-argument bug (unknown: dict = {}) -- every
    # OutputScope built without an explicit `unknown=` kwarg shares the
    # SAME dict object process-wide, so mutating it in place here would
    # leak b"\x06" into every later PSBT's outputs too and make their
    # own construction blow up with "Duplicated key". Assigning a fresh
    # dict sidesteps that entirely.
    out.unknown = {b"\x06": _serialize_tap_tree(tap_tree_entries)}
    out.taproot_bip32_derivations[key_a.to_public()] = (
        [leaf_hashes[key_a.to_public().xonly().hex()]],
        DerivationPath(fp_a, DERIVATION_PATH),
    )
    out.taproot_bip32_derivations[key_b.to_public()] = (
        [leaf_hashes[key_b.to_public().xonly().hex()]],
        DerivationPath(fp_b, DERIVATION_PATH),
    )

    return p, root_a, root_b, tap_tree_entries, merkle_root, change_script_pubkey.data


class TestTaprootChangeOutputRecognition:
    """
    2026-08-06: DynastyTrust's change output previously carried no
    taproot metadata at all (fixed separately, Rust side:
    attach_tap_change_output_metadata). Even with that metadata present,
    PSBTParser's own _parse_outputs only ever tried a single-key p2tr
    reconstruction for change-matching -- it had no way to verify a
    multi-leaf tree, so real change was indistinguishable from an
    external destination on the confirm screen.

    _parse_tap_tree / _tap_tree_merkle_root / _tap_tweak_xonly close that
    gap using only embit's already-public primitives (tagged_hash,
    secp256k1 bindings, compact-size parsing) -- no change to embit
    itself. These tests prove both that real change is now recognized,
    and -- just as important -- that a forged or unrelated claim is NOT
    trusted into a false positive.
    """

    seed_a = PSBTTestData.seed
    seed_b = PSBTTestData.multisig_key_2
    seed_unrelated = PSBTTestData.multisig_key_3

    def test_our_own_tap_tree_merkle_root_matches_embits_reference_implementation(self):
        """Sanity check on the reconstruction algorithm itself, independent
        of PSBTParser: our from-scratch merkle root (built from the raw
        depth/leaf_version/script triples, as a real signer would receive
        them over the wire) must equal embit's own descriptor-driven
        _tweak_helper root for the exact same tree."""
        _, _, _, tap_tree_entries, real_merkle_root, _ = _build_psbt_with_multileaf_change(
            self.seed_a, self.seed_b
        )
        our_root, our_leaf_hashes = PSBTParser._tap_tree_merkle_root(tap_tree_entries)
        assert our_root == real_merkle_root
        assert len(our_leaf_hashes) == 2

    def test_change_is_recognized_for_signer_a(self):
        psbt, root_a, root_b, *_ = _build_psbt_with_multileaf_change(self.seed_a, self.seed_b)
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.num_change_outputs == 1, "real multi-leaf change must be recognized, not shown as a destination"
        assert parser.num_destinations == 0

    def test_change_is_recognized_for_signer_b(self):
        psbt, root_a, root_b, *_ = _build_psbt_with_multileaf_change(self.seed_a, self.seed_b)
        parser = PSBTParser(psbt, self.seed_b, network=SettingsConstants.REGTEST)
        assert parser.num_change_outputs == 1
        assert parser.num_destinations == 0

    def test_unrelated_seed_does_not_falsely_recognize_change(self):
        """A seed with no key in the tree at all must NOT be told this is
        its own change -- the honest fallback (show as destination) stays
        in place when we genuinely aren't a signer here."""
        psbt, *_ = _build_psbt_with_multileaf_change(self.seed_a, self.seed_b)
        parser = PSBTParser(psbt, self.seed_unrelated, network=SettingsConstants.REGTEST)
        assert parser.num_change_outputs == 0
        assert parser.num_destinations == 1

    def test_forged_tap_tree_is_not_trusted_into_a_false_positive(self):
        """Security regression guard: if the declared tap_tree does NOT
        actually tweak to the real output scriptPubkey (a coordinator
        lying about the tree, or simple corruption), the output must NOT
        be accepted as change even though a real signer key is claimed on
        it. This is the exact failure mode a shortcut fix (trusting the
        claimed derivation path without verifying the real script) would
        have been vulnerable to."""
        psbt, root_a, root_b, tap_tree_entries, _, _ = _build_psbt_with_multileaf_change(
            self.seed_a, self.seed_b
        )
        # Corrupt the declared tree: swap in a different (but
        # well-formed) single-leaf tree so parsing succeeds but the
        # tweak no longer matches the real output script.
        forged_leaf = tap_tree_entries[0][2]
        forged_entries = [(0, tap_tree_entries[0][1], forged_leaf)]
        psbt.outputs[0].unknown = {b"\x06": _serialize_tap_tree(forged_entries)}

        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.num_change_outputs == 0, "a tree that doesn't match the real output must never be accepted as change"
        assert parser.num_destinations == 1

    def test_malformed_tap_tree_bytes_fail_closed_without_crashing(self):
        """Truncated/garbage PSBT_OUT_TAP_TREE bytes must degrade to the
        existing fallback (not recognized as change), not raise and abort
        the whole PSBT parse."""
        psbt, root_a, root_b, *_ = _build_psbt_with_multileaf_change(self.seed_a, self.seed_b)
        psbt.outputs[0].unknown = {b"\x06": b"\x01"}  # truncated: depth byte with nothing after it

        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.num_change_outputs == 0
        assert parser.num_destinations == 1

    def test_claimed_pubkey_not_actually_ours_is_not_trusted(self):
        """Security regression guard: if taproot_bip32_derivations claims
        a pubkey that does NOT actually derive from our own seed at the
        stated path (a coordinator asserting a key belongs to us that
        doesn't), that claim must be rejected rather than trusted at face
        value -- even though the tree itself is genuine."""
        psbt, root_a, root_b, tap_tree_entries, _, _ = _build_psbt_with_multileaf_change(
            self.seed_a, self.seed_b
        )
        # Replace signer A's claimed derivation path with one that does
        # NOT actually produce key_a's pubkey from seed_a.
        wrong_path = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0, 0, 99]
        pub, (leaves, derivation_path) = list(psbt.outputs[0].taproot_bip32_derivations.items())[0]
        psbt.outputs[0].taproot_bip32_derivations[pub] = (
            leaves,
            DerivationPath(derivation_path.fingerprint, wrong_path),
        )

        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.num_change_outputs == 0, "a claimed key that doesn't actually derive from our seed must not be trusted"
        assert parser.num_destinations == 1



def _matching_registered_descriptor(root_a, root_b) -> Descriptor:
    """Rebuilds a tr(NUMS,{pk(A),pk(B)}) descriptor that resolves to the
    exact same output _build_psbt_with_multileaf_change() compiled the
    change output against -- what a user would actually scan/register on
    the device ahead of time. Unlike the helper's own internal descriptor
    (which uses bare derived pubkeys, fine for compiling a PSBT's tap tree
    metadata but not what a real registration QR contains), this uses
    xpub-based keys with a fixed (non-wildcard) /0/0 suffix -- the same
    shape DynastyTrust's own compiler emits ([fp/path]xpub/0/0, see its
    "Address type" doctrine). embit's Descriptor.owns() only matches
    extended (xpub) keys via check_derivation() -- a bare pubkey key has
    is_extended == False and gets silently skipped, so this distinction
    isn't cosmetic, it's the difference between owns() being able to
    verify this output at all or not."""
    def account_key_str(root):
        fp = root.my_fingerprint.hex()
        account_xpub = root.derive([0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0]).to_public()
        xpub_str = account_xpub.to_base58(version=NETWORKS[SettingsConstants.map_network_to_embit(SettingsConstants.REGTEST)]["xpub"])
        return f"[{fp}/86h/1h/0h]{xpub_str}/0/0"

    desc_str = f"tr({NUMS_HEX},{{pk({account_key_str(root_a)}),pk({account_key_str(root_b)})}})"
    return Descriptor.from_string(desc_str)


class TestVerifyMultisigOutputAgainstRegisteredTaprootDescriptor:
    """
    A registered wallet descriptor is the stronger of the two checks this
    fork does for a taproot multi-leaf output: _parse_outputs (tested
    above) only proves the PSBT is internally consistent with itself.
    verify_multisig_output() proves the output matches a policy the user
    imported and confirmed OUT OF BAND, before this specific PSBT ever
    existed -- the actual anti-blind-signing control other taproot-
    miniscript-capable wallets (Coldcard/Specter/Ledger, via Liana) rely
    on registered descriptors for. PSBTParser.verify_multisig_output()
    just delegates to embit's own Descriptor.owns(), which already reads
    taproot_bip32_derivations -- this proves that delegation actually
    works end to end for a real multi-leaf tree, rather than assuming it
    does because the code looks right.
    """

    seed_a = PSBTTestData.seed
    seed_b = PSBTTestData.multisig_key_2
    seed_unrelated = PSBTTestData.multisig_key_3

    def test_real_change_is_verified_against_the_registered_descriptor(self):
        psbt, root_a, root_b, *_ = _build_psbt_with_multileaf_change(self.seed_a, self.seed_b)
        descriptor = _matching_registered_descriptor(root_a, root_b)

        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.verify_multisig_output(descriptor, change_num=0) is True

    def test_verification_also_passes_for_the_other_signer(self):
        psbt, root_a, root_b, *_ = _build_psbt_with_multileaf_change(self.seed_a, self.seed_b)
        descriptor = _matching_registered_descriptor(root_a, root_b)

        parser = PSBTParser(psbt, self.seed_b, network=SettingsConstants.REGTEST)
        assert parser.verify_multisig_output(descriptor, change_num=0) is True

    def test_a_different_registered_wallet_does_not_falsely_verify(self):
        """Security regression guard: the whole point of registering a
        descriptor ahead of time is to catch a PSBT that doesn't actually
        belong to the wallet you think it does. A genuine multi-leaf
        change output must NOT verify against a DIFFERENT wallet's
        descriptor just because both are well-formed tr_multileaf
        policies."""
        psbt, root_a, root_b, *_ = _build_psbt_with_multileaf_change(self.seed_a, self.seed_b)
        seed_other = PSBTTestData.multisig_key_3
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(SettingsConstants.REGTEST)]
        root_other = bip32.HDKey.from_seed(seed_other.seed_bytes, version=embit_network["xprv"])
        # A different, otherwise well-formed 2-leaf wallet -- swaps in an
        # unrelated third key in place of signer B.
        wrong_descriptor = _matching_registered_descriptor(root_a, root_other)

        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.verify_multisig_output(wrong_descriptor, change_num=0) is False



class TestTaprootScriptPathChangeFlagsForRegisteredDescriptorVerification:
    """
    2026-08-07: found while wiring up the confirm-screen UX for registered
    taproot descriptors. PSBTChangeDetailsView decides how to verify a
    change output using ONLY psbt_parser.is_multisig, which checks for an
    OP_CHECKMULTISIG-style script -- never true for taproot. Without a
    second signal, a genuine tr_multileaf change output (recognized as
    real change by _parse_outputs's tap-tree verification, tested above)
    fell into the "single sig" verification branch, which can only ever
    derive ONE key and test it against a bare p2tr(key) script. That can
    never match a multi-leaf output's real internal-key+tap-tree tweaked
    script, so the view would show "verification failed" for change that
    was already proven genuine moments earlier -- exactly the kind of
    false alarm that trains a user to stop trusting real warnings.

    change_data["is_taproot_script_path"] is the fix: True whenever the
    output's claimed signer key carries a non-empty taproot leaf-hash list
    (BIP371 PSBT_OUT_TAP_BIP32_DERIVATION's leaf-hash array), which only
    happens for a key tied to a specific tapscript leaf, never for a plain
    key-path-only taproot output. These tests prove the flag is set
    correctly for both shapes, since getting this backwards in either
    direction is its own real failure mode (False for a real multi-leaf
    output reintroduces the false-alarm bug; True for an ordinary
    single-key output would wrongly route it through multisig-style
    verification and demand a registered descriptor for a wallet that
    never needed one).
    """

    seed_a = PSBTTestData.seed
    seed_b = PSBTTestData.multisig_key_2

    def test_multileaf_change_is_flagged_as_taproot_script_path(self):
        psbt, *_ = _build_psbt_with_multileaf_change(self.seed_a, self.seed_b)
        parser = PSBTParser(psbt, self.seed_a, network=SettingsConstants.REGTEST)
        change_data = parser.get_change_data(0)
        assert change_data["is_taproot_script_path"] is True

        # The exact bug this closes: the old single-signal check would
        # have sent this output down the wrong verification branch.
        assert parser.is_multisig is False, "is_multisig itself correctly stays False for taproot -- that's not the bug, using it ALONE was"

    def test_single_key_taproot_change_is_not_flagged_as_script_path(self):
        """A plain key-path-only taproot change output (no tap tree at
        all) must NOT be flagged -- it's correctly handled by the existing
        single-sig verification branch, and mis-flagging it would demand a
        registered descriptor for a wallet that was never multi-key."""
        embit_network = NETWORKS[SettingsConstants.map_network_to_embit(SettingsConstants.REGTEST)]
        root_a = bip32.HDKey.from_seed(self.seed_a.seed_bytes, version=embit_network["xprv"])
        derivation_path = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0, 1, 0]  # change branch
        key_a = root_a.derive(derivation_path)
        fp_a = root_a.my_fingerprint

        from embit import script as script_module
        change_script = script_module.p2tr(key_a.to_public())

        scaffold_key = root_a.derive([0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0, 0, 0])
        scaffold_script = script_module.p2tr(scaffold_key.to_public())

        tx_in = TransactionInput(bytes(32), 0)
        tx_out = TransactionOutput(99_990_000, change_script)
        tx = Transaction(vin=[tx_in], vout=[tx_out])
        p = PSBT(tx)
        p.inputs[0].witness_utxo = TransactionOutput(100_000_000, scaffold_script)
        # Key-path-only: leaf-hash list is empty (no tap tree, no leaf).
        p.outputs[0].taproot_bip32_derivations[key_a.to_public()] = (
            [],
            DerivationPath(fp_a, derivation_path),
        )

        parser = PSBTParser(p, self.seed_a, network=SettingsConstants.REGTEST)
        assert parser.num_change_outputs == 1
        change_data = parser.get_change_data(0)
        assert change_data["is_taproot_script_path"] is False
