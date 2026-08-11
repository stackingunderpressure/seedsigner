"""
Operator, 2026-08-11: "Make sure that we modified the seed signer patch
to be able to scan in the PSBT of the same type, the tap[script] route/
tap leaf" -- verifying the device correctly handles DynastyTrust's real,
CURRENT tapscript leaf shapes, not just the ones the earlier taproot
test files happened to fix bugs against.

Grounding against protocol/src/policy_compiler.rs's build_multileaf
(DynastyTrust repo, 2026-08-10's "Rebuild fallback leaf as owner-only,
no timelock" cut) turned up a real gap in test COVERAGE (the underlying
_parse_leaf_quorum code was already correct on inspection, but nothing
exercised it): a standard vault's real tree today is three leaves --
founders (multi_a, no timelock), backup (multi_a, NO timelock, a
SEPARATE key set from founders), inheritance (and_v(v:after(N),
multi_a(...)) with heir keys). Every existing taproot fixture in this
test suite covers either a TIMELOCKED middle leaf (the older "recovery"
shape, reusing founder keys) or a single bare pk() leaf (k=n=1) -- none
of them exercise a bare, UNWRAPPED multi_a(...) with k>1 or n>1 and no
timelock at all, which is exactly what a real "2-of-3 backup keys"
vault produces. This file closes that gap with the actual current
3-leaf shape, its own distinct key set per leaf, and a real,
independently verified Schnorr signature over the backup leaf.
"""

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


# Same NUMS point DynastyTrust's compiler uses (protocol/src/
# policy_compiler.rs's NUMS_HEX) as the unspendable internal key for
# every tr_multileaf policy -- no key-path spend is ever possible.
NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
ACCOUNT_PATH = [0x80000000 + 86, 0x80000000 + 1, 0x80000000 + 0]  # m/86'/1'/0'
DERIVATION_PATH = ACCOUNT_PATH + [0, 0]


def _key_str(root):
    """`[fp/86h/1h/0h]tpub.../0/0` -- the real DynastyTrust key-origin
    shape (an account-level xpub with a `/0/0` suffix in the descriptor
    text), same convention test_taproot_leaf_summary.py's
    _account_key_str uses and for the same reason: a bare pre-derived
    xonly key would hide the derivation-mismatch bug class that shape
    guards against."""
    fp = root.my_fingerprint
    account_xpub = root.derive(ACCOUNT_PATH).to_public()
    return f"[{fp.hex()}/86h/1h/0h]{account_xpub.to_base58()}/0/0"


def _build_founders_backup_inheritance_psbt(
    founder_seeds, backup_seeds, heir_seeds, signing_leaf: str,
    network: str = SettingsConstants.REGTEST, after_height: int = 500,
):
    """
    Builds a real 3-leaf taproot PSBT matching build_multileaf's actual
    current standard-vault tree (no protector):
        tr(NUMS, {founders, {backup, inheritance}})
    where founders = multi_a(2, F1, F2), backup = multi_a(2, B1, B2)
    with NO timelock wrapper and a key set disjoint from founders'
    (exactly what "Rebuild fallback leaf as owner-only, no timelock"
    produces), and inheritance = and_v(v:after(N), multi_a(2, H1, H2))
    with a third, disjoint key set.

    `signing_leaf` selects which leaf's control block + tap_key_origin
    get attached to the PSBT's single input, exactly as a real
    coordinator only attaches the one leaf actually being spent through
    -- one of "founders", "backup", "inheritance".

    Returns (psbt, descriptor, signing_roots) -- signing_roots is the
    list of HDKey roots whose keys are eligible to sign the selected
    leaf, so the caller can call psbt.sign_with(root) for each.
    """
    embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]

    def roots(seeds):
        return [bip32.HDKey.from_seed(s.seed_bytes, version=embit_network["xprv"]) for s in seeds]

    founder_roots = roots(founder_seeds)
    backup_roots = roots(backup_seeds)
    heir_roots = roots(heir_seeds)

    founder_keys = ",".join(_key_str(r) for r in founder_roots)
    backup_keys = ",".join(_key_str(r) for r in backup_roots)
    heir_keys = ",".join(_key_str(r) for r in heir_roots)

    desc_str = (
        f"tr({NUMS_HEX},{{multi_a(2,{founder_keys}),"
        f"{{multi_a(2,{backup_keys}),and_v(v:after({after_height}),multi_a(2,{heir_keys}))}}}})"
    )
    descriptor = Descriptor.from_string(desc_str)
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

    def leaf_is(cb_entry, wants_timelock: bool):
        ms_str = str(cb_entry[4].miniscript)
        has_timelock = "after" in ms_str or "older" in ms_str
        return has_timelock == wants_timelock

    if signing_leaf == "founders":
        # Founders and backup are both bare (no timelock) multi_a leaves
        # of the same k/n shape -- disambiguate by which root set derives
        # keys actually present in the leaf's script.
        signing_roots = founder_roots
    elif signing_leaf == "backup":
        signing_roots = backup_roots
    elif signing_leaf == "inheritance":
        signing_roots = heir_roots
    else:
        raise ValueError(signing_leaf)

    signing_xonlys = {r.derive(DERIVATION_PATH).to_public().xonly() for r in signing_roots}
    cb, raw_script_bytes, v, leaf_hash, leaf = next(
        c for c in control_blocks
        if any(xonly.hex() in c[4].miniscript.compile().hex() for xonly in signing_xonlys)
    )

    inp.taproot_scripts[cb] = raw_script_bytes + bytes([v])
    for r in signing_roots:
        key = r.derive(DERIVATION_PATH)
        inp.taproot_bip32_derivations[key.to_public()] = (
            [leaf_hash], DerivationPath(r.my_fingerprint, DERIVATION_PATH),
        )

    return p, descriptor, signing_roots


class TestDynastyTrustBackupLeaf:
    """The untimelocked, separate-key-set backup leaf -- the shape
    2026-08-10's "Rebuild fallback leaf as owner-only, no timelock" cut
    produces and that no prior fixture in this suite exercised."""

    founder_seeds = [PSBTTestData.seed, PSBTTestData.multisig_key_2]
    backup_seeds = [PSBTTestData.multisig_key_3, PSBTTestData.recipient_seed]
    heir_seeds = [PSBTTestData.recipient_multisig_key_2, PSBTTestData.recipient_multisig_key_3]

    def test_backup_leaf_quorum_parses_as_untimelocked(self):
        """The real gap this file closes: _parse_leaf_quorum's bare-
        multi_a branch (no and_v wrapper at all) was correct on
        inspection but had no direct test with k>1/n>1. DynastyTrust's
        backup leaf is exactly that shape."""
        p, descriptor, _ = _build_founders_backup_inheritance_psbt(
            self.founder_seeds, self.backup_seeds, self.heir_seeds, signing_leaf="backup",
        )
        parser = PSBTParser(p, self.backup_seeds[0], network=SettingsConstants.REGTEST)
        summary = parser.get_signing_leaf_summary(registered_descriptor=descriptor)
        assert summary is not None
        assert summary["quorum_k"] == 2
        assert summary["quorum_n"] == 2
        assert summary["timelock_kind"] is None, "backup must report no timelock, matching 'anytime, harder'"
        assert summary["timelock_value"] is None
        # num_eligible_keys counts how many keys THIS PARSER's own seed
        # controls on the leaf, not the leaf's total signer count (which
        # quorum_n already reports) -- backup_seeds[0]'s seed controls
        # exactly one of the two backup keys, matching the original
        # fixture's same single-signer-per-parser convention.
        assert summary["num_eligible_keys"] == 1

    def test_inheritance_leaf_quorum_still_reports_its_timelock(self):
        """Sanity check the same fixture's inheritance leg still reports
        correctly -- confirms the 3-leaf tree itself, not just the
        backup leg in isolation, is built right."""
        p, descriptor, _ = _build_founders_backup_inheritance_psbt(
            self.founder_seeds, self.backup_seeds, self.heir_seeds, signing_leaf="inheritance", after_height=52_560,
        )
        parser = PSBTParser(p, self.heir_seeds[0], network=SettingsConstants.REGTEST)
        summary = parser.get_signing_leaf_summary(registered_descriptor=descriptor)
        assert summary is not None
        assert summary["quorum_k"] == 2
        assert summary["quorum_n"] == 2
        assert summary["timelock_kind"] == "after_height"
        assert summary["timelock_value"] == 52_560

    def test_backup_leaf_signs_with_a_real_verifiable_schnorr_signature(self):
        """The actual crypto, not just AST parsing: sign the backup leaf
        with both of its (separate-from-founders) keys and independently
        verify each signature against the real BIP341 tapscript sighash."""
        p, descriptor, signing_roots = _build_founders_backup_inheritance_psbt(
            self.founder_seeds, self.backup_seeds, self.heir_seeds, signing_leaf="backup",
        )
        inp = p.inputs[0]

        for root in signing_roots:
            assert p.sign_with(root) == 1
        assert len(inp.taproot_sigs) == 2

        for (pub, leaf_hash), sigdata in inp.taproot_sigs.items():
            sig = ec.Signature(sigdata[:64])
            ctrl, sc = next(iter(inp.taproot_scripts.items()))
            leaf_version, script = sc[-1], Script(sc[:-1])
            assert hashes.tagged_hash("TapLeaf", bytes([leaf_version]) + script.serialize()) == leaf_hash
            sighash = p.sighash(0, sighash=0, ext_flag=1, script=script, leaf_version=leaf_version)
            assert pub.schnorr_verify(sig, sighash), "backup-leaf signature must verify against the real sighash"

    def test_backup_leaf_sig_count_and_trim_are_not_dropped(self):
        """The same class of bug d2a0bdb fixed for the tranche fixture,
        confirmed here specifically for the backup leaf's exact shape."""
        p, _descriptor, signing_roots = _build_founders_backup_inheritance_psbt(
            self.founder_seeds, self.backup_seeds, self.heir_seeds, signing_leaf="backup",
        )
        assert PSBTParser.sig_count(p) == 0
        for root in signing_roots:
            p.sign_with(root)
        assert PSBTParser.sig_count(p) == 2

        trimmed = PSBTParser.trim(p)
        assert PSBTParser.sig_count(trimmed) == 2
        assert len(trimmed.inputs[0].taproot_sigs) == 2
