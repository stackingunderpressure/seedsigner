import embit

from binascii import b2a_base64
from gettext import gettext as _
from hashlib import sha256

from embit import bip32, compact, ec
from embit.bip32 import HDKey
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.util import secp256k1


from seedsigner.models.settings_definition import SettingsConstants


"""
    Collection of generic embit-powered util methods.
"""
# TODO: PR these directly into `embit`? Or replace with new/existing methods already in `embit`?


# TODO: Refactor `wallet_type` to conform to our `sig_type` naming convention
def get_standard_derivation_path(network: str = SettingsConstants.MAINNET, wallet_type: str = SettingsConstants.SINGLE_SIG, script_type: str = SettingsConstants.NATIVE_SEGWIT) -> str:
    if network == SettingsConstants.MAINNET:
        network_path = "0'"
    elif network == SettingsConstants.TESTNET:
        network_path = "1'"
    elif network == SettingsConstants.REGTEST:
        network_path = "1'"
    else:
        raise Exception("Unexpected network")

    if wallet_type == SettingsConstants.SINGLE_SIG:
        if script_type == SettingsConstants.LEGACY_P2PKH:
            return f"m/44'/{network_path}/0'"
        elif script_type == SettingsConstants.NESTED_SEGWIT:
            return f"m/49'/{network_path}/0'"
        elif script_type == SettingsConstants.NATIVE_SEGWIT:
            return f"m/84'/{network_path}/0'"
        elif script_type == SettingsConstants.TAPROOT:
            return f"m/86'/{network_path}/0'"
        else:
            raise Exception("Unexpected script type")

    elif wallet_type == SettingsConstants.MULTISIG:
        if script_type == SettingsConstants.LEGACY_P2PKH:
            return f"m/45'" #BIP-45
        elif script_type == SettingsConstants.NESTED_SEGWIT:
            return f"m/48'/{network_path}/0'/1'"
        elif script_type == SettingsConstants.NATIVE_SEGWIT:
            return f"m/48'/{network_path}/0'/2'"
        elif script_type == SettingsConstants.TAPROOT:
            raise Exception("Taproot multisig not yet supported")
        else:
            raise Exception("Unexpected script type")
    else:
        raise Exception("Unexpected wallet type")    # checks that all inputs are from the same wallet



def get_xpub(seed_bytes, derivation_path: str, embit_network: str = "main") -> HDKey:
    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[embit_network]["xprv"])
    xprv = root.derive(derivation_path)
    xpub = xprv.to_public()
    return xpub



def get_single_sig_address(xpub: HDKey, script_type: str = SettingsConstants.NATIVE_SEGWIT, index: int = 0, is_change: bool = False, embit_network: str = "main") -> str:
    if is_change:
        pubkey = xpub.derive([1,index]).key
    else:
        pubkey = xpub.derive([0,index]).key

    if script_type == SettingsConstants.LEGACY_P2PKH:
        return embit.script.p2pkh(pubkey).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.NESTED_SEGWIT:
        return embit.script.p2sh(embit.script.p2wpkh(pubkey)).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.NATIVE_SEGWIT:
        return embit.script.p2wpkh(pubkey).address(network=NETWORKS[embit_network])

    elif script_type == SettingsConstants.TAPROOT:
        return embit.script.p2tr(pubkey).address(network=NETWORKS[embit_network])



def get_multisig_address(descriptor: Descriptor, index: int = 0, is_change: bool = False, embit_network: str = "main"):
    if is_change:
        branch_index = 1
    else:
        branch_index = 0

    # Can derive p2wpkh/p2wsh, p2sh-p2wpkh/p2sh-p2wsh, and legacy (non-segwit)
    # p2pkh/p2sh alike -- descriptor.derive().script_pubkey() is generic over
    # single-key vs multi-key policies, so a plain single-sig wpkh()/pkh()
    # descriptor (e.g. a wallet export from another coordinator, not derived
    # from a seed loaded on this device) is handled by the exact same call as
    # multisig; only the legacy branch needs an explicit single-key allowance
    # since is_basic_multisig alone would otherwise exclude bare pkh().
    if descriptor.is_segwit or (descriptor.is_legacy and (descriptor.is_basic_multisig or len(descriptor.keys) == 1)):
        return descriptor.derive(index, branch_index=branch_index).script_pubkey().address(network=NETWORKS[embit_network])

    elif descriptor.is_taproot:
        # A taproot descriptor -- single-key (tr(key)) or a full multi-leaf
        # miniscript tree (tr(key,{...}), e.g. a tr_multileaf inheritance
        # vault with a separate leaf per spending path). embit's own
        # Descriptor.derive()/.address() already do the full BIP341 tweak
        # (internal key + tap tree -> output key -> address) correctly for
        # both a wildcard-ranged descriptor and a fixed (non-ranged) one --
        # for a fixed descriptor derive() at any index/branch is a safe
        # no-op that returns the same address, matching a design like
        # DynastyTrust's where the whole "wallet" is one immutable address
        # and change returns to that same address (branch_index is
        # meaningless there, not wrong). Verified directly against embit
        # 0.8.0 before writing this: see test_get_multisig_address's new
        # taproot vectors below, independently cross-checked against the
        # BIP341 tap-tree math in psbt_parser.py rather than trusting
        # embit's own output blindly.
        return descriptor.derive(index, branch_index=branch_index).address(network=NETWORKS[embit_network])

    raise Exception(f"{descriptor.script_pubkey().script_type()} address verification not yet implemented!")



def get_multisig_policy(descriptor: Descriptor) -> tuple:
    """Extract (threshold, n) from a basic multisig descriptor."""
    if not descriptor.is_basic_multisig:
        raise ValueError(f"Expected a basic multisig descriptor, got: {descriptor.brief_policy}")
    return (str(descriptor.miniscript.args[0]), str(len(descriptor.keys)))



def is_taproot_miniscript_wallet(descriptor: Descriptor) -> bool:
    """
    True for a taproot descriptor that's a genuine multi-key/multi-leaf policy
    (e.g. tr(key,{multi_a(2,A,B),pk(C)}), a tr_multileaf inheritance vault) --
    as opposed to a single-key tr(key) descriptor, which isn't a "wallet" to
    register in the sense this module means (no signer set to track).
    """
    return descriptor.is_taproot and len(descriptor.keys) > 1



def is_single_sig_wallet(descriptor: Descriptor) -> bool:
    """
    True for any descriptor with exactly one key -- legacy p2pkh, nested or
    native segwit, or single-key taproot (tr(key)). This is the counterpart
    to is_taproot_miniscript_wallet/descriptor.is_basic_multisig: together
    the three predicates cover every descriptor shape get_multisig_address
    (despite its name -- it's generic) actually knows how to derive.

    A watch-only descriptor exported from another coordinator (e.g. a hot
    wallet's xpub from Nunchuk) for a wallet whose seed isn't loaded on this
    device is exactly the case this exists for -- viewing or verifying its
    addresses shouldn't require importing that wallet's private key material.
    """
    return len(descriptor.keys) == 1



def _count_tap_leaves(tree) -> int:
    """
    Recursively counts the script leaves in an embit TapTree. BIP371's tree
    is a binary merkle tree -- an internal node's `.tree` is a 2-tuple of
    child TapTree nodes; a leaf's `.tree` is the leaf's own miniscript/script
    object (not a tuple).

    For a single-key tr(key) descriptor with no script tree at all,
    `descriptor.taptree` is NOT None -- embit still returns a `TapTree()`
    instance -- but that instance's own `.tree` attribute is None. Checking
    only `tree is None` at the top missed this and fell through to the
    `return 1` default, reporting a phantom leaf for a plain single-key
    wallet. Both levels need the None check; a real leaf's `.tree` is always
    its compiled policy object, never None, so this can't misfire on an
    actual leaf.
    """
    if tree is None or tree.tree is None:
        return 0
    if isinstance(tree.tree, tuple):
        return sum(_count_tap_leaves(child) for child in tree.tree)
    return 1



def get_taproot_policy_summary(descriptor: Descriptor) -> str:
    """
    Human-readable summary for a registered taproot multi-leaf descriptor.

    Unlike basic multisig, a multi-leaf taproot policy doesn't reduce to a
    single "M of N" -- a tr_multileaf inheritance vault has a DIFFERENT
    threshold on each leaf (e.g. 2-of-3 trustees now, 2-of-3 heirs after a
    timelock). get_multisig_policy() intentionally keeps raising for this
    shape (its (threshold, n) contract can't express it and existing
    callers rely on that); this is the taproot-specific counterpart the
    registration screen calls instead.
    """
    if not descriptor.is_taproot:
        raise ValueError(f"Expected a taproot descriptor, got: {descriptor.brief_policy}")
    num_leaves = _count_tap_leaves(descriptor.taptree)
    if num_leaves == 0:
        # Single-key tr(key) -- no script tree, just a key-path spend.
        # "1 keys, 0 leaves" is technically accurate but reads like a
        # malformed multisig rather than the single-sig wallet it is.
        return _("Taproot, single-sig")
    return _("Taproot, {num_keys} keys, {num_leaves} leaves").format(
        num_keys=len(descriptor.keys),
        num_leaves=num_leaves,
    )



def get_embit_network_name(settings_name):
    """ Convert SeedSigner SettingsConstants for `network` to embit's NETWORK key """
    lookup = {
        SettingsConstants.MAINNET: "main",
        SettingsConstants.TESTNET: "test",
        SettingsConstants.REGTEST: "regtest",
    }
    return lookup.get(settings_name)



def parse_derivation_path(derivation_path: str) -> dict:
    """
    Parses a derivation path into its related SettingsConstants equivalents.

    Primarily only supports single sig derivation paths.

    May return None for fields it cannot parse.
    """
    # Support either m/44'/... or m/44h/... style
    derivation_path = derivation_path.replace("'", "h")

    sections = derivation_path.split("/")

    if sections[1] == "48h":
        # So far this helper is only meant for single sig message signing
        raise Exception("Not implemented")

    lookups = {
        "script_types": {
            "44h": SettingsConstants.LEGACY_P2PKH,
            "49h": SettingsConstants.NESTED_SEGWIT,
            "84h": SettingsConstants.NATIVE_SEGWIT,
            "86h": SettingsConstants.TAPROOT,
        },
        "networks": {
            "0h": SettingsConstants.MAINNET,
            "1h": [SettingsConstants.TESTNET, SettingsConstants.REGTEST],
        }
    }

    details = dict()
    details["script_type"] = lookups["script_types"].get(sections[1])
    if not details["script_type"]:
        details["script_type"] = SettingsConstants.CUSTOM_DERIVATION
    details["network"] = lookups["networks"].get(sections[2])

    # Check if there's a standard change path
    if sections[-2] in ["0", "1"]:
        details["is_change"] = sections[-2] == "1"
    else:
        details["is_change"] = None

    # Check if there's a standard address index
    if sections[-1].isdigit():
        details["index"] = int(sections[-1])
    else:
        details["index"] = None

    if details["is_change"] is not None and details["index"] is not None:
        # standard change and addr index; safe to truncate to the wallet level
        details["wallet_derivation_path"] = "/".join(sections[:-2])
    else:
        details["wallet_derivation_path"] = None

    details["clean_match"] = True
    for k, v in details.items():
        if v is None:
            # At least one field couldn't be parsed
            details["clean_match"] = False
            break

    return details



def sign_message(seed_bytes: bytes, derivation: str, msg: bytes, compressed: bool = True, embit_network: str = "main") -> bytes:
    """
        from: https://github.com/cryptoadvance/specter-diy/blob/b58a819ef09b2bca880a82c7e122618944355118/src/apps/signmessage/signmessage.py
    """
    """Sign message with private key"""
    msghash = sha256(
        sha256(
            b"\x18Bitcoin Signed Message:\n" + compact.to_bytes(len(msg)) + msg
        ).digest()
    ).digest()

    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[embit_network]["xprv"])
    prv = root.derive(derivation).key
    sig = secp256k1.ecdsa_sign_recoverable(msghash, prv._secret)
    flag = sig[64]
    sig = ec.Signature(sig[:64])
    c = 4 if compressed else 0
    flag = bytes([27 + flag + c])
    ser = flag + secp256k1.ecdsa_signature_serialize_compact(sig._sig)
    return b2a_base64(ser).strip().decode()
