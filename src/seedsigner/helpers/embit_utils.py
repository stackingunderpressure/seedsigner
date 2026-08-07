import embit
import logging
import re

from binascii import b2a_base64
from hashlib import sha256

from embit import bip32, compact, ec
from embit.bip32 import HDKey
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.util import secp256k1


from seedsigner.models.settings_definition import SettingsConstants

logger = logging.getLogger(__name__)


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
    True for a BARE single-key descriptor -- legacy p2pkh, nested or native
    segwit, or single-key taproot (tr(key)) -- with no miniscript policy
    wrapped around that key. This is the counterpart to
    is_taproot_miniscript_wallet/descriptor.is_basic_multisig: together the
    three predicates cover every descriptor shape get_multisig_address
    (despite its name -- it's generic) actually knows how to derive.

    Checking `descriptor.miniscript is None` (not just `len(keys) == 1`) is
    the fix for a real gap: a single KEY doesn't mean a single-sig POLICY.
    `wsh(and_v(v:older(144),pk(A)))` has exactly one key but is a timelocked
    vault -- embit still parses it into `descriptor.miniscript`, unlike a
    bare wpkh()/pkh()/tr(key), where `.miniscript` is None. Accepting the
    timelocked shape here and labelling it "Single-sig" (which the
    registration confirmation screen would have done before this fix) would
    hide the very condition the user is being asked to confirm. A
    single-key miniscript policy with real conditions isn't supported by
    this predicate at all -- it correctly falls through to "unsupported"
    rather than being mislabeled; genuine support for it is separate,
    future work.

    A watch-only descriptor exported from another coordinator (e.g. a hot
    wallet's xpub from Nunchuk) for a wallet whose seed isn't loaded on this
    device is exactly the case this exists for -- viewing or verifying its
    addresses shouldn't require importing that wallet's private key material.
    """
    return len(descriptor.keys) == 1 and descriptor.miniscript is None



# BIP341's standard "nothing up my sleeve" point (H), used by Liana,
# DynastyTrust, and this fork's own tr_multileaf test vectors as the
# taproot internal key when a wallet's design wants NO key-path spend to
# exist at all -- every real spend must go through a declared script-path
# leaf. A descriptor whose internal key is anything else has a genuine,
# spendable key-path alongside its leaves (the shape some third-party
# coordinators, e.g. Nunchuk-style inheritance plans, produce).
NUMS_INTERNAL_KEY_XONLY_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

# BIP371 taproot trees are capped at depth 128; anything deeper than that
# cannot be a well-formed tree at all. Used as a hard recursion guard so a
# malformed or adversarial descriptor can't drive unbounded recursion here.
_MAX_TAP_TREE_DEPTH = 128


def is_nums_internal_key(descriptor: Descriptor) -> bool:
    """
    True when a taproot descriptor's internal key is the standard BIP341
    NUMS point -- provably unspendable, meaning this wallet has NO key-path
    spend at all, only its declared script-path leaves. False for any real,
    spendable internal key.
    """
    if not descriptor.is_taproot:
        return False
    try:
        return descriptor.key.xonly().hex() == NUMS_INTERNAL_KEY_XONLY_HEX
    except Exception:
        return False



def _count_tap_leaves(tree, _depth: int = 0) -> int:
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

    `_depth` guards against unbounded recursion on a malformed/adversarial
    tree -- BIP341 caps real trees at depth 128, so anything deeper is
    already invalid and not worth walking further.
    """
    if tree is None or tree.tree is None:
        return 0
    if _depth > _MAX_TAP_TREE_DEPTH:
        raise ValueError("Tap tree exceeds BIP341's maximum depth -- malformed descriptor")
    if isinstance(tree.tree, tuple):
        return sum(_count_tap_leaves(child, _depth + 1) for child in tree.tree)
    return 1



def get_taproot_policy_summary(descriptor: Descriptor) -> dict:
    """
    Raw facts about a taproot descriptor's policy shape. Returns raw data,
    not a formatted string: this is a helper, not a view, and translation
    (gettext) belongs at the view layer -- same convention
    PSBTParser.get_signing_leaf_summary follows, and the one this function
    itself used to violate (it used to return a pre-translated string,
    the only gettext use anywhere in this file).

    Unlike basic multisig, a multi-leaf taproot policy doesn't reduce to a
    single "M of N" -- a tr_multileaf inheritance vault has a DIFFERENT
    threshold on each leaf (e.g. 2-of-3 trustees now, 2-of-3 heirs after a
    timelock). get_multisig_policy() intentionally keeps raising for this
    shape (its (threshold, n) contract can't express it and existing
    callers rely on that); this is the taproot-specific counterpart the
    registration screen calls instead.

    Returns:
        {
            "num_keys": int,
            "num_leaves": int,               # 0 for a single-key tr(key)
            "keypath_spendable": bool,        # True unless the internal key is the NUMS point
        }
    """
    if not descriptor.is_taproot:
        raise ValueError(f"Expected a taproot descriptor, got: {descriptor.brief_policy}")
    try:
        num_leaves = _count_tap_leaves(descriptor.taptree)
    except ValueError:
        # _count_tap_leaves' own depth guard raising means the tree is
        # malformed/adversarial (deeper than BIP341's real 128-leaf cap),
        # not that this function's caller did anything wrong. Every
        # caller of this summary (the registration confirmation screen,
        # Address Explorer's policy display) shows the user a summary
        # string, not a crash screen -- degrade to "leaves unknown"
        # rather than letting a scanned QR crash the flow.
        logger.warning("Tap tree exceeds max depth; treating leaf count as unknown", exc_info=True)
        num_leaves = 0
    return {
        "num_keys": len(descriptor.keys),
        "num_leaves": num_leaves,
        "keypath_spendable": not is_nums_internal_key(descriptor),
    }



# Matches a key origin `]` immediately followed by a bare 64-hex-char
# x-only pubkey (no extended-key prefix like xpub/tpub, since those are
# base58, not hex) with nothing derivable after it -- e.g.
# `[fp/86h/1h/0h/0/0]<64 hex chars>`. An xpub-based key expression at the
# same position instead starts with an alphabetic base58 prefix and can
# still have `/0/*` appended.
_BARE_XONLY_LEAF_KEY_RE = re.compile(r'\][0-9a-fA-F]{64}(?:[,)]|$)')


def is_bare_taproot_leaf_key_descriptor(descriptor_str: str) -> bool:
    """
    True only for a taproot descriptor carrying a leaf key expressed as
    an already-derived, non-extendable bare x-only pubkey (e.g.
    `tr(H,{pk([fp/86h/1h/0h/0/0]<64-hex-xonly>)})`) -- the one shape the
    legacy `/0/*` -> `/{0,1}/*` change-branch rewrite (meant for
    xpub-based legacy/segwit multisig key expressions) actively corrupts:
    appending `/{0,1}/*` to a key that can't be derived any further makes
    Descriptor.from_string raise. An ordinary xpub-based taproot
    descriptor (e.g. `tr([fp/path]xpub.../0/*)`) is exactly as derivable
    as a legacy multisig xpub and is NOT this shape -- it should still
    receive the same rewrite, not be blanket-excluded just because it
    starts with `tr(`.
    """
    return bool(_BARE_XONLY_LEAF_KEY_RE.search(descriptor_str))



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
