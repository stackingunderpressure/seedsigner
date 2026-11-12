from embit import ec, hashes
from embit.util import secp256k1


def control_block(leaf_version: int, internal_xonly: bytes, merkle_root: bytes, merkle_path: bytes) -> bytes:
    """
    A BIP-341 control block for one leaf: (leaf version | output key parity), the
    internal key, then the leaf's merkle path.

    The parity bit matters. PSBTParser proves each supplied leaf against the address
    being spent (see PSBTParser._proven_leaf_hash) and, like the network, refuses a
    control block whose parity bit does not match the real output key.

    The output key is tweaked here with the raw curve call: embit's
    PublicKey.taproot_tweak() normalizes its result to an even key, which throws the
    parity away.
    """
    tweak = hashes.tagged_hash("TapTweak", internal_xonly + merkle_root)
    point = secp256k1.ec_pubkey_parse(b"\x02" + internal_xonly)
    secp256k1.ec_pubkey_tweak_add(point, bytes(tweak))
    parity = ec.PublicKey(point).sec()[0] & 1
    return bytes([leaf_version | parity]) + internal_xonly + merkle_path
