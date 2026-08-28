import pytest

from embit.descriptor import Descriptor

from seedsigner.helpers import embit_utils


NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"


def _account_key_str(seed_words: str, path: str, fingerprint_hex: str, network: str = "test") -> str:
    """Same helper as TestTaprootDescriptorRegistration in test_embit_utils.py."""
    from embit.bip32 import HDKey
    from embit.networks import NETWORKS
    from seedsigner.models.seed import Seed
    seed = Seed(seed_words.split())
    root = HDKey.from_seed(seed.seed_bytes, version=NETWORKS[network]["xprv"])
    assert root.my_fingerprint.hex() == fingerprint_hex, "test vector's own seed doesn't match its documented fingerprint"
    account_xpub = root.derive(f"m/{path}").to_public()
    return f"[{fingerprint_hex}/{path}]{account_xpub.to_base58(version=NETWORKS[network]['xpub'])}"


KEY_A = _account_key_str("abandon " * 11 + "about", "86h/1h/0h", "73c5da0a")
KEY_B = _account_key_str("baby mass dust captain baby mass dust captain baby mass dust casino", "86h/1h/0h", "0be174ee")
KEY_C = _account_key_str("captain baby mass dust captain baby mass dust captain baby mass dutch", "86h/1h/0h", "8d55ff0d")


class TestGetTaprootLeafSummaries:
    """
    get_taproot_leaf_summaries -- the whole-tree counterpart to
    PSBTParser.get_signing_leaf_summary. Registration-time (no PSBT, no
    derived key needed): quorum counts and timelock values are literal
    facts about the policy structure, not about which child index a key
    was derived to.
    """

    def test_simple_two_leaf_pk_descriptor(self):
        """Same shape as TestTaprootDescriptorRegistration._tr_multileaf_descriptor
        in test_embit_utils.py -- two bare pk() leaves, no thresholds, no
        timelocks."""
        desc_str = f"tr({NUMS_HEX},{{pk({KEY_A}/0/0),pk({KEY_B}/0/0)}})"
        descriptor = Descriptor.from_string(desc_str)
        summaries = embit_utils.get_taproot_leaf_summaries(descriptor)
        assert summaries == [
            {"quorum_k": 1, "quorum_n": 1, "timelock_kind": None, "timelock_value": None},
            {"quorum_k": 1, "quorum_n": 1, "timelock_kind": None, "timelock_value": None},
        ]

    def test_founders_and_timelocked_recovery(self):
        """The real DynastyTrust 2-leaf shape: 2-of-3 founders now, 2-of-3
        recovery after an absolute CLTV height -- exact same policy string
        shape test_taproot_leaf_summary.py builds real PSBTs against."""
        keys = f"{KEY_A}/0/0,{KEY_B}/0/0,{KEY_C}/0/0"
        desc_str = f"tr({NUMS_HEX},{{multi_a(2,{keys}),and_v(v:after(500),multi_a(2,{keys}))}})"
        descriptor = Descriptor.from_string(desc_str)
        summaries = embit_utils.get_taproot_leaf_summaries(descriptor)
        assert summaries == [
            {"quorum_k": 2, "quorum_n": 3, "timelock_kind": None, "timelock_value": None},
            {"quorum_k": 2, "quorum_n": 3, "timelock_kind": "after_height", "timelock_value": 500},
        ]

    def test_older_time_recovery_matches_nunchuk_operand_order(self):
        """Nunchuk-style export wraps the quorum, not the timelock, in
        and_v's v: slot -- and_v(v:multi_a(...),older(N)) -- and BIP68's
        time flag (bit 22) means this older() value is in 512-second
        units, not raw blocks. Proves both the reversed operand order and
        the unit decoding are correct at the whole-tree level, matching
        PSBTParser._parse_leaf_quorum's own documented behavior."""
        keys = f"{KEY_A}/0/0,{KEY_B}/0/0,{KEY_C}/0/0"
        BIP68_TIME_FLAG = 0x400000
        raw_older = BIP68_TIME_FLAG | 100  # 100 * 512 seconds = 51200 seconds
        desc_str = f"tr({NUMS_HEX},{{multi_a(2,{keys}),and_v(v:multi_a(2,{keys}),older({raw_older}))}})"
        descriptor = Descriptor.from_string(desc_str)
        summaries = embit_utils.get_taproot_leaf_summaries(descriptor)
        assert summaries[1] == {"quorum_k": 2, "quorum_n": 3, "timelock_kind": "older_time", "timelock_value": 51200}

    def test_four_leaf_tree_preserves_left_to_right_order(self):
        """DynastyTrust's real 4-leaf shape (founders/recovery/inheritance/
        second_inheritance): founder@depth1, recovery@depth2,
        inheritance@depth3, second_inheritance@depth3 -- the
        {L1,{L2,{L3,L4}}} tree nest_leaves()/build_multileaf produce in
        policy_compiler.rs. Each leaf uses a distinct quorum so a mixed-up
        order would be caught, not just a mixed-up count."""
        keys = f"{KEY_A}/0/0,{KEY_B}/0/0,{KEY_C}/0/0"
        founders = f"multi_a(2,{keys})"
        recovery = f"and_v(v:after(500),multi_a(2,{keys}))"
        inheritance = f"and_v(v:after(1000),multi_a(1,{KEY_A}/0/0,{KEY_B}/0/0))"
        second_inheritance = f"and_v(v:after(2000),pk({KEY_C}/0/0))"
        desc_str = f"tr({NUMS_HEX},{{{founders},{{{recovery},{{{inheritance},{second_inheritance}}}}}}})"
        descriptor = Descriptor.from_string(desc_str)
        summaries = embit_utils.get_taproot_leaf_summaries(descriptor)
        assert len(summaries) == 4
        assert summaries[0] == {"quorum_k": 2, "quorum_n": 3, "timelock_kind": None, "timelock_value": None}
        assert summaries[1] == {"quorum_k": 2, "quorum_n": 3, "timelock_kind": "after_height", "timelock_value": 500}
        assert summaries[2] == {"quorum_k": 1, "quorum_n": 2, "timelock_kind": "after_height", "timelock_value": 1000}
        assert summaries[3] == {"quorum_k": 1, "quorum_n": 1, "timelock_kind": "after_height", "timelock_value": 2000}

    def test_non_taproot_descriptor_raises(self):
        with pytest.raises(ValueError):
            embit_utils.get_taproot_leaf_summaries(Descriptor.from_string(
                f"wpkh({KEY_A}/{{0,1}}/*)"
            ))

    def test_single_key_taproot_has_no_leaves(self):
        """A bare tr(key) with no script tree at all -- _count_tap_leaves'
        own None-handling means this returns an empty list, not a phantom
        leaf; MultisigWalletDescriptorView never offers "Policy details"
        for this shape (len(...) > 1 gate) since the one-line policy
        summary already says everything."""
        descriptor = Descriptor.from_string(f"tr({KEY_A}/0/0)")
        assert embit_utils.get_taproot_leaf_summaries(descriptor) == []

    def test_unrecognized_leaf_shape_reports_none_rather_than_guessing(self):
        """A leaf shape outside the small set tr_multileaf-style policies
        actually produce (here: a hashlock, sha256()) -- must report
        all-None for that leaf, never a wrong guess."""
        desc_str = f"tr({NUMS_HEX},{{pk({KEY_A}/0/0),sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333)}})"
        descriptor = Descriptor.from_string(desc_str)
        summaries = embit_utils.get_taproot_leaf_summaries(descriptor)
        assert len(summaries) == 2
        assert summaries[0] == {"quorum_k": 1, "quorum_n": 1, "timelock_kind": None, "timelock_value": None}
        assert summaries[1] == {"quorum_k": None, "quorum_n": None, "timelock_kind": None, "timelock_value": None}
