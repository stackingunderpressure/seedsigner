"""
Outside review, 2026-11-27, two medium findings in this fork:

1. Without a registered descriptor, an output whose tap tree holds one of
   this seed's keys was counted as presumed CHANGE. A tree such as
   tr(NUMS,{pk(you), pk(attacker)}) qualifies, and the attacker can spend
   it alone -- so money leaving was shown as coming back, guarded only by a
   "not verified" note. Now: until a descriptor confirms it, such an output
   is counted as money leaving (settle_unverified_script_tree_change).

2. The change-index warning only fired past 10,000 addresses from the
   inputs, while DynastyTrust refuses change past address 999 and its Core
   recovery steps import [0, 999]. Change the app and a Core restore would
   never find could be signed without a word. Now: more than 1,000 past the
   inputs' smallest address index is flagged (the reviewer's first option;
   stock's relative rule kept, only the width changed).
"""
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants

from psbt_testing_util import PSBTTestData
from test_taproot_change_output import _build_psbt_with_multileaf_change, _matching_registered_descriptor


seed_a = PSBTTestData.seed
seed_b = PSBTTestData.multisig_key_2  # stands in for "the attacker" in finding 1


def _parsed():
    psbt, root_a, root_b, *_ = _build_psbt_with_multileaf_change(seed_a, seed_b)
    return PSBTParser(psbt, seed_a, network=SettingsConstants.REGTEST), root_a, root_b


def test_without_a_descriptor_script_tree_change_is_counted_as_money_leaving():
    parser, *_ = _parsed()
    amount = parser.get_change_data(0)["amount"]
    parser.settle_unverified_script_tree_change(None)
    assert parser.num_change_outputs == 0
    assert parser.change_amount == 0
    assert parser.spend_amount == amount
    assert len(parser.destination_addresses) == 1


def test_with_the_vaults_own_descriptor_it_stays_change():
    parser, root_a, root_b = _parsed()
    parser.settle_unverified_script_tree_change(_matching_registered_descriptor(root_a, root_b))
    assert parser.num_change_outputs == 1
    assert parser.spend_amount == 0


def test_settling_twice_does_not_double_count():
    parser, *_ = _parsed()
    parser.settle_unverified_script_tree_change(None)
    spend = parser.spend_amount
    parser.settle_unverified_script_tree_change(None)
    assert parser.spend_amount == spend


def test_change_far_past_the_inputs_is_flagged_at_1000_not_10000():
    parser, *_ = _parsed()
    assert PSBTParser.CHANGE_ADDRESS_INDEX_WINDOW == 1_000
    # No input on this change branch, so the window is measured from address 0.
    path = lambda i: [0x80000000 + 86, 0x80000000 + 1, 0x80000000, 1, i]
    assert parser._is_change_address_index_within_window(path(999)) is True
    assert parser._is_change_address_index_within_window(path(1_000)) is True   # exactly the window: stock rule
    assert parser._is_change_address_index_within_window(path(1_001)) is False
    assert parser._is_change_address_index_within_window(path(9_000)) is False  # the reviewer's case
