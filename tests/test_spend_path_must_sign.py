"""
Must-sign keys on a spending path (DynastyTrust, 2026-11-12): a leaf may
name keys that must EACH sign, on top of k of n others --
and_v(v:pk(H), multi_a(k, ...)), optionally dated. Operator: "make sure
everything is correct and the screens are obvious to what they are
signing."

Two things are held here:
  1. PSBTParser reads that shape from the registered descriptor's parsed
     miniscript, says how many must-sign keys the leaf has and whether
     THIS seed's key is one of them -- and still refuses to describe a
     shape it does not understand.
  2. PSBTSpendPathScreen never puts a line underneath its button. A dated
     path used to: four labelled lines did not fit on 240px and the last
     one, "Your Keys", was hidden. The screen does not scroll. Those
     checks need the REAL renderer, which this suite replaces with a
     mock for every other test (tests/base.py), so they live in
     tests/screenshot_generator/spend_path_layout.py and are run from
     here in a process of their own.
"""
import os
import subprocess
import sys

import pytest
from embit.descriptor.miniscript import Miniscript

from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.seed import Seed


def _keys(n):
    """n distinct, valid compressed public keys (hex)."""
    root = Seed(["abandon"] * 11 + ["about"]).seed_bytes
    from embit import bip32
    master = bip32.HDKey.from_seed(root)
    return [master.derive([0x80000000 + 86, 0x80000000 + 1, 0x80000000 + i, 0, 0]).to_public().sec().hex() for i in range(n)]


def _ms(text):
    return Miniscript.from_string(text, taproot=True)


def _xonly(hexkey):
    return bytes.fromhex(hexkey)[1:]


class TestLeafRequirement:
    def test_one_must_sign_key_beside_a_group(self):
        h, b, c = _keys(3)
        req = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:pk({h}),multi_a(1,{b},{c}))"))
        assert (req["k"], req["n"]) == (1, 2)
        assert req["must_sign"] == [_xonly(h)]
        assert req["timelock_kind"] is None

    def test_dated_must_sign_with_a_one_key_group_compiled_as_thresh(self):
        """The exact shape the compiler emits for 'H must sign + 1 of 1, after N'."""
        h, b = _keys(2)
        req = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:and_v(v:pk({h}),thresh(1,pk({b}))),after(900000))"))
        assert (req["k"], req["n"]) == (1, 1)
        assert req["must_sign"] == [_xonly(h)]
        assert (req["timelock_kind"], req["timelock_value"]) == ("after_height", 900000)

    def test_two_must_sign_keys(self):
        h1, h2, b, c = _keys(4)
        req = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:pk({h1}),and_v(v:pk({h2}),multi_a(2,{b},{c})))"))
        assert (req["k"], req["n"]) == (2, 2)
        assert sorted(req["must_sign"]) == sorted([_xonly(h1), _xonly(h2)])

    def test_plain_shapes_have_no_must_sign_keys(self):
        a, b, c = _keys(3)
        assert PSBTParser._parse_leaf_requirement(_ms(f"multi_a(2,{a},{b},{c})")) == {
            "k": 2, "n": 3, "k2": None, "n2": None, "group_keys": [[_xonly(a), _xonly(b), _xonly(c)]],
            "must_sign": [], "timelock_kind": None, "timelock_value": None}
        assert PSBTParser._parse_leaf_requirement(_ms(f"pk({a})"))["must_sign"] == []
        dated = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:multi_a(2,{a},{b}),after(950000))"))
        assert (dated["k"], dated["n"], dated["must_sign"], dated["timelock_value"]) == (2, 2, [], 950000)
        # Single keys with no group are an all-of-them quorum, not "must-sign + nothing".
        both = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:pk({a}),pk({b}))"))
        assert (both["k"], both["n"], both["must_sign"]) == (2, 2, [])

    def test_two_groups_that_must_both_be_met(self):
        """A consent gate, or "one parent and every kid": both groups are
        reported, in script order, with the keys of each."""
        a, b, c, d, e, f = _keys(6)
        consent = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:multi_a(2,{a},{b},{c}),thresh(1,pk({d})))"))
        assert (consent["k"], consent["n"], consent["k2"], consent["n2"], consent["must_sign"]) == (2, 3, 1, 1, [])
        assert consent["group_keys"] == [[_xonly(a), _xonly(b), _xonly(c)], [_xonly(d)]]

        parent_and_kids = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:multi_a(1,{a},{b}),multi_a(3,{c},{d},{e}))"))
        assert (parent_and_kids["k"], parent_and_kids["n"], parent_and_kids["k2"], parent_and_kids["n2"]) == (1, 2, 3, 3)

        with_must = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:pk({f}),and_v(v:multi_a(1,{a},{b}),multi_a(1,{c},{d})))"))
        assert (with_must["k"], with_must["n"], with_must["k2"], with_must["n2"], with_must["must_sign"]) == (1, 2, 1, 2, [_xonly(f)])

    def test_shapes_it_does_not_understand_are_not_described(self):
        a, b, c, d, e, f = _keys(6)
        blank = {"k": None, "n": None, "k2": None, "n2": None, "group_keys": [], "must_sign": [], "timelock_kind": None, "timelock_value": None}
        # Three groups.
        three = PSBTParser._parse_leaf_requirement(_ms(f"and_v(v:multi_a(1,{a},{b}),and_v(v:multi_a(1,{c},{d}),multi_a(1,{e},{f})))"))
        assert three == blank
        # An OR.
        an_or = PSBTParser._parse_leaf_requirement(_ms(f"or_d(pk({a}),and_v(v:older(10),pk({b})))"))
        assert an_or == blank

    def test_the_old_tuple_never_states_k_of_n_for_a_must_sign_leaf(self):
        """_parse_leaf_quorum has no slot for must-sign keys; '1 of 2'
        alone would understate what the leaf needs."""
        h, b, c = _keys(3)
        assert PSBTParser._parse_leaf_quorum(_ms(f"and_v(v:pk({h}),multi_a(1,{b},{c}))")) == (None, None, None, None)
        assert PSBTParser._parse_leaf_quorum(_ms(f"multi_a(2,{h},{b},{c})")) == (2, 3, None, None)
        # Nor for a second group: "1 of 2" alone would hide the other half.
        d = _keys(4)[3]
        assert PSBTParser._parse_leaf_quorum(_ms(f"and_v(v:multi_a(1,{h},{b}),multi_a(1,{c},{d}))")) == (None, None, None, None)


class TestSpendPathScreenLayout:
    def test_layout_checks_pass_with_the_real_renderer(self):
        here = os.path.dirname(os.path.abspath(__file__))
        target = os.path.join(here, "screenshot_generator", "spend_path_layout.py")
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--no-cov", "-p", "no:cacheprovider", target],
            cwd=os.path.dirname(here), capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-1000:]


class TestChangeScreenButtonsSayWhatTheyDo:
    def test_labels(self):
        from seedsigner.views.psbt_views import PSBTChangeDetailsView
        assert PSBTChangeDetailsView.SKIP_VERIFICATION.button_label == "Skip (not verified)"
        import inspect
        src = inspect.getsource(PSBTChangeDetailsView)
        assert '_("Load descriptor")' in src and "Verify multisig addr" not in src
