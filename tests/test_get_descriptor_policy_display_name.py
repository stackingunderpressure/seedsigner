import pytest

import base  # hardware-dependency mocking as an import side effect; must precede importing seedsigner.views.*

from embit.descriptor import Descriptor

from seedsigner.views.seed_views import get_descriptor_policy_display_name


class TestGetDescriptorPolicyDisplayName:
    """
    Round-2 audit finding: this function used to dispatch on bare
    `len(descriptor.keys) == 1` to decide "Single-sig", reintroducing the
    exact mislabeling embit_utils.is_single_sig_wallet's `miniscript is
    None` check exists to prevent -- a single-key TIMELOCKED policy
    (e.g. wsh(and_v(v:older(144),pk(A)))) has exactly one key but is not
    a single-sig policy in the sense that matters to a user confirming
    what they're signing. This is currently unreachable through the
    normal registration flow (scan_views.py's gate filters non-basic-
    multisig/non-taproot-miniscript/non-single-sig shapes out first),
    but Address Explorer calls this function directly, and any future
    caller with no such gate must not get a wrong label or a crash.
    """

    def test_bare_single_key_is_single_sig(self):
        descriptor = Descriptor.from_string(
            "wpkh([73c5da0a/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/{0,1}/*)#2aj6cvca"
        )
        assert get_descriptor_policy_display_name(descriptor) == "Single-sig"

    def test_single_key_timelocked_policy_is_not_mislabeled_single_sig(self):
        descriptor = Descriptor.from_string(
            "wsh(and_v(v:older(144),pk([73c5da0a/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/{0,1}/*)))"
        )
        assert len(descriptor.keys) == 1
        result = get_descriptor_policy_display_name(descriptor)
        assert result != "Single-sig", "must not hide the timelock condition behind the single-sig label"
        assert result == "Custom policy"

    def test_basic_multisig_reports_threshold(self):
        descriptor = Descriptor.from_string(
            "wsh(sortedmulti(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,"
            "[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,"
            "[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))#zw6cnrlk"
        )
        assert get_descriptor_policy_display_name(descriptor) == "2 of 3"
