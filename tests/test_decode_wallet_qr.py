from seedsigner.models.decode_qr import DecodeQR
from seedsigner.models.qr_type import QRType
from seedsigner.models.settings import SettingsConstants


def _detect(s: str) -> str:
    return DecodeQR.detect_segment_type(s, wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)


class TestWalletDescriptorQrDetection:
    """
    detect_segment_type used to classify a wallet-descriptor QR only by
    checking for the literal substring "sortedmulti" -- which happened to
    work for every descriptor already covered by the existing flow tests
    (they all use sortedmulti()), silently masking that every other valid
    descriptor shape fell through to QRType.INVALID and was never even
    handed to the taproot/single-sig support built downstream in
    scan_views.py, tools_views.py, and embit_utils.py. These tests exercise
    the classification step directly and independently of any specific
    downstream flow, so this class of gap can't hide behind a flow test
    that happens to pick a "sortedmulti" example again.
    """

    def test_basic_multisig_sortedmulti_is_recognized(self):
        # The shape every existing flow test already covers -- must keep working.
        desc = "wsh(sortedmulti(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))#zw6cnrlk"
        assert _detect(desc) == QRType.WALLET__GENERIC

    def test_plain_multi_without_sorted_prefix_is_recognized(self):
        # "multi(" alone (no "sorted" prefix) never contained the literal
        # substring "sortedmulti" -- this was silently broken too.
        desc = "wsh(multi(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))"
        assert _detect(desc) == QRType.WALLET__GENERIC

    def test_single_sig_native_segwit_is_recognized(self):
        desc = "wpkh([73c5da0a/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)"
        assert _detect(desc) == QRType.WALLET__GENERIC

    def test_single_sig_legacy_is_recognized(self):
        desc = "pkh([73c5da0a/44h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)"
        assert _detect(desc) == QRType.WALLET__GENERIC

    def test_single_key_taproot_is_recognized(self):
        desc = "tr([73c5da0a/86h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)"
        assert _detect(desc) == QRType.WALLET__GENERIC

    def test_taproot_multi_leaf_multi_a_with_relative_timelock_is_recognized(self):
        """
        A real Nunchuk-style inheritance-plan export: a taproot descriptor
        with a REAL key at the internal-key position (not a NUMS point --
        so key-path spending is a live 4th path here, distinct from
        DynastyTrust's NUMS-anchored tr_multileaf vaults), a multi_a()
        "now" leaf, and an and_v(v:multi_a(...), older(N)) leaf with a
        RELATIVE (CSV) timelock rather than the absolute after() this
        fleet's own DynastyTrust vaults use. Previously invisible to
        detect_segment_type entirely -- no "sortedmulti" substring anywhere
        in it (multi_a is a different miniscript fragment).
        """
        desc = (
            "tr(xpub661MyMwAqRbcGcsuusXYzWiehTp32FNRHK3jfmGH7Bp1hodY7urbX3GWykM4tqoQ71rPNv9y5w11eSgFjxpC4QjUvA5zfUEB1c7c5oLnhDw/<0;1>/*,"
            "{multi_a(2,[a8260677/87h/0h/0h]xpub6CVBUbA2QfgKzCZQJgdTMC9CkBqT5LD7CjXMSwN1ueWWcs8z8ucceYV4rhF9e62A3CFZAh4rAvoD29jvcbQs5V1SX1eqRhoKvbJc57QeVmZ/<0;1>/*,"
            "[73be5f8d/87h/0h/0h]xpub6BmrGMdTR3Hcg1HAsEb1CVnoG5LNBf2JELzVepxRaW4eGiZfcKx4WAP325xekwvuH8GDqMjLAPP7GmTRCXUeBJwUV6LzT9jSgLAeri5wM6E/<0;1>/*),"
            "and_v(v:multi_a(1,[a8260677/48h/0h/1h/2h]xpub6DuonnAizryvxT1WGUKJ9PBSuaRZKKTJa1t6LhtBmFA6U9xHTt3LoNNDo1a2TNwBByaH4dwXxVPJWDo9dLsFg8G43CJP9smnx7aCK2QJEf2/<0;1>/*,"
            "[73be5f8d/48h/0h/1h/2h]xpub6E2JVNxNNYqznU7Z8h5N9C4GZZJbs4S5cCh6j4zQHoomzucbyCJrF6rV9PRvggLGZmSR7b1XPnAyvTxDgNpx23to4LHcLgzh9StwxtZsP45/<0;1>/*),older(4199366))})"
        )
        assert _detect(desc) == QRType.WALLET__GENERIC

    def test_unrelated_qr_types_are_not_misclassified(self):
        # Regression guard: the broadened check shouldn't start swallowing
        # non-descriptor QR types.
        assert _detect("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") != QRType.WALLET__GENERIC
        assert _detect("abandon " * 11 + "about") != QRType.WALLET__GENERIC

    def test_account_ur_is_recognized(self):
        assert _detect("UR:CRYPTO-ACCOUNT/some-bytewords-payload") == QRType.ACCOUNT__UR


class TestIsWalletDescriptorProperty:
    """
    DecodeQR.is_wallet_descriptor is the actual gate that decides whether
    a scanned QR gets routed into the wallet-registration flow at all --
    detect_segment_type correctly classifying a QR as QRType.ACCOUNT__UR
    (a UR:CRYPTO-ACCOUNT export, e.g. a coordinator's "bundle several
    xpubs into one account" QR) isn't enough by itself if this property
    doesn't also recognize that type. get_wallet_descriptor() and
    get_percent_complete() both already had explicit ACCOUNT__UR
    handling; this property was the one place it got left out, so a
    UR:CRYPTO-ACCOUNT QR would decode completely and then be silently
    treated as "not a wallet descriptor at all."
    """

    def _decode_qr_with_type(self, qr_type):
        decoder = DecodeQR.__new__(DecodeQR)
        decoder.qr_type = qr_type
        decoder.decoder = None
        return decoder

    def test_account_ur_is_recognized_as_a_wallet_descriptor(self):
        decoder = self._decode_qr_with_type(QRType.ACCOUNT__UR)
        assert decoder.is_wallet_descriptor is True

    def test_output_ur_is_still_recognized_as_a_wallet_descriptor(self):
        # Regression guard: ACCOUNT__UR must be ADDITIVE, not a
        # replacement that drops OUTPUT__UR's existing coverage.
        decoder = self._decode_qr_with_type(QRType.OUTPUT__UR)
        assert decoder.is_wallet_descriptor is True

    def test_unrelated_types_are_still_not_wallet_descriptors(self):
        decoder = self._decode_qr_with_type(QRType.PSBT__UR2)
        assert decoder.is_wallet_descriptor is False
