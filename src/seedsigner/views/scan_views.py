import logging
import re

from gettext import gettext as _
from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import BackStackView, ErrorView, MainMenuView, NotYetImplementedView, View, Destination
from seedsigner.gui.screens.screen import ButtonOption

logger = logging.getLogger(__name__)



class ScanView(View):
    """
        The catch-all generic scanning View that will accept any of our supported QR
        formats and will route to the most sensible next step.

        Can also be used as a base class for more specific scanning flows with
        dedicated errors when an unexpected QR type is scanned (e.g. Scan PSBT was
        selected but a SeedQR was scanned).
    """
    instructions_text = _mft("Scan a QR code")
    invalid_qr_type_message = _mft("QRCode not recognized or not yet supported.")


    def __init__(self):
        from seedsigner.models.decode_qr import DecodeQR

        super().__init__()
        # Define the decoder here to make it available to child classes' is_valid_qr_type
        # checks and so we can inject data into it in the test suite's `before_run()`.
        self.wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        self.decoder: DecodeQR = DecodeQR(wordlist_language_code=self.wordlist_language_code)


    @property
    def is_valid_qr_type(self):
        return True


    def run(self):
        from seedsigner.gui.screens.scan_screens import ScanScreen

        # Start the live preview and background QR reading
        self.run_screen(
            ScanScreen,
            instructions_text=self.instructions_text,
            decoder=self.decoder
        )

        # A long scan might have exceeded the screensaver timeout; ensure screensaver
        # doesn't immediately engage when we leave here.
        self.controller.reset_screensaver_timeout()

        # Handle the results
        if self.decoder.is_complete:
            if not self.is_valid_qr_type:
                # We recognized the QR type but it was not the type expected for the
                # current flow.
                # Report QR types in more human-readable text (e.g. QRType
                # `seed__compactseedqr` as "seed: compactseedqr").
                # TODO: cleanup l10n presentation
                return Destination(ErrorView, view_args=dict(
                    title="Error",
                    status_headline=_("Wrong QR Type"),
                    text=_(self.invalid_qr_type_message) + f""", received "{self.decoder.qr_type.replace("__", ": ").replace("_", " ")}\" format""",
                    button_text="Back",
                    next_destination=Destination(BackStackView, skip_current_view=True),
                ))

            if self.decoder.is_seed:
                seed_mnemonic = self.decoder.get_seed_phrase()

                if not seed_mnemonic:
                    # seed is not valid, Exit if not valid with message
                    return Destination(NotYetImplementedView)
                else:
                    # Found a valid mnemonic seed! All new seeds should be considered
                    #   pending (might set a passphrase, SeedXOR, etc) until finalized.
                    from seedsigner.models.seed import Seed
                    from .seed_views import SeedFinalizeView
                    self.controller.storage.set_pending_seed(
                        Seed(mnemonic=seed_mnemonic, wordlist_language_code=self.wordlist_language_code)
                    )
                    if self.settings.get_value(SettingsConstants.SETTING__PASSPHRASE) == SettingsConstants.OPTION__REQUIRED:
                        from seedsigner.views.seed_views import SeedAddPassphraseView
                        return Destination(SeedAddPassphraseView)
                    else:
                        return Destination(SeedFinalizeView)
            
            elif self.decoder.is_psbt:
                from seedsigner.views.psbt_views import PSBTSelectSeedView
                psbt = self.decoder.get_psbt()
                self.controller.psbt = psbt
                self.controller.psbt_parser = None
                return Destination(PSBTSelectSeedView, skip_current_view=True)

            elif self.decoder.is_settings:
                from seedsigner.views.settings_views import SettingsIngestSettingsQRView
                data = self.decoder.get_settings_data()
                return Destination(SettingsIngestSettingsQRView, view_args=dict(data=data))
            
            elif self.decoder.is_wallet_descriptor:
                from embit.descriptor import Descriptor
                from seedsigner.views.seed_views import MultisigWalletDescriptorView
                descriptor_str = self.decoder.get_wallet_descriptor()

                orig_descriptor_str = descriptor_str
                # This legacy `/0/*` -> `/{0,1}/*` rewrite is meant for
                # legacy/segwit multisig-style key expressions
                # ([fp/path]xpub/0/*) and actively corrupts a taproot
                # leaf key expressed as a bare, already-derived xonly
                # pubkey with no further derivation possible (e.g.
                # [fp/path/0/0]<64-hex-xonly>) -- appending /{0,1}/* to a
                # key that can't be derived any further makes
                # Descriptor.from_string raise. Taproot descriptors don't
                # need this rewrite in the first place: a multi-leaf
                # tree's leaves are matched directly against the PSBT's
                # own leaf hashes (PSBTParser.get_signing_leaf_summary),
                # not via Descriptor.owns()'s wildcard-branch machinery
                # the way legacy multisig change verification is.
                if not descriptor_str.lstrip().startswith("tr("):
                    try:
                        if len(re.findall (r'\[([0-9,a-f,A-F]+?)(\/[0-9,\/,h\']+?)\].*?(\/0\/\*)', descriptor_str)) > 0:
                            p = re.compile(r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h\']+?\].*?)(\/0\/\*)')
                            descriptor_str = p.sub(r'\1/{0,1}/*', descriptor_str)
                        elif len(re.findall (r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h,\']+?\][a-z,A-Z,0-9]*?)([\,,\)])', descriptor_str)) > 0:
                            p = re.compile(r'(\[[0-9,a-f,A-F]+?\/[0-9,\/,h,\']+?\][a-z,A-Z,0-9]*?)([\,,\)])')
                            descriptor_str = p.sub(r'\1/{0,1}/*\2', descriptor_str)
                    except Exception as e:
                        logger.info(repr(e), exc_info=True)
                        descriptor_str = orig_descriptor_str

                try:
                    descriptor = Descriptor.from_string(descriptor_str)
                except Exception as e:
                    # The scanned QR is the primary attacker-controlled
                    # input surface on this device -- a malformed or
                    # unparseable descriptor should land on a clean error,
                    # not a raw exception/debug screen.
                    logger.info("Could not parse scanned descriptor: %s", repr(e), exc_info=True)
                    return Destination(ErrorView, view_args=dict(
                        title="Error",
                        status_headline=_("Invalid Descriptor"),
                        text=_("QRCode did not contain a valid wallet descriptor."),
                        button_text="Back",
                        next_destination=Destination(BackStackView, skip_current_view=True),
                    ))

                from seedsigner.helpers.embit_utils import is_taproot_miniscript_wallet, is_single_sig_wallet
                if not descriptor.is_basic_multisig and not is_taproot_miniscript_wallet(descriptor) and not is_single_sig_wallet(descriptor):
                    # A descriptor policy shape we don't know how to derive
                    # addresses for (not basic multisig, not a taproot
                    # multi-leaf wallet, not single-key). Log only the
                    # policy shape, never the descriptor itself -- a
                    # descriptor scanned here can legitimately embed an
                    # xprv (e.g. a coordinator backup export), and private
                    # key material must never be written to a log line on
                    # money-touching firmware.
                    logger.info("Received unsupported descriptor policy: %s", descriptor.brief_policy)
                    return Destination(NotYetImplementedView)

                self.controller.multisig_wallet_descriptor = descriptor
                return Destination(MultisigWalletDescriptorView, skip_current_view=True)
            
            elif self.decoder.is_address:
                from seedsigner.views.seed_views import AddressVerificationStartView
                address = self.decoder.get_address()
                (script_type, network) = self.decoder.get_address_type()

                return Destination(
                    AddressVerificationStartView,
                    skip_current_view=True,
                    view_args={
                        "address": address,
                        "script_type": script_type,
                        "network": network,
                    }
                )
            
            elif self.decoder.is_sign_message:
                from seedsigner.views.seed_views import SeedSignMessageStartView
                qr_data = self.decoder.get_qr_data()

                return Destination(
                    SeedSignMessageStartView,
                    view_args=dict(
                        derivation_path=qr_data["derivation_path"],
                        message=qr_data["message"],
                    )
                )
            
            else:
                return Destination(NotYetImplementedView)

        elif self.decoder.is_invalid:
            # For now, don't even try to re-do the attempted operation, just reset and
            # start everything over.
            self.controller.resume_main_flow = None
            return Destination(ScanInvalidQRTypeView)

        return Destination(MainMenuView)



class ScanPSBTView(ScanView):
    instructions_text = _mft("Scan Transaction")
    invalid_qr_type_message = _mft("Expected a transaction")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_psbt



class ScanSeedQRView(ScanView):
    instructions_text = _mft("Scan SeedQR")
    invalid_qr_type_message = _mft("Expected a SeedQR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_seed



class ScanWalletDescriptorView(ScanView):
    instructions_text = _mft("Scan descriptor")
    invalid_qr_type_message = _mft("Expected a wallet descriptor QR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_wallet_descriptor



class ScanAddressView(ScanView):
    instructions_text = _mft("Scan address QR")
    invalid_qr_type_message = _mft("Expected an address QR")

    @property
    def is_valid_qr_type(self):
        return self.decoder.is_address



class ScanInvalidQRTypeView(View):
    def run(self):
        from seedsigner.gui.screens import WarningScreen

        # TODO: This screen says "Error" but is intentionally using the WarningScreen in
        # order to avoid the perception that something is broken on our end. This should
        # either change to use the red ErrorScreen or the "Error" title should be
        # changed to something softer.
        self.run_screen(
            WarningScreen,
            title=_("Error"),
            status_headline=_("Unknown QR Type"),
            text=_("QRCode is invalid or is a data format not yet supported."),
            button_data=[ButtonOption("Back to Main Menu")],
        )

        return Destination(MainMenuView, clear_history=True)
