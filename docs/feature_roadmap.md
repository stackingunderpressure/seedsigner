# Feature Roadmap

Current focus: v0.5.0 preview releases.

*Note: It may or may not make sense to do minor bugfix preview releases along the way (e.g. 1.0 -> 1.1).*


## v0.5.0 Pre-Release 1.x
* Scan SeedQR/CompactSeedQR
* Add/Edit passphrase
* View seed words with configurable warnings
* Export xpub with configurable warnings and flow determined by Settings
* Scan PSBT
* Full PSBT review screens
* "Full Spend" (no change) warning
* Fully verify PSBT change addresses
* Send signed PSBT via QR
* QR display dimming/brightness UP/DOWN
* Subset of configurable Settings; persistent Settings storage
* SettingsQR integration proof-of-concept

Screens will be functional but not necessarily in their final presentation state (icons, text, positioning, etc.).


## v0.5.0 Pre-Release 2.x
* Existing screen refinement (visual presentation, text, etc.)
* Create new seed via image entropy
* Manual mnemonic seed word entry
* 12th/24th word calculation
* SeedQR/CompactSeedQR manual transcription UI with configurable UI style (dots vs grid)
* Single sig address scan and verification
* SettingsQR standalone UI refinement
* Fix broken tests
* All GUI Components support scrollable Screens


## v0.5.0 Pre-Release 3.x
* Settings: I/O Test
* Create new seed via dice rolls
* Custom derivation paths in xpub export flow
* QR display dimming/brightness, framerate, density(?) controls in transparent overlay
* HRF partner logo on startup
* Improve test suite coverage
* Further existing screen refinement
* "Final" bugfixes


## Initial v0.5.0 Release
All of the above!


## Beyond v0.5.0
These features will not be included in the initial v0.5.0 release and will have varying degrees of priority for subsequent releases (or possibly not at all).

* Multisig wallet descriptor QR scan(?) and address verification(?)
* Sign taproot transactions
* Non-taproot native segwit (wsh) miniscript wallets with OR/AND/timelock
  policy combinators -- currently rejected at the descriptor-shape gate
  in scan_views.py regardless of import method (BSMS, Coldcard export,
  raw descriptor), since it's neither basic multisig, taproot, nor
  single-sig. A real, separate body of work from the tr_multileaf
  taproot support: parsing embit's non-taproot miniscript AST for
  arbitrary combinator trees, deriving wsh() addresses for it, and
  showing the OR/AND policy tree on the registration/signing screens the
  way the taproot leaf disclosure does today. (Surfaced 2026-08-07
  testing a Nunchuk-built wsh() test wallet, "GiftLockerTest" -- see
  below; that specific idea is NOT going this route, noted here only
  because the gap itself is real and could resurface with a different
  wallet.)
* "Gift Locker" (originated 2023, predates DynastyTrust): lock UTXOs
  under a timelock with a key-recovery service -- structurally this is
  DynastyTrust's own founders-now / timelocked-recovery leaf pattern
  under different framing, not a distinct wsh() miniscript engine.
  Decided 2026-08-07: build it as another DynastyTrust vault TEMPLATE
  on the existing tr_multileaf taproot compiler (see
  dynastytrust/apps/web/src/lib/vault-templates.ts), not as a separate
  wallet type -- meaning it needs NO new SeedSigner work at all once
  built; every taproot leaf/quorum/timelock disclosure fixed this
  session already covers it. Original board notes: education, spending
  vs. storing key split, FOSS, steel-QR engraving for backup. Tracked
  for real in the DynastyTrust repo, not here -- this line is a pointer
  only.
* Multi-language support (Transifex free for open source projects)
* Multisig: sign PSBT with multiple keys at once
* Custom OS, possibly with swappable SD card PSBT and multisig wallet descriptor storage
* Decoy game mode at launch (Snake, Tetris, Sudoku...?)
* BIP-39 wordlists in additional languages
* Address message signing
* UI color scheme customization
* Specify missing entropy for 12th/24th word calculation


# v0.6 and Beyond...?
* Alternate hardware profile / touchscreen
* PGP signer
* Liquid?
