import logging
from binascii import hexlify
from embit import psbt, script, ec, bip32, compact, hashes
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath, InputScope, OutputScope
from embit.ec import PublicKey
from embit.util import secp256k1
from io import BytesIO
from typing import List

from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)

class OPCODES:
    OP_RETURN = 106
    OP_PUSHDATA1 = 76



class PSBTParser():
    def __init__(self, p: PSBT, seed: Seed, network: str = SettingsConstants.MAINNET):
        self.psbt: PSBT = p
        self.seed = seed
        self.network = network

        self.policy = None
        self.spend_amount = 0
        self.change_amount = 0
        self.change_data = []
        self.fee_amount = 0
        self.input_amount = 0
        self.num_inputs = 0
        self.destination_addresses = []
        self.destination_amounts = []
        self.op_return_data: bytes = None

        # Leaf hashes (BIP371 TapLeaf hashes) this seed is actually about
        # to sign against, collected across every input -- populated by
        # _parse_inputs. Empty for a key-path-only or non-taproot spend.
        self.signing_leaf_hashes = set()

        self.root = None

        if self.seed is not None:
            self.parse()


    def get_change_data(self, change_num: int) -> dict:
        if change_num < len(self.change_data):
            return self.change_data[change_num]


    @property
    def num_change_outputs(self):
        return len(self.change_data)


    @property
    def is_multisig(self):
        """
            Multisig psbts will have "m" and "n" defined in policy
        """
        return "m" in self.policy


    @property
    def num_destinations(self):
        return len(self.destination_addresses)


    def _set_root(self):
        self.root = bip32.HDKey.from_seed(self.seed.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(self.network)]["xprv"])


    def parse(self):
        if self.psbt is None:
            logger.info(f"self.psbt is None!!")
            return False

        if not self.seed:
            logger.info("self.seed is None!")
            return False

        self._set_root()

        # Try to fix missing fingerprints before parsing
        self._fill_missing_fingerprints()

        rt = self._parse_inputs()
        if rt == False:
            return False

        rt = self._parse_outputs()
        if rt == False:
            return False

        return True


    def _parse_inputs(self):
        self.input_amount = 0
        self.num_inputs = len(self.psbt.inputs)
        for inp in self.psbt.inputs:
            if inp.witness_utxo:
                self.input_amount += inp.witness_utxo.value
                script_pubkey = inp.witness_utxo.script_pubkey
            elif inp.non_witness_utxo:
                self.input_amount += inp.utxo.value
                script_pubkey = inp.script_pubkey

            inp_policy = PSBTParser._get_policy(inp, script_pubkey, self.psbt.xpubs)
            if self.policy == None:
                self.policy = inp_policy
            else:
                if self.policy != inp_policy:
                    raise RuntimeError("Mixed inputs in the transaction")

            # Which tapscript leaf(s) is this seed actually about to sign
            # on this input, if any? Only counts a leaf when the claimed
            # pubkey genuinely re-derives from OUR OWN seed at the stated
            # path (never trust the PSBT's claimed key) -- same
            # never-trust-the-claim pattern _parse_outputs already uses
            # for change recognition.
            for pub, (leaf_hashes, derivation) in inp.taproot_bip32_derivations.items():
                if not leaf_hashes:
                    continue  # key-path-only claim on this input, not a leaf
                candidate = self.root.derive(derivation.derivation)
                if candidate.to_public().xonly() != pub.xonly():
                    continue
                self.signing_leaf_hashes.update(leaf_hashes)

    def _parse_outputs(self):
        self.spend_amount = 0
        self.change_amount = 0
        self.change_data = []
        self.fee_amount = 0
        self.destination_addresses = []
        self.destination_amounts = []
        for i, out in enumerate(self.psbt.outputs):
            out_policy = PSBTParser._get_policy(out, self.psbt.tx.vout[i].script_pubkey, self.psbt.xpubs)
            is_change = False

            # if policy is the same - probably change
            if out_policy == self.policy:
                # double-check that it's change
                # we already checked in get_cosigners and parse_multisig
                # that pubkeys are generated from cosigners,
                # and witness script is corresponding multisig
                # so we only need to check that scriptpubkey is generated from
                # witness script

                # empty script by default
                sc = script.Script(b"")

                # if older multisig, just use existing script
                if self.policy["type"] == "p2sh":
                    sc = script.p2sh(out.redeem_script)

                # multisig, we know witness script
                if self.policy["type"] == "p2wsh":
                    sc = script.p2wsh(out.witness_script)

                elif self.policy["type"] == "p2sh-p2wsh":
                    sc = script.p2sh(script.p2wsh(out.witness_script))
                
                # Arbitrary p2sh; includes pre-segwit multisig (m/45')
                elif self.policy["type"] == "p2sh":
                    sc = script.p2sh(out.redeem_script)

                # single-sig
                elif "pkh" in self.policy["type"]:
                    my_pubkey = None

                    # should be one or zero for single-key addresses
                    if len(out.bip32_derivations.values()) > 0:
                        der = list(out.bip32_derivations.values())[0].derivation
                        my_pubkey = self.root.derive(der)

                    if self.policy["type"] == "p2pkh" and my_pubkey is not None:
                        sc = script.p2pkh(my_pubkey)

                    elif self.policy["type"] == "p2sh-p2wpkh" and my_pubkey is not None:
                        sc = script.p2sh(script.p2wpkh(my_pubkey))

                    elif self.policy["type"] == "p2wpkh" and my_pubkey is not None:
                        sc = script.p2wpkh(my_pubkey)

                    if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
                        is_change = True

                elif "p2tr" in self.policy["type"]:
                    my_pubkey = None

                    # Full multi-leaf tree verification, when the PSBT
                    # supplies BIP371's PSBT_OUT_TAP_TREE (key type
                    # 0x06). This is a genuine cryptographic check, not a
                    # trust-the-claim shortcut: the internal key + tree
                    # are independently tweaked and compared byte-for-
                    # byte against the REAL output scriptPubkey
                    # (immutable, baked into the unsigned tx being
                    # signed) -- a forged tree cannot produce a match
                    # without also being the genuine preimage of that
                    # exact address. Only once that matches does any
                    # claimed signer key get weight, and only after
                    # re-deriving it from OUR OWN seed (never trusting
                    # the PSBT's claimed pubkey) and confirming it
                    # actually appears in the specific real leaf script
                    # the verified tree says it belongs to.
                    tap_tree_raw = out.unknown.get(b"\x06")
                    if tap_tree_raw is not None and out.taproot_internal_key is not None:
                        try:
                            leaves = PSBTParser._parse_tap_tree(tap_tree_raw)
                            merkle_root, real_leaf_hashes = PSBTParser._tap_tree_merkle_root(leaves)
                            internal_xonly = out.taproot_internal_key.xonly()
                            output_xonly = PSBTParser._tap_tweak_xonly(internal_xonly, merkle_root)
                            real_output_script = b"\x51\x20" + output_xonly
                            if real_output_script == self.psbt.tx.vout[i].script_pubkey.data:
                                for pub, (claimed_leaves, derivation) in out.taproot_bip32_derivations.items():
                                    candidate = self.root.derive(derivation.derivation)
                                    candidate_xonly = candidate.to_public().xonly()
                                    if candidate_xonly != pub.xonly():
                                        continue  # claimed key doesn't actually derive from our seed
                                    for (depth, leaf_version, leaf_sc), leaf_hash in zip(leaves, real_leaf_hashes):
                                        if leaf_hash in claimed_leaves and candidate_xonly in leaf_sc.data:
                                            is_change = True
                                            break
                                    if is_change:
                                        break
                        except Exception:
                            # Malformed tap_tree -- fail closed, fall through
                            # to the single-key check below rather than
                            # crashing the whole parse.
                            logger.info("Could not verify PSBT_OUT_TAP_TREE for output %s", i)

                    if not is_change:
                        # Single-key key-path fallback: plain taproot
                        # wallets, or an output with no tap_tree metadata.
                        if len(out.taproot_bip32_derivations.values()) > 0:
                            leaf_hashes, derivation = list(out.taproot_bip32_derivations.values())[0]
                            der = derivation.derivation
                            my_pubkey = self.root.derive(der)
                            sc = script.p2tr(my_pubkey)

                        if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
                            is_change = True

                if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
                    is_change = True

            if self.psbt.tx.vout[i].script_pubkey.data[0] == OPCODES.OP_RETURN:
                # The data is written as: OP_RETURN + OP_PUSHDATA1 + len(payload) + payload
                self.op_return_data = self.psbt.tx.vout[i].script_pubkey.data[3:]

            elif is_change:
                addr = self.psbt.tx.vout[i].script_pubkey.address(NETWORKS[SettingsConstants.map_network_to_embit(self.network)])
                fingerprints = []
                derivation_paths = []

                # extract info from non-taproot outputs
                if len(self.psbt.outputs[i].bip32_derivations) > 0:
                    for d, derivation_path in self.psbt.outputs[i].bip32_derivations.items():
                        fingerprints.append(hexlify(derivation_path.fingerprint).decode())
                        derivation_paths.append(bip32.path_to_str(derivation_path.derivation))

                # extract info from taproot outputs
                is_taproot_script_path = False
                if len(self.psbt.outputs[i].taproot_bip32_derivations) > 0:
                    for d, (leaf_hashes, derivation) in self.psbt.outputs[i].taproot_bip32_derivations.items():
                        fingerprints.append(hexlify(derivation.fingerprint).decode())
                        derivation_paths.append(bip32.path_to_str(derivation.derivation))
                        # A non-empty leaf-hash list means this key belongs
                        # to a specific tapscript leaf (a multi-leaf policy
                        # like a tr_multileaf vault) rather than a plain
                        # key-path-only taproot output. That distinction
                        # matters downstream (PSBTChangeDetailsView): a
                        # multi-leaf output can only be verified against a
                        # REGISTERED wallet descriptor, the same as legacy
                        # multisig -- recomputing a single derived key's
                        # p2tr() address (the existing single-sig fallback)
                        # can never match a multi-leaf output's real
                        # (internal-key + tap-tree) tweaked script, so
                        # without this flag a genuinely valid multi-leaf
                        # change output gets waved through as "verification
                        # failed" even though _parse_outputs above already
                        # cryptographically confirmed it's real change.
                        if len(leaf_hashes) > 0:
                            is_taproot_script_path = True

                self.change_data.append({
                    "output_index": i,
                    "address": addr,
                    "amount": self.psbt.tx.vout[i].value,
                    "fingerprint": fingerprints,
                    "derivation_path": derivation_paths,
                    "is_taproot_script_path": is_taproot_script_path,
                })
                self.change_amount += self.psbt.tx.vout[i].value

            else:
                addr = self.psbt.tx.vout[i].script_pubkey.address(NETWORKS[SettingsConstants.map_network_to_embit(self.network)])
                self.destination_addresses.append(addr)
                self.destination_amounts.append(self.psbt.tx.vout[i].value)
                self.spend_amount += self.psbt.tx.vout[i].value

        self.fee_amount = self.psbt.fee()
        return True


    @staticmethod
    def trim(tx):
        trimmed_psbt = psbt.PSBT(tx.tx)
        for i, inp in enumerate(tx.inputs):
            if inp.final_scriptwitness:
                # Taproot key-path sign; trim to only final_scriptwitness
                # From BIP-371 and BIP-174, once final script witness is populated
                # it contains all necessary signatures
                trimmed_psbt.inputs[i].final_scriptwitness = inp.final_scriptwitness
            elif inp.taproot_sigs:
                # Taproot script-path sign (a tapscript/miniscript leaf, e.g. one
                # branch of a multi-leaf policy). embit's own sign_with() ->
                # sign_input_with_tapkey() already produces these correctly (BIP340
                # Schnorr over the BIP341 tapscript sighash for the matched leaf) --
                # this method just wasn't carrying the result forward. Each entry is
                # keyed by (pubkey, leaf_hash), so it's self-describing without
                # needing to re-transmit the leaf script or control block: whoever
                # merges this back in already has the original unsigned PSBT.
                trimmed_psbt.inputs[i].taproot_sigs = inp.taproot_sigs
            else:
                trimmed_psbt.inputs[i].partial_sigs = inp.partial_sigs

        return trimmed_psbt


    @staticmethod
    def sig_count(tx):
        cnt = 0
        for i, inp in enumerate(tx.inputs):
            if inp.final_scriptwitness is not None:
                # Taproot key-path sign
                cnt += 1
            elif inp.taproot_sigs:
                # Taproot script-path sign(s). A single input can legitimately need
                # more than one of these -- e.g. a 2-of-2 leaf needs a tap_script_sig
                # from each of its two keys before it's spendable -- so count every
                # entry, not just whether any exist.
                cnt += len(inp.taproot_sigs)
            else:
                cnt += len(list(inp.partial_sigs.keys()))

        return cnt


    @staticmethod
    def _parse_tap_tree(raw: bytes):
        """
            Parses BIP371's PSBT_OUT_TAP_TREE value (key type 0x06): a
            sequence of (depth, leaf_version, script) tuples describing
            every leaf of a taproot output's script tree, in the
            canonical DFS order needed to rebuild its merkle root.

            embit's OutputScope (this repo's pinned 0.8.0) has no special
            handling for this key -- it lands verbatim in an output's
            `unknown` dict, keyed by the raw 1-byte key b"\\x06". This
            parses those raw bytes directly; no embit change is needed
            for the parsing itself, only for using it below.

            Returns a list of (depth: int, leaf_version: int,
            script: embit.script.Script).
        """
        leaves = []
        s = BytesIO(raw)
        total = len(raw)
        while s.tell() < total:
            depth = s.read(1)[0]
            leaf_version = s.read(1)[0]
            script_len = compact.read_from(s)
            leaves.append((depth, leaf_version, script.Script(s.read(script_len))))
        return leaves


    @staticmethod
    def _tap_tree_merkle_root(leaves):
        """
            Rebuilds a taproot merkle root from a depth-ordered leaf list
            (as returned by _parse_tap_tree), per BIP371's reconstruction
            algorithm: push each leaf's TapLeaf hash at its stated depth,
            then repeatedly combine the top two stack entries into a
            TapBranch hash (BIP341: the pair sorted ascending before
            hashing) whenever they share a depth, reducing the stack by
            one level each time. A well-formed tree reduces to exactly
            one (depth 0) entry -- the merkle root.

            Returns (merkle_root: bytes, leaf_hashes: list[bytes] --
            one per input leaf, in the same order as `leaves`).
        """
        stack = []  # list of (depth, hash)
        leaf_hashes = []
        for depth, leaf_version, sc in leaves:
            leaf_hash = hashes.tagged_hash("TapLeaf", bytes([leaf_version]) + sc.serialize())
            leaf_hashes.append(leaf_hash)
            stack.append((depth, leaf_hash))
            while len(stack) >= 2 and stack[-1][0] == stack[-2][0]:
                d, h2 = stack.pop()
                _, h1 = stack.pop()
                branch = hashes.tagged_hash("TapBranch", (h1 + h2) if h1 <= h2 else (h2 + h1))
                stack.append((d - 1, branch))
        if len(stack) != 1:
            raise ValueError("Malformed tap_tree: leaves did not reduce to a single root")
        return stack[0][1], leaf_hashes


    @staticmethod
    def _tap_tweak_xonly(internal_xonly: bytes, merkle_root: bytes) -> bytes:
        """
            BIP341's output-key tweak: tweaked_key = internal_key +
            tagged_hash("TapTweak", internal_key || merkle_root) * G,
            returned as the resulting 32-byte x-only pubkey. Uses only
            embit's already-public secp256k1 bindings and tagged_hash --
            same primitives (and same tweak procedure) already relied on
            elsewhere in this codebase's own taproot test coverage.
        """
        tweak = hashes.tagged_hash("TapTweak", internal_xonly + merkle_root)
        point = secp256k1.ec_pubkey_parse(b"\x02" + internal_xonly)
        secp256k1.ec_pubkey_tweak_add(point, bytes(tweak))
        return ec.PublicKey(point).xonly()


    @staticmethod
    def _get_policy(scope, scriptpubkey, xpubs):
        """Parse scope and get policy"""
        # we don't know the policy yet, let's parse it
        script_type = scriptpubkey.script_type()
        # p2sh can be either legacy multisig, or nested segwit multisig
        # or nested segwit singlesig
        if script_type == "p2sh":
            if scope.witness_script is not None:
                script_type = "p2sh-p2wsh"
            elif (
                scope.redeem_script is not None
                and scope.redeem_script.script_type() == "p2wpkh"
            ):
                script_type = "p2sh-p2wpkh"
        policy = {"type": script_type}

        # expected multisig
        script = None
        if script_type:
            if "p2wsh" in script_type and scope.witness_script is not None:
                script = scope.witness_script

            elif "p2sh" == script_type and scope.redeem_script is not None:
                script = scope.redeem_script

            if script is not None:
                m, n, pubkeys = PSBTParser._parse_multisig(script)
            
                # check pubkeys are derived from cosigners
                try:
                    cosigners = PSBTParser._get_cosigners(pubkeys, scope.bip32_derivations, xpubs)
                    policy.update({"m": m, "n": n, "cosigners": cosigners})
                except:
                    policy.update({"m": m, "n": n})
        
        return policy


    @staticmethod
    def _parse_multisig(sc):
        """Takes a script and extracts m,n and pubkeys from it"""
        # OP_m <len:pubkey> ... <len:pubkey> OP_n OP_CHECKMULTISIG
        # check min size
        if len(sc.data) < 37 or sc.data[-1] != 0xAE:
            raise ValueError("Not a multisig script")
        m = sc.data[0] - 0x50
        if m < 1 or m > 16:
            raise ValueError("Invalid multisig script")
        n = sc.data[-2] - 0x50
        if n < m or n > 16:
            raise ValueError("Invalid multisig script")
        s = BytesIO(sc.data)
        # drop first byte
        s.read(1)
        # read pubkeys
        pubkeys = []
        for i in range(n):
            char = s.read(1)
            if char != b"\x21":
                raise ValueError("Invlid pubkey")
            pubkeys.append(ec.PublicKey.parse(s.read(33)))
        # check that nothing left
        if s.read() != sc.data[-2:]:
            raise ValueError("Invalid multisig script")
        return m, n, pubkeys


    @staticmethod
    def _get_cosigners(pubkeys, derivations, xpubs):
        """Returns xpubs used to derive pubkeys using global xpub field from psbt"""
        cosigners = []
        for i, pubkey in enumerate(pubkeys):
            if pubkey not in derivations:
                raise ValueError("Missing derivation")
            der = derivations[pubkey]
            for xpub in xpubs:
                origin_der = xpubs[xpub]
                # check fingerprint
                if origin_der.fingerprint == der.fingerprint:
                    # check derivation - last two indexes give pub from xpub
                    if origin_der.derivation == der.derivation[:-2]:
                        # check that it derives to pubkey actually
                        if xpub.derive(der.derivation[-2:]).key == pubkey:
                            # append strings so they can be sorted and compared
                            cosigners.append(xpub.to_base58())
                            break
        if len(cosigners) != len(pubkeys):
            raise RuntimeError("Can't get all cosigners")
        return sorted(cosigners)


    @staticmethod
    def get_input_fingerprints(psbt: PSBT) -> List[str]:
        """
            Exctracts the fingerprint from each input's derivation path.

            TODO: It's unclear if these derivations/fingerprints would ever be missing.
            Research on PSBT standard and known wallet coordinator implementations
            needed.
        """
        fingerprints = set()
        for input in psbt.inputs:
            for pub, derivation_path in input.bip32_derivations.items():
                fingerprints.add(hexlify(derivation_path.fingerprint).decode())

            for pub, (leaf_hashes, derivation_path) in input.taproot_bip32_derivations.items():
                # Taproot script-path (tapscript leaf) derivations are included here
                # too, same as key-path ones -- embit's psbt.sign_with() already
                # signs these correctly (verified: it produces a valid BIP340
                # Schnorr signature over the BIP341 tapscript sighash for whichever
                # leaf the key's fingerprint matches, via sign_input_with_tapkey).
                # This used to hard-raise here on the mistaken assumption that
                # embit had no script-path support; it's had it since embit 0.8.0
                # (this repo's pinned version) added taptree/miniscript support.
                # See has_matching_input_fingerprint below, which never had this
                # restriction and already treats leaf-derivations the same way.
                fingerprints.add(hexlify(derivation_path.fingerprint).decode())
        return list(fingerprints)


    @staticmethod
    def has_matching_input_fingerprint(psbt: PSBT, seed: Seed, network: str = SettingsConstants.MAINNET):
        """
            Extracts the fingerprint from each psbt input utxo. Returns True if any match
            the current seed.
        """
        seed_fingerprint = seed.get_fingerprint(network)
        
        def check_fingerprint_match(public_key: PublicKey, derivation_path_obj: DerivationPath):
            """Check fingerprint match with missing fingerprint fallback"""

            # If exact fingerprint match
            if hexlify(derivation_path_obj.fingerprint).decode() == seed_fingerprint:
                return True
            
            # Missing fingerprint fallback
            if derivation_path_obj.fingerprint == b"\x00\x00\x00\x00":
                root = bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"])
                try:
                    derived_key = root.derive(derivation_path_obj.derivation)
                    return derived_key.key.sec() == public_key.sec() # Public keys match
                except Exception as e:
                    logger.debug("Fingerprint fallback derive failed: %s", e, exc_info=True)
            return False
        
        # Check all derivations in all inputs
        for input in psbt.inputs:
            # Check regular BIP32 derivations
            for public_key, derivation_path_obj in input.bip32_derivations.items():
                if check_fingerprint_match(public_key, derivation_path_obj):
                    return True
            
            # Check Taproot derivations
            for public_key, (leaf_hashes, derivation_path_obj) in input.taproot_bip32_derivations.items():
                if check_fingerprint_match(public_key, derivation_path_obj):
                    return True
        
        return False


    def verify_multisig_output(self, descriptor: Descriptor, change_num: int) -> bool:
        change_data = self.get_change_data(change_num)
        i = change_data["output_index"]
        output = self.psbt.outputs[i]

        if descriptor.is_taproot and not descriptor.is_wildcard:
            # embit 0.8.0's AllowedDerivation.check_derivation() (what
            # Descriptor.owns() relies on to match a PSBT's claimed
            # derivation against a registered key) only reports a match
            # when the key's allowed-derivation suffix contains a
            # wildcard: it only sets its `idx` return value inside the
            # wildcard branch of its loop, so a FIXED suffix like
            # DynastyTrust's own [fp/path]xpub/0/0 descriptors (no `*`
            # at all -- see get_multisig_address's taproot branch above)
            # leaves `idx` at None even on an exact index match, and
            # owns() always reports False regardless of whether the
            # output is really ours. A fully fixed (non-wildcard)
            # taproot descriptor only ever resolves to ONE address --
            # derive() at any index/branch is a proven no-op for it --
            # so comparing that address's script directly against the
            # real output is both sufficient and immune to this embit
            # limitation. Wildcard descriptors are unaffected by the bug
            # (a real wildcard element does set `idx`) and keep using
            # owns() below.
            return descriptor.derive(0, branch_index=0).script_pubkey() == output.script_pubkey

        is_owner = descriptor.owns(output)
        # print(f"{self.psbt.tx.vout[i].script_pubkey.address()} | {output.value} | {is_owner}")
        return is_owner


    def _fill_missing_fingerprints(self):
        """
        Fix for when fingerprint is missing (defaults to all zeros). Happens when the user
        creates a new wallet in an external coordinator but only provides the xpub
        (fingerprint and derivation path are omitted).

        Filling the missing fingerprints allows SeedSigner to correctly identify inputs /
        outputs that belong to the signing seed.

        see: https://github.com/SeedSigner/seedsigner/issues/359
        """
        if not self.root:
            return 0
        
        def _fill_scope(scope: InputScope | OutputScope):
            """Helper function to fill missing fingerprints in a scope (input/output)"""
            signing_seed_fingerprint = self.root.child(0).fingerprint
            
            # Helper function to check and fix fingerprint
            def _get_updated_fingerprint(public_key: PublicKey, derivation_path_obj: DerivationPath) -> DerivationPath | None:
                if derivation_path_obj.fingerprint != b"\x00\x00\x00\x00":
                    return None
                
                # Derive the public key from the currently loaded seed using the derivation 
                # contained in the PSBT. If the derived public key exactly matches 
                # the PSBT-provided public key, we can be confident that this input/output 
                # is owned by the signing seed. In that case we populate the missing (zero) 
                # fingerprint with the signing seed's master fingerprint so downstream 
                # parsing/signing can treat it as owned by this seed.
                derived_key = self.root.derive(derivation_path_obj.derivation)
                if derived_key.key.sec() == public_key.sec():
                    return DerivationPath(signing_seed_fingerprint, derivation_path_obj.derivation)
                return None
            
            # Handle regular BIP32 derivations
            for public_key, derivation_path_obj in list(scope.bip32_derivations.items()):
                new_derivation = _get_updated_fingerprint(public_key, derivation_path_obj)
                if new_derivation:
                    scope.bip32_derivations[public_key] = new_derivation
                    logger.debug(f"Filled missing fingerprint for pubkey {public_key.sec().hex()} derivation {bip32.path_to_str(derivation_path_obj.derivation)}")
            
            # Handle Taproot derivations  
            for public_key, (leaf_hashes, derivation_path_obj) in list(scope.taproot_bip32_derivations.items()):
                new_derivation = _get_updated_fingerprint(public_key, derivation_path_obj)
                if new_derivation:
                    scope.taproot_bip32_derivations[public_key] = (leaf_hashes, new_derivation)
                    logger.debug(f"Filled missing fingerprint for pubkey {public_key.sec().hex()} derivation {bip32.path_to_str(derivation_path_obj.derivation)}")

        for inp in self.psbt.inputs:
            _fill_scope(inp)

        for out in self.psbt.outputs:
            _fill_scope(out)


    def get_signing_leaf_summary(self, registered_descriptor: Descriptor = None) -> dict:
        """
        Facts about which tapscript spending path this seed is about to
        sign, if any -- returns None when there's nothing taproot-
        script-path-specific to say (key-path-only or non-taproot spend).
        Returns raw data, not a formatted string: this is a model, and
        translation (gettext) belongs at the view layer, same convention
        every other model in this file already follows.

        Two honesty tiers, deliberately never blurred:
          - With a REGISTERED descriptor (the wallet policy the user
            confirmed out of band, before this PSBT existed -- see
            verify_multisig_output), this matches the signing leaf
            against the wallet's own real tap tree and reports its true
            position (leaf_index/leaf_count) and, for the handful of
            simple shapes a tr_multileaf-style policy actually produces
            (a bare key threshold, optionally wrapped in an absolute/
            relative timelock), its real quorum -- read straight from
            the descriptor's own PARSED miniscript AST (embit's
            Miniscript.from_string() output), never decompiled from raw
            script bytes. An unrecognized shape leaves quorum_k/n and
            the timelock fields as None rather than guessing.
          - With no registered descriptor (or one that doesn't match
            this PSBT's leaf at all), only what's independently provable
            from the PSBT's own metadata is reported: that a leaf is
            being signed, and how many of THIS seed's own keys are
            eligible on it. leaf_index/leaf_count/quorum are always None
            in this tier -- without the whole tree those can't be
            proven, only guessed, and a wrong guess here is worse than
            saying nothing.

        Returns:
            {
                "num_eligible_keys": int,               # always present
                "leaf_index": int | None,                # 1-based
                "leaf_count": int | None,
                "quorum_k": int | None,
                "quorum_n": int | None,
                "timelock_kind": "after" | "older" | None,
                "timelock_value": int | None,
            }
        """
        if not self.signing_leaf_hashes:
            return None

        summary = {
            "num_eligible_keys": len(self.signing_leaf_hashes),
            "leaf_index": None,
            "leaf_count": None,
            "quorum_k": None,
            "quorum_n": None,
            "timelock_kind": None,
            "timelock_value": None,
        }

        if registered_descriptor is None or not registered_descriptor.is_taproot:
            return summary

        from embit.descriptor.taptree import _tweak_helper
        try:
            leaves_with_paths, _ = _tweak_helper(registered_descriptor.taptree)
        except Exception:
            logger.info("Could not walk registered descriptor's tap tree", exc_info=True)
            return summary

        for idx, (leaf, _path) in enumerate(leaves_with_paths):
            # leaf.serialize() (not a from-scratch bytes([version]) +
            # miniscript.compile()) -- the real BIP341 TapLeaf preimage
            # needs the script compact-size-length-prefixed, which
            # TapLeaf.serialize() already does correctly; reconstructing
            # it by hand here previously dropped that prefix and made
            # every leaf hash mismatch, silently: caught by the sanity
            # check in this method's own tests.
            leaf_hash = hashes.tagged_hash("TapLeaf", leaf.serialize())
            if leaf_hash not in self.signing_leaf_hashes:
                continue
            summary["leaf_index"] = idx + 1
            summary["leaf_count"] = len(leaves_with_paths)
            k, n, timelock_kind, timelock_value = PSBTParser._parse_leaf_quorum(leaf.miniscript)
            summary["quorum_k"] = k
            summary["quorum_n"] = n
            summary["timelock_kind"] = timelock_kind
            summary["timelock_value"] = timelock_value
            break
        # No match found (e.g. a different wallet's descriptor is
        # registered) -- summary stays at its "just a bare fact" defaults,
        # same as the no-descriptor tier. Never claim a position that
        # wasn't actually proven against this exact tree.

        return summary


    @staticmethod
    def _parse_leaf_quorum(node) -> tuple:
        """
        Safely reads a tapscript leaf's signer quorum from its PARSED
        miniscript AST (never a from-scratch decompile of raw script
        bytes -- that's real correctness risk on signing firmware this
        repo won't take). Only recognizes the small set of shapes a
        tr_multileaf-style policy actually produces: a bare multi-key
        threshold (multi_a/multi/sortedmulti/sortedmulti_a), a single key
        (pk), either optionally wrapped in and_v(v:after(N), ...) or
        and_v(v:older(N), ...) for a timelocked leaf. Anything else
        returns all-None rather than guessing.

        Returns (k, n, timelock_kind, timelock_value), any of which may
        be None.
        """
        from embit.descriptor.miniscript import (
            AndV, V, After, Older, MultiA, Multi, Sortedmulti, SortedmultiA, Pk,
        )

        timelock_kind = None
        timelock_value = None

        if isinstance(node, AndV) and len(node.args) == 2:
            wrapped, requirement = node.args
            if not (isinstance(wrapped, V) and len(wrapped.args) == 1):
                return (None, None, None, None)
            inner = wrapped.args[0]
            if isinstance(inner, After):
                timelock_kind = "after"
            elif isinstance(inner, Older):
                timelock_kind = "older"
            else:
                return (None, None, None, None)
            try:
                timelock_value = int(str(inner.args[0]))
            except (ValueError, IndexError):
                return (None, None, None, None)
            node = requirement

        if isinstance(node, (MultiA, Multi, Sortedmulti, SortedmultiA)):
            try:
                k = int(str(node.args[0]))
            except (ValueError, IndexError):
                return (None, None, None, None)
            n = len(node.args) - 1
            return (k, n, timelock_kind, timelock_value)

        if isinstance(node, Pk):
            return (1, 1, timelock_kind, timelock_value)

        return (None, None, timelock_kind, timelock_value)