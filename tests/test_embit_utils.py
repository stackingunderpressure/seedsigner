import pytest

from seedsigner.models.settings_definition import SettingsConstants as SC
from seedsigner.helpers import embit_utils


def test_get_standard_derivation_path():
    """
    tests seedsigner.helpers.embit_utils.get_standard_derivation_path()
    """

    vectors_args_expected = {
        # single sig
        tuple(): "m/84'/0'/0'",
        (SC.MAINNET,): "m/84'/0'/0'",
        (SC.MAINNET, SC.SINGLE_SIG, ): "m/84'/0'/0'",

        (SC.MAINNET, SC.SINGLE_SIG, SC.NATIVE_SEGWIT): "m/84'/0'/0'",
        (SC.TESTNET, SC.SINGLE_SIG, SC.NATIVE_SEGWIT): "m/84'/1'/0'",
        (SC.REGTEST, SC.SINGLE_SIG, SC.NATIVE_SEGWIT): "m/84'/1'/0'",

        (SC.MAINNET, SC.SINGLE_SIG, SC.NESTED_SEGWIT): "m/49'/0'/0'",
        (SC.TESTNET, SC.SINGLE_SIG, SC.NESTED_SEGWIT): "m/49'/1'/0'",
        (SC.REGTEST, SC.SINGLE_SIG, SC.NESTED_SEGWIT): "m/49'/1'/0'",

        (SC.MAINNET, SC.SINGLE_SIG, SC.TAPROOT): "m/86'/0'/0'",
        (SC.TESTNET, SC.SINGLE_SIG, SC.TAPROOT): "m/86'/1'/0'",
        (SC.REGTEST, SC.SINGLE_SIG, SC.TAPROOT): "m/86'/1'/0'",

        (SC.MAINNET, SC.SINGLE_SIG, SC.LEGACY_P2PKH): "m/44'/0'/0'",
        (SC.TESTNET, SC.SINGLE_SIG, SC.LEGACY_P2PKH): "m/44'/1'/0'",
        (SC.REGTEST, SC.SINGLE_SIG, SC.LEGACY_P2PKH): "m/44'/1'/0'",


        # multi sig
        (SC.MAINNET, SC.MULTISIG, SC.NATIVE_SEGWIT): "m/48'/0'/0'/2'",
        (SC.TESTNET, SC.MULTISIG, SC.NATIVE_SEGWIT): "m/48'/1'/0'/2'",
        (SC.REGTEST, SC.MULTISIG, SC.NATIVE_SEGWIT): "m/48'/1'/0'/2'",

        (SC.MAINNET, SC.MULTISIG, SC.NESTED_SEGWIT): "m/48'/0'/0'/1'",
        (SC.TESTNET, SC.MULTISIG, SC.NESTED_SEGWIT): "m/48'/1'/0'/1'",
        (SC.REGTEST, SC.MULTISIG, SC.NESTED_SEGWIT): "m/48'/1'/0'/1'",

        (SC.MAINNET, SC.MULTISIG, SC.TAPROOT): Exception,
        (SC.TESTNET, SC.MULTISIG, SC.TAPROOT): Exception,
        (SC.REGTEST, SC.MULTISIG, SC.TAPROOT): Exception,

        (SC.MAINNET, SC.MULTISIG, SC.LEGACY_P2PKH): "m/45'",

        # intentionally fall into exceptions
        (SC.MAINNET, SC.SINGLE_SIG, 'invalid'): Exception,
        (SC.MAINNET, SC.MULTISIG, 'invalid'): Exception,
        (SC.MAINNET, 'invalid', SC.NATIVE_SEGWIT): Exception,

        # nonsense arguments
        ("A",): Exception,
        ("B", "A"): Exception,
        ("C", "B", "A"): Exception,
        (True,): Exception,
        (False, True): Exception,
        (tuple(),): Exception,
    }
    func = embit_utils.get_standard_derivation_path

    print()
    for args, expected in vectors_args_expected.items():

        # test successful calls
        if type(expected) is str:
            # call with ordered params
            print(f"asserting {func.__name__}(*{args}) == {repr(expected)}")
            assert func(*args) == expected

            # call with named params
            a_dict = {}
            if len(args) == 1: a_dict = {'network': args[0]}
            elif len(args) == 2: a_dict = {'network': args[0], 'wallet_type': args[1]}
            elif len(args) == 3: a_dict = {'network': args[0], 'wallet_type': args[1], 'script_type': args[2]}
            print(f"asserting {func.__name__}(**{a_dict}) == {repr(expected)}")
            assert func(**a_dict) == expected

        # test exceptions
        else: 
            # call with ordered params
            with pytest.raises(expected):
                print(f"asserting {func.__name__}(*{args}) raises Exception")
                func(*args)

            # call with named params
            a_dict = {}
            if len(args) == 1: a_dict = {'network': args[0]}
            elif len(args) == 2: a_dict = {'network': args[0], 'wallet_type': args[1]}
            elif len(args) == 3: a_dict = {'network': args[0], 'wallet_type': args[1], 'script_type': args[2]}
            print(f"asserting {func.__name__}(**{a_dict}) raises Exception")
            with pytest.raises(expected):
                func(**a_dict)


def test_get_xpub():
    """
    tests seedsigner.helpers.embit_utils.get_xpub()
    """

    from binascii import unhexlify
    from embit import bip39, bip32

    # test vectors originate from:
    #   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    #   https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
    #   https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    #   https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
    #   https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
    vector_seeds = (
        unhexlify("000102030405060708090a0b0c0d0e0f"),
        unhexlify("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"),
        unhexlify("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"),
        unhexlify("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"),
        bip39.mnemonic_to_seed("abandon "*11 + "about"),
    )

    vectors_args_expected = {
        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
        (vector_seeds[0], "m/", "main"): "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        (vector_seeds[0], "m/0'", "main"): "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        (vector_seeds[0], "m/0h/1", "main"): "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        (vector_seeds[0], "m/0'/1/2h", "main"): "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        (vector_seeds[0], "m/0'/1/2h/2", "main"): "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        (vector_seeds[0], "m/0'/1/2h/2/1000000000", "main"): "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",

        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-2
        (vector_seeds[1], "m/", "main"): "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        (vector_seeds[1], "m/0", "main"): "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        (vector_seeds[1], "m/0/2147483647'", "main"): "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        (vector_seeds[1], "m/0/2147483647h/1", "main"): "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        (vector_seeds[1], "m/0/2147483647'/1/2147483646h", "main"): "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        (vector_seeds[1], "m/0/2147483647h/1/2147483646'/2", "main"): "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",

        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-3
        (vector_seeds[2], "m/", "main"): "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        (vector_seeds[2], "m/0h", "main"): "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",

        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-4
        (vector_seeds[3], "m/", "main"): "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
        (vector_seeds[3], "m/0'", "main"): "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
        (vector_seeds[3], "m/0h/1'", "main"): "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",

        #
        # embit_utils.get_xpub() returns the generic bip32 version "xpub", NOT the zpub/Zpub/ypub/Ypub extended versions
        #

        # https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors
        # https://github.com/satoshilabs/slips/blob/master/slip-0132.md#bitcoin-test-vectors
        (vector_seeds[4], "m/84'/0'/0'", "main"):
             bip32.HDKey.from_string("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs").to_base58(version=b'\x04\x88\xb2\x1e'),

        # https://github.com/satoshilabs/slips/blob/master/slip-0132.md#bitcoin-test-vectors
        (vector_seeds[4], "m/49'/0'/0'", "main"): 
             bip32.HDKey.from_string("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP").to_base58(version=b'\x04\x88\xb2\x1e'),
        
        # https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki#test-vectors
        (vector_seeds[4], "m/49'/1'/0'", "test"): 
             bip32.HDKey.from_string("upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY").to_base58(version=b'\x04\x35\x87\xcf'),

        # https://github.com/satoshilabs/slips/blob/master/slip-0132.md#bitcoin-test-vectors
        (vector_seeds[4], "m/44'/0'/0'", "main"): 
             bip32.HDKey.from_string("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj").to_base58(version=b'\x04\x88\xb2\x1e'),

        # https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
        (vector_seeds[4], "m/86'/0'/0'", "main"): "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",

    }
    func = embit_utils.get_xpub

    print()
    for args, expected in vectors_args_expected.items():
        print("\nasserting...")

        # call without optional params (default is "main")
        if args[2] == "main":
            print(f'  {func.__name__}({args[0]}, "{args[1]}") == "{expected}"')
            assert str(func(args[0], args[1])) == expected

        # call with ordered params
        print(f'  {func.__name__}(*{args}) == "{expected}"')
        assert str(func(*args)) == expected

        # call with named params
        print(f'  {func.__name__}(seed_bytes={args[0]}, derivation_path="{args[1]}", embit_network="{args[2]}") == "{expected}"')
        assert str(func(seed_bytes=args[0], derivation_path=args[1], embit_network=args[2])) == expected
        

def test_get_single_sig_address():
    """
    tests seedsigner.helpers.embit_utils.get_single_sig_address()
    """

    from embit.bip32 import HDKey

    # test vectors originate from:
    #   https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
    #   https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    #   https://iancoleman.io/bip39/
    #   https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki

    vectors_args_expected = {
        # https://github.com/satoshilabs/slips/blob/master/slip-0132.md#bitcoin-test-vectors (first payment address of native segwit on mainnet)
        (HDKey.from_string("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"), "nat", 0, False, "main"):
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        # jdlcdl: derived via iancoleman test vector for first change address of native segwit on mainnet
        (HDKey.from_string("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"), "nat", 0, True, "main"):
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        
        # https://github.com/satoshilabs/slips/blob/master/slip-0132.md#bitcoin-test-vectors (first payment address of nested segwit on mainnet)
        (HDKey.from_string("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"), "nes", 0, False, "main"):
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        # jdlcdl: derived via iancoleman test vector for first change address of nested segwit on mainnet
        (HDKey.from_string("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"), "nes", 0, True, "main"):
            "34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7",

        # https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki#test-vectors (first payment address of nested segwit on testnet)
        (HDKey.from_string("upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY"), "nes", 0, False, "test"):
            "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
        # jdlcdl: derived via iancoleman test vector for first change address of nested segwit on testnet
        (HDKey.from_string("upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY"), "nes", 0, True, "test"):
            "2MvdUi5o3f2tnEFh9yGvta6FzptTZtkPJC8",

        # https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors (first payment address of taproot on mainnet)
        (HDKey.from_string("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"), "tr", 0, False, "main"):
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",

        # https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors (second payment address of taproot on mainnet)
        (HDKey.from_string("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"), "tr", 1, False, "main"):
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",

        # https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors (first change address of taproot on mainnet)
        (HDKey.from_string("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"), "tr", 0, True, "main"):
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",

        # jdlcdl: derived via electrum m/44'/1'/0 (first payment address p2pkh on testnet)
        (HDKey.from_string("tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba"), "leg", 0, False, "test"):
            "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",

        # jdlcdl: derived via electrum m/44'/1'/0 (first change address p2pkh on testnet)
        (HDKey.from_string("tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba"), "leg", 0, True, "test"):
            "mi8nhzZgGZQthq6DQHbru9crMDerUdTKva",

        # https://github.com/satoshilabs/slips/blob/master/slip-0132.md#bitcoin-test-vectors (first payment address p2pkh on mainnet)
        (HDKey.from_string("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"), "leg", 0, False, "main"):
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",

        # 3rdIteration: derived via electrum m/44'/0'/0 (first change address p2pkh on mainnet)
        (HDKey.from_string("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"), "leg", 0, True, "main"):
            "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH",

        # jdlcdl: nonsense script_type falls off end of function returning None.  TODO: Would it be preferred to "else: raise ValueError"?
        (HDKey.from_string("tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba"), "NONSENSE", 0, True, "test"):
            "None",
    }
    func = embit_utils.get_single_sig_address

    print()
    for args, expected in vectors_args_expected.items():
        print("\nasserting...")

        # call without optional params (defaults: script_type="nat", index=0, is_change=False, embit_network="main")
        if args[1:5] == ("nat", 0, False, "main"):
            print(f'  {func.__name__}(HDKey.from_string("{args[0]}")) == "{expected}"')
            assert str(func(args[0])) == expected

        # call with ordered params
        print(f'  {func.__name__}(HDKey.from_string("{args[0]}"), *{args[1:5]}) == "{expected}"')
        assert str(func(*args)) == expected

        # call with named params
        print(f'  {func.__name__}(xpub=HDKey.from_string("{args[0]}"), script_type="{args[1]}", index={args[2]}, is_change={args[3]}, embit_network="{args[4]}") == "{expected}"')
        assert str(func(xpub=args[0], script_type=args[1], index=args[2], is_change=args[3], embit_network=args[4])) == expected


def test_get_multisig_address():
    """
    tests seedsigner.helpers.embit_utils.get_multisig_address()
    """

    from embit.descriptor import Descriptor

    # jdlcdl: these vectors created with electrum & sparrow as a 2 of 3 multisig based on BIP-39 and BIP-32 standard-path wallets
    #    keystore1 = 0x00*16 = 73c5da0a = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    #    keystore2 = 0x11*16 = 0be174ee = 'baby mass dust captain baby mass dust captain baby mass dust casino'
    #    keystore3 = 0x22*16 = 8d55ff0d = 'captain baby mass dust captain baby mass dust captain baby mass dutch'

    vector_args_expected = { 
        # multisig native segwit on testnet, first payment and change addresses
        ("wsh(sortedmulti(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))#zw6cnrlk" , 0, False, "test"): "tb1q7tpecll8jhp77yqdeyt2t8q5swxmmqeh2v22cqpms5dxlp6p27dqlftet8",
        ("wsh(sortedmulti(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))#zw6cnrlk" , 0, True, "test"): "tb1q7h94ywhfjrpxdfzwl4dcawrg80r4rywswjrh447x4n3e5t3m0jms9jh7pm",

        # multisig nested segwit on testnet, first payment and change addresses
        ("sh(wsh(sortedmulti(2,[73c5da0a/48h/1h/1h/0h/1h]tpubDFH9dgzveyD8yHQb8VrpG8FYAuwcLMHMje2CCcbBo1FpaGzYVtJeYYxcYgRqSTta5utUFts8nPPHs9C2bqoxrey5jia6Dwf9mpwrPq7YvcJ/{0,1}/*,[0be174ee/48h/1h/0h/1h]tpubDEsePyLPkbxbnj6XuKvWwdERHaKkikZxaGJ9sJqmM7okbZXgkNSFiGU6GX6qEes6kD8f9Z9FosYB9UEnBSgBEyEwwJhj4uUcFE1WE8VtKoh/{0,1}/*,[8d55ff0d/48h/1h/0h/1h]tpubDDxNVWk924RTT3vyGLHdSDoZ2JUVX7jUsPcwCQ9MrKHAtJrW5zECTF9rFHCvqu526E4PjHp61hBknts2c5aGexvX7hvCZ8TGPvQFdzxxy59/{0,1}/*)))#2ujlfp73", 0, False, "test"): "2MtgJH28mZWNWU7VRU4ba6ciFbRRGYWZDt3",
        ("sh(wsh(sortedmulti(2,[73c5da0a/48h/1h/1h/0h/1h]tpubDFH9dgzveyD8yHQb8VrpG8FYAuwcLMHMje2CCcbBo1FpaGzYVtJeYYxcYgRqSTta5utUFts8nPPHs9C2bqoxrey5jia6Dwf9mpwrPq7YvcJ/{0,1}/*,[0be174ee/48h/1h/0h/1h]tpubDEsePyLPkbxbnj6XuKvWwdERHaKkikZxaGJ9sJqmM7okbZXgkNSFiGU6GX6qEes6kD8f9Z9FosYB9UEnBSgBEyEwwJhj4uUcFE1WE8VtKoh/{0,1}/*,[8d55ff0d/48h/1h/0h/1h]tpubDDxNVWk924RTT3vyGLHdSDoZ2JUVX7jUsPcwCQ9MrKHAtJrW5zECTF9rFHCvqu526E4PjHp61hBknts2c5aGexvX7hvCZ8TGPvQFdzxxy59/{0,1}/*)))#2ujlfp73", 0, True, "test"): "2NAjjwUQqwD9XRGLeQ6TitSUyMHUz3cLiWm",

        # legacy multisig p2sh on testnet, first payment and change addresses
        ("sh(sortedmulti(2,[8d55ff0d/45h]tpubDANogJ2yfnizHwX7fSi5kUVzybyuPXDhgHB2TR9TUvkSLZFW73cRq4STKFDpx7qjJJiisyq82tbu4CeiYtmKEmT1xoCq9P8BPvXV31HUh6d/{0,1}/*,[0be174ee/45h]tpubDBkeVF2tDNT1Pz7L47iJeBB6RokU12LX6x4E6Ph8T89hmjQfB77q1AMyGwL8qpREVGq9sCJEbWwmnemwNTxnpxGn1di7BGy8jx9wEi5Vahu/{0,1}/*,[73c5da0a/45h]tpubDBKsGC1UqBDNvx9aivFmxZNgeZTUnmsCFGhWrqkLzucUCDePvbWWm3n8tAaAwMmxBG2ihdKCG9fzBdUnMxKx5PrkiqSZFi6Vkv6msUs9ddN/{0,1}/*))#p5t8sa8c", 0, False, "test"): "2NBXci43Y2fagvrFYTg3QmXj2LCPU2oaRFH",
        ("sh(sortedmulti(2,[8d55ff0d/45h]tpubDANogJ2yfnizHwX7fSi5kUVzybyuPXDhgHB2TR9TUvkSLZFW73cRq4STKFDpx7qjJJiisyq82tbu4CeiYtmKEmT1xoCq9P8BPvXV31HUh6d/{0,1}/*,[0be174ee/45h]tpubDBkeVF2tDNT1Pz7L47iJeBB6RokU12LX6x4E6Ph8T89hmjQfB77q1AMyGwL8qpREVGq9sCJEbWwmnemwNTxnpxGn1di7BGy8jx9wEi5Vahu/{0,1}/*,[73c5da0a/45h]tpubDBKsGC1UqBDNvx9aivFmxZNgeZTUnmsCFGhWrqkLzucUCDePvbWWm3n8tAaAwMmxBG2ihdKCG9fzBdUnMxKx5PrkiqSZFi6Vkv6msUs9ddN/{0,1}/*))#p5t8sa8c", 0, True, "test"): "2MuWQTq7hUGiX1HpXuPRnf7YTM42H5zoEwj",

        # multisig taproot on testnet, not supported
        # TODO: find what a multisig-taproot descriptor would look like and add a test so we can fall into the last condition exception.

        # some policy that is not supported:
        # TODO: find anything non supported so we can drop off the function: Would it be preferred to "else: raise ValueError()"?
        #("sh(multi(2,[8d55ff0d/45h]tpubDANogJ2yfnizHwX7fSi5kUVzybyuPXDhgHB2TR9TUvkSLZFW73cRq4STKFDpx7qjJJiisyq82tbu4CeiYtmKEmT1xoCq9P8BPvXV31HUh6d/{0,1}/*,[0be174ee/45h]tpubDBkeVF2tDNT1Pz7L47iJeBB6RokU12LX6x4E6Ph8T89hmjQfB77q1AMyGwL8qpREVGq9sCJEbWwmnemwNTxnpxGn1di7BGy8jx9wEi5Vahu/{0,1}/*,[73c5da0a/45h]tpubDBKsGC1UqBDNvx9aivFmxZNgeZTUnmsCFGhWrqkLzucUCDePvbWWm3n8tAaAwMmxBG2ihdKCG9fzBdUnMxKx5PrkiqSZFi6Vkv6msUs9ddN/{0,1}/*))#", 0, False, "test"): None,

    }
    func = embit_utils.get_multisig_address

    print()
    for args, expected in vector_args_expected.items():
        descriptor = Descriptor.from_string(args[0])

        print("\nasserting...")

        # test successful calls
        if type(expected) == str:
            # call with optional params (defaults: index=0, is_change=False, embit_network="main")
            if args[1:4] == (0, False, 'main'):
                print(f'  {func.__name__}(Descriptor.from_string("{descriptor}")) == "{expected}"')
                assert func(descriptor) == expected

            # call with ordered params
            print(f'  {func.__name__}(Descriptor.from_string("{descriptor}"), *{args[1:4]}) == "{expected}"')
            assert func(descriptor, *args[1:4]) == expected

            # call with named params
            print(f'  {func.__name__}(descriptor=Descriptor.from_string("{descriptor}"), index={args[1]}, is_change={args[2]}, embit_network="{args[3]}") == "{expected}"')
            assert func(descriptor=descriptor, index=args[1], is_change=args[2], embit_network=args[3]) == expected

        # test exceptions
        else:
            # call with ordered params
            with pytest.raises(expected):
                print(f'  {func.__name__}(Descriptor.from_string("{descriptor}"), *{args[1:4]}) raises Exception')
                func(descriptor, *args[1:4])

            # call with named params
            with pytest.raises(expected):
                print(f'  {func.__name__}(descriptor=Descriptor.from_string("{descriptor}"), index={args[1]}, is_change={args[2]}, embit_network="{args[3]}") raises Exception"')
                func(descriptor=descriptor, index=args[1], is_change=args[2], embit_network=args[3])


def test_get_multisig_policy():
    """
    tests seedsigner.helpers.embit_utils.get_multisig_policy()
    """
    from embit.descriptor import Descriptor

    # Reuses the same 2-of-3 multisig descriptors from test_get_multisig_address
    vectors_descriptor_expected = {
        # native segwit 2-of-3
        "wsh(sortedmulti(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))#zw6cnrlk": ("2", "3"),
        # nested segwit 2-of-3
        "sh(wsh(sortedmulti(2,[73c5da0a/48h/1h/1h/0h/1h]tpubDFH9dgzveyD8yHQb8VrpG8FYAuwcLMHMje2CCcbBo1FpaGzYVtJeYYxcYgRqSTta5utUFts8nPPHs9C2bqoxrey5jia6Dwf9mpwrPq7YvcJ/{0,1}/*,[0be174ee/48h/1h/0h/1h]tpubDEsePyLPkbxbnj6XuKvWwdERHaKkikZxaGJ9sJqmM7okbZXgkNSFiGU6GX6qEes6kD8f9Z9FosYB9UEnBSgBEyEwwJhj4uUcFE1WE8VtKoh/{0,1}/*,[8d55ff0d/48h/1h/0h/1h]tpubDDxNVWk924RTT3vyGLHdSDoZ2JUVX7jUsPcwCQ9MrKHAtJrW5zECTF9rFHCvqu526E4PjHp61hBknts2c5aGexvX7hvCZ8TGPvQFdzxxy59/{0,1}/*)))#2ujlfp73": ("2", "3"),
        # legacy p2sh 2-of-3
        "sh(sortedmulti(2,[8d55ff0d/45h]tpubDANogJ2yfnizHwX7fSi5kUVzybyuPXDhgHB2TR9TUvkSLZFW73cRq4STKFDpx7qjJJiisyq82tbu4CeiYtmKEmT1xoCq9P8BPvXV31HUh6d/{0,1}/*,[0be174ee/45h]tpubDBkeVF2tDNT1Pz7L47iJeBB6RokU12LX6x4E6Ph8T89hmjQfB77q1AMyGwL8qpREVGq9sCJEbWwmnemwNTxnpxGn1di7BGy8jx9wEi5Vahu/{0,1}/*,[73c5da0a/45h]tpubDBKsGC1UqBDNvx9aivFmxZNgeZTUnmsCFGhWrqkLzucUCDePvbWWm3n8tAaAwMmxBG2ihdKCG9fzBdUnMxKx5PrkiqSZFi6Vkv6msUs9ddN/{0,1}/*))#p5t8sa8c": ("2", "3"),
    }

    for desc_str, (expected_threshold, expected_n) in vectors_descriptor_expected.items():
        descriptor = Descriptor.from_string(desc_str)
        threshold, n = embit_utils.get_multisig_policy(descriptor)
        assert threshold == expected_threshold
        assert n == expected_n

    # Non-multisig descriptor should raise ValueError
    with pytest.raises(ValueError):
        embit_utils.get_multisig_policy(Descriptor.from_string(
            "wpkh([73c5da0a/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/{0,1}/*)#2aj6cvca"
        ))


def test_parse_derivation_path():
    # Shouldn't care if input uses "'" or "h"
    derivation_path = "m/84'/0'/0'/0/0"

    result = embit_utils.parse_derivation_path(derivation_path)
    assert result["script_type"] == SC.NATIVE_SEGWIT
    assert result["network"] == SC.MAINNET

    result = embit_utils.parse_derivation_path(derivation_path.replace("'", "h"))
    assert result["script_type"] == SC.NATIVE_SEGWIT
    assert result["network"] == SC.MAINNET

    # Now exhaustively test supported permutations
    vectors_args = {
        (SC.MAINNET, SC.NATIVE_SEGWIT, False): "m/84'/0'/0'/0/5",
        (SC.TESTNET, SC.NATIVE_SEGWIT, False): "m/84'/1'/0'/0/5",
        (SC.REGTEST, SC.NATIVE_SEGWIT, False): "m/84'/1'/0'/0/5",
        (SC.MAINNET, SC.NATIVE_SEGWIT, True): "m/84'/0'/0'/1/5",
        (SC.TESTNET, SC.NATIVE_SEGWIT, True): "m/84'/1'/0'/1/5",
        (SC.REGTEST, SC.NATIVE_SEGWIT, True): "m/84'/1'/0'/1/5",

        (SC.MAINNET, SC.NESTED_SEGWIT, False): "m/49'/0'/0'/0/5",
        (SC.TESTNET, SC.NESTED_SEGWIT, False): "m/49'/1'/0'/0/5",
        (SC.REGTEST, SC.NESTED_SEGWIT, False): "m/49'/1'/0'/0/5",
        (SC.MAINNET, SC.NESTED_SEGWIT, True): "m/49'/0'/0'/1/5",
        (SC.TESTNET, SC.NESTED_SEGWIT, True): "m/49'/1'/0'/1/5",
        (SC.REGTEST, SC.NESTED_SEGWIT, True): "m/49'/1'/0'/1/5",

        (SC.MAINNET, SC.TAPROOT, False): "m/86'/0'/0'/0/5",
        (SC.TESTNET, SC.TAPROOT, False): "m/86'/1'/0'/0/5",
        (SC.REGTEST, SC.TAPROOT, False): "m/86'/1'/0'/0/5",
        (SC.MAINNET, SC.TAPROOT, True): "m/86'/0'/0'/1/5",
        (SC.TESTNET, SC.TAPROOT, True): "m/86'/1'/0'/1/5",
        (SC.REGTEST, SC.TAPROOT, True): "m/86'/1'/0'/1/5",

        (SC.MAINNET, SC.LEGACY_P2PKH, False): "m/44'/0'/0'/0/5",
        (SC.TESTNET, SC.LEGACY_P2PKH, False): "m/44'/1'/0'/0/5",
        (SC.REGTEST, SC.LEGACY_P2PKH, False): "m/44'/1'/0'/0/5",
        (SC.MAINNET, SC.LEGACY_P2PKH, True): "m/44'/0'/0'/1/5",
        (SC.TESTNET, SC.LEGACY_P2PKH, True): "m/44'/1'/0'/1/5",
        (SC.REGTEST, SC.LEGACY_P2PKH, True): "m/44'/1'/0'/1/5",

        # Try a typical custom derivation path (Unchained vault keys)
        (SC.MAINNET, SC.CUSTOM_DERIVATION, False): "m/45'/0'/0'/0/5",
        (SC.TESTNET, SC.CUSTOM_DERIVATION, False): "m/45'/1'/0'/0/5",
        (SC.REGTEST, SC.CUSTOM_DERIVATION, False): "m/45'/1'/0'/0/5",
        (SC.MAINNET, SC.CUSTOM_DERIVATION, True): "m/45'/0'/0'/1/5",
        (SC.TESTNET, SC.CUSTOM_DERIVATION, True): "m/45'/1'/0'/1/5",
        (SC.REGTEST, SC.CUSTOM_DERIVATION, True): "m/45'/1'/0'/1/5",

        # CRAZY custom derivation paths
        (None, SC.CUSTOM_DERIVATION, False, 5): "m/123'/9083270/9083270/9083270/9083270/0/5",

        # non-standard change and/or index
        (None, SC.CUSTOM_DERIVATION, None, 5): "m/9'/78/5",
        (None, SC.CUSTOM_DERIVATION, None, 5): "m/9'/78'/5",
        (None, SC.CUSTOM_DERIVATION, None, None): "m/9'/78'/5'",
        (None, SC.CUSTOM_DERIVATION, False, None): "m/9'/0/5'",
    }

    for expected_result, derivation_path in vectors_args.items():
        actual_result = embit_utils.parse_derivation_path(derivation_path)

        if expected_result[0] == SC.MAINNET:
            assert actual_result["network"] == expected_result[0]
            assert actual_result["clean_match"] is True
        elif expected_result[0] is None:
            assert actual_result["network"] is None
            assert actual_result["clean_match"] is False
        else:
            # Testnet and regtest are returned as a list since the parser can't tell which is intended
            assert expected_result[0] in actual_result["network"]
            assert actual_result["clean_match"] is True

        assert actual_result["script_type"] == expected_result[1]
        assert actual_result["is_change"] == expected_result[2]

        if len(expected_result) == 4:
            assert actual_result["index"] == expected_result[3]
        else:
            assert actual_result["index"] == int(derivation_path.split("/")[-1])



class TestTaprootDescriptorRegistration:
    """
    Descriptor registration for a taproot multi-leaf policy (e.g. a
    DynastyTrust tr_multileaf inheritance vault) -- the missing piece
    identified after the taproot script-path SIGNING fix: SeedSigner could
    already sign a tapscript leaf, but scan_views.py's registration gate
    rejected any non-basic-multisig descriptor outright (NotYetImplementedView),
    and even past that, get_multisig_address's taproot branch just raised
    "not yet implemented" and get_multisig_policy hard-required
    is_basic_multisig. This class tests the replacements:
    is_taproot_miniscript_wallet(), get_multisig_address()'s new taproot
    branch, and get_taproot_policy_summary().

    Uses the same real BIP-39 seeds as test_get_multisig_address's own
    vectors rather than throwaway random keys, and cross-checks every
    derived address independently against psbt_parser's own from-scratch
    BIP341 tap-tree math (already proven correct against schnorr_verify in
    test_taproot_scriptpath.py) instead of only checking embit's
    Descriptor output against itself.
    """

    def _account_key_str(self, seed_words: str, path: str, fingerprint_hex: str, network: str = "test") -> str:
        from embit.bip32 import HDKey
        from embit.networks import NETWORKS
        from seedsigner.models.seed import Seed
        seed = Seed(seed_words.split())
        root = HDKey.from_seed(seed.seed_bytes, version=NETWORKS[network]["xprv"])
        assert root.my_fingerprint.hex() == fingerprint_hex, "test vector's own seed doesn't match its documented fingerprint"
        account_xpub = root.derive(f"m/{path}").to_public()
        return f"[{fingerprint_hex}/{path}]{account_xpub.to_base58(version=NETWORKS[network]['xpub'])}"

    def _tr_multileaf_descriptor(self):
        """A fixed (non-wildcard) 2-leaf taproot descriptor, the same
        tr_multileaf shape DynastyTrust compiles: separate pk() leaves,
        each key a fixed /0/0 child of an account-level xpub, exactly the
        `[fp/path]xpub/0/0` form DynastyTrust's own descriptor upgrade
        emits (see its CLAUDE.md "Address type" doctrine)."""
        from embit.descriptor import Descriptor
        NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        # Same keystores as test_get_multisig_address's vectors.
        key_a = self._account_key_str("abandon " * 11 + "about", "86h/1h/0h", "73c5da0a")
        key_b = self._account_key_str("baby mass dust captain baby mass dust captain baby mass dust casino", "86h/1h/0h", "0be174ee")
        desc_str = f"tr({NUMS_HEX},{{pk({key_a}/0/0),pk({key_b}/0/0)}})"
        return Descriptor.from_string(desc_str)

    def test_is_taproot_miniscript_wallet(self):
        descriptor = self._tr_multileaf_descriptor()
        assert embit_utils.is_taproot_miniscript_wallet(descriptor) is True

        from embit.descriptor import Descriptor
        single_key = Descriptor.from_string(
            "tr([73c5da0a/86h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/0)"
        )
        assert embit_utils.is_taproot_miniscript_wallet(single_key) is False

        basic_multisig = Descriptor.from_string(
            "wsh(sortedmulti(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))#zw6cnrlk"
        )
        assert embit_utils.is_taproot_miniscript_wallet(basic_multisig) is False, "basic multisig has its own is_basic_multisig path, not this one"

    def test_is_single_sig_wallet(self):
        from embit.descriptor import Descriptor

        native_segwit = Descriptor.from_string(
            "wpkh([73c5da0a/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/{0,1}/*)#2aj6cvca"
        )
        assert embit_utils.is_single_sig_wallet(native_segwit) is True

        single_key_taproot = Descriptor.from_string(
            "tr([73c5da0a/86h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/0)"
        )
        assert embit_utils.is_single_sig_wallet(single_key_taproot) is True

        multi_leaf = self._tr_multileaf_descriptor()
        assert embit_utils.is_single_sig_wallet(multi_leaf) is False, "3 keys (NUMS + 2 signers), not single-sig"

        basic_multisig = Descriptor.from_string(
            "wsh(sortedmulti(2,[8d55ff0d/48h/1h/0h/2h]tpubDDxNVWk924RTUhdkVB2uLHw1hGMPNMGufpZefhkkswjbZppVZcuMdjYKQN4ewUog9vbL6RBLFPRWcgTGT7kYP79N6thyJ43ELUs4N2szXMg/{0,1}/*,[73c5da0a/48h/1h/0h/2h]tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*,[0be174ee/48h/1h/0h/2h]tpubDEsePyLPkbxbrDiZSTTWdsviiNtiQjrvvzZnkLtG72QYLBygEsXePRsTdXi8DeMA7taCuuvoEBjUAfFrsNZeQJqfvG9fFoujYWbFPYUn7ux/{0,1}/*))#zw6cnrlk"
        )
        assert embit_utils.is_single_sig_wallet(basic_multisig) is False

    def test_get_multisig_address_single_sig_segwit_matches_independent_derivation(self):
        """The gap this session actually fixed: a plain single-sig wpkh()
        descriptor exported from another coordinator (e.g. Nunchuk) used to
        hit get_multisig_address's final `raise` because neither is_segwit's
        multisig-only guard nor the taproot branch applied to it -- except
        is_segwit was never multisig-only to begin with; the real blocker
        was entirely at the routing layer (scan_views.py / tools_views.py),
        which is what the other assertions in this test file's flow-level
        tests cover. This test cross-checks the actual math independently:
        derive the expected pubkey/address straight from the xpub via
        embit's own bip32/script primitives (a second, independent code
        path from Descriptor.derive()) and confirm get_multisig_address
        lands on exactly the same address for both receive and change,
        at more than just index 0."""
        from embit import bip32, script
        from embit.descriptor import Descriptor
        from embit.networks import NETWORKS

        desc_str = "wpkh([73c5da0a/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/{0,1}/*)#2aj6cvca"
        descriptor = Descriptor.from_string(desc_str)
        xpub = bip32.HDKey.from_base58("tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba")

        for index, is_change in [(0, False), (5, False), (0, True), (12, True)]:
            expected_pubkey = xpub.derive([1 if is_change else 0, index]).key
            expected_address = script.p2wpkh(expected_pubkey).address(network=NETWORKS["test"])
            actual_address = embit_utils.get_multisig_address(descriptor=descriptor, index=index, is_change=is_change, embit_network="test")
            assert actual_address == expected_address
            assert actual_address.startswith("tb1q")

    def test_get_multisig_address_single_sig_legacy(self):
        """Legacy single-sig (pkh) previously fell through get_multisig_address's
        legacy branch entirely -- that branch required is_basic_multisig, which
        a bare pkh() key never satisfies. Cross-checked against embit's own
        p2pkh script/address primitives directly."""
        from embit import bip32, script
        from embit.descriptor import Descriptor
        from embit.networks import NETWORKS

        desc_str = "pkh([73c5da0a/44h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/{0,1}/*)"
        descriptor = Descriptor.from_string(desc_str)
        xpub = bip32.HDKey.from_base58("tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba")

        expected_pubkey = xpub.derive([0, 3]).key
        expected_address = script.p2pkh(expected_pubkey).address(network=NETWORKS["test"])
        actual_address = embit_utils.get_multisig_address(descriptor=descriptor, index=3, is_change=False, embit_network="test")
        assert actual_address == expected_address

    def test_get_multisig_address_taproot_matches_independent_tap_tree_math(self):
        """The real regression this closes: get_multisig_address's taproot
        branch used to unconditionally raise. Cross-checks the address
        two ways: against psbt_parser's own from-scratch BIP341 merkle
        root + tweak reconstruction (independent of embit's Descriptor),
        and against calling derive() a second time at a different
        (still-fixed) index to confirm a non-wildcard descriptor really
        is index-invariant, not coincidentally correct at index 0."""
        from embit.descriptor.taptree import _tweak_helper
        from embit.networks import NETWORKS
        from embit.script import Script
        from seedsigner.models.psbt_parser import PSBTParser

        descriptor = self._tr_multileaf_descriptor()
        address = embit_utils.get_multisig_address(descriptor, index=0, is_change=False, embit_network="test")
        change_address = embit_utils.get_multisig_address(descriptor, index=0, is_change=True, embit_network="test")
        assert address == change_address, "a fixed (non-wildcard) tr_multileaf vault has exactly one address; change returns to it"

        # Independent cross-check: walk the descriptor's own tap tree the
        # same way test_taproot_change_output.py's already-verified helper
        # does (real depth/leaf_version per leaf, not a guessed constant),
        # then re-derive the merkle root + tweaked output key via
        # psbt_parser's own from-scratch static helpers -- a second,
        # independent code path -- and confirm it lands on the exact same
        # address embit_utils.get_multisig_address just returned.
        # .taptree on the raw (un-derived) descriptor still references
        # the parent xpubs, not the resolved /0/0 child keys -- derive()
        # first, same as get_multisig_address itself must (see its
        # taproot branch), then read .taptree off the derived result.
        derived_descriptor = descriptor.derive(0, branch_index=0)
        leaves_with_paths, _ = _tweak_helper(derived_descriptor.taptree)
        tap_tree_entries = []
        for leaf, path in leaves_with_paths:
            depth = len(path) // 32
            leaf_script = Script(leaf.miniscript.compile())
            tap_tree_entries.append((depth, leaf.version, leaf_script))
        our_root, _ = PSBTParser._tap_tree_merkle_root(tap_tree_entries)
        internal_key_xonly = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        our_output_xonly = PSBTParser._tap_tweak_xonly(internal_key_xonly, our_root)
        our_script = bytes([0x51, 0x20]) + our_output_xonly
        embit_network = NETWORKS["test"]
        our_address = Script(our_script).address(network=embit_network)
        assert our_address == address, "independent BIP341 reconstruction must match embit's own Descriptor.derive().address()"

        # Different index, still a no-op for a fixed descriptor.
        address_at_5 = embit_utils.get_multisig_address(descriptor, index=5, is_change=False, embit_network="test")
        assert address_at_5 == address

    def test_get_multisig_address_taproot_single_sig(self):
        """Single-key tr(key) still routes through the same taproot
        branch (is_taproot_miniscript_wallet excludes it from the
        *registration* gate, but get_multisig_address itself has no
        reason to reject it -- it's the ordinary key-path taproot case)."""
        from embit.descriptor import Descriptor
        descriptor = Descriptor.from_string(
            "tr([73c5da0a/86h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/0)"
        )
        address = embit_utils.get_multisig_address(descriptor, index=0, is_change=False, embit_network="test")
        assert address.startswith("tb1p")

    def test_get_taproot_policy_summary(self):
        descriptor = self._tr_multileaf_descriptor()
        summary = embit_utils.get_taproot_policy_summary(descriptor)
        # descriptor.keys includes the NUMS internal key plus both signer
        # keys -- 3 total, not just the 2 signers.
        assert "3 keys" in summary
        assert "2 leaves" in summary
        assert "Taproot" in summary

        # Non-taproot descriptor should raise ValueError, mirroring
        # get_multisig_policy's own non-basic-multisig guard.
        from embit.descriptor import Descriptor
        with pytest.raises(ValueError):
            embit_utils.get_taproot_policy_summary(Descriptor.from_string(
                "wpkh([73c5da0a/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/{0,1}/*)#2aj6cvca"
            ))

        # Single-key tr(key) has 0 leaves -- should read as "single-sig",
        # not the technically-true-but-confusing "1 keys, 0 leaves".
        single_key = Descriptor.from_string(
            "tr([73c5da0a/86h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/0)"
        )
        single_key_summary = embit_utils.get_taproot_policy_summary(single_key)
        assert single_key_summary == "Taproot, single-sig"
        assert "0 leaves" not in single_key_summary

    def test_get_taproot_policy_summary_counts_a_larger_tree_correctly(self):
        """A 3-leaf tree (uneven binary tree -- 1 leaf at depth 1, 2 at
        depth 2) to prove leaf counting walks the whole tree, not just
        the top-level split, since a naive `len(taptree.tree)` would
        always report 2 regardless of how deep the tree actually goes."""
        from embit.descriptor import Descriptor
        NUMS_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        key_a = self._account_key_str("abandon " * 11 + "about", "86h/1h/0h", "73c5da0a")
        key_b = self._account_key_str("baby mass dust captain baby mass dust captain baby mass dust casino", "86h/1h/0h", "0be174ee")
        key_c = self._account_key_str("captain baby mass dust captain baby mass dust captain baby mass dutch", "86h/1h/0h", "8d55ff0d")
        desc_str = f"tr({NUMS_HEX},{{pk({key_a}/0/0),{{pk({key_b}/0/0),pk({key_c}/0/0)}}}})"
        descriptor = Descriptor.from_string(desc_str)
        summary = embit_utils.get_taproot_policy_summary(descriptor)
        # NUMS internal key + 3 signer keys = 4.
        assert "4 keys" in summary
        assert "3 leaves" in summary
