'''Command line tool for ecdh kem'''
# pylint: disable=invalid-name
import argparse
import sys
from ._helper import Helper
from ._constants import CURVES as _CURVES
from ._constants import HASH_ALGORITHMS as _HASH_ALGORITHMS
from .public_key import PublicKey
from .key_pair import KeyPair

def extract(args):
    '''Extract a public key and save it'''
    try:
        key_pair = KeyPair.load(args.keyfile, args.password)
    except ValueError as e:
        print(e.message)
        sys.exit(1)
    with open(args.output, 'x', encoding='utf-8') if args.output != '-' else sys.stdout as outp:
        key_pair.public_key().save(outp)

def generate(args):
    '''Generate a keypair'''
    curve = _CURVES[args.curve]
    key_pair = Helper(curve).generate_keypair()
    key_pair.save(args.keyfile, args.password)

def decrypt(args):
    '''Decrypt the ciphertext and produce the shared secret'''
    try:
        key_pair = KeyPair.load(args.keyfile, args.password)
    except ValueError as e:
        print(e.message)
        sys.exit(1)
    with open(
        args.ciphertext, encoding='utf-8'
        ) if args.ciphertext != '-' else sys.stdin as ciphertext_file, open(
        args.output, 'x', encoding='utf-8'
        ) if args.output != '-' else sys.stdout as output_file:
        ciphertext = ciphertext_file.read()
        shared_secret = Helper.decrypt(key_pair, ciphertext)
        output_file.write(shared_secret)

def encrypt(args):
    '''Generate and encrypt a shared secret'''
    with open(args.pubkeyfile, 'r', encoding='utf-8') as pubkeyfile:
        public_key = PublicKey.load(pubkeyfile)
    with open(
        args.ciphertext,
        'x',
        encoding='utf-8') if args.ciphertext != '-' else sys.stdout as ciphertext_file, open(
            args.sharedsecret,
            'x',
            encoding='utf-8'
            ) as sharedsecret_file:
        sharedsecret, ciphertext = Helper.encrypt(public_key, args)
        ciphertext_file.write(ciphertext)
        sharedsecret_file.write(sharedsecret)

parser = argparse.ArgumentParser(
                    prog='es',
                    description='Implements the ECDH signature protocol',
                    )
subparsers = parser.add_subparsers(required=True)
# extract command arguments
extractparser = subparsers.add_parser('extract')
extractparser.add_argument(
    '-k',
    '--keyfile',
    help='File to read the private key from',
    action='store',
    type=str,
    required=True
    )
extractparser.add_argument(
    '-p',
    '--password',
    help='Password to be used for keyfile',
    action='store',
    type=str,
    required=True
    )
extractparser.add_argument(
    '-o',
    '--output',
    help='Output file for the public key',
    action='store',
    type=str,
    required=False,
    default='-'
    )
extractparser.set_defaults(func=extract)
# Generate command arguments
genparser = subparsers.add_parser('generate')
genparser.add_argument(
    '-c',
    '--curve',
    help='Curve to use',
    action='store',
    choices=_CURVES.keys(),
    default='secp256k1',
    )
genparser.add_argument(
    '-k',
    '--keyfile',
    help='File to store the private key',
    action='store',
    type=str,
    required=True
    )
genparser.add_argument(
    '-p',
    '--password',
    help='Password to be used for keyfile',
    action='store',
    type=str,
    required=True
    )
genparser.set_defaults(func=generate)
# decrypt command arguments
decryptparser = subparsers.add_parser('decrypt')
decryptparser.add_argument(
    '-k',
    '--keyfile',
    help='File to read the private key from',
    action='store',
    type=str,
    required=True
    )
decryptparser.add_argument(
    '-p',
    '--password',
    help='Password to be used for keyfile',
    action='store',
    type=str,
    required=True
    )
decryptparser.add_argument(
    '-c',
    '--ciphertext',
    help='File containing the ciphertext of the shared key',
    action='store',
    type=str,
    required=False,
    default='-'
    )
decryptparser.add_argument(
    '-o',
    '--output',
    help='Output file for shared key (stdout by default)',
    action='store',
    type=str,
    required=False,
    default='-'
    )
decryptparser.set_defaults(func=decrypt)
# encrypt command arguments
encryptparser = subparsers.add_parser('encrypt')
encryptparser.add_argument(
    '-p',
    '--pubkeyfile',
    help='File to read the public key from',
    action='store',
    type=str,
    required=True
    )
encryptparser.add_argument(
    '-c',
    '--ciphertext',
    help='File to store the ciphertext in',
    action='store',
    type=str,
    required=False,
    )
encryptparser.add_argument(
    '-s',
    '--sharedsecret',
    help='File containing the shared secret',
    action='store',
    type=str,
    required=True,
    )
encryptparser.add_argument(
    '-S',
    '--sha',
    help='Secure hash algorithm to use for the signature generation',
    action='store',
    type=str,
    required=False,
    default='sha256',
    choices=_HASH_ALGORITHMS.keys()
    )
encryptparser.set_defaults(func=encrypt)

parsed_args = parser.parse_args(args=sys.argv[1:])
parsed_args.func(parsed_args)
