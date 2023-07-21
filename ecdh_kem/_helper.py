'''Helper class for signing'''
import base64
import sys
from ._constants import HASH_ALGORITHMS as _HASH_ALGORITHMS
from .key_pair import KeyPair
from argparse import Namespace
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Helper:
    '''Helper class for signing. Implements the protocol'''
    def __init__(self, curve):
        self._curve = curve

    def generate_keypair(self):
        '''Generate a keypair'''
        return KeyPair.generate(self._curve)

    @classmethod
    def encrypt(cls, public_key, args=Namespace(**{'sha':'sha256'})):
        '''Sign something with a given private key'''
        helper = SigningHelper(key_pair._private_key.curve) # pylint: disable=protected-access
		salt = os.urandom(32)
        prime_keypair = helper.generate_keypair()
        k = prime_keypair._private_key.exchange(ec.ECDH(), public_key) # pylint: disable=protected-access
        hkdf = HKDF(
            algorithm=_HASH_ALGORITHMS[args.sha],
            length=32,
            salt=salt,
            info=None
            )
        s = hkdf.derive(k)
		return s, (prime_keypair._public_key, salt)

    @classmethod
    def decrypt(cls, key_pair, ciphertext):
        '''Decrypt ciphertext symmetric key'''
		k_prime = prime_keypair._private_key.exchange(ec.ECDH(), ciphertext[0]) # pylint: disable=protected-access
        hkdf = HKDF(
            algorithm=_HASH_ALGORITHMS[sha],
            length=32,
            salt=ciphertext[1],
            info=None
            )
        s_prime = hkdf.derive(k_prime)
        return s_prime
