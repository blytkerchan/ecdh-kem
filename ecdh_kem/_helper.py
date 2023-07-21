'''Helper class for signing'''
import base64
import json
import os
from ._constants import HASH_ALGORITHMS as _HASH_ALGORITHMS
from .key_pair import KeyPair
from argparse import Namespace
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class Helper:
    '''Helper class for signing. Implements the protocol'''
    def __init__(self, curve):
        self._curve = curve

    def generate_keypair(self):
        '''Generate a keypair'''
        return KeyPair.generate(self._curve)

    @classmethod
    def _decode_ciphertext(cls, encoded_ciphertext):
        '''Decide a ciphertext from base64'''
        ciphertext_json = base64.b64decode(encoded_ciphertext)
        ciphertext = json.loads(ciphertext_json)
        ciphertext['salt'] = base64.b64decode(ciphertext['salt'])
        ciphertext['public_bytes'] = base64.b64decode(ciphertext['public_bytes'])
        ciphertext['public_key'] = serialization.load_der_public_key(ciphertext['public_bytes'])
        return ciphertext

    @classmethod
    def _encode_ciphertext(cls, sha, salt, prime_keypair):
        '''Encode a ciphertext to base64'''
        public_bytes = prime_keypair._public_key.public_bytes( # pylint: disable=protected-access
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ciphertext = {
            'sha': sha,
            'salt': str(base64.b64encode(salt), encoding='utf-8'),
            'public_bytes': str(base64.b64encode(public_bytes), encoding='utf-8')
        }
        ciphertext_json = json.dumps(ciphertext)
        return str(base64.b64encode(bytes(ciphertext_json, 'utf-8')), encoding='utf-8')

    @classmethod
    def encrypt(cls, public_key, args=Namespace(**{'sha':'sha256'})):
        '''Sign something with a given private key'''
        helper = Helper(public_key._public_key.curve) # pylint: disable=protected-access
        salt = os.urandom(32)
        prime_keypair = helper.generate_keypair()
        k = prime_keypair._private_key.exchange(ec.ECDH(), public_key._public_key) # pylint: disable=protected-access
        hkdf = HKDF(
            algorithm=_HASH_ALGORITHMS[args.sha],
            length=32,
            salt=salt,
            info=None
            )
        s = hkdf.derive(k)
        return str(base64.b64encode(s), encoding='utf-8'), Helper._encode_ciphertext(args.sha, salt, prime_keypair)

    @classmethod
    def decrypt(cls, key_pair, encoded_ciphertext):
        '''Decrypt ciphertext symmetric key'''
        ciphertext = Helper._decode_ciphertext(encoded_ciphertext)
        k = key_pair._private_key.exchange(ec.ECDH(), ciphertext['public_key']) # pylint: disable=protected-access
        hkdf = HKDF(
            algorithm=_HASH_ALGORITHMS[ciphertext['sha']],
            length=32,
            salt=ciphertext['salt'],
            info=None
            )
        return str(base64.b64encode(hkdf.derive(k)), encoding='utf-8')
