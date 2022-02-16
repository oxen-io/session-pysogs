import sogs.model.user
from nacl.signing import SigningKey
import nacl.bindings as salt
from sogs.hashing import blake2b
import sogs.crypto


class User(sogs.model.user.User):
    def __init__(self, blinded=False):
        self.ed_key = SigningKey.generate()

        if blinded:
            a = self.ed_key.to_curve25519_private_key().encode()
            k = salt.crypto_core_ed25519_scalar_reduce(blake2b(sogs.crypto.server_pubkey_bytes, digest_size=64))
            ka = salt.crypto_core_ed25519_scalar_mul(k, a)
            kA = salt.crypto_scalarmult_ed25519_base_noclamp(ka)
            session_id = '15' + kA.hex()
        else:
            session_id = '05' + self.ed_key.to_curve25519_private_key().public_key.encode().hex()

        super().__init__(session_id=session_id, touch=True)
