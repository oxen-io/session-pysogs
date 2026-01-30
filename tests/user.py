import sogs.model.user
from nacl.signing import SigningKey
import nacl.bindings as sodium
import sogs.crypto
from sogs.hashing import blake2b

from session_util import blinding


class User(sogs.model.user.User):
    def __init__(self, blinded15=False, blinded25=False):
        self.is_blinded15 = blinded15
        self.is_blinded25 = blinded25

        self.ed_key = SigningKey.generate()

        self.a = self.ed_key.to_curve25519_private_key().encode()
        self.ka15 = sodium.crypto_core_ed25519_scalar_mul(sogs.crypto.blinding15_factor, self.a)
        self.kA15 = sodium.crypto_scalarmult_ed25519_base_noclamp(self.ka15)

        pub25 = blinding.blind25_key_pair(
            self.ed_key.encode(), sogs.crypto.server_pubkey_bytes
        ).pubkey

        self.unblinded_id = '05' + self.ed_key.to_curve25519_private_key().public_key.encode().hex()
        self.blinded15_id = '15' + self.kA15.hex()
        self.blinded25_id = '25' + pub25.hex()
        if blinded25:
            session_id = self.blinded25_id
        elif blinded15:
            session_id = self.blinded15_id
        else:
            session_id = self.unblinded_id

        super().__init__(session_id=session_id, touch=True)
