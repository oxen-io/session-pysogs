import sogs.model.user
from nacl.signing import SigningKey
import nacl.bindings as sodium
import sogs.crypto


class User(sogs.model.user.User):
    def __init__(self, blinded15=False):
        self.ed_key = SigningKey.generate()

        self.a = self.ed_key.to_curve25519_private_key().encode()
        self.ka15 = sodium.crypto_core_ed25519_scalar_mul(sogs.crypto.blinding15_factor, self.a)
        self.kA15 = sodium.crypto_scalarmult_ed25519_base_noclamp(self.ka15)
        self.blinded15_id = '15' + self.kA15.hex()
        if blinded15:
            session_id = self.blinded15_id
        else:
            session_id = '05' + self.ed_key.to_curve25519_private_key().public_key.encode().hex()

        super().__init__(session_id=session_id, touch=True)
