import sogs.model.user
from nacl.signing import SigningKey
import nacl.bindings as sodium
import sogs.crypto
from sogs.hashing import blake2b


class User(sogs.model.user.User):
    def __init__(self, blinded15=False, blinded25=False):
        self.ed_key = SigningKey.generate()

        self.a = self.ed_key.to_curve25519_private_key().encode()
        self.ka15 = sodium.crypto_core_ed25519_scalar_mul(sogs.crypto.blinding15_factor, self.a)
        self.kA15 = sodium.crypto_scalarmult_ed25519_base_noclamp(self.ka15)
        self.ka25 = sodium.crypto_core_ed25519_scalar_mul(
            sodium.crypto_core_ed25519_scalar_reduce(
                blake2b(
                    [
                        self.ed_key.verify_key.to_curve25519_public_key().encode(),
                        sogs.crypto.server_pubkey_bytes,
                    ],
                    digest_size=64,
                )
            ),
            self.a,
        )
        self.kA25 = sodium.crypto_scalarmult_ed25519_base_noclamp(self.ka15)
        self.blinded15_id = '15' + self.kA15.hex()
        self.blinded25_id = '25' + self.kA25.hex()
        if blinded25:
            session_id = self.blinded25_id
        elif blinded15:
            session_id = self.blinded15_id
        else:
            session_id = '05' + self.ed_key.to_curve25519_private_key().public_key.encode().hex()

        super().__init__(session_id=session_id, touch=True)
