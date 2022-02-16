import sogs.model.user
from nacl.public import PrivateKey


class User(sogs.model.user.User):
    def __init__(self, prefix='05'):
        self.privkey = PrivateKey.generate()
        super().__init__(session_id=prefix + self.privkey.public_key.encode().hex(), touch=True)
