import sogs.config as config
import os
from sogs.web import app
import configparser
import sqlalchemy.exc
from nacl.public import PrivateKey
from sogs.plugins_interface import HexEncoder, SigningKey
from sogs.plugins.captcha_plugin import CaptchaPlugin


def get_plugin_privkey(key_file):
    # generate seed as needed
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            _privkey = PrivateKey(f.read())
    else:
        _privkey = PrivateKey.generate()
        with open(os.open(key_file, os.O_CREAT | os.O_WRONLY, 0o400), 'wb') as f:
            f.write(_privkey.encode())

    _privkey_bytes = _privkey.encode()

    return _privkey_bytes


def run_captcha_plugin(db=None, ini: str = "captcha.ini"):
    conf_ini = ini
    if not os.path.exists(conf_ini):
        app.logger.warning(f"{ini} does not exist")
        conf_ini = None

    if not conf_ini:
        return

    key_file = "captcha_x25519"

    app.logger.info(f"Loading captcha plugin config from {conf_ini}")
    cp = configparser.ConfigParser()
    cp.read(conf_ini)

    # Mandatory configs
    if cp.has_option('plugin', 'key_file'):
        key_file = cp.get('plugin', 'key_file')
    captcha_privkey_bytes = get_plugin_privkey(key_file)
    if not captcha_privkey_bytes:
        app.logger.warning("plugin private key missing")
        return

    sogs_key_hex_str = None
    if cp.has_option('sogs', 'sogs_pubkey_hex'):
        sogs_key_hex_str = cp.get('sogs', 'sogs_pubkey_hex')
    if not sogs_key_hex_str:
        app.logger.warning("sogs public key hex missing")
        return

    # Optional configs
    captcha_name = "CAPTCHA"
    if cp.has_option('plugin', 'name'):
        captcha_name = cp.get('plugin', 'name')

    captcha_retry_limit = 3
    if cp.has_option('plugin', 'retry_limit'):
        captcha_retry_limit = cp.getint('plugin', 'retry_limit')

    captcha_write_timeout = 0
    if cp.has_option('plugin', 'write_timeout'):
        captcha_write_timeout = cp.getint('plugin', 'write_timeout')

    captcha_refresh_timeout = 60
    if cp.has_option('plugin', 'refresh_timeout'):
        captcha_refresh_timeout = cp.getint('plugin', 'refresh_timeout')

    captcha_retry_timeout = 120
    if cp.has_option('plugin', 'retry_timeout'):
        captcha_retry_timeout = cp.getint('plugin', 'retry_timeout')

    sogs_address = config.OMQ_LISTEN
    if cp.has_option('sogs', 'sogs_address'):
        sogs_address = cp.get('sogs', 'sogs_address')

    from nacl.public import PublicKey

    sogs_key = PublicKey(HexEncoder.decode(str.encode(sogs_key_hex_str)))
    sogs_key_bytes = sogs_key.encode()

    privkey = SigningKey(captcha_privkey_bytes)
    print(f"privkey: {privkey.encode(HexEncoder)}")
    privkey_bytes = privkey.encode()
    pubkey_bytes = privkey.verify_key.encode()
    print(f"pubkey: {privkey.verify_key.encode(HexEncoder)}")
    plugin = CaptchaPlugin(
        sogs_address,
        sogs_key_bytes,
        privkey_bytes,
        pubkey_bytes,
        captcha_name,
        write_timeout=captcha_write_timeout,
        retry_limit=captcha_retry_limit,
        retry_timeout=captcha_retry_timeout,
        refresh_timeout=captcha_refresh_timeout
    )

    plugin_key = SigningKey(plugin.x_pub)

    from sogs.db import query

    if db is not None:
        try:
            with db.transaction():
                query(
                    "INSERT INTO plugins (auth_key, global, approver, subscribe) VALUES (:key, 1, 1, 1)",
                    key=plugin_key.encode(),
                )

            print(f"CAPTCHA({plugin.x_pub.hex()}) has been added.")
        except sqlalchemy.exc.IntegrityError:
            print(f"CAPTCHA({plugin.x_pub.hex()}) is already added.")

    plugin.run()
