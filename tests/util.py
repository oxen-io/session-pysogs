from typing import Union


def pad64(data: Union[bytes, str]):
    """Returns the bytes (or str.encode()) padded to length 64 by appending null bytes"""
    if isinstance(data, str):
        data = data.encode()
    assert len(data) <= 64
    if len(data) < 64:
        return data + b'\0' * (64 - len(data))
    return data
