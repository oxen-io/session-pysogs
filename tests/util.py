from typing import Union


def pad32(data: Union[bytes, str]):
    """Returns the bytes (or str.encode()) padded to length 32 by appending null bytes"""
    if isinstance(data, str):
        data = data.encode()
    assert len(data) <= 32
    if len(data) < 32:
        return data + b'\0' * (32 - len(data))
    return data
