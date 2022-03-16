from typing import Union
import time
from contextlib import contextmanager
import sogs.config


def pad64(data: Union[bytes, str]):
    """Returns the bytes (or str.encode()) padded to length 64 by appending null bytes"""
    if isinstance(data, str):
        data = data.encode()
    assert len(data) <= 64
    if len(data) < 64:
        return data + b'\0' * (64 - len(data))
    return data


class FuzzyTime:
    epsilon = 0.25

    def delta(self, other):
        return abs(float(other) - (self._t + time.time()))

    def __init__(self, t):
        self._t = float(t)

    def __eq__(self, other):
        return self.delta(other) <= self.epsilon

    def __mul__(self, other):
        return FuzzyTime(self._t * float(other))

    def __repr__(self):
        return f"<fuzzy-time: {self.delta(0)}>"


class from_now:
    @staticmethod
    def seconds(n):
        return FuzzyTime(n)

    @staticmethod
    def minutes(n):
        return from_now.seconds(60) * n

    @staticmethod
    def hours(n):
        return from_now.minutes(60) * n

    @staticmethod
    def days(n):
        return from_now.hours(24) * n


@contextmanager
def config_override(**kwargs):
    """
    Context manager that locally overrides one or more sogs.config.XXX values for all given XXX keys
    in kwargs.  The original config values are restored when leaving the context.

    e.g.

        with config_override(UPLOAD_FILE_MAX_SIZE=1024):
            ...
    """

    restore = {}
    for k, v in kwargs.items():
        restore[k] = getattr(sogs.config, k)
        setattr(sogs.config, k, v)

    try:
        yield None
    finally:
        for k, v in restore.items():
            setattr(sogs.config, k, v)
