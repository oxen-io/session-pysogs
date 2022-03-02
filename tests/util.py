from typing import Union
import time


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


def seconds(n):
    return FuzzyTime(n)


def minutes(n):
    return seconds(n) * 60


def hours(n):
    return minutes(n) * 60


def days(n):
    return hours(24) * n
