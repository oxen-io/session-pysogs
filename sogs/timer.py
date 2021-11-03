import logging

try:
    import uwsgi
except ModuleNotFoundError:
    import sys

    logging.error(
        """
WARNING:

Failed to load uwsgidecorators; we probably aren't running under uwsgi.

File cleanup and session version updating will not be enabled!
"""
    )

    class timer:
        """Do-nothing stub"""

        def __init__(self, secs, **kwargs):
            pass

        def __call__(self, f):
            pass


else:
    from uwsgidecorators import timer
