import logging

try:
    import uwsgi
except ModuleNotFoundError:
    class postfork:
        """Simple non-uwsgi stub that just calls the postfork function"""
        def __init__(self, f):
            f()

        def __call__(self, f):
            pass
else:
    from uwsgidecorators import postfork
