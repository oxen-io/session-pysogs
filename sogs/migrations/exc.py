class DatabaseUpgradeRequired(RuntimeError):
    """Thrown when using check_only=True in database migrations and an upgrade is required."""

    def __init__(self, desc):
        super().__init__(f"Database upgrade required: {desc}")
