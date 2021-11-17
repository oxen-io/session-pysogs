from . import config
import coloredlogs

coloredlogs.install(level=config.LOG_LEVEL, milliseconds=True, isatty=True)
