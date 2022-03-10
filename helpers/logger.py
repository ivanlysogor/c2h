from functools import wraps
import logging
import os
from .config import LOG_FILE, APP_NAME


# A special helper to add logging
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - '
                              '%(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)


# a decorator to add a debug logging of any function execution
def add_debug(func):
    @wraps(func)
    def wrapper(self, *argc, **kargc):
        logger.debug(f'{self.__class__.__name__} '
                     f'method with name {func.__name__} at {func} invoked')
        res = func(self, *argc, **kargc)
        return res
    return wrapper
