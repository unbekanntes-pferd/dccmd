"""
Errors thrown in dccmd
"""

from httpx import ConnectError, ConnectTimeout


# error parsing a DRACOON base url
class DCPathParseError(Exception):
    """ error raised if DRACOON url format invalid """
    #pylint: disable=W0235
    def __init__(self, msg: str = "Invalid DRACOON url"):
        super().__init__(msg)

# error parsing DRACOON client credentials
class DCClientParseError(Exception):
    """ error raised if client creds cannot be parsed """
    #pylint: disable=W0235
    def __init__(self, msg: str):
        super().__init__(msg)

# error parsing DRACOON client credentials
class DCClientNotFoundError(Exception):
    """ error raised if a client config is not found """
    #pylint: disable=W0235
    def __init__(self, msg: str):
        super().__init__(msg)

# invalid CLI argument combination
class DCInvalidArgumentError(Exception):
    """ error raised for invalid arguments """
    #pylint: disable=W0235
    def __init__(self, msg: str):
        super().__init__(msg)
