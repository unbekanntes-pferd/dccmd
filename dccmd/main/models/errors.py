"""
Errors thrown in dccmd
"""
# re-import
from httpx import ConnectError

class DCBaseError(Exception):
    """ base client error """
    def __init__(self, message: str):
        super().__init__()
        self.message = message


# error parsing a DRACOON base url
class DCPathParseError(DCBaseError):
    """ error raised if DRACOON url format invalid """
    #pylint: disable=W0235
    def __init__(self, msg: str = "Invalid DRACOON url"):
        super().__init__(msg)

# error parsing DRACOON client credentials
class DCClientParseError(DCBaseError):
    """ error raised if client creds cannot be parsed """
    #pylint: disable=W0235
    def __init__(self, msg: str):
        super().__init__(msg)

# error parsing DRACOON client credentials
class DCClientNotFoundError(DCBaseError):
    """ error raised if a client config is not found """
    #pylint: disable=W0235
    def __init__(self, msg: str):
        super().__init__(msg)

# invalid CLI argument combination
class DCInvalidArgumentError(DCBaseError):
    """ error raised for invalid arguments """
    #pylint: disable=W0235
    def __init__(self, msg: str):
        super().__init__(msg)
