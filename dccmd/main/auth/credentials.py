"""
All functions to store credentials (authentication, client, crypto)
Using keyring
"""

import keyring

from ..models.errors import DCClientParseError

SERVICE_NAME = "DRACOON Commander"


def store_credentials(base_url: str, refresh_token: str):
    """store refresh token for given DRACOON url"""
    keyring.set_password(SERVICE_NAME, base_url, refresh_token)
    return


def get_credentials(base_url: str) -> str:
    """get stored refresh token for given DRACOON url"""
    return keyring.get_password(SERVICE_NAME, base_url)


def delete_credentials(base_url: str):
    """delete stored refresh token for given DRACOON url"""
    keyring.delete_password(SERVICE_NAME, base_url)
    return


def store_crypto_credentials(base_url: str, crypto_secret: str):
    """store encryption password for given DRACOON url"""
    keyring.set_password(SERVICE_NAME, base_url + "-crypto", crypto_secret)
    return


def get_crypto_credentials(base_url: str) -> str:
    """get encryption password for given DRACOON url"""
    return keyring.get_password(SERVICE_NAME, base_url + "-crypto")


def delete_crypto_credentials(base_url: str):
    """delete stored encryption password for given DRACOON url"""
    keyring.delete_password(SERVICE_NAME, base_url + "-crypto")
    return


def store_client_credentials(base_url: str, client_id: str, client_secret: str):
    """store client credentials (client id and secret) for given DRACOON url"""
    keyring.set_password(
        SERVICE_NAME, base_url + "-client", f"{client_id} {client_secret}"
    )
    return


def get_client_credentials(base_url: str) -> tuple[str, str]:
    """store client credentials (client id and secret) for given DRACOON url"""
    creds = keyring.get_password(SERVICE_NAME, base_url + "-client")

    return parse_client_credentials(creds)


def delete_client_credentials(base_url: str):
    """store client credentials (client id and secret) for given DRACOON url"""
    keyring.delete_password(SERVICE_NAME, base_url + "-client")
    return


def parse_client_credentials(credentials: str) -> tuple[str, str]:
    """parse (split) client credentials (client id and secret) for given DRACOON url"""
    if not credentials:
        raise DCClientParseError("No client credentials found.")

    if len(credentials.split(" ")) != 2:
        raise DCClientParseError("Invalid client format")

    creds = credentials.split(" ")

    return creds[0], creds[1]
    