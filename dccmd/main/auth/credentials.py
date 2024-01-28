"""
All functions to store credentials (authentication, client, crypto)
Using keyring
"""

import os
import configparser
import keyring
import pathlib
import typer
from appdirs import AppDirs

from ..models.errors import DCClientParseError
from dccmd import __version__

SERVICE_NAME = "DRACOON Commander"
app_dirs = AppDirs(SERVICE_NAME)
APP_PATH = pathlib.Path(app_dirs.user_data_dir)
CONFIG_FILE = "dccmd.ini"
CONFIG_PATH = APP_PATH.joinpath(CONFIG_FILE)
TOKEN_NAME = "token"
ENCRYPTION_NAME = "encryption"
CLIENT_CREDENTIALS_NAME = "client"

def load_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    return config

def are_credentials_stored(base_url: str) -> bool:
    config = load_config()
    has_base_url = base_url in config
    if has_base_url:
        has_token = TOKEN_NAME in config[base_url]
    else: 
        has_token = False

    return has_token

def are_crypto_credentials_stored(base_url: str) -> bool:
    config = load_config()
    has_base_url = base_url in config
    if has_base_url:
        has_crypto = ENCRYPTION_NAME in config[base_url]
    else: 
        has_crypto = False

    return has_crypto   

def store_credentials(base_url: str, refresh_token: str, cli_mode: bool):
    """store refresh token for given DRACOON url"""
    if cli_mode:
        if not are_credentials_stored(base_url=base_url) and typer.confirm("Store credentials as insecure config file?", default=False):
            store_credentials_insecure(base_url=base_url, refresh_token=refresh_token)
    else:
        keyring.set_password(SERVICE_NAME, base_url, refresh_token)

def store_credentials_insecure(base_url: str, refresh_token: str):
    config = load_config()
    if base_url not in config:
        config[base_url] = {}
    config[base_url][TOKEN_NAME] = refresh_token
    os.makedirs(APP_PATH, exist_ok=True)
    with open(CONFIG_PATH, 'w') as config_file:
        config.write(config_file)


def get_credentials(base_url: str, cli_mode: bool):
    """get stored refresh token for given DRACOON url"""
    if cli_mode:
        return get_credentials_insecure(base_url=base_url)
    else:
        return keyring.get_password(SERVICE_NAME, base_url)

def get_credentials_insecure(base_url: str):
    config = load_config()
    return config.get(base_url, TOKEN_NAME, fallback=None)

def delete_credentials(base_url: str, cli_mode: bool):
    """delete stored refresh token for given DRACOON url"""
    if cli_mode:
        delete_credentials_insecure()
    else:
        keyring.delete_password(SERVICE_NAME, base_url)

def delete_credentials_insecure(base_url: str):
    config = load_config()
    if base_url in config and TOKEN_NAME in config[base_url]:
        del config[base_url][TOKEN_NAME]
        with open(CONFIG_PATH, 'w') as config_file:
            config.write(config_file)

def store_crypto_credentials(base_url: str, crypto_secret: str, cli_mode: bool):
    """store encryption password for given DRACOON url"""
    if cli_mode:
        if not are_crypto_credentials_stored(base_url=base_url) and typer.confirm("Store encryption secret as insecure config file?", default=False):
           store_crypto_credentials_insecure(base_url=base_url, crypto_secret=crypto_secret)
    else:
        keyring.set_password(SERVICE_NAME, base_url + "-crypto", crypto_secret)

def store_crypto_credentials_insecure(base_url: str, crypto_secret: str):
    config = load_config()
    if base_url not in config:
        config[base_url] = {}
    config[base_url][ENCRYPTION_NAME] = crypto_secret
    os.makedirs(APP_PATH, exist_ok=True)
    with open(CONFIG_PATH, 'w') as config_file:
        config.write(config_file)

def get_crypto_credentials(base_url: str, cli_mode: bool) -> str:
    """get encryption password for given DRACOON url"""
    if cli_mode:
        return get_crypto_credentials_insecure(base_url=base_url)
    else:
        return keyring.get_password(SERVICE_NAME, base_url + "-crypto")

def get_crypto_credentials_insecure(base_url: str) -> str:
    config = load_config()
    return config.get(base_url, ENCRYPTION_NAME, fallback=None)

def delete_crypto_credentials(base_url: str, cli_mode: bool):
    """delete stored encryption password for given DRACOON url"""
    if cli_mode:
        delete_crypto_credentials_insecure(base_url=base_url)
    else:
        keyring.delete_password(SERVICE_NAME, base_url + "-crypto")


def delete_crypto_credentials_insecure(base_url: str):
    config = load_config()
    if base_url in config and ENCRYPTION_NAME in config[base_url]:
        del config[base_url][ENCRYPTION_NAME]
        with open(CONFIG_PATH, 'w') as config_file:
            config.write(config_file)


def store_client_credentials(base_url: str, client_id: str, client_secret: str, cli_mode: bool):
    """store client credentials (client id and secret) for given DRACOON url"""
    if cli_mode:
        store_client_credentials_insecure(base_url=base_url, client_id=client_id, client_secret=client_secret)
    else:
        keyring.set_password(
        SERVICE_NAME, base_url + "-client", f"{client_id} {client_secret}"
    )      

def store_client_credentials_insecure(base_url: str, client_id: str, client_secret: str):
    config = load_config()
    if base_url not in config:
        config[base_url] = {}
    config[base_url][CLIENT_CREDENTIALS_NAME] = f"{client_id} {client_secret}"
    os.makedirs(APP_PATH, exist_ok=True)
    with open(CONFIG_PATH, 'w') as config_file:
        config.write(config_file)

def get_client_credentials(base_url: str, cli_mode: bool) -> tuple[str, str]:
    """store client credentials (client id and secret) for given DRACOON url"""
    if cli_mode:
        creds = get_client_credentials_insecure(base_url=base_url)
    else:
        creds = keyring.get_password(SERVICE_NAME, base_url + "-client")
        
    return parse_client_credentials(creds)

def get_client_credentials_insecure(base_url: str):
    config = load_config()
    return config.get(base_url, CLIENT_CREDENTIALS_NAME, fallback=None)

def delete_client_credentials(base_url: str, cli_mode: bool):
    """store client credentials (client id and secret) for given DRACOON url"""
    if cli_mode:
        delete_client_credentials_insecure(base_url=base_url)
    else:
        keyring.delete_password(SERVICE_NAME, base_url + "-client")


def delete_client_credentials_insecure(base_url: str):
    config = load_config()
    if base_url in config and CLIENT_CREDENTIALS_NAME in config[base_url]:
        del config[base_url][CLIENT_CREDENTIALS_NAME]
        with open(CONFIG_PATH, 'w') as config_file:
            config.write(config_file)

def parse_client_credentials(credentials: str) -> tuple[str, str]:
    """parse (split) client credentials (client id and secret) for given DRACOON url"""
    if not credentials:
        raise DCClientParseError("No client credentials found.")

    if len(credentials.split(" ")) != 2:
        raise DCClientParseError("Invalid client format")

    creds = credentials.split(" ")

    return creds[0], creds[1]
    