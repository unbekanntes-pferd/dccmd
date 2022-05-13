"""
DRACOON commands to manage users
All functions require user manager permission

"""

# std import
import sys
import asyncio
import logging

# external imports
import typer
import httpx

from dracoon import DRACOON

from dccmd.main.auth.util import init_dracoon

from .util import parse_csv, create_users


users_app = typer.Typer()


@users_app.command()
def csv_import(
    source_path: str = typer.Argument(
        ...,
        help="Full path to a CSV file containing user data to bulk import",
    ),
    target_path: str = typer.Argument(
        ..., help="DRACOON url to import users to"
    ),
    cli_mode: bool = typer.Option(
        False, help="When active, accepts username and password"
    ),
    debug: bool = typer.Option(
        False, help="When active, sets log level to DEBUG and streams log"
    ),
    username: str = typer.Argument(
        None, help="Username to log in to DRACOON - only works with active cli mode"
    ),
    password: str = typer.Argument(
        None, help="Password to log in to DRACOON - only works with active cli mode"
    ),

):
    """ Add a list of users to DRACOON from a CSV file """
    async def _import_users():

        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=target_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        user_list = parse_csv(source_path=source_path)

        await create_users(dracoon=dracoon, user_list=user_list)

    asyncio.run(_import_users())


@users_app.command()
def sync():
    """ Sync a list of users: Add / remove users in DRACOON """
    pass

@users_app.command()
#pylint: disable=C0103
def ls():
    """ Get a list of users in DRACOON """
    pass

@users_app.command()
#pylint: disable=C0103
def rm():
    """ Delete a user """
    pass
