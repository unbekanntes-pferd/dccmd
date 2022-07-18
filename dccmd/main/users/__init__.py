"""
DRACOON commands to manage users
All functions require user manager permission

"""

# std import
import asyncio

# external imports
import typer

from dccmd.main.auth.util import init_dracoon

from .manage import parse_csv, create_users, delete_user, find_user_by_username, get_users
from .print import pretty_print, csv_print


users_app = typer.Typer()


@users_app.command()
def csv_import(
    source_path: str = typer.Argument(
        ...,
        help="Full path to a CSV file containing user data to bulk import",
    ),
    target_path: str = typer.Argument(..., help="DRACOON url to import users to"),
    oidc_id: int = typer.Argument(None, help="Numeric id of OIDC config"),
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
    """Add a list of users to DRACOON from a CSV file"""

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

        await create_users(dracoon=dracoon, user_list=user_list, oidc_id=oidc_id)
        await dracoon.logout()

    asyncio.run(_import_users())


@users_app.command()
# pylint: disable=C0103
def ls(
    target_path: str = typer.Argument(..., help="DRACOON url to import users to"),
    search_string: str = typer.Argument(
        "", help="Search string (first name OR last name OR username)."
    ),
    csv: bool = typer.Option(
        False, help="When active, outputs users as comma separated list"
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
    """Get a list of users in DRACOON"""
    async def _list_users(search_string: str = ''):
        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=target_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        users = await get_users(dracoon=dracoon, search_string=search_string)

        if csv:
            csv_print(user_list=users)
        else:
            pretty_print(user_list=users)

        await dracoon.logout()


    asyncio.run(_list_users(search_string=search_string))
 


@users_app.command()
# pylint: disable=C0103
def rm(
    target_path: str = typer.Argument(..., help="DRACOON url to import users to"),
    user_login: str = typer.Argument(
        ..., help="Username (login) of the user to delete in DRACOON."
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
    """Delete a user"""

    async def _delete_user(user_name: str):
        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=target_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        user = await find_user_by_username(dracoon, user_name)
        await delete_user(dracoon, user.id)

        await dracoon.logout()

        asyncio.run(_delete_user(user_login))
