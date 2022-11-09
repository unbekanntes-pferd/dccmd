import asyncio
import typer

rooms_app = typer.Typer()


@rooms_app.command()
def add_user(
    source_path: str = typer.Argument(
        ...,
        help="Full path to the room fro which a user needs to be added.",
    ),
    user: str = typer.Option(
        None,
        "--user",
        "-u",
        help="Username of the user to add to the room",
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
    """ Add a user by username to a room """
    async def _add_user():
        pass

    asyncio.run(_add_user())

@rooms_app.command()
def add_group(
    source_path: str = typer.Argument(
        ...,
        help="Full path to the room fro which a user needs to be added.",
    ),
    group: str = typer.Option(
        None,
        "--group",
        "-g",
        help="Group name of the group to add to the room",
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
    """ Add a group by group name to a room """
    async def _add_group():
        pass

    asyncio.run(_add_group())

@rooms_app.command()
def remove_user(
    source_path: str = typer.Argument(
        ...,
        help="Full path to the room from which a user needs to be removed.",
    ),
    user: str = typer.Option(
        None,
        "--user",
        "-u",
        help="Username of the user to add to the room",
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
    """ Remove a user by username from a room """
    async def _remove_user():
        pass

    asyncio.run(_remove_user())

@rooms_app.command()
def remove_group(
    source_path: str = typer.Argument(
        ...,
        help="Full path to the room from which a group needs to be removed.",
    ),
    group: str = typer.Option(
        None,
        "--group",
        "-g",
        help="Group name of the group to add to the room",
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
    """ Remove a group by group name from a room """
    async def _remove_group():
        pass

    asyncio.run(_remove_group())

@rooms_app.command()
def list_users(
    source_path: str = typer.Argument(
        ...,
        help="Full path to the room for which user permissions need to be displayed.",
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
    """ List all user permissions for a specific room """
    async def _list_users():
        pass

    asyncio.run(_list_users())

@rooms_app.command()
def list_groups():
    """ List all group permissions for a specific room """
    async def _list_users():
        pass

    asyncio.run(_list_users())

