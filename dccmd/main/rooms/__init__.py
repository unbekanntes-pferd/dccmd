import asyncio
import sys
import typer

from dracoon.nodes.models import NodeType

from dccmd.main.auth.util import init_dracoon
from dccmd.main.util import format_error_message, format_success_message, parse_path

from .print import (pretty_print_group_perms, pretty_print_user_perms,
                    csv_print_group_perms, csv_print_user_perms)
from .permissions import (get_room_user_permissions, get_room_group_permissions, add_room_user,
                          add_room_group, remove_room_group, remove_room_user, parse_permissions_template)

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
    permission: str = typer.Option(
        None,
        "--permissions",
        "-p",
        help="Permissions template (read, edit, admin)",
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
        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(source_path)

        node_info = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if node_info is None or node_info.type != NodeType.room:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Invalid target path: {source_path}"))
            sys.exit(1)

        perms = parse_permissions_template(perms=permission)

        await add_room_user(room_id=node_info.id, username=user, permission_template=perms, dracoon=dracoon)
        await dracoon.logout()
        typer.echo(format_success_message(f"Added user {user} with permission {permission} to room {node_info.name}."))

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
    permission: str = typer.Option(
        None,
        "--permissions",
        "-p",
        help="Permissions template (read, edit, admin)",
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
        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(source_path)

        node_info = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if node_info is None or node_info.type != NodeType.room:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Invalid target path: {source_path}"))
            sys.exit(1)

        perms = parse_permissions_template(perms=permission)

        await add_room_group(room_id=node_info.id, name=group, permission_template=perms, dracoon=dracoon)
        await dracoon.logout()
        typer.echo(format_success_message(f"Added group {group} with permission {permission} to room {node_info.name}."))

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
        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(source_path)
        node_info = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if node_info is None or node_info.type != NodeType.room:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Invalid target path: {source_path}"))
            sys.exit(1)

        await remove_room_user(room_id=node_info.id, username=user, dracoon=dracoon)
        await dracoon.logout()
        typer.echo(format_success_message(f"Removed user {user} from room {node_info.name}."))

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
        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(source_path)

        node_info = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if node_info is None or node_info.type != NodeType.room:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Invalid target path: {source_path}"))
            sys.exit(1)

        await remove_room_group(room_id=node_info.id, name=group, dracoon=dracoon)

        await dracoon.logout()
        typer.echo(format_success_message(f"Removed group {group} from room {node_info.name}."))

    asyncio.run(_remove_group())

@rooms_app.command()
def list_users(
    source_path: str = typer.Argument(
        ...,
        help="Full path to the room for which user permissions need to be displayed.",
    ),
    csv: bool = typer.Option(
        False, help="When active, outputs user permissions as comma separated list"
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
        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(source_path)
        dracoon.logger.debug(parsed_path)
        node_info = await dracoon.nodes.get_node_from_path(path=parsed_path)


        if node_info is None or node_info.type != NodeType.room:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Invalid target path: {source_path}"))
            sys.exit(1)

        user_permissions = await get_room_user_permissions(room_id=node_info.id, dracoon=dracoon)

        if csv:
            csv_print_user_perms(user_permissions=user_permissions)
        else:
            pretty_print_user_perms(user_permissions=user_permissions)

        await dracoon.logout()

    asyncio.run(_list_users())

@rooms_app.command()
def list_groups(
    source_path: str = typer.Argument(
        ...,
        help="Full path to the room for which group permissions need to be displayed.",
    ),
    csv: bool = typer.Option(
        False, help="When active, outputs group permissions as comma separated list"
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
    """ List all group permissions for a specific room """
    async def _list_groups():
        # get authenticated DRACOON instance
        dracoon, _ = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(source_path)

        node_info = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if node_info is None or node_info.type != NodeType.room:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Invalid target path: {source_path}"))
            sys.exit(1)

        group_permissions = await get_room_group_permissions(room_id=node_info.id, dracoon=dracoon)

        if csv:
            csv_print_group_perms(group_permissions=group_permissions)
        else:
            pretty_print_group_perms(group_permissions=group_permissions)

        await dracoon.logout()

    asyncio.run(_list_groups())

