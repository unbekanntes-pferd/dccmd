"""
DRACOON Commander
A CLI DRACOON client

"""

__version__ = "0.5.0"

# std imports
import sys
import os
import asyncio

# external imports
from dracoon.nodes.models import NodeType
from dracoon.errors import (
    DRACOONHttpError,
    HTTPConflictError,
    HTTPForbiddenError,
    InvalidPathError,
    InvalidFileError,
    FileConflictError,
    HTTPUnauthorizedError
)
import typer


# internal imports
from dccmd.main.util import (
    graceful_exit,
    parse_file_name,
    parse_path,
    parse_new_path,
    format_error_message,
    format_success_message,
    format_and_print_node,
    to_readable_size,
)
from dccmd.main.auth import auth_app
from dccmd.main.auth.client import client_app
from dccmd.main.auth.util import init_dracoon
from dccmd.main.auth.credentials import (
    get_crypto_credentials,
    delete_credentials
)

from dccmd.main.crypto import crypto_app
from dccmd.main.users import users_app
from dccmd.main.rooms import rooms_app
from dccmd.main.users.manage import find_user_by_username
from dccmd.main.crypto.keys import distribute_missing_keys
from dccmd.main.crypto.util import init_keypair
from dccmd.main.upload import create_folder_struct, bulk_upload, is_directory, is_file
from dccmd.main.download import create_download_list, bulk_download
from dccmd.main.models import DCTransfer, DCTransferList
from dccmd.main.models.errors import (DCPathParseError, ConnectError)

# initialize CLI app
app = typer.Typer()
app.add_typer(typer_instance=client_app, name="client", help="Manage client info")
app.add_typer(typer_instance=auth_app, name="auth", help="Manage authentication credentials")
app.add_typer(typer_instance=crypto_app, name="crypto", help="Manage crypto credentials")
app.add_typer(typer_instance=users_app, name="users", help="Manage users")
app.add_typer(typer_instance=rooms_app, name="rooms", help="Manage room permissions")


@app.command()
def upload(
    source_dir_path: str = typer.Argument(
        ..., help="Source directory path to a file or folder to upload."
    ),
    target_path: str = typer.Argument(
        ..., help="Target path in a DRACOON instance pointing to a folder or room."
    ),
    cli_mode: bool = typer.Option(
        False, help="When active, accepts username and password"
    ),
    debug: bool = typer.Option(
        False, help="When active, sets log level to DEBUG and streams log"
    ),
    overwrite: bool = typer.Option(
        False,
        help="When active, will overwrite uploads of files with same name.",
    ),
    auto_rename: bool = typer.Option(
        False, help="When active, will auto-rename uploads of files with same name."
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Upload a folder content recursively"
    ),
    velocity: int = typer.Option(
        2,
        "--velocity",
        "-v",
        help="Concurrent requests factor (1: slow, 2: normal, 3: fast)",
    ),
    username: str = typer.Argument(
        None, help="Username to log in to DRACOON - only works with active cli mode"
    ),
    password: str = typer.Argument(
        None, help="Password to log in to DRACOON - only works with active cli mode"
    ),
    encryption_password: str = typer.Argument(
        None, help="Encryption password in use in DRACOON - only works with active cli mode"
    )
):
    """Upload a file or folder into DRACOON """

    async def _upload():

        # get authenticated DRACOON instance
        dracoon, base_url = await init_dracoon(
            url_str=target_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(target_path)
        dracoon.logger.debug(parsed_path)
        node_info = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if node_info is None:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Invalid target path: {target_path}"))
            sys.exit(1)

        if node_info.isEncrypted is True:
            if cli_mode:
                crypto_secret = get_crypto_credentials(base_url=base_url, cli_mode=cli_mode)
                if not crypto_secret:
                    crypto_secret = encryption_password
            else:
                crypto_secret = get_crypto_credentials(base_url, cli_mode)
            await init_keypair(
                dracoon=dracoon, base_url=base_url, cli_mode=cli_mode, crypto_secret=crypto_secret
            )

        is_folder = is_directory(folder_path=source_dir_path)
        is_file_path = is_file(folder_path=source_dir_path)

        resolution_strategy = "fail"

        if overwrite:
            resolution_strategy = "overwrite"

        if overwrite and auto_rename:
            typer.echo(
                format_error_message(
                    msg="Conflict: cannot use both resolution strategies (auto-rename / overwrite)."
                )
            )
            sys.exit(1)

        if auto_rename:
            resolution_strategy = "autorename"

        # uploading a folder must be used with -r flag
        if is_folder and not recursive:
            typer.echo(
                format_error_message(
                    msg="Folder can only be uploaded via recursive (-r) flag."
                )
            )
        # upload a folder and all related content
        elif is_folder and recursive:
            await create_folder_struct(
                source=source_dir_path, target=parsed_path, dracoon=dracoon,
                velocity=velocity
            )
            await bulk_upload(
                source=source_dir_path,
                target=parsed_path,
                dracoon=dracoon,
                resolution_strategy=resolution_strategy,
                velocity=velocity,
            )
            try:
                folder_name = parse_file_name(full_path=source_dir_path)
            except DCPathParseError:
                folder_name = source_dir_path
            typer.echo(f'{format_success_message(f"Folder {folder_name} uploaded.")}')
        # upload a single file
        elif is_file_path:
            file_size = os.path.getsize(source_dir_path)
            transfer_list = DCTransferList(total=file_size, file_count=1)
            transfer = DCTransfer(transfer=transfer_list)
            try:
                await dracoon.upload(
                    file_path=source_dir_path,
                    target_path=parsed_path,
                    resolution_strategy=resolution_strategy,
                    callback_fn=transfer.update,
                    raise_on_err=True,
                )
            except HTTPUnauthorizedError:
                await graceful_exit(dracoon=dracoon)
                delete_credentials(base_url=base_url)
                format_error_message(
                        msg="Re-authentication required - please run operation again with new login."
                )
                sys.exit(1)
            except HTTPForbiddenError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(
                        msg="Insufficient permissions (create required)."
                    )
                )
                sys.exit(1)
            except HTTPConflictError:
                await dracoon.logout()
                typer.echo(format_error_message(msg="File already exists."))
                sys.exit(1)
            except InvalidPathError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(msg=f"Target path not found. ({target_path})")
                )
                sys.exit(1)
            except DRACOONHttpError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(msg="An error ocurred uploading the file.")
                )
                sys.exit(1)

            try:
                file_name = parse_file_name(full_path=source_dir_path)
            except DCPathParseError:
                file_name = source_dir_path

            typer.echo(f'{format_success_message(f"File {file_name} uploaded.")}')
        # handle invalid path
        else:
            typer.echo(
            format_error_message(msg=f"Provided path must be a folder or file. ({source_dir_path})")
            )

        # node id must be from parent room if folder
        if node_info.type == NodeType.folder:
            distrib_node_id = node_info.authParentId
        if node_info.type == NodeType.room:
            distrib_node_id = node_info.id
        else:
            distrib_node_id = None

        if node_info.isEncrypted is True and distrib_node_id is not None:
            await distribute_missing_keys(dracoon=dracoon, room_id=distrib_node_id)

        await dracoon.logout()

    asyncio.run(_upload())


@app.command()
def mkdir(
    dir_path: str = typer.Argument(
        ...,
        help="Full path to create a folder in DRACOON (e.g. dracoon.team/mynewfolder).",
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
    """Create a folder in a DRACOON parent path"""

    async def _create_folder():

        # get authenticated DRACOON instance
        dracoon, base_url = await init_dracoon(
            url_str=dir_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_new_path(full_path=dir_path)

        folder_name = parse_file_name(full_path=dir_path)

        parent_node = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if parent_node is None:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Node not found: {parsed_path}"))
            sys.exit(1)

        payload = dracoon.nodes.make_folder(name=folder_name, parent_id=parent_node.id)

        try:
            await dracoon.nodes.create_folder(folder=payload, raise_on_err=True)
        except HTTPUnauthorizedError:
            await graceful_exit(dracoon=dracoon)
            delete_credentials(base_url=base_url)
            format_error_message(
                        msg="Re-authentication required - please run operation again with new login."
                )
            sys.exit(1)
        except HTTPConflictError:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Name already exists: {dir_path}"))
            sys.exit(1)
        except HTTPForbiddenError:
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg="Insufficient permissions (create permission required)."
                )
            )
            sys.exit(1)
        except DRACOONHttpError:
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg="An error ocurred - folder could not be created."
                )
            )
            sys.exit(1)

        typer.echo(format_success_message(msg=f"Folder {folder_name} created."))
        await dracoon.logout()

    asyncio.run(_create_folder())


@app.command()
def mkroom(
    dir_path: str = typer.Argument(
        ...,
        help="Full path to create a room (inherit permissions) in DRACOON (e.g. dracoon.team/room)",
    ),
    admin_user: str = typer.Option(
        None,
        "--admin-user",
        "-au",
        help="Username of the admin user of the room",
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
    """Create a room (inherit permissions) in a DRACOON parent path"""

    async def _create_room():

        # get authenticated DRACOON instance
        dracoon, base_url = await init_dracoon(
            url_str=dir_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_new_path(full_path=dir_path)

        if parsed_path == "/":
            parent_node = None
            parent_id = 0
        else:
            parent_node = await dracoon.nodes.get_node_from_path(path=parsed_path)
            parent_id = parent_node.id

        room_name = parse_file_name(full_path=dir_path)

        if parsed_path != "/" and parent_node is None:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Node not found: {parsed_path}"))
            sys.exit(1)
        if parent_node and parent_node.type != NodeType.room:
            await dracoon.logout()
            typer.echo(
                format_error_message(msg=f"Parent path must be a room: {parsed_path}")
            )
            sys.exit(1)

        if not admin_user and parent_id == 0:
            await dracoon.logout()
            typer.echo(
                format_error_message(msg="An admin user must be provided on root path.")
            )
            sys.exit(1)

        if admin_user and parent_id != 0:
            user_info = await find_user_by_username(dracoon=dracoon, user_name=admin_user, as_user_manager=False, room_id=parent_id)
            payload = dracoon.nodes.make_room(name=room_name, parent_id=parent_id, inherit_perms=False, admin_ids=[user_info.userInfo.id]) # type: ignore
        if admin_user and parent_id == 0:
            user_info = await find_user_by_username(dracoon=dracoon, user_name=admin_user)
            payload = dracoon.nodes.make_room(name=room_name, inherit_perms=False, admin_ids=[user_info.id], parent_id=None) # type: ignore
        else:
            payload = dracoon.nodes.make_room(
            name=room_name, parent_id=parent_id, inherit_perms=True
            )

        try:
            await dracoon.nodes.create_room(room=payload, raise_on_err=True)
        except HTTPUnauthorizedError:
            await graceful_exit(dracoon=dracoon)
            delete_credentials(base_url=base_url)
            format_error_message(
                        msg="Re-authentication required - please run operation again with new login."
                )
            sys.exit(1)
        except HTTPConflictError:
            typer.echo(format_error_message(msg=f"Name already exists: {dir_path}"))
            await dracoon.logout()
            sys.exit(1)
        except HTTPForbiddenError:
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg="Insufficient permissions (room admin required)."
                )
            )
            sys.exit(1)
        except DRACOONHttpError:
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg="An error ocurred - room could not be created."
                )
            )
            sys.exit(1)
        except TimeoutError:
            typer.echo(
                format_error_message(
                    msg="Connection timeout - room could not be created."
                )
            )
            sys.exit(1)
        except ConnectError:
            typer.echo(
                format_error_message(
                    msg="Connection error - room could not be created."
                )
            )
            sys.exit(1)

        typer.echo(format_success_message(msg=f"Room {room_name} created."))
        await dracoon.logout()

    asyncio.run(_create_room())


@app.command()
#pylint: disable=C0103
def rm(
    source_path: str = typer.Argument(
        ...,
        help="Full path to delete a file / folder or room in DRACOON (e.g. dracoon.team/file.txt).",
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Delete room / folder recursively."
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
    """Delete a file / folder / room in DRACOON"""

    async def _delete_node():

        # get authenticated DRACOON instance
        dracoon, base_url = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(full_path=source_path)

        node_name = parse_file_name(full_path=source_path)

        node = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if node is None:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Node not found: {parsed_path}"))
            sys.exit(1)
        if node.type == NodeType.room and not recursive:
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg="Room can only be deleted with recursive flag (-r)."
                )
            )
            sys.exit(1)
        if node.type == NodeType.folder and not recursive:
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg="Folder can only be deleted with recursive flag (-r)."
                )
            )
            sys.exit(1)
        try:
            await dracoon.nodes.delete_node(node_id=node.id, raise_on_err=True)
        except HTTPUnauthorizedError:
            await graceful_exit(dracoon=dracoon)
            delete_credentials(base_url=base_url)
            format_error_message(
                        msg="Re-authentication required - please run operation again with new login."
                )
            sys.exit(1)
        except HTTPForbiddenError:
            await dracoon.logout()
            typer.echo(
                format_error_message(msg="Insufficient permissions (delete required).")
            )
            sys.exit(1)
        except DRACOONHttpError:
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg="An error ocurred - node could not be deleted."
                )
            )
            sys.exit(1)
        except TimeoutError:
            typer.echo(
                format_error_message(
                    msg="Connection timeout - room could not be created."
                )
            )
            sys.exit(1)
        except ConnectError:
            typer.echo(
                format_error_message(
                    msg="Connection error - room could not be created."
                )
            )
            sys.exit(1)


        typer.echo(format_success_message(msg=f"Node {node_name} deleted."))
        await dracoon.logout()

    asyncio.run(_delete_node())


@app.command()
#pylint: disable=C0103
def ls(
    source_path: str = typer.Argument(
        ...,
        help="Full path to delete a file / folder or room in DRACOON (e.g. dracoon.team/file.txt).",
    ),
    inode: bool = typer.Option(False, "--inode", "-i", help="Display node id"),
    long_list: bool = typer.Option(
        False, "--long", "-l", help="Use a long listing format"
    ),
    human_readable: bool = typer.Option(
        False, "--human-readable", "-h", help="Use human readable sizes"
    ),
    cli_mode: bool = typer.Option(
        False, help="When active, accepts username and password"
    ),
    debug: bool = typer.Option(
        False, help="When active, sets log level to DEBUG and streams log"
    ),
    all_items: bool = typer.Option(
        False, help="When active, returns all items without prompt"
    ),
    room_manager: bool = typer.Option(
        False, help="When active, returns all nodes as room admin / manager"
    ),
    username: str = typer.Argument(
        None, help="Username to log in to DRACOON - only works with active cli mode"
    ),
    password: str = typer.Argument(
        None, help="Password to log in to DRACOON - only works with active cli mode"
    ),
):
    """List all nodes in a DRACOON path"""

    async def _list_nodes():

        # get authenticated DRACOON instance
        dracoon, base_url = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(full_path=source_path)
      
        if parsed_path == "/":
            parent_node = None
            parent_id = 0
        else:
            parent_node = await dracoon.nodes.get_node_from_path(path=parsed_path)
            parent_id = parent_node.id

        if parent_node is None and parsed_path != "/":
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Node not found: {parsed_path}"))
            sys.exit(1)
        if parent_node and parent_node.type == NodeType.file:
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg=f"Path must be a room or a folder ({source_path})"
                )
            )
            sys.exit(1)
        try:
            nodes = await dracoon.nodes.get_nodes(parent_id=parent_id, room_manager=room_manager, raise_on_err=True)
        except HTTPUnauthorizedError:
            await graceful_exit(dracoon=dracoon)
            delete_credentials(base_url=base_url)
            format_error_message(
                        msg="Re-authentication required - please run operation again with new login."
                )
            sys.exit(1)
        except HTTPForbiddenError:
            await dracoon.logout()
            typer.echo(
                format_error_message(msg="Insufficient permissions (delete required).")
            )
            sys.exit(1)
        except DRACOONHttpError:
            await dracoon.logout()
            typer.echo(format_error_message(msg="Error listing nodes."))
            sys.exit(1)
        except TimeoutError:
            typer.echo(
                format_error_message(
                    msg="Connection timeout - could not list nodes."
                )
            )
            sys.exit(1)
        except ConnectError:
            typer.echo(
                format_error_message(
                    msg="Connection error - could not list nodes."
                )
            )
            sys.exit(1)

        # handle more than 500 items
        if nodes.range.total > 500:
            if not all_items:
                show_all = typer.confirm(
                f"More than 500 nodes in {parsed_path} - display all?"
            )
            else:
                show_all = all_items

            if not show_all:
                typer.echo(f"{nodes.range.total} nodes – only 500 displayed.")
                raise typer.Abort()

            for offset in range(500, nodes.range.total, 500):
                try:
                    nodes_res = await dracoon.nodes.get_nodes(
                        parent_id=parent_id, offset=offset, room_manager=room_manager, raise_on_err=True
                    )
                    nodes.items.extend(nodes_res.items)
                except HTTPUnauthorizedError:
                    await graceful_exit(dracoon=dracoon)
                    delete_credentials(base_url=base_url)
                    format_error_message(
                            msg="Re-authentication required - please run operation again with new login."
                    )
                    sys.exit(1)
                except HTTPForbiddenError:
                    await dracoon.logout()
                    typer.echo(
                        format_error_message(
                            msg="Insufficient permissions (delete required)."
                        )
                    )
                    sys.exit(1)
                except DRACOONHttpError:
                    await dracoon.logout()
                    typer.echo(format_error_message(msg="Error listing nodes."))
                    sys.exit(1)
                except TimeoutError:
                    typer.echo(
                        format_error_message(
                            msg="Connection timeout - could not list nodes."
                        )
                    )
                    sys.exit(1)
                except ConnectError:
                    typer.echo(
                        format_error_message(
                            msg="Connection error - could not list nodes."
                        )
                    )
                    sys.exit(1)

        if long_list and parent_node is not None and human_readable:
            if parent_node.size:
                size = parent_node.size
            else:
                size = 0
            typer.echo(f"total {to_readable_size(size)}")
        elif long_list and parent_node is not None:
            typer.echo(f"total {parent_node.size}")

        for node in nodes.items:
            format_and_print_node(
                node=node,
                inode=inode,
                long_list=long_list,
                readable_size=human_readable,
            )

        await dracoon.logout()

    asyncio.run(_list_nodes())


@app.command()
def download(
    source_path: str = typer.Argument(
        ..., help="Source path to a file in DRACOON to download."
    ),
    target_dir_path: str = typer.Argument(
        ..., help="Target directory path to a folder."
    ),
    cli_mode: bool = typer.Option(
        False, help="When active, accepts username and password"
    ),
    debug: bool = typer.Option(
        False, help="When active, sets log level to DEBUG and streams log"
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Download a folder / room content recursively"
    ),
    velocity: int = typer.Option(
        2,
        "--velocity",
        "-v",
        help="Concurrent requests factor (1: slow, 10: max)",
    ),
    username: str = typer.Argument(
        None, help="Username to log in to DRACOON - only works with active cli mode"
    ),
    password: str = typer.Argument(
        None, help="Password to log in to DRACOON - only works with active cli mode"
    ),
    encryption_password: str = typer.Argument(
        None, help="Encryption password in use in DRACOON - only works with active cli mode"
    )
):
    """
    Download a file, folder or room from DRACOON 
    """

    async def _download():

        # get authenticated DRACOON instance
        dracoon, base_url = await init_dracoon(
            url_str=source_path,
            username=username,
            password=password,
            cli_mode=cli_mode,
            debug=debug,
        )

        # remove base url from path
        parsed_path = parse_path(full_path=source_path)

        file_name = parse_file_name(full_path=source_path)

        node_info = await dracoon.nodes.get_node_from_path(path=parsed_path)

        if not node_info:
            await dracoon.logout()
            typer.echo(format_error_message(msg=f"Node not found ({parsed_path})."))
            sys.exit(1)


        if node_info and node_info.isEncrypted is True:

            if cli_mode:
                crypto_secret = get_crypto_credentials(base_url=base_url, cli_mode=cli_mode)
                if not crypto_secret:
                    crypto_secret = encryption_password
            else:
                crypto_secret = get_crypto_credentials(base_url, cli_mode=cli_mode)
            await init_keypair(
                dracoon=dracoon, base_url=base_url, cli_mode=cli_mode, crypto_secret=crypto_secret
            )
        
        is_container = node_info.type == NodeType.folder or node_info.type == NodeType.room
        is_file_path = node_info.type == NodeType.file

        if is_container and not recursive:
            typer.echo(
                format_error_message(
                    msg="Folder or room can only be downloaded via recursive (-r) flag."
                )
            )
            await dracoon.logout()
            sys.exit(1)
        elif is_container and recursive:
            try:
                download_list = await create_download_list(dracoon=dracoon, node_info=node_info,
                                                           target_path=target_dir_path)
            except InvalidPathError:
                typer.echo(
                    format_error_message(
                        msg=f"Target path does not exist ({target_dir_path})"
                    )
                )
                await dracoon.logout()
                sys.exit(1)

            try:
                await bulk_download(dracoon=dracoon, download_list=download_list, velocity=velocity)
                typer.echo(
                    f'{format_success_message(f"{node_info.type.value} {node_info.name} downloaded to {target_dir_path}.")}'
                )
            except HTTPUnauthorizedError:
                await graceful_exit(dracoon=dracoon)
                delete_credentials(base_url=base_url)
                format_error_message(
                        msg="Re-authentication required - please run operation again with new login."
                )
                sys.exit(1)
            except FileConflictError:
                typer.echo(
                    format_error_message(
                        msg=f"File already exists on target path ({target_dir_path})"
                    )
                )
                sys.exit(1)
            except DRACOONHttpError:
                await dracoon.logout()
                typer.echo(format_error_message(msg="Error downloading file."))
                sys.exit(1)
            except PermissionError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(
                        msg=f"Cannot write on target path ({target_dir_path})"
                    )
                )
            finally:
                await dracoon.logout()
        elif is_file_path:
            if node_info.size:
                size = node_info.size
            else:
                size = 0
            transfer = DCTransferList(total=size, file_count=1)
            download_job = DCTransfer(transfer=transfer)

            try:
                await dracoon.download(
                    file_path=parsed_path,
                    target_path=target_dir_path,
                    raise_on_err=True,
                    callback_fn=download_job.update
                )
                typer.echo(
                f'{format_success_message(f"File {file_name} downloaded to {target_dir_path}.")}'
            )
            # to do: replace with handling via PermissionError
            except UnboundLocalError:
                await dracoon.logout()
                typer.echo(
                format_error_message(msg=f"Insufficient permissions on target path ({target_dir_path})")
                )
                sys.exit(1)
            except InvalidPathError:
                await dracoon.logout()
                typer.echo(
                format_error_message(msg=f"Path must be a folder ({target_dir_path})")
                )
                sys.exit(1)
            except InvalidFileError:
                await dracoon.logout()
                typer.echo(format_error_message(msg=f"File does not exist ({parsed_path})"))
                sys.exit(1)
            except FileConflictError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(
                        msg=f"File already exists on target path ({target_dir_path})"
                    )
                )
                sys.exit(1)
            except HTTPUnauthorizedError:
                await graceful_exit(dracoon=dracoon)
                delete_credentials(base_url=base_url)
                format_error_message(
                        msg="Re-authentication required - please run operation again with new login."
                )
                sys.exit(1)
            except DRACOONHttpError:
                await dracoon.logout()
                typer.echo(format_error_message(msg="Error downloading file."))
                sys.exit(1)
            except PermissionError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(
                        msg=f"Cannot write on target path ({target_dir_path})"
                    )
                )
                sys.exit(1)
            except KeyboardInterrupt:
                await dracoon.logout()
                typer.echo(
                f'{format_success_message(f"Download canceled ({file_name}).")}'
            )



    asyncio.run(_download())


@app.command()
def version():
    """
    Dsiplay current version of DRACOON Commander
    """

    typer.echo(
               "@@@@@@@@@@@@@@@@@@      @@@@@@@@@@@@@@@@@@      @@@@@@@@@@@@@@@@@@      @@@@@@@@@        @@@@@@@@@   @@@@@@@@@@@@@@@@@@\n"                                           
               "@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@      @@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@\n"                                           
               "@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@    @@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@\n"                                           
               "@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@@   @@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@                @@@@@@@@                @@@@@@@@@@@@@ @@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@                @@@@@@@@                @@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@                @@@@@@@@                @@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@                @@@@@@@@                @@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@                @@@@@@@@                @@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@                @@@@@@@@                @@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@                @@@@@@@@                @@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@                @@@@@@@@                @@@@@@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@     @@@@@@@@   @@@@@@@@      @@@@@@@@  @@@@@@@@ @@@@@@@@@@@@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@     @@@@@@@@   @@@@@@@@     @@@@@@@@   @@@@@@@@      @@@@@@@@  @@@@@@@@  @@@@@@@@ @@@@@@@   @@@@@@@@     @@@@@@@@\n"                                           
               "@@@@@@@@ @@@@@@@@@@@@   @@@@@@@@  @@@@@@@@@@@   @@@@@@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@  @@@@@@@   @@@@@@@@@@@  @@@@@@@@\n"                                           
               "@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@@@@@@@@@@@@@@  @@@@@@@@   @@@@@   @@@@@@@   @@@@@@@@@@@@@@@@@@@@@\n"                                           
               "@@@@@@@@@@@@@@@@@@@     @@@@@@@@@@@@@@@@@@@@      @@@@@@@@@@@@@@@@@@@@    @@@@@@    @@@    @@@@@@@    @@@@@@@@@@@@@@@@@@@@\n"                                           
               "@@@@@@@@@@@@@@@@        @@@@@@@@@@@@@@@@             @@@@@@@@@@@@@@@@@       @@@     @     @@@@@@@        @@@@@@@@@@@@@@@@\n"                                           
               "@@@@@@@@@@@@@           @@@@@@@@@@@@@                   @@@@@@@@@@@@@@                     @@@@@@@           @@@@@@@@@@@@@\n"                                           
               "@@@@@@@@@@              @@@@@@@@@@                          @@@@@@@@@@                     @@@@@@@              @@@@@@@@@@\n"                                           
               "@@@@@@@                 @@@@@@@                                @@@@@@@                     @@@@@@@                 @@@@@@@\n"                                           
               "@@@@                    @@@@                                      @@@@                     @@@@@@@                    @@@@\n"                                           
               "@                       @                                            @                        @@@@                       @\n"                                           
                                                                                                                                                         
    )

    typer.echo(f"                        DRACOON Commander (dccmd) version {__version__}")
    typer.echo("                        Octavio Simone 2022")
    typer.echo("                        https://github.com/unbekanntes-pferd/dccmd")


if __name__ == "__main__":
    app()
