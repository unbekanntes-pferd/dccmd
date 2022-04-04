"""
Collection of helpers / utils
- String conversion
- Size formatting
- String parsing
- String formatting (error, success)
"""


from pathlib import Path
import asyncio
import math

import typer

from dracoon import DRACOON
from dracoon.nodes.models import Node, NodeType

from ..models.errors import DCPathParseError


def remove_https(path: str):
    """remove https from a path"""
    # remove unnecessary https://
    if path[:8] == "https://":
        return path[8:]
    else:
        return path


def split_path(path: str):
    """split a path on separator '/'"""
    # split on /
    path_parts = path.split("/")

    # path must contain at least one room and base url
    if len(path_parts) < 2:
        raise DCPathParseError("Invalid DRACOON URL format")

    return path_parts


def parse_base_url(full_path: str):
    """get base url from full path"""
    full_path = remove_https(full_path)
    path_parts = split_path(full_path)

    # return first element (base url)
    return f"https://{path_parts[0]}"


def parse_file_name(full_path: str):
    """get file name from full path"""
    full_path = remove_https(full_path)
    path_parts = split_path(full_path)

    # return last element (file name)
    return path_parts[-1]


def parse_path(full_path: str):
    """get path from full path (no base url)"""
    full_path = remove_https(full_path)
    path_parts = split_path(full_path)

    # remove base url
    return f"/{'/'.join(path_parts[1:])}"


def parse_new_path(full_path: str):
    """get path from full path (no base url, new folder / room removed)"""
    full_path = remove_https(full_path)
    path_parts = split_path(full_path)

    # remove base url
    return f"/{'/'.join(path_parts[1:-1])}"


def format_error_message(msg: str):
    """format error message"""
    error_txt = typer.style("\nError", fg=typer.colors.RED)

    return f"{error_txt} {msg}"


def format_success_message(msg: str):
    """format success message"""
    success_txt = typer.style("OK: ", fg=typer.colors.GREEN, bold=True)

    return f"{success_txt} {msg}"


async def graceful_exit(dracoon: DRACOON):
    """gracefully close client and revoke access token"""
    await dracoon.logout()


def format_and_print_node(
    node: Node, inode: bool, long_list: bool, readable_size: bool
):
    """format node string (used in ls)"""

    node_string = ""
    if inode:
        node_string += f"{node.id} "

    if long_list:
        if node.type == NodeType.folder:
            node_string += "d-"
        elif node.type == NodeType.room:
            node_string += "R-"
        else:
            node_string += "--"

        if node.permissions.manage:
            node_string += "m"
        else:
            node_string += "-"
        if node.permissions.read:
            node_string += "r"
        else:
            node_string += "-"
        if node.permissions.create:
            node_string += "w"
        else:
            node_string += "-"
        if node.permissions.change:
            node_string += "c"
        else:
            node_string += "-"
        if node.permissions.delete:
            node_string += "d-"
        else:
            node_string += "--"
        if node.permissions.manageDownloadShare:
            node_string += "m"
        else:
            node_string += "-"
        if node.permissions.manageUploadShare:
            node_string += "m-"
        else:
            node_string += "--"
        if node.permissions.readRecycleBin:
            node_string += "r"
        else:
            node_string += "-"
        if node.permissions.restoreRecycleBin:
            node_string += "r"
        else:
            node_string += "-"
        if node.permissions.deleteRecycleBin:
            node_string += "d "
        else:
            node_string += "- "

        size = node.size

        if readable_size:
            size = to_readable_size(node.size)

        #pylint: disable=C0301
        node_string += f"{node.updatedBy.firstName} {node.updatedBy.lastName} {size} {node.timestampModification.strftime('%Y %b %d %H:%M')} "

    if node.type == NodeType.room or node.type == NodeType.folder:
        node_string += typer.style(node.name, bold=True)
    else:
        node_string += f"{node.name}"

    typer.echo(node_string)


def to_readable_size(size: int) -> str:
    """convert a byte size into human readable size string with unit conversion"""

    if size == 0:
        return "0 B"

    units = ("B", "KB", "MB", "GB", "TB", "PB")

    exp = int(math.floor(math.log(size, 1024)))
    pot = math.pow(1024, exp)
    res = round(size / pot, 2)

    return f"{res} {units[exp]}"