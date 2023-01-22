"""
Module with utility functions for user management
- User creation / deletion / listing
- Formatting
"""

import sys
import csv
import asyncio
from typing import Optional, Union

from dracoon import DRACOON
from dracoon.errors import (
    HTTPConflictError,
    HTTPBadRequestError,
    HTTPForbiddenError,
    DRACOONHttpError,
)
from dracoon.nodes.responses import RoomUser
from dracoon.user.responses import UserItem
from pydantic import BaseModel
import typer

from dccmd.main.util import format_error_message, format_success_message
from dccmd.main.upload import is_file


HEADER_FIELDS = ["first name", "firstname", "last name", "lastname", "email",
                 "login"]


class ParsedUser(BaseModel):
    """object representing a parsed user"""

    first_name: str
    last_name: str
    email: str
    login: Optional[str]


def parse_csv(source_path: str) -> list[ParsedUser]:
    """open a CSV file with given path and create a list of user entries"""
    if not is_file(source_path):
        typer.echo(
            format_error_message(msg=f"Provided path is not a file: {source_path}")
        )
        sys.exit(1)

    user_list = []

    with open(file=source_path, mode="r", encoding="utf8") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")

        header = next(csv_reader)

        if not validate_header(header=header):
            typer.echo(
                format_error_message(
                    msg="Invalid field names. Allowed field names: 'first name', 'last name', 'email', 'login'"
                )
            )
            sys.exit(1)

        normalized_header = header_to_lower(header=header)

        idx_first_name = get_first_name_field(header=normalized_header)
        idx_last_name = get_last_name_field(header=normalized_header)
        idx_email = get_email_field(header=normalized_header)
        idx_login = get_login_field(header=normalized_header)

        for user in csv_reader:

            parsed_user = {
                "first_name": user[idx_first_name],
                "last_name": user[idx_last_name],
                "email": user[idx_email],
                "login": None,
            }

            if idx_login != -1:
                parsed_user["login"] = user[idx_login]

            user_list.append(ParsedUser(**parsed_user))

        return user_list


def validate_header(header: list[str]) -> bool:
    """validate CSV header - reject invalid field names"""

    if len(header) < 1:
        return False

    for field in header:
        if field.lower() not in HEADER_FIELDS:
            return False

    return True


def header_to_lower(header: list[str]) -> list[str]:
    """normalized all header fields to lowercase"""
    return [field.lower() for field in header]


def get_first_name_field(header: list[str]) -> int:
    """gets index of first name field"""
    try:
        idx_1 = header.index("first name")
    except ValueError:
        idx_1 = None
    try:
        idx_2 = header.index("firstname")
    except ValueError:
        idx_2 = None

    if idx_1 is not None:
        return idx_1
    if idx_2 is not None:
        return idx_2


def get_last_name_field(header: list[str]) -> int:
    """gets index of last name field"""
    try:
        idx_1 = header.index("last name")
    except ValueError:
        idx_1 = None
    try:
        idx_2 = header.index("lastname")
    except ValueError:
        idx_2 = None

    if idx_1 is not None:
        return idx_1
    if idx_2 is not None:
        return idx_2


def get_email_field(header: list[str]) -> int:
    """gets index of email field"""
    return header.index("email")


def get_login_field(header: list[str]) -> int:
    """gets index of login field"""
    try:
        idx = header.index("login")
    except ValueError:
        idx = None

    return idx


async def create_users(
    dracoon: DRACOON, user_list: list[ParsedUser], oidc_id: int = None
):
    """function bulk creating all users from parsed list"""

    user_create_reqs = []

    for user in user_list:

        if oidc_id is not None:
            user_create_reqs.append(
                create_oidc_user(dracoon=dracoon, user=user, oidc_id=oidc_id)
            )
        else:
            user_create_reqs.append(create_local_user(dracoon=dracoon, user=user))

    user_create_reqs = [asyncio.ensure_future(item) for item in user_create_reqs]

    for batch in dracoon.batch_process(coro_list=user_create_reqs, batch_size=25):
        try:
            await asyncio.gather(*batch)
        except HTTPForbiddenError:
            for req in user_create_reqs:
                req.cancel()
            await dracoon.logout()
            typer.echo(
                format_error_message(
                    msg="Insufficient permissions (user manager required)."
                )
            )
            sys.exit(1)
        except HTTPConflictError:
            continue
        except HTTPBadRequestError:
            continue
        except DRACOONHttpError:
            continue


def create_local_user(dracoon: DRACOON, user: ParsedUser):
    """helper creating a coroutine to create a local user"""
    payload = dracoon.users.make_local_user(
        first_name=user.first_name, last_name=user.last_name, email=user.email
    )

    return dracoon.users.create_user(user=payload, raise_on_err=True)


def create_oidc_user(dracoon: DRACOON, user: ParsedUser, oidc_id: int):
    """helper creating a coroutine to create an OIDC user"""

    if user.login is None:
        user.login = user.email

    payload = dracoon.users.make_oidc_user(
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        login=user.login,
        oidc_id=oidc_id,
    )

    return dracoon.users.create_user(user=payload, raise_on_err=True)


async def delete_user(dracoon: DRACOON, user_id: int):
    """ delete a user from DRACOON with given user id """
    try:
        await dracoon.users.delete_user(user_id=user_id, raise_on_err=True)
        typer.echo(format_success_message(msg=f"User with id {user_id} deleted."))
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg="Insufficient permissions (user manager required)."
                )
            )
        sys.exit(1)
    except HTTPBadRequestError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg="User cannot be deleted: last admin in room or role."
                )
            )
        sys.exit(1)
    except DRACOONHttpError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg="An error ocurred - could not delete user."
                )
            )
        sys.exit(1)

async def get_users(dracoon: DRACOON, search_string: str = ''):
    """ get a list of users with optional search string """ 

    # ignore search if empty string
    if search_string == '':
        search_filter = None
    else:
        search_filter = f'userName:cn:{search_string}|firstName:cn:{search_string}|lastName:cn:{search_string}'

    try:
        user_list = await dracoon.users.get_users(filter=search_filter, offset=0)
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg="Insufficient permissions (user manager required)."
                )
            )
        sys.exit(1)
    except DRACOONHttpError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg="An error ocurred - could not delete user."
                )
            )
        sys.exit(1)

    if user_list.range.total > 500:
        user_reqs = [dracoon.users.get_users(filter=search_filter, offset=offset) for offset in range(500, user_list.range.total, 500)]

        for batch in dracoon.batch_process(coro_list=user_reqs, batch_size=5):
            user_batches = asyncio.gather(*batch)

            for item in user_batches:
                user_list.items.extend(item.items)

    return user_list


async def find_user_by_username(dracoon: DRACOON, user_name: str, as_user_manager: bool = True, 
                                room_id: int = None) -> Union[RoomUser, UserItem]:
    """ Find a user by username """
    #user_name = parse.quote(user_name)

    if not as_user_manager and room_id is None:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg="Cannot find user without user manager and room id."
                )
            )
        sys.exit(1)

    try:
        if as_user_manager:
            user_list = await dracoon.users.get_users(filter=f'userName:eq:{user_name}')
        else:
            filter_str = "isGranted:eq:any|user:cn:"
            user_list = await dracoon.nodes.get_room_users(room_id=room_id, filter=f"{filter_str}{user_name}")
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg="Insufficient permissions (user manager required)."
                )
            )
        sys.exit(1)
    except DRACOONHttpError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg="An error ocurred - could not find user."
                )
            )
        sys.exit(1)

    if len(user_list.items) == 0 or len(user_list.items) > 1:
        await dracoon.logout()
        typer.echo(
            format_error_message(
                msg=f"No user found with username '{user_name}'."
                )
            )
        sys.exit(1)

    return user_list.items[0]








