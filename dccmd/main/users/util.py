"""
Module with utility functions for user management
- User creation / deletion / listing
- Formatting
"""

import sys
import csv
import asyncio
from typing import Optional

from dracoon import DRACOON
from dracoon.errors import (HTTPConflictError, HTTPBadRequestError, 
                            HTTPForbiddenError, HTTPStatusError)
from pydantic import BaseModel
import typer

from dccmd.main.util import format_error_message
from dccmd.main.upload import is_file


HEADER_FIELDS = ["first name", "firstname", "last name", "lastname", "email", "login"]


class ParsedUser(BaseModel):
    """ object representing a parsed user """
    first_name: str
    last_name: str
    email: str
    login: Optional[str]

def parse_csv(source_path: str) -> list[ParsedUser]:
    """ open a CSV file with given path and create a list of user entries """
    if not is_file(source_path):
        typer.echo(format_error_message(msg=f"Provided path is not a file: {source_path}"))
        sys.exit(1)

    user_list = []

    with open(file=source_path, mode='r', encoding='utf8') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")

        header = next(csv_reader)

        if not validate_header(header=header):
            typer.echo(format_error_message(msg="Invalid field names. Allowed field names: 'first name', 'last name', 'email', 'login'"))
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
                "login": None
            }

            if idx_login != -1:
                parsed_user["login"] = user[idx_login]

            user_list.append(ParsedUser(**parsed_user))

        return user_list


def validate_header(header: list[str]) -> bool:
    """ validate CSV header - reject invalid field names """

    if len(header) < 1:
        return False

    for field in header:
        if field.lower() not in HEADER_FIELDS:
            return False

    return True


def header_to_lower(header: list[str]) -> list[str]:
    """ normalized all header fields to lowercase """
    return [field.lower() for field in header]

def get_first_name_field(header: list[str]) -> int:
    """ gets index of first name field """
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
    """ gets index of last name field """
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
    """ gets index of email field """
    return header.index("email")


def get_login_field(header: list[str]) -> int:
    """ gets index of login field """
    try:
        idx = header.index("login")
    except ValueError:
        idx = None

    return idx

async def create_users(dracoon: DRACOON, user_list: list[ParsedUser], oidc_id: int = None):
    """ function bulk creating all users from parsed list """

    user_create_reqs = []

    for user in user_list:

        if oidc_id is not None:
            user_create_reqs.append(create_oidc_user(dracoon=dracoon, user=user, oidc_id=oidc_id))
        else:
            user_create_reqs.append(create_local_user(dracoon=dracoon, user=user))

    for batch in dracoon.batch_process(coro_list=user_create_reqs, batch_size=25):
        try:
            await asyncio.gather(*batch)
        except HTTPForbiddenError:
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
        except HTTPStatusError:
            continue

def create_local_user(dracoon: DRACOON, user: ParsedUser):
    """ helper creating a coroutine to create a local user """
    payload = dracoon.users.make_local_user(first_name=user.first_name, last_name=user.last_name,
                                            email=user.email)

    return dracoon.users.create_user(user=payload, raise_on_err=True)

def create_oidc_user(dracoon: DRACOON, user: ParsedUser, oidc_id: int):
    """ helper creating a coroutine to create an OIDC user """

    if user.login is None:
        user.login = user.email

    payload = dracoon.users.make_oidc_user(first_name=user.first_name, last_name=user.last_name,
                                           email=user.email, login=user.login, oidc_id=oidc_id)

    return dracoon.users.create_user(user=payload, raise_on_err=True)
