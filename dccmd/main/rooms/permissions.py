"""
Functions to perform room admin tasks
- get permissions
- assign / remove users & groups
"""

import sys
import typer

from dracoon import DRACOON
from dracoon.errors import HTTPForbiddenError, HTTPNotFoundError, DRACOONHttpError
from dracoon.nodes.models import (Permissions, UpdateRoomUsers, UpdateRoomGroups, 
                                  UpdateRoomGroupItem, UpdateRoomUserItem)
from dracoon.nodes.responses import RoomGroup, RoomGroupList, RoomUserList

from dccmd.main.models.errors import DCInvalidArgumentError
from dccmd.main.rooms.models import PermissionTemplate
from dccmd.main.users.manage import find_user_by_username
from dccmd.main.util import format_error_message


async def get_room_user_permissions(room_id: int, dracoon: DRACOON) -> RoomUserList:
    """ get user permissions in a room """
    try:
        user_permissions = await dracoon.nodes.get_room_users(room_id=room_id)
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Insufficient permissions (room access required)."
                )
            )
        sys.exit(1)
    except HTTPNotFoundError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Room not found."
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
    else:
        return user_permissions


async def get_room_group_permissions(room_id: int, dracoon: DRACOON) -> RoomGroupList:
    """ get group permissions in a room """
    try:
        group_permissions = await dracoon.nodes.get_room_groups(room_id=room_id)
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Insufficient permissions (room access required)."
                )
            )
        sys.exit(1)
    except HTTPNotFoundError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Room not found."
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
    else:
        return group_permissions

async def add_room_user(room_id: int, username: str, permission_template: PermissionTemplate, dracoon: DRACOON):
    """ assign a user to a room """
    user = await find_user_by_username(dracoon=dracoon, user_name=username, as_user_manager=False, room_id=room_id)
    permissions = create_permissions(permissions=permission_template, dracoon=dracoon)

    #user_update = dracoon.nodes.make_permission_update(id=user.userInfo.id, permission=permissions)
    users_update = UpdateRoomUsers(items=[UpdateRoomUserItem(id=user.userInfo.id, permissions=permissions)])
    try:
        await dracoon.nodes.update_room_users(room_id=room_id, users_update=users_update)
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Insufficient permissions (room admin required)."
                )
            )
        sys.exit(1)
    except HTTPNotFoundError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Room not found."
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

async def add_room_group(room_id: int, name: str, permission_template: PermissionTemplate, dracoon: DRACOON):
    """ assign a group to a room """
    group = await get_group_by_name(room_id=room_id, name=name, dracoon=dracoon)
    permissions = create_permissions(permissions=permission_template, dracoon=dracoon)
    #group_update = dracoon.nodes.make_permission_update(id=group.id, permission=permissions)
    groups_update = UpdateRoomGroups(items=[UpdateRoomGroupItem(id=group.id, permissions=permissions)])

    try:
        await dracoon.nodes.update_room_groups(room_id=room_id, groups_update=groups_update)
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Insufficient permissions (room admin required)."
                )
            )
        sys.exit(1)
    except HTTPNotFoundError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Room not found."
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

async def remove_room_user(room_id: int, username: str, dracoon: DRACOON):
    """ remove user from room """
    user = await find_user_by_username(dracoon=dracoon, user_name=username, as_user_manager=False, room_id=room_id)

    try:
        await dracoon.nodes.delete_room_users(room_id=room_id, user_list=[user.userInfo.id])
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Insufficient permissions (room admin required)."
                )
            )
        sys.exit(1)
    except HTTPNotFoundError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Room not found."
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


async def remove_room_group(room_id: int, name: str, dracoon: DRACOON):
    """ remove group from room """
    group = await get_group_by_name(room_id=room_id, name=name, dracoon=dracoon)

    try:
        await dracoon.nodes.delete_room_groups(room_id=room_id, group_list=[group.id])
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Insufficient permissions (room admin required)."
                )
            )
        sys.exit(1)
    except HTTPNotFoundError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Room not found."
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

async def get_group_by_name(room_id: int, name: str, dracoon: DRACOON) -> RoomGroup:
    """ get a group by name """
    search_filter = f"name:cn:{name}|isGranted:eq:any"
    try:
        group_list = await dracoon.nodes.get_room_groups(room_id=room_id, filter=search_filter)
    except HTTPForbiddenError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Insufficient permissions (room access required)."
                )
            )
        sys.exit(1)
    except HTTPNotFoundError:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg="Room not found."
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

    if len(group_list.items) != 1:
        await dracoon.logout()
        typer.echo(
            format_error_message(
            msg=f"Unique group not found ({name}) Found {len(group_list.items)} groups."
                )
            )
        sys.exit(1)

    return group_list.items[0]

def set_read_perms(permissions: Permissions):
    """ set read specific permissions """
    permissions.read = True
    permissions.manageDownloadShare = True

def set_edit_perms(permissions: Permissions):
    """ set edit specific permissions """
    permissions.create = True
    permissions.change = True
    permissions.delete = True
    permissions.manageUploadShare = True
    permissions.readRecycleBin = True
    permissions.restoreRecycleBin = True

def set_room_admin_perms(permissions: Permissions):
    """ set room admin specific permissions """
    permissions.manage = True
    permissions.deleteRecycleBin = True

def create_permissions(permissions: PermissionTemplate, dracoon: DRACOON) -> Permissions:
    """ create permission payload from template """

    perms = dracoon.nodes.make_permissions(manage=False, read=False, create=False, change=False, delete=False, manage_shares=False,
                                           manage_file_requests=False, delete_recycle_bin=False, restore_recycle_bin=False,
                                           read_recycle_bin=False)

    if not isinstance(permissions, PermissionTemplate):
        raise DCInvalidArgumentError

    if permissions == PermissionTemplate.READ:
        set_read_perms(permissions=perms)

    if permissions == PermissionTemplate.EDIT:
        set_read_perms(permissions=perms)
        set_edit_perms(permissions=perms)


    if permissions == PermissionTemplate.ROOM_ADMIN:
        set_read_perms(permissions=perms)
        set_read_perms(permissions=perms)
        set_room_admin_perms(permissions=perms)

    return perms

def parse_permissions_template(perms: str) -> PermissionTemplate:
    """ parse str into template """
    perms = perms.lower()

    if perms == 'read':
        return PermissionTemplate.READ
    if perms == 'edit':
        return PermissionTemplate.EDIT
    if perms == 'admin':
        return PermissionTemplate.ROOM_ADMIN
    else:
        typer.echo(
            format_error_message(msg=f"Provided permission is not a valid template: {perms}")
        )
        sys.exit(1)
