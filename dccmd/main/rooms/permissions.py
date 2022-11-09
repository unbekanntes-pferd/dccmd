from dracoon import DRACOON
from dracoon.errors import HTTPForbiddenError, HTTPNotFoundError
from dracoon.nodes.models import Permissions, UpdateRoomUsers

from dccmd.main.models.errors import DCInvalidArgumentError
from dccmd.main.rooms.models import PermissionTemplate
from dccmd.main.users.manage import find_user_by_username


async def get_room_user_permissions():
    pass

async def get_room_group_permissions():
    pass

async def add_room_user(room_id: int, username: str, permission_template: PermissionTemplate, dracoon: DRACOON):

    user = await find_user_by_username(dracoon=dracoon, user_name=username, as_user_manager=False, room_id=room_id)
    permissions = create_permissions(permissions=permission_template, dracoon=dracoon)

    user_update = dracoon.nodes.make_permission_update(id=user.id, permission=permissions)
    users_update = UpdateRoomUsers(items=[user_update])
    try:
        await dracoon.nodes.update_room_users(room_id=room_id, users_update=users_update)
    except HTTPForbiddenError:
        pass
    except HTTPNotFoundError:
        pass


async def add_room_group(name: str, permission_template: PermissionTemplate, dracoon: DRACOON):
    pass

async def remove_room_user(username: str, dracoon: DRACOON):
    pass

async def remove_room_group(name: str, dracoon: DRACOON):
    pass

async def get_group_by_name(name: str, dracoon: DRACOON):
    pass

def create_permissions(permissions: PermissionTemplate, dracoon: DRACOON) -> Permissions:

    perms = dracoon.nodes.make_permissions(manage=False, read=False, create=False, change=False, delete=False, manage_shares=False, 
                                           manage_file_requests=False, delete_recycle_bin=False, restore_recycle_bin=False, 
                                           read_recycle_bin=False)

    if not isinstance(permissions, PermissionTemplate):
        raise DCInvalidArgumentError

    if permissions == PermissionTemplate.READ:
        perms.read = True
        perms.manageDownloadShare = True

    if permissions == PermissionTemplate.EDIT:
        perms.read = True
        perms.create = True
        perms.change = True
        perms.delete = True
        perms.manageDownloadShare = True
        perms.manageUploadShare = True
        perms.readRecycleBin = True
        perms.restoreRecycleBin = True

    if permissions == PermissionTemplate.ROOM_ADMIN:
        perms.read = True
        perms.create = True
        perms.change = True
        perms.delete = True
        perms.manageDownloadShare = True
        perms.manageUploadShare = True
        perms.readRecycleBin = True
        perms.restoreRecycleBin = True
        perms.manage = True
        perms.deleteRecycleBin = True

    return perms

