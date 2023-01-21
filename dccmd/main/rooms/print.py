import typer

from dracoon.nodes.responses import RoomUserList, RoomGroupList

def pretty_print_user_perms(user_permissions: RoomUserList):
    """ print user permissions """
    # header
    typer.echo("user id | first name | last name | email | username | manage | read | create | change | delete | mange shares | manage file requests | read recyclebin | restore recycle bin | delete recycle bin")
    for user in user_permissions.items:
        typer.echo(f"{user.userInfo.id} | {user.userInfo.firstName} | {user.userInfo.lastName} | {user.userInfo.email} | {user.userInfo.userName} | {user.permissions.manage} | {user.permissions.read} | {user.permissions.create} | {user.permissions.change} | {user.permissions.delete} | {user.permissions.manageDownloadShare} | {user.permissions.manageUploadShare} | {user.permissions.readRecycleBin} | {user.permissions.restoreRecycleBin} | {user.permissions.deleteRecycleBin}")

def pretty_print_group_perms(group_permissions: RoomGroupList):
    """ print group permissions """
    # header
    typer.echo("group id | name | manage | read | create | change | delete | mange shares | manage file requests | read recyclebin | restore recycle bin | delete recycle bin")
    for group in group_permissions.items:
        typer.echo(f"{group.id} | {group.name} | {group.permissions.manage} | {group.permissions.read} | {group.permissions.create} | {group.permissions.change} | {group.permissions.delete} | {group.permissions.manageDownloadShare} | {group.permissions.manageUploadShare} | {group.permissions.readRecycleBin} | {group.permissions.restoreRecycleBin} | {group.permissions.deleteRecycleBin}")


def csv_print_user_perms(user_permissions: RoomUserList):
    """ print user permissions in CSV format """
    # header
    typer.echo("user id,first name,last name,email,username,manage,read,create,change,delete,mange shares,manage file requests,read recyclebin,restore recycle bin,delete recycle bin")
    for user in user_permissions.items:
        typer.echo(f"{user.userInfo.id},{user.userInfo.firstName},{user.userInfo.lastName},{user.userInfo.email},{user.userInfo.userName},{user.permissions.manage},{user.permissions.read},{user.permissions.create},{user.permissions.change},{user.permissions.delete},{user.permissions.manageDownloadShare},{user.permissions.manageUploadShare},{user.permissions.readRecycleBin},{user.permissions.restoreRecycleBin},{user.permissions.deleteRecycleBin}")


def csv_print_group_perms(group_permissions: RoomGroupList):
    """ print group permissions in CSV format """
    # header
    typer.echo("group id,name,manage,read,create,change,delete,mange shares,manage file requests,read recyclebin,restore recycle bin,delete recycle bin")
    for group in group_permissions.items:
        typer.echo(f"{group.id},{group.name},{group.permissions.manage},{group.permissions.read},{group.permissions.create},{group.permissions.change},{group.permissions.delete},{group.permissions.manageDownloadShare},{group.permissions.manageUploadShare},{group.permissions.readRecycleBin},{group.permissions.restoreRecycleBin},{group.permissions.deleteRecycleBin}")
