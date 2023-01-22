import typer

from dracoon.user.responses import UserList, RoleList

def pretty_print(user_list: UserList):
    """ prints a list of users with regular separator """
    # print header
    typer.echo("id | first name | last name | email | username | lastLoginAt | createdAt | isRoomManager | isConfigManager | isUserManager | isGroupManager | isAuditor")

    for user in user_list.items:
        roles = parse_user_roles(user.userRoles)
        typer.echo(f"{user.id} | {user.firstName} | {user.lastName} | {user.email} | {user.userName} | {user.lastLoginSuccessAt} | {user.createdAt} | {roles['config']} | {roles['user']} | {roles['group']} | {roles['room']} | {roles['audit']}")


def csv_print(user_list: UserList):
    """ prints a list of users with comma separator """
    # print header
    typer.echo("id,firstName,lastName,mail,userName,lastLoginAt,createdAt,isConfigManager,isUserManager,isGroupManager,isRoomManager,isAuditor")
    for user in user_list.items:
        roles = parse_user_roles(user.userRoles)
        typer.echo(f"{user.id},{user.firstName},{user.lastName},{user.email},{user.userName},{user.lastLoginSuccessAt},{user.createdAt},{roles['config']},{roles['user']},{roles['group']},{roles['room']},{roles['audit']}")


def parse_user_roles(user_roles: RoleList):
    """" parse user roles """

    roles = {
            "room": "false",
            "user": "false",
            "group": "false",
            "config": "false",
            "audit": "false"
        }

    if user_roles is None:
        return roles
    
    for role in user_roles.items:
        if role.id == 1:
            roles["config"] = "true"
        if role.id == 2:
            roles["user"] = "true"
        if role.id == 3:
            roles["group"] = "true"
        if role.id == 4:
            roles["room"] = "true"
        if role.id == 5:
            roles["audit"] = "true"

    return roles