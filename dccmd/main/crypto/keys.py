"""
Module implementig file key distrubtion for
crypto uploads and beyond
"""

import typer

from dracoon import DRACOON
from dracoon.crypto import decrypt_file_key, encrypt_file_key_public


async def distribute_missing_keys(
    dracoon: DRACOON, file_id: int = None, room_id: int = None
):
    """get missing file keys by filter (room or file)"""

    missing_keys = await dracoon.nodes.get_missing_file_keys(
        room_id=room_id, file_id=file_id
    )

    typer.echo(f"Total keys: {missing_keys.range.total}")

    keys = dracoon.nodes.make_set_file_keys(file_key_list=[])

    # loop through every missing key entry
    #pylint: disable=C0301
    with typer.progressbar(iterable=missing_keys.items, label="Distributing file keys...") as missing_keys_list:
        for key in missing_keys_list:

            for file_item in missing_keys.files:
                # match file by id
                if key.fileId == file_item.id:
                    file_key = file_item.fileKeyContainer
                    # get plain file key
                    plain_file_key = decrypt_file_key(
                        file_key=file_key, keypair=dracoon.plain_keypair
                    )

            for user in missing_keys.users:
                if key.userId == user.id:
                    public_key = user.publicKeyContainer

            user_file_key = encrypt_file_key_public(
                plain_file_key=plain_file_key, public_key=public_key
            )

            file_key_item = dracoon.nodes.make_set_file_key_item(
                file_id=key.fileId, user_id=key.userId, file_key=user_file_key
            )

            keys.items.append(file_key_item)

    await dracoon.nodes.set_file_keys(file_keys=keys)
