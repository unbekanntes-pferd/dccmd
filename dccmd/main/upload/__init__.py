"""
Module implementing bulk upload of files
and bulk creation of folders in DRACOON
"""


import os
import platform
import sys
import asyncio
from pathlib import Path

import typer
from httpx import WriteTimeout
from dracoon import DRACOON
from dracoon.errors import (
    InvalidPathError,
    HTTPConflictError,
    HTTPForbiddenError,
    HTTPStatusError,
)

from ..util import format_error_message, to_readable_size
from ..auth.credentials import get_crypto_credentials, store_crypto_credentials


class DirectoryItem:
    """object representing a directory with all required path elements"""

    def __init__(self, dir_path: str, base_path: str):
        if is_win32():
            self.dir_path = dir_path.replace("\\", "/")
        else:
            self.dir_path = dir_path
        self.abs_path = self.dir_path.replace(base_path, "")
        self.name = self.abs_path.split("/")[-1]
        self.parent_path = ("/").join(self.abs_path.split("/")[:-1])
        self.level = len(self.abs_path.split("/")) - 1


class DirectoryItemList:
    """object representing a list of all directories in a source path"""

    def __init__(self, source_path: str):

        # reject invalid source path
        if not is_directory(folder_path=source_path):
            raise InvalidPathError()

        # convert path strings to items
        self.dir_list = convert_to_dir_items(
            dir_list=fast_scandir(dirname=source_path), base_dir=source_path
        )
        # get unique depth levels
        self.levels = set([dir.level for dir in self.dir_list])

    def get_level(self, level: int) -> list[DirectoryItem]:
        """get all directories in a depth level"""
        level_list = [dir for dir in self.dir_list if dir.level == level]
        level_list.sort(key=lambda dir: dir.abs_path)
        return level_list

    def get_by_parent(self, parent: str):
        """get all directories by parent"""
        return [dir for dir in self.dir_list if dir.parent_path == parent]

    def get_batches(self, level: int) -> list[list[DirectoryItem]]:
        """create batches based on depth levels"""
        parent_list = set([dir.parent_path for dir in self.get_level(level=level)])

        return [self.get_by_parent(parent) for parent in parent_list]


class FileItem:
    """object representing a single file"""

    def __init__(self, dir_path: str, base_path: str):
        if is_win32():
            self.dir_path = dir_path.replace("\\", "/")
        else:
            self.dir_path = dir_path
        self.abs_path = self.dir_path.replace(base_path, "")
        self.name = self.abs_path.split("/")[-1]
        self.parent_path = ("/").join(self.abs_path.split("/")[:-1])
        self.level = len(self.abs_path.split("/")) - 1
        self.size = os.path.getsize(self.dir_path)


class FileItemList:
    """object representing all files in a path (recursively)"""

    def __init__(self, source_path: str):

        # reject invalid source paths
        if not is_directory(folder_path=source_path):
            raise InvalidPathError()

        # get list of all files
        self.file_list = [
            FileItem(dir_path, source_path)
            for dir_path in fast_scanfile(dirname=source_path)
        ]
        # get unique levels
        self.levels = set([file_item.level for file_item in self.file_list])

    def get_level(self, level: int) -> list[FileItem]:
        """get depth level by number"""
        return [item for item in self.file_list if item.level == level]

    def sort_by_size(self):
        """sort files by file size"""
        self.file_list.sort(key=lambda item: item.size, reverse=True)


def convert_to_dir_items(dir_list: list[str], base_dir: str) -> list[DirectoryItem]:
    """convert a list of paths to a list of directory items (helper class)"""

    #pylint: disable=W0108
    dir_list.sort(key=lambda x: len(x))
    parsed_list = [DirectoryItem(dir_path=x, base_path=base_dir) for x in dir_list]
    parsed_list.sort(key=lambda dir: dir.level)

    return parsed_list


def fast_scandir(dirname: str) -> list[str]:
    """return list of all folders in a given parent directory (recursive)"""
    subfolders = [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders


def fast_scanfile(dirname: str) -> list[str]:
    """return list of all files in a given parent directory (recursive)"""
    files = [f.path for f in os.scandir(dirname) if f.is_file()]
    subfolders = [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
        files.extend(fast_scanfile(dirname))
    return files


def is_directory(folder_path: str) -> bool:
    """check if path is a directory"""
    parsed_path = Path(folder_path)

    return parsed_path.is_dir()


def is_file(folder_path: str) -> bool:
    """check if path is a file"""
    parsed_path = Path(folder_path)

    return parsed_path.is_file()


def is_win32() -> bool:
    """check if OS is Windows"""
    return platform.system() == "Windows"


async def create_folder_struct(source: str, target: str, dracoon: DRACOON):
    """create all necessary folders for a recursive folder upload"""

    async def process_batch(batch):
        """process a batch of folders to create"""

        path = target + batch[0].parent_path
        parent_node = await dracoon.nodes.get_node_from_path(path)

        parent_id = parent_node.id

        # create list of folder requests
        folder_reqs = [
            create_folder(name=item.name, parent_id=parent_id, dracoon=dracoon)
            for item in batch
        ]

        # process 10 folders per batch
        for reqs in dracoon.batch_process(coro_list=folder_reqs, batch_size=10):
            try:
                await asyncio.gather(*reqs)
            except HTTPConflictError:
                continue
            except HTTPForbiddenError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(
                        msg="Insufficient permissions (create required)."
                    )
                )
                sys.exit(2)
            except HTTPStatusError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(msg="An error ocurred creating the folder.")
                )
                sys.exit(2)
            except WriteTimeout:
                continue

    sub_folders = DirectoryItemList(source_path=source)

    typer.echo(f"{len(sub_folders.dir_list)} folders to process.")

    with typer.progressbar(
        iterable=sub_folders.levels, label="Creating folder structure..."
    ) as levels:
        # iterate over all levels (depth)
        for level in levels:

            # fetch batches per level
            batches = sub_folders.get_batches(level=level)

            # process 3 batches in parallel per level
            for batch in dracoon.batch_process(
                coro_list=[process_batch(item) for item in batches], batch_size=3
            ):
                await asyncio.gather(*batch)


async def bulk_upload(
    source: str,
    target: str,
    dracoon: DRACOON,
    resolution_strategy: str = "fail",
    velocity: int = 2,
):
    """upload a list of files in a given source path"""

    file_list = FileItemList(source_path=source)
    file_list.sort_by_size()

    if velocity > 10:
        velocity = 10
    elif velocity < 1:
        velocity = 1

    concurrent_reqs = velocity * 5

    typer.echo(f"{len(file_list.file_list)} files to upload.")

    upload_reqs = [
        dracoon.upload(
            file_path=item.dir_path,
            target_path=(target + item.parent_path),
            resolution_strategy=resolution_strategy,
            display_progress=False,
        )
        for item in file_list.file_list
    ]
    total_files = len(upload_reqs)
    total_size = sum([item.size for item in file_list.file_list])

    typer.echo(f"{to_readable_size(size=total_size)} total.")

    with typer.progressbar(length=total_files, label="Uploading files...") as progress:
        for batch in dracoon.batch_process(
            coro_list=upload_reqs, batch_size=concurrent_reqs
        ):
            progress.update(len(batch))
            try:
                await asyncio.gather(*batch)
            except HTTPConflictError:
                # ignore file already exists error
                pass
            except HTTPForbiddenError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(
                        msg="Insufficient permissions (create / esdit required)."
                    )
                )
                sys.exit(2)
            except HTTPStatusError:
                await dracoon.logout()
                typer.echo(
                    format_error_message(msg="An error ocurred uploading files.")
                )
                sys.exit(2)
            except WriteTimeout:
                continue


def create_folder(name: str, parent_id: int, dracoon: DRACOON):
    """helper to create folder creation requests"""

    folder = dracoon.nodes.make_folder(name=name, parent_id=parent_id)

    return dracoon.nodes.create_folder(folder=folder, raise_on_err=True)
