"""
Module implementing bulk download from DRACOON

"""

import sys
import asyncio
from pathlib import Path

import typer
from tqdm import tqdm
from dracoon import DRACOON
from dracoon.errors import InvalidPathError, DRACOONHttpError
from dracoon.nodes.responses import NodeList, Node, NodeType

from ..models import DCTransfer, DCTransferList
from ..util import format_error_message


class DownloadDirectoryItem:
    """object representing a directory with all required path elements"""
    def __init__(self, dir_path: str, base_path: str):
        base_path = Path(base_path)
        self.abs_path = base_path.joinpath(dir_path[1:])
        self.path = dir_path
        self.name = self.abs_path.name
        self.parent_path = self.abs_path.parent
        self.level = len(self.path.split("/")) - 1

class DownloadFileItem:
    """ object representing a single file with all required path infos """
    def __init__(self, dir_path: str, base_path: str, node_info: Node):
        base_path = Path(base_path)
        self.abs_path = base_path.joinpath(dir_path[1:])
        self.path = dir_path
        self.name = self.abs_path.name
        self.parent_path = self.abs_path.parent
        self.level = len(self.path.split("/")) - 1
        self.node = node_info


class DownloadList:
    """ list of files and folders within a room (subrooms excluded) """
    def __init__(self, file_list: NodeList, folder_list: NodeList, node: Node, target_path: str):
        self.file_list = file_list
        self.folder_list = folder_list
        self.node = node
        self.target_path = target_path
        print(self.base_level)
    
    def get_level(self, level: int) -> list[DownloadDirectoryItem]:
        """get all directories in a depth level"""
        level_list = [dir for dir in self.folder_items if dir.level == level]
        level_list.sort(key=lambda dir: dir.path)
        return level_list

    def get_by_parent(self, parent: str):
        """get all directories by parent"""
        return [dir for dir in self.folder_items if dir.parent_path == parent]

    def get_batches(self, level: int) -> list[list[DownloadDirectoryItem]]:
        """create batches based on depth levels"""
        parent_list = set([dir.parent_path for dir in self.get_level(level=level)])

        return [self.get_by_parent(parent) for parent in parent_list]

    @property
    def total_size(self) -> int:
        """ returns total download size """
        return sum([node.size for node in self.file_list.items])

    @property
    def file_paths(self) -> list[str]:
        """ returns all file paths in alphabetical order """
        return sorted([f"{node.parentPath}{node.name}" for node in self.file_list.items])

    @property
    def folder_paths(self) -> list[str]:
        """ returns all folder paths in alphabetical order """
        return sorted([f"{normalize_parent_path(parent_path=node.parentPath, level=self.base_level)}{node.name}" for node in self.folder_list.items])

    @property
    def folder_items(self) -> list[DownloadDirectoryItem]:
        """ returns folder item including level """
        return [DownloadDirectoryItem(dir_path=dir_path, base_path=self.target_path) for dir_path in self.folder_paths]

    @property
    def file_items(self) -> list[DownloadFileItem]:
        """ returns folder item including level """
        return [DownloadFileItem(dir_path=f"{normalize_parent_path(parent_path=node.parentPath, level=self.base_level)}{node.name}", 
                base_path=self.target_path, node_info=node) for node in self.file_list.items]

    @property
    def levels(self):
        """ returns levels """ 
        return set([dir.level for dir in self.folder_items])

    @property
    def base_level(self):
        """ return base level of the source container """
        path_comp = self.node.parentPath.split("/")

        if len(path_comp) == 2:
            return 0
        elif len(path_comp) >= 3:
            return len(path_comp) - 2

def normalize_parent_path(parent_path: str, level: int):
    """ remove parent path components if root on specific level """
    path_comp = parent_path.split('/')
    normalized_comp = path_comp[level+1:]
    return "/" + "/".join(normalized_comp)


def create_folder(name: str, target_dir_path: str):
    """ creates a folder in a target directory """
    target_path = Path(target_dir_path)

    if not target_path.is_dir():
        raise InvalidPathError(message=f"Path {target_path} is not a folder: Creating {name} failed.")

    target_path = target_path.joinpath(name)
    target_path.mkdir()


async def get_nodes(dracoon: DRACOON, parent_id: int, node_type: NodeType, depth_level: int = -1) -> NodeList:
    """ get all files for a given parent id """
    node_filter = 'type:eq:'


    if node_type == NodeType.file:
        node_filter += NodeType.file.value
    if node_type == NodeType.folder:
        node_filter += NodeType.folder.value
    if node_type == NodeType.room:
        node_filter += NodeType.room.value

    node_list = await dracoon.nodes.search_nodes(search="*", parent_id=parent_id, depth_level=depth_level, filter=node_filter)
    if node_list.range.total > 500:
        node_reqs = [
            dracoon.nodes.search_nodes(search="*", parent_id=parent_id, depth_level=depth_level, offset=offset, filter=node_filter)
            for offset in range(500, node_list.range.total, 500)
            ]
        for reqs in dracoon.batch_process(coro_list=node_reqs, batch_size=20):
            node_lists = await asyncio.gather(*reqs)
            for item in node_lists:
                node_list.items.extend(item.items)

    return node_list


async def create_download_list(dracoon: DRACOON, node_info: Node, target_path: str) -> DownloadList:
    """ returns a list of files and folders for bulk download operations """

    target_path_check = Path(target_path)
    if not target_path_check.is_dir():
        raise InvalidPathError(message=f"Path {target_path_check} is not a folder.")

    # get all files and folders within path
    all_files = await get_nodes(dracoon=dracoon, parent_id=node_info.id, node_type=NodeType.file)
    all_folders = await get_nodes(dracoon=dracoon, parent_id=node_info.id, node_type=NodeType.folder)

    # only consider those with authParentId of the parent room if the source is a room (exclude sub rooms)
    if node_info.type == NodeType.room:
        all_files.items = [item for item in all_files.items if item.authParentId == node_info.id]
        all_folders.items = [item for item in all_folders.items if item.authParentId == node_info.id]

    return DownloadList(file_list=all_files, folder_list=all_folders, node=node_info, target_path=target_path)

async def bulk_download(dracoon: DRACOON, download_list: DownloadList, velocity: int = 2):
    """ download all files within a room (excluded: sub rooms) """

    if len(download_list.file_list.items) <= 0:
        typer.echo(format_error_message(f"No files to download in {download_list.node.parentPath}{download_list.node.name}"))
        sys.exit(1)

    if velocity > 10:
        velocity = 10
    elif velocity < 1:
        velocity = 1

    concurrent_reqs = velocity * 5

    # create main folder
    try:
        create_folder(name=download_list.node.name, target_dir_path=download_list.target_path)
    except FileExistsError:
        pass

    progress = tqdm(unit='folder level', total=len(download_list.levels), unit_scale=True)
    for level in download_list.levels:
        
        for batch in download_list.get_batches(level):
            for folder in batch:
                try:
                    create_folder(name=folder.name,target_dir_path=folder.parent_path)
                except FileExistsError:
                    continue
        progress.update()

    progress.close()

    transfer_list = DCTransferList(total=download_list.total_size, file_count=len(download_list.file_items))


    download_reqs = []

    for file_item in download_list.file_items:
        download_job = DCTransfer(transfer=transfer_list)
        download_req = dracoon.download(target_path=file_item.parent_path, callback_fn=download_job.update,
                                        source_node_id=file_item.node.id, chunksize=1048576)
        download_reqs.append(asyncio.ensure_future(download_req))

    for downloads in dracoon.batch_process(coro_list=download_reqs, batch_size=concurrent_reqs):
        try:
            await asyncio.gather(*downloads)
        except DRACOONHttpError:
            for req in download_reqs:
                req.cancel()
                typer.echo(format_error_message("Download could not be finished."))
    

    
