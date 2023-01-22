from dracoon.nodes.models import TransferJob
from tqdm import tqdm
from .errors import DCInvalidArgumentError


class DCTransferList:
    """ object to manage one or multiple transfers with progress bar """
    def __init__(self, total: int, file_count: int):

        if file_count <= 0 or total <= 0:
            raise DCInvalidArgumentError(msg="Total and file count must be a positive number.")

        self.total = total
        self.file_count = file_count
        self.file_progress = tqdm(unit='file', total=self.file_count, unit_scale=True)
        self.progress = tqdm(unit='iMB',unit_divisor=1024, total=self.total, unit_scale=True)

    def update_byte_progress(self, val: int):
        """ updates transferred bytes """
        self.progress.update(val)

    def update_file_count(self):
        """ updates file count """
        self.file_progress.update(1)

    def __del__(self):
        self.progress.close()
        self.file_progress.close()


class DCTransfer(TransferJob):
    """ a single transfer managed by DCTransferList """

    def __init__(self, transfer: DCTransferList):
        super().__init__()

        self.transfer = transfer

    def update(self, val: int, total: int = None):
        """ callback function to track progress """
        if total is not None and val == 0:
            self.total += total
        
        self.update_progress(val)
        self.transfer.update_byte_progress(val)

        if self.progress == 1:
            self.transfer.update_file_count()
    