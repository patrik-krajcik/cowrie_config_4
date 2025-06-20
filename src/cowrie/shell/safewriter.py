
import fcntl

class SafeFileWriter:
    """
    A safe file writer that uses fcntl to lock the file during writes.
    Use with 'with' statement to ensure proper lock and unlock.
    """

    def __init__(self, file_path: str, mode: str = 'a+'):
        """
        Initialize with file path and mode.
        Default mode is 'a+' (read/write, create if not exists).
        """
        self.file_path = file_path
        self.mode = mode
        self.file = None

    def __enter__(self):
        """
        Open the file and lock it exclusively.
        """
        self.file = open(self.file_path, self.mode)
        fcntl.flock(self.file, fcntl.LOCK_EX)
        return self.file

    def __exit__(self, exc_type, exc_val, exc_tb):
    
        if self.file:
            try:
                fcntl.flock(self.file, fcntl.LOCK_UN)
            except Exception:
                pass  # ignore unlock errors
            self.file.close()
