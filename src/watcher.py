import time
from typing import Callable

from watchdog.events import FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from src.database import LogDatabase
from src.logger import get_logger
from src.parser import LogParser

logger = get_logger(__name__)


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, filepath: str, parser: LogParser, callback: Callable):
        self.filepath = filepath
        self.parser = parser
        self.callback = callback
        self._offset = self._get_file_size()

    def _get_file_size(self) -> int:
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                f.seek(0, 2)
                return f.tell()
        except FileNotFoundError:
            return 0

    def on_modified(self, event):
        if not isinstance(event, FileModifiedEvent):
            return
        if not event.src_path.replace("\\", "/").endswith(
            self.filepath.replace("\\", "/")
        ):
            return

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                f.seek(self._offset)
                new_lines = f.readlines()
                self._offset = f.tell()
        except FileNotFoundError:
            return

        entries = []
        for line in new_lines:
            entry = self.parser.parse_line(line)
            if entry:
                entries.append(entry)

        if entries:
            self.callback(entries)
            logger.info(f"Processed {len(entries)} new entries")


class LogWatcher:
    def __init__(self, filepath: str, db: LogDatabase):
        self.filepath = filepath
        self.db = db
        self.parser = LogParser()
        self.observer = Observer()

    def _on_new_entries(self, entries):
        self.db.insert_entries(entries)

    def start(self):
        import os

        directory = os.path.dirname(os.path.abspath(self.filepath))
        handler = LogFileHandler(self.filepath, self.parser, self._on_new_entries)
        self.observer.schedule(handler, directory, recursive=False)
        self.observer.start()
        logger.info(f"Watching {self.filepath}")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.observer.stop()
        self.observer.join()
        logger.info("Watcher stopped")
