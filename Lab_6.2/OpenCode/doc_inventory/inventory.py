import os
import pathlib
from datetime import datetime
from typing import List, Dict, Any

class SecurityError(ValueError):
    """Raised when an operation attempts to access outside the allowed test folder."""
    pass

class DocumentInventory:
    """Safe document inventory scanner restricted to a specified base directory."""

    def __init__(self, base_dir: str | pathlib.Path):
        self.base_dir = pathlib.Path(base_dir).resolve()
        if not self.base_dir.exists():
            raise FileNotFoundError(f"Base directory does not exist: {self.base_dir}")
        if not self.base_dir.is_dir():
            raise NotADirectoryError(f"Base path is not a directory: {self.base_dir}")

    def _validate_path(self, file_path: pathlib.Path) -> pathlib.Path:
        """Ensure the file path resolves to a location strictly inside self.base_dir."""
        resolved = file_path.resolve()
        try:
            resolved.relative_to(self.base_dir)
        except ValueError:
            raise SecurityError(f"Access denied: Path '{file_path}' is outside base directory '{self.base_dir}'")
        return resolved

    def scan(self, extensions: List[str] | None = None) -> List[Dict[str, Any]]:
        """
        Scans the base directory recursively for files.
        Optionally filters by file extensions (e.g., ['.pdf', '.txt']).
        """
        inventory = []
        # Normalize extensions if provided
        norm_extensions = {ext.lower() for ext in extensions} if extensions else None

        for root, _, files in os.walk(self.base_dir):
            root_path = pathlib.Path(root)
            for file in files:
                file_path = root_path / file
                # Validate path safety
                try:
                    safe_path = self._validate_path(file_path)
                except SecurityError:
                    continue

                ext = safe_path.suffix.lower()
                if norm_extensions and ext not in norm_extensions:
                    continue

                stat = safe_path.stat()
                rel_path = safe_path.relative_to(self.base_dir)

                item = {
                    "name": safe_path.name,
                    "path": str(rel_path),
                    "absolute_path": str(safe_path),
                    "size_bytes": stat.st_size,
                    "extension": ext,
                    "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
                inventory.append(item)

        # Sort inventory by path for consistent output
        inventory.sort(key=lambda x: x["path"])
        return inventory


def generate_inventory(base_dir: str | pathlib.Path, extensions: List[str] | None = None) -> List[Dict[str, Any]]:
    """Convenience function to generate a document inventory."""
    scanner = DocumentInventory(base_dir)
    return scanner.scan(extensions=extensions)
