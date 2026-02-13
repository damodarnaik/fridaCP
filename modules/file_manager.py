"""
File Manager - Application file browsing with su access.
Handles /data/data/<package> with view and download.
"""
import os
import posixpath
from typing import List, Dict, Optional, Tuple
from utils.logger import logger
import config


class FileManager:
    """Manages application files on device using su"""

    def __init__(self, device_manager):
        self.device_manager = device_manager

    def list_app_files(self, device_id: str, package_name: str, path: str = None) -> List[Dict]:
        """
        List files in app data directory using su.
        Returns: List of {name, type, size, permissions, path}
        """
        try:
            if not path:
                path = f"/data/data/{package_name}"

            # Try su first (required for /data/data)
            success, output = self.device_manager.execute_adb_command(
                device_id,
                ["shell", "su", "-c", f"ls -la '{path}'"],
                timeout=config.ADB_LONG_TIMEOUT
            )

            if not success:
                # Fallback: run-as
                success, output = self.device_manager.execute_adb_command(
                    device_id,
                    ["shell", "run-as", package_name, "ls", "-la", path],
                    timeout=config.ADB_LONG_TIMEOUT
                )

            if not success:
                logger.error(f"Cannot list files at {path}")
                return []

            files = []
            lines = output.strip().split('\n')

            for line in lines:
                # Skip header line
                if line.startswith("total") or not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 7:
                    continue

                permissions = parts[0]
                name = parts[-1]

                # Skip . and ..
                if name in ['.', '..']:
                    continue

                is_dir = permissions.startswith('d')
                is_link = permissions.startswith('l')

                # Try to parse size
                size = ""
                try:
                    # Size is usually the 5th field
                    size_val = parts[4] if len(parts) >= 5 else ""
                    if size_val.isdigit():
                        size = self._format_size(int(size_val))
                except:
                    pass

                full_path = posixpath.join(path, name) if not path.endswith('/') else path + name

                files.append({
                    "name": name,
                    "type": "directory" if is_dir else ("link" if is_link else "file"),
                    "size": size,
                    "permissions": permissions,
                    "path": full_path,
                })

            # Sort: directories first, then files
            files.sort(key=lambda x: (0 if x["type"] == "directory" else 1, x["name"].lower()))

            logger.info(f"Listed {len(files)} items in {path}")
            return files

        except Exception as e:
            logger.error(f"Error listing files: {str(e)[:80]}")
            return []

    def view_file(self, device_id: str, package_name: str, file_path: str) -> Optional[str]:
        """View file contents using su"""
        try:
            success, output = self.device_manager.execute_adb_command(
                device_id,
                ["shell", "su", "-c", f"cat '{file_path}'"],
                timeout=config.ADB_LONG_TIMEOUT
            )

            if not success:
                # Fallback: run-as
                success, output = self.device_manager.execute_adb_command(
                    device_id,
                    ["shell", "run-as", package_name, "cat", file_path],
                    timeout=config.ADB_LONG_TIMEOUT
                )

            if success:
                logger.info(f"Viewed: {file_path}")
                return output
            else:
                logger.error("Cannot read file")
                return None

        except Exception as e:
            logger.error(f"View file error: {str(e)[:80]}")
            return None

    def download_file(self, device_id: str, package_name: str, file_path: str) -> Tuple[bool, str]:
        """Download file from device to local machine"""
        try:
            filename = os.path.basename(file_path)
            temp_device_path = f"/sdcard/Download/{filename}"
            local_path = os.path.join(config.DOWNLOAD_DIRECTORY, filename)

            # Copy from protected dir to sdcard using su
            success, _ = self.device_manager.execute_adb_command(
                device_id,
                ["shell", "su", "-c", f"cp '{file_path}' '{temp_device_path}'"],
                timeout=config.ADB_LONG_TIMEOUT
            )

            if not success:
                # Fallback: run-as + cat redirect
                success, _ = self.device_manager.execute_adb_command(
                    device_id,
                    ["shell", "run-as", package_name, "cat", file_path, ">", temp_device_path],
                    timeout=config.ADB_LONG_TIMEOUT
                )

            if not success:
                return False, "Cannot copy file (root required)"

            # Make readable
            self.device_manager.execute_adb_command(
                device_id, ["shell", "chmod", "644", temp_device_path]
            )

            # Pull to local machine
            success, output = self.device_manager.execute_adb_command(
                device_id, ["pull", temp_device_path, local_path],
                timeout=config.ADB_LONG_TIMEOUT
            )

            # Cleanup temp on device
            self.device_manager.execute_adb_command(
                device_id, ["shell", "rm", "-f", temp_device_path]
            )

            if success:
                logger.info(f"Downloaded: {filename}")
                return True, local_path
            else:
                return False, f"Pull failed: {output[:100]}"

        except Exception as e:
            logger.error(f"Download error: {str(e)[:80]}")
            return False, str(e)[:150]

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format byte size to human readable"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024*1024):.1f} MB"
        else:
            return f"{size_bytes / (1024*1024*1024):.2f} GB"
