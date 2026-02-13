"""
Application Manager - Lists installed apps using Frida (frida-ps -Uai style).
Uses PID for all operations.
"""
import frida
import time
from typing import List, Dict, Optional
from utils.logger import logger
from utils.error_handler import error_handler


class AppManager:
    """Manages Android applications - listing, PID lookup, start/stop"""

    def __init__(self, device_manager):
        self.device_manager = device_manager

    def list_applications(self, device_id: str, include_system: bool = True) -> List[Dict]:
        """
        List installed applications similar to frida-ps -Uai.
        Returns: List of {pid, name, identifier} dicts.
        """
        try:
            device = self._get_frida_device(device_id)
            if not device:
                # Fallback to ADB method
                return self._list_apps_adb(device_id, include_system)

            apps = device.enumerate_applications(scope="full")
            result = []

            for app in apps:
                # Filter system apps if requested
                if not include_system:
                    if self._is_system_app(app.identifier):
                        continue

                result.append({
                    "pid": app.pid if app.pid else 0,
                    "name": app.name or app.identifier,
                    "identifier": app.identifier,
                })

            # Sort: running apps first (pid > 0), then by name
            result.sort(key=lambda x: (-1 if x["pid"] > 0 else 0, x["name"].lower()))

            logger.info(f"Found {len(result)} applications")
            return result

        except frida.ServerNotRunningError:
            logger.error("Frida server not running. Run 'Setup Frida' first.")
            return self._list_apps_adb(device_id, include_system)
        except Exception as e:
            logger.error(f"Error listing apps: {str(e)[:100]}")
            return self._list_apps_adb(device_id, include_system)

    def _get_frida_device(self, device_id: str):
        """Get Frida device by ID (supports both USB and emulator)"""
        try:
            # Try matching by ID
            for device in frida.enumerate_devices():
                if device.id == device_id:
                    return device

            # Try USB device
            try:
                return frida.get_usb_device(timeout=3)
            except:
                pass

            # Try remote (for emulators like 127.0.0.1:port)
            if ":" in device_id:
                try:
                    return frida.get_device_manager().add_remote_device(device_id)
                except:
                    pass

            # Fallback: try to get any device
            try:
                return frida.get_usb_device(timeout=3)
            except:
                return None

        except Exception as e:
            logger.error(f"Cannot get Frida device: {str(e)[:80]}")
            return None

    def _list_apps_adb(self, device_id: str, include_system: bool = True) -> List[Dict]:
        """Fallback: list apps via ADB when Frida isn't available"""
        try:
            flag = "" if include_system else "-3"
            success, output = self.device_manager.execute_adb_command(
                device_id, ["shell", "pm", "list", "packages", flag]
            )
            if not success:
                return []

            result = []
            for line in output.strip().split('\n'):
                if line.startswith("package:"):
                    pkg = line.replace("package:", "").strip()
                    pid = self._get_pid_adb(device_id, pkg)
                    result.append({
                        "pid": pid,
                        "name": pkg,
                        "identifier": pkg,
                    })

            result.sort(key=lambda x: (-1 if x["pid"] > 0 else 0, x["name"].lower()))
            return result
        except:
            return []

    def _is_system_app(self, identifier: str) -> bool:
        system_prefixes = [
            "com.android.", "com.google.android.gms",
            "com.google.android.gsf", "com.google.android.providers",
            "android", "com.samsung.", "com.sec.",
            "com.qualcomm.", "com.mediatek."
        ]
        return any(identifier.startswith(p) or identifier == p for p in system_prefixes)

    def _get_pid_adb(self, device_id: str, package_name: str) -> int:
        """Get PID via ADB"""
        try:
            success, output = self.device_manager.execute_adb_command(
                device_id, ["shell", "pidof", package_name]
            )
            if success and output.strip():
                return int(output.strip().split()[0])
        except:
            pass
        return 0

    def get_app_pid(self, device_id: str, package_name: str) -> int:
        """Get PID of app. Returns 0 if not running."""
        # Try Frida first
        try:
            device = self._get_frida_device(device_id)
            if device:
                for proc in device.enumerate_processes():
                    if proc.name == package_name or package_name in str(proc.parameters):
                        return proc.pid
        except:
            pass
        return self._get_pid_adb(device_id, package_name)

    def is_app_running(self, device_id: str, package_name: str) -> bool:
        return self.get_app_pid(device_id, package_name) > 0

    def kill_app(self, device_id: str, package_name: str) -> bool:
        try:
            success, _ = self.device_manager.execute_adb_command(
                device_id, ["shell", "am", "force-stop", package_name]
            )
            if success:
                logger.info(f"Killed {package_name}")
            return success
        except:
            return False

    def start_app(self, device_id: str, package_name: str) -> bool:
        """Start an application and return True if successful"""
        try:
            # Try monkey launcher (most reliable)
            success, _ = self.device_manager.execute_adb_command(
                device_id,
                ["shell", "monkey", "-p", package_name,
                 "-c", "android.intent.category.LAUNCHER", "1"]
            )
            if success:
                time.sleep(1)
                logger.info(f"Started {package_name}")
                return True

            # Fallback: resolve activity
            success, output = self.device_manager.execute_adb_command(
                device_id,
                ["shell", "cmd", "package", "resolve-activity", "--brief", package_name]
            )
            if success:
                lines = output.strip().split('\n')
                for line in lines:
                    if "/" in line and not line.startswith("Priority"):
                        activity = line.strip()
                        self.device_manager.execute_adb_command(
                            device_id, ["shell", "am", "start", "-n", activity]
                        )
                        time.sleep(1)
                        return True

            return False
        except Exception as e:
            logger.error(f"Error starting app: {str(e)[:50]}")
            return False
