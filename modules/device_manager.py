"""
Device Manager - ADB device detection, monitoring, and root verification.
Supports both physical devices and emulators.
"""
import subprocess
import threading
import time
from typing import List, Dict, Callable, Optional
from utils.logger import logger
from utils.error_handler import error_handler
import config


class DeviceManager:
    """Manages Android device connections via ADB (physical + emulator)"""

    def __init__(self):
        self.devices: Dict[str, dict] = {}  # {device_id: {status, type, rooted}}
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.callbacks: List[Callable] = []
        self.socketio = None

    def set_socketio(self, socketio):
        self.socketio = socketio

    def add_callback(self, callback: Callable):
        self.callbacks.append(callback)

    def _notify(self):
        for cb in self.callbacks:
            try:
                cb(self.devices.copy())
            except Exception as e:
                logger.error(f"Callback error: {str(e)[:50]}")
        if self.socketio:
            self.socketio.emit("devices_update", self.get_devices_list())

    def get_devices(self) -> Dict[str, dict]:
        """Get connected devices via adb devices"""
        try:
            result = subprocess.run(
                ["adb", "devices", "-l"],
                capture_output=True, text=True, timeout=config.ADB_TIMEOUT
            )
            devices = {}
            lines = result.stdout.strip().split('\n')[1:]

            for line in lines:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    device_id = parts[0]
                    status = parts[1]

                    # Determine device type
                    is_emulator = (
                        device_id.startswith("emulator-") or
                        "vbox" in line.lower() or
                        "genymotion" in line.lower() or
                        device_id.startswith("127.0.0.1") or
                        device_id.startswith("10.0.2.") or
                        device_id.startswith("localhost")
                    )

                    # Extract model info
                    model = "Unknown"
                    for part in parts[2:]:
                        if part.startswith("model:"):
                            model = part.replace("model:", "").replace("_", " ")
                            break

                    devices[device_id] = {
                        "status": status,
                        "type": "emulator" if is_emulator else "physical",
                        "model": model,
                        "rooted": False  # checked separately
                    }

            return devices

        except subprocess.TimeoutExpired:
            logger.error("ADB command timed out")
            return {}
        except FileNotFoundError:
            logger.error("ADB not found. Install Android SDK Platform Tools and add to PATH")
            return {}
        except Exception as e:
            logger.error(f"Error getting devices: {str(e)[:80]}")
            return {}

    def check_root(self, device_id: str) -> bool:
        """Check if device has root (su) access"""
        try:
            success, output = self.execute_adb_command(
                device_id, ["shell", "su", "-c", "id"]
            )
            if success and "uid=0" in output:
                return True
            return False
        except:
            return False

    def get_device_architecture(self, device_id: str) -> str:
        """Get device CPU architecture"""
        try:
            success, output = self.execute_adb_command(
                device_id, ["shell", "getprop", "ro.product.cpu.abi"]
            )
            if success:
                abi = output.strip()
                arch = config.ARCH_MAP.get(abi, None)
                if arch:
                    logger.info(f"Device architecture: {abi} -> {arch}")
                    return arch
                # Direct match attempt
                if "arm64" in abi:
                    return "arm64"
                elif "arm" in abi:
                    return "arm"
                elif "x86_64" in abi:
                    return "x86_64"
                elif "x86" in abi:
                    return "x86"
            return "arm64"  # default
        except:
            return "arm64"

    def get_device_info(self, device_id: str) -> dict:
        """Get comprehensive device info"""
        info = {"id": device_id}
        try:
            # Android version
            s, o = self.execute_adb_command(device_id, ["shell", "getprop", "ro.build.version.release"])
            info["android_version"] = o.strip() if s else "?"

            # Model
            s, o = self.execute_adb_command(device_id, ["shell", "getprop", "ro.product.model"])
            info["model"] = o.strip() if s else "?"

            # Architecture
            info["architecture"] = self.get_device_architecture(device_id)

            # Root check
            info["rooted"] = self.check_root(device_id)

        except Exception as e:
            logger.error(f"Device info error: {str(e)[:50]}")
        return info

    def get_devices_list(self) -> list:
        """Get devices as a list for API response"""
        result = []
        for device_id, info in self.devices.items():
            result.append({
                "id": device_id,
                "status": info.get("status", "unknown"),
                "type": info.get("type", "unknown"),
                "model": info.get("model", "Unknown"),
                "rooted": info.get("rooted", False)
            })
        return result

    def _monitor_loop(self):
        logger.info("Device monitoring started")
        while self.monitoring:
            try:
                new_devices = self.get_devices()

                # Check for changes
                changed = False
                if set(new_devices.keys()) != set(self.devices.keys()):
                    changed = True
                else:
                    for did, info in new_devices.items():
                        if did not in self.devices or self.devices[did]["status"] != info["status"]:
                            changed = True
                            break

                if changed:
                    # Log changes
                    for did in new_devices:
                        if did not in self.devices:
                            logger.info(f"Device connected: {did} ({new_devices[did]['type']})")
                            # Check root for new devices
                            if new_devices[did]["status"] == "device":
                                new_devices[did]["rooted"] = self.check_root(did)
                    for did in self.devices:
                        if did not in new_devices:
                            logger.warning(f"Device disconnected: {did}")

                    self.devices = new_devices
                    self._notify()

                time.sleep(config.DEVICE_POLL_INTERVAL)

            except Exception as e:
                logger.error(f"Monitor error: {str(e)[:50]}")
                time.sleep(config.DEVICE_POLL_INTERVAL)

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.devices = self.get_devices()
            # Check root for initial devices
            for did, info in self.devices.items():
                if info["status"] == "device":
                    self.devices[did]["rooted"] = self.check_root(did)
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self._notify()

    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=3)

    def execute_adb_command(self, device_id: str, command: list, timeout: int = None) -> tuple:
        """Execute ADB command on specific device"""
        try:
            cmd = ["adb", "-s", device_id] + command
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout or config.ADB_TIMEOUT
            )
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except Exception as e:
            error_msg = error_handler.handle_adb_error(e)
            return False, error_msg
