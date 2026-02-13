"""
Script Manager - Frida script injection via spawn or PID attach.
All operations use PID-based attachment.
"""
import frida
import time
from typing import Optional, Callable, Tuple
from utils.logger import logger
from utils.error_handler import error_handler


class ScriptManager:
    """Manages Frida script injection - spawn and attach by PID"""

    def __init__(self, device_manager, app_manager):
        self.device_manager = device_manager
        self.app_manager = app_manager
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.message_callback: Optional[Callable] = None
        self.socketio = None
        self.current_pid: int = 0

    def set_socketio(self, socketio):
        self.socketio = socketio

    def set_message_callback(self, callback: Callable):
        self.message_callback = callback

    def _on_message(self, message, data):
        """Handle messages from Frida script"""
        try:
            if message['type'] == 'send':
                payload = message.get('payload', '')
                msg_str = str(payload)
                if self.socketio:
                    self.socketio.emit("script_output", {"type": "send", "payload": msg_str})
                if self.message_callback:
                    self.message_callback(msg_str)
            elif message['type'] == 'error':
                error_msg = message.get('description', 'Unknown script error')
                if self.socketio:
                    self.socketio.emit("script_output", {"type": "error", "payload": error_msg})
                if self.message_callback:
                    self.message_callback(f"ERROR: {error_msg}")
        except Exception as e:
            logger.error(f"Message handler error: {str(e)[:60]}")

    def _get_frida_device(self, device_id: str):
        """Get Frida device (USB or emulator)"""
        try:
            for device in frida.enumerate_devices():
                if device.id == device_id:
                    return device
            try:
                return frida.get_usb_device(timeout=3)
            except:
                pass
            if ":" in device_id:
                try:
                    return frida.get_device_manager().add_remote_device(device_id)
                except:
                    pass
            return frida.get_usb_device(timeout=3)
        except:
            return None

    def spawn_and_attach(self, device_id: str, package_name: str, script_code: str) -> Tuple[bool, str]:
        """
        Spawn mode: Kill old process -> spawn -> attach by PID -> load script -> resume.
        """
        try:
            self._cleanup_session()

            # Kill if running
            if self.app_manager.is_app_running(device_id, package_name):
                logger.info(f"Killing {package_name}...")
                self.app_manager.kill_app(device_id, package_name)
                time.sleep(1)

            device = self._get_frida_device(device_id)
            if not device:
                return False, "Cannot connect to Frida device"

            # Spawn and get PID
            logger.info(f"Spawning {package_name}...")
            pid = device.spawn([package_name])
            self.current_pid = pid

            # Attach by PID
            self.session = device.attach(pid)
            self.session.on("detached", self._on_session_detached)

            # Load script
            if script_code and script_code.strip():
                self.script = self.session.create_script(script_code)
                self.script.on('message', self._on_message)
                self.script.load()

            # Resume process
            device.resume(pid)

            msg = f"Spawned {package_name} (PID: {pid})"
            logger.info(msg)
            return True, msg

        except frida.ServerNotRunningError:
            return False, "Frida server not running on device"
        except Exception as e:
            error_msg = error_handler.handle_frida_error(e)
            return False, error_msg

    def attach_to_pid(self, device_id: str, pid: int, script_code: str) -> Tuple[bool, str]:
        """
        Attach mode: Attach to existing running PID -> load script.
        """
        try:
            self._cleanup_session()

            device = self._get_frida_device(device_id)
            if not device:
                return False, "Cannot connect to Frida device"

            logger.info(f"Attaching to PID {pid}...")
            self.session = device.attach(pid)
            self.session.on("detached", self._on_session_detached)
            self.current_pid = pid

            # Load script
            if script_code and script_code.strip():
                self.script = self.session.create_script(script_code)
                self.script.on('message', self._on_message)
                self.script.load()
                logger.info("Script loaded on running process")
            else:
                logger.info("Attached without script")

            return True, f"Attached to PID {pid}"

        except frida.ProcessNotFoundError:
            return False, f"PID {pid} not found or not running"
        except frida.ServerNotRunningError:
            return False, "Frida server not running on device"
        except Exception as e:
            error_msg = error_handler.handle_frida_error(e)
            return False, error_msg

    def attach_to_package(self, device_id: str, package_name: str, script_code: str) -> Tuple[bool, str]:
        """Attach by package name (resolves to PID first)"""
        pid = self.app_manager.get_app_pid(device_id, package_name)
        if pid <= 0:
            # Start app first
            logger.info(f"Starting {package_name}...")
            self.app_manager.start_app(device_id, package_name)
            time.sleep(2)
            pid = self.app_manager.get_app_pid(device_id, package_name)
            if pid <= 0:
                return False, f"{package_name} is not running and couldn't be started"

        return self.attach_to_pid(device_id, pid, script_code)

    def _on_session_detached(self, reason, crash):
        """Handle session detach"""
        logger.warning(f"Session detached: {reason}")
        if self.socketio:
            self.socketio.emit("script_output", {
                "type": "detached",
                "payload": f"Session detached: {reason}"
            })
        self.session = None
        self.script = None

    def detach(self) -> bool:
        try:
            self._cleanup_session()
            logger.info("Detached from process")
            return True
        except Exception as e:
            logger.error(f"Detach error: {str(e)[:50]}")
            return False

    def _cleanup_session(self):
        try:
            if self.script:
                self.script.unload()
                self.script = None
            if self.session:
                self.session.detach()
                self.session = None
            self.current_pid = 0
        except:
            self.script = None
            self.session = None
            self.current_pid = 0

    def is_attached(self) -> bool:
        return self.session is not None
