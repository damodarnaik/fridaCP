"""
Runtime Monitor - Method call tracing via Frida.
Re-exports for backward compatibility; primary class inspection is in class_inspector.py.
"""
import frida
from typing import Optional, Callable
from utils.logger import logger
from utils.error_handler import error_handler


class RuntimeMonitor:
    """Monitors runtime method calls and parameters"""

    def __init__(self, device_manager):
        self.device_manager = device_manager
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.callback: Optional[Callable] = None
        self.socketio = None
        self.monitoring = False

    def set_socketio(self, socketio):
        self.socketio = socketio

    def set_callback(self, callback: Callable):
        self.callback = callback

    def _get_frida_device(self, device_id: str):
        try:
            for device in frida.enumerate_devices():
                if device.id == device_id:
                    return device
            return frida.get_usb_device(timeout=3)
        except:
            return None

    def _on_message(self, message, data):
        try:
            if message['type'] == 'send':
                payload = message.get('payload', {})
                if self.socketio:
                    self.socketio.emit("runtime_event", payload)
                if self.callback:
                    self.callback(payload)
            elif message['type'] == 'error':
                error_msg = message.get('description', 'Unknown error')
                logger.error(f"Monitor error: {error_msg[:100]}")
        except Exception as e:
            logger.error(f"Monitor msg error: {str(e)[:50]}")

    def generate_hook_script(self, class_pattern: str = "*") -> str:
        return """
Java.perform(function() {
    console.log("[*] Runtime monitoring started");
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("PATTERN") !== -1 || "PATTERN" === "*") {
                try { hookClass(className); } catch(e) {}
            }
        },
        onComplete: function() {
            console.log("[*] Enumeration complete");
        }
    });

    function hookClass(className) {
        try {
            var cls = Java.use(className);
            var methods = cls.class.getDeclaredMethods();
            methods.forEach(function(method) {
                try {
                    var name = method.getName();
                    var overloads = cls[name];
                    if (overloads) {
                        overloads.overloads.forEach(function(overload) {
                            try {
                                overload.implementation = function() {
                                    var args = Array.prototype.slice.call(arguments);
                                    var argsStr = args.map(function(a) {
                                        try { return JSON.stringify(a); } catch(e) { return String(a); }
                                    }).join(", ");
                                    var retval = this[name].apply(this, arguments);
                                    send({
                                        type: "method_call",
                                        class: className,
                                        method: name,
                                        args: argsStr,
                                        return: String(retval)
                                    });
                                    return retval;
                                };
                            } catch(e) {}
                        });
                    }
                } catch(e) {}
            });
        } catch(e) {}
    }
});
""".replace("PATTERN", class_pattern)

    def start_monitoring(self, device_id: str, package_name: str, class_pattern: str = "*") -> tuple:
        try:
            if self.monitoring:
                self.stop_monitoring()

            device = self._get_frida_device(device_id)
            if not device:
                return False, "Cannot connect to Frida device"

            self.session = device.attach(package_name)
            script_code = self.generate_hook_script(class_pattern)
            self.script = self.session.create_script(script_code)
            self.script.on('message', self._on_message)
            self.script.load()
            self.monitoring = True
            return True, "Monitoring started"

        except frida.ProcessNotFoundError:
            return False, f"{package_name} not running"
        except Exception as e:
            return False, error_handler.handle_frida_error(e)

    def stop_monitoring(self) -> bool:
        try:
            if self.script:
                self.script.unload()
                self.script = None
            if self.session:
                self.session.detach()
                self.session = None
            self.monitoring = False
            return True
        except:
            self.monitoring = False
            return False

    def is_monitoring(self) -> bool:
        return self.monitoring
