"""
Class Inspector - Enumerate loaded classes and methods in real-time.
Generates hookable Frida scripts for selected functions.
"""
import frida
import json
import time
from typing import Optional, List, Dict, Callable, Tuple
from utils.logger import logger
from utils.error_handler import error_handler


class ClassInspector:
    """Inspects loaded classes and methods, generates hook scripts"""

    def __init__(self, device_manager, app_manager):
        self.device_manager = device_manager
        self.app_manager = app_manager
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.socketio = None
        self._classes_result = []
        self._methods_result = []

    def set_socketio(self, socketio):
        self.socketio = socketio

    def _get_frida_device(self, device_id: str):
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

    def _attach_to_app(self, device_id: str, package_name: str):
        """Attach to app for inspection"""
        try:
            self._cleanup()

            device = self._get_frida_device(device_id)
            if not device:
                return False, "Cannot connect to Frida device"

            # Get PID
            pid = self.app_manager.get_app_pid(device_id, package_name)
            if pid <= 0:
                # Start app
                self.app_manager.start_app(device_id, package_name)
                time.sleep(2)
                pid = self.app_manager.get_app_pid(device_id, package_name)
                if pid <= 0:
                    return False, f"{package_name} not running"

            self.session = device.attach(pid)
            return True, f"Attached to PID {pid}"

        except frida.ServerNotRunningError:
            return False, "Frida server not running"
        except Exception as e:
            return False, error_handler.handle_frida_error(e)

    def enumerate_classes(self, device_id: str, package_name: str, filter_pattern: str = "") -> Tuple[bool, list]:
        """
        Enumerate all loaded Java classes in the running application.
        Returns (success, list_of_class_names)
        """
        try:
            self._cleanup()  # Clean previous sessions

            success, msg = self._attach_to_app(device_id, package_name)
            if not success:
                return False, msg

            self._classes_result = []
            event_received = {"done": False}

            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message.get('payload', {})
                    if isinstance(payload, dict):
                        if payload.get("type") == "classes":
                            self._classes_result = payload.get("classes", [])
                            event_received["done"] = True
                        elif payload.get("type") == "error":
                            logger.error(f"Enum error: {payload.get('message', '')[:100]}")
                            event_received["done"] = True

            script_code = """
Java.perform(function() {
    try {
        var classes = [];
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                classes.push(className);
            },
            onComplete: function() {
                send({type: "classes", classes: classes});
            }
        });
    } catch(e) {
        send({type: "error", message: e.toString()});
    }
});
"""
            self.script = self.session.create_script(script_code)
            self.script.on('message', on_message)
            self.script.load()

            # Wait for results (up to 30 seconds)
            timeout = 30
            start = time.time()
            while not event_received["done"] and time.time() - start < timeout:
                time.sleep(0.1)

            # Apply filter
            classes = self._classes_result
            if filter_pattern:
                filter_lower = filter_pattern.lower()
                classes = [c for c in classes if filter_lower in c.lower()]

            # Sort
            classes.sort()

            self._cleanup()
            logger.info(f"Enumerated {len(classes)} classes")
            return True, classes

        except Exception as e:
            self._cleanup()
            return False, error_handler.handle_frida_error(e)

    def enumerate_methods(self, device_id: str, package_name: str, class_name: str) -> Tuple[bool, list]:
        """
        Enumerate methods of a specific class.
        Returns (success, list_of_method_info_dicts)
        """
        try:
            self._cleanup()

            success, msg = self._attach_to_app(device_id, package_name)
            if not success:
                return False, msg

            self._methods_result = []
            event_received = {"done": False}

            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message.get('payload', {})
                    if isinstance(payload, dict):
                        if payload.get("type") == "methods":
                            self._methods_result = payload.get("methods", [])
                            event_received["done"] = True
                        elif payload.get("type") == "error":
                            logger.error(f"Method enum error: {payload.get('message', '')[:100]}")
                            event_received["done"] = True

            # Escape class name for JS
            escaped_class = class_name.replace("\\", "\\\\").replace("'", "\\'")

            script_code = f"""
Java.perform(function() {{
    try {{
        var cls = Java.use('{escaped_class}');
        var methods = cls.class.getDeclaredMethods();
        var constructors = cls.class.getDeclaredConstructors();
        var result = [];

        // Regular methods
        for (var i = 0; i < methods.length; i++) {{
            var m = methods[i];
            var name = m.getName();
            var returnType = m.getReturnType().getName();
            var paramTypes = m.getParameterTypes();
            var params = [];
            for (var j = 0; j < paramTypes.length; j++) {{
                params.push(paramTypes[j].getName());
            }}
            var modifiers = m.getModifiers();
            result.push({{
                name: name,
                returnType: returnType,
                params: params,
                isStatic: (modifiers & 0x0008) !== 0,
                signature: returnType + ' ' + name + '(' + params.join(', ') + ')',
                type: 'method'
            }});
        }}

        // Constructors
        for (var i = 0; i < constructors.length; i++) {{
            var c = constructors[i];
            var paramTypes = c.getParameterTypes();
            var params = [];
            for (var j = 0; j < paramTypes.length; j++) {{
                params.push(paramTypes[j].getName());
            }}
            result.push({{
                name: '$init',
                returnType: 'void',
                params: params,
                isStatic: false,
                signature: '$init(' + params.join(', ') + ')',
                type: 'constructor'
            }});
        }}

        send({{type: "methods", methods: result}});
    }} catch(e) {{
        send({{type: "error", message: e.toString()}});
    }}
}});
"""
            self.script = self.session.create_script(script_code)
            self.script.on('message', on_message)
            self.script.load()

            # Wait for results
            timeout = 15
            start = time.time()
            while not event_received["done"] and time.time() - start < timeout:
                time.sleep(0.1)

            methods = self._methods_result
            methods.sort(key=lambda x: x.get("name", "").lower())

            self._cleanup()
            logger.info(f"Found {len(methods)} methods in {class_name}")
            return True, methods

        except Exception as e:
            self._cleanup()
            return False, error_handler.handle_frida_error(e)

    @staticmethod
    def generate_hook_script(class_name: str, method_info: dict) -> str:
        """
        Generate a ready-to-use hookable Frida script for a function.
        Includes argument/return value logging and proper overload handling.
        """
        method_name = method_info.get("name", "unknown")
        params = method_info.get("params", [])
        return_type = method_info.get("returnType", "void")
        is_static = method_info.get("isStatic", False)
        method_type = method_info.get("type", "method")

        escaped_class = class_name.replace("'", "\\'")

        # Build overload args string
        overload_args = ", ".join([f'"{p}"' for p in params])

        # Build argument names
        arg_names = [f"arg{i}" for i in range(len(params))]
        arg_list = ", ".join(arg_names)

        # Build arg logging
        arg_log_parts = []
        for i, (name, ptype) in enumerate(zip(arg_names, params)):
            arg_log_parts.append(f'        console.log("    {name} ({ptype}): " + {name});')
        arg_logging = "\n".join(arg_log_parts) if arg_log_parts else '        console.log("    (no args)");'

        if method_type == "constructor":
            # Constructor hook
            script = f"""// Hook: {class_name}.<init>({', '.join(params)})
Java.perform(function() {{
    var targetClass = Java.use('{escaped_class}');

    targetClass.$init.overload({overload_args}).implementation = function({arg_list}) {{
        console.log("[*] {class_name}.$init called");
        console.log("    Arguments:");
{arg_logging}

        // Call original constructor
        this.$init({arg_list});

        console.log("[*] Constructor completed");
    }};

    console.log("[+] Hooked: {class_name}.$init");
}});"""
        else:
            # Regular method hook
            return_handling = ""
            if return_type != "void":
                return_handling = f"""
        var retval = this.{method_name}({arg_list});
        console.log("    Return ({return_type}): " + retval);
        return retval;"""
            else:
                return_handling = f"""
        this.{method_name}({arg_list});
        console.log("    Return: void");"""

            script = f"""// Hook: {class_name}.{method_name}({', '.join(params)}) -> {return_type}
Java.perform(function() {{
    var targetClass = Java.use('{escaped_class}');

    targetClass.{method_name}.overload({overload_args}).implementation = function({arg_list}) {{
        console.log("[*] {class_name}.{method_name} called");
        console.log("    Arguments:");
{arg_logging}
{return_handling}
    }};

    console.log("[+] Hooked: {class_name}.{method_name}");
}});"""

        return script

    def _cleanup(self):
        try:
            if self.script:
                self.script.unload()
                self.script = None
            if self.session:
                self.session.detach()
                self.session = None
        except:
            self.script = None
            self.session = None
