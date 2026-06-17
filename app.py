"""
Frida Childs Play - Flask + SocketIO Web Application
Main entry point
"""
import os
import json
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO

from modules.device_manager import DeviceManager
from modules.frida_manager import FridaManager
from modules.app_manager import AppManager
from modules.script_manager import ScriptManager
from modules.file_manager import FileManager
from modules.runtime_monitor import RuntimeMonitor
from modules.class_inspector import ClassInspector
from utils.logger import logger
import config

# Flask App Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Initialize Managers
device_manager = DeviceManager()
frida_manager = FridaManager(device_manager)
app_manager = AppManager(device_manager)
script_manager = ScriptManager(device_manager, app_manager)
file_manager = FileManager(device_manager)
runtime_monitor = RuntimeMonitor(device_manager)
class_inspector = ClassInspector(device_manager, app_manager)

# Set SocketIO on all managers
logger.set_socketio(socketio)
device_manager.set_socketio(socketio)
frida_manager.set_socketio(socketio)
script_manager.set_socketio(socketio)
runtime_monitor.set_socketio(socketio)

# Routes

@app.route('/')
def index():
    return render_template('index.html')


# Device API

@app.route('/api/devices')
def get_devices():
    """Get connected devices list"""
    devices = device_manager.get_devices_list()
    return jsonify({"devices": devices})


@app.route('/api/device/<device_id>/info')
def get_device_info(device_id):
    """Get detailed info for a device"""
    info = device_manager.get_device_info(device_id)
    return jsonify(info)


# Frida Setup API

@app.route('/api/frida/status/<device_id>')
def frida_status(device_id):
    """Get Frida status on host and device"""
    host_version = frida_manager.check_host_frida()
    device_version = frida_manager.check_device_frida(device_id)
    server_running = frida_manager.is_frida_server_running(device_id)

    return jsonify({
        "host_version": host_version,
        "device_version": device_version,
        "server_running": server_running
    })


@app.route('/api/frida/setup/<device_id>', methods=['POST'])
def frida_setup(device_id):
    """Full Frida setup - detect, install, sync versions"""
    data = request.get_json() or {}
    sudo_password = data.get("sudo_password")

    success, message = frida_manager.sync_versions(device_id, sudo_password)
    return jsonify({"success": success, "message": message})


# Application API

@app.route('/api/apps/<device_id>')
def list_apps(device_id):
    """List installed applications (frida-ps -Uai style)"""
    include_system = request.args.get("system", "false").lower() == "true"
    apps = app_manager.list_applications(device_id, include_system)
    return jsonify({"apps": apps})


@app.route('/api/app/pid/<device_id>/<package_name>')
def get_app_pid(device_id, package_name):
    """Get PID of a specific app"""
    pid = app_manager.get_app_pid(device_id, package_name)
    return jsonify({"pid": pid, "running": pid > 0})


@app.route('/api/app/start/<device_id>/<package_name>', methods=['POST'])
def start_app(device_id, package_name):
    success = app_manager.start_app(device_id, package_name)
    return jsonify({"success": success})


@app.route('/api/app/kill/<device_id>/<package_name>', methods=['POST'])
def kill_app(device_id, package_name):
    success = app_manager.kill_app(device_id, package_name)
    return jsonify({"success": success})


# File Manager API

@app.route('/api/files/<device_id>/<package_name>')
def list_files(device_id, package_name):
    """List files in app directory"""
    path = request.args.get("path", f"/data/data/{package_name}")
    files = file_manager.list_app_files(device_id, package_name, path)
    return jsonify({"files": files, "path": path})


@app.route('/api/files/view/<device_id>/<package_name>')
def view_file_content(device_id, package_name):
    """View file content"""
    file_path = request.args.get("path")
    if not file_path:
        return jsonify({"error": "No path specified"}), 400

    content = file_manager.view_file(device_id, package_name, file_path)
    if content is not None:
        return jsonify({"content": content, "path": file_path})
    else:
        return jsonify({"error": "Cannot read file"}), 500


@app.route('/api/files/download/<device_id>/<package_name>')
def download_file(device_id, package_name):
    """Download file from device"""
    file_path = request.args.get("path")
    if not file_path:
        return jsonify({"error": "No path specified"}), 400

    success, result = file_manager.download_file(device_id, package_name, file_path)
    if success:
        return send_file(result, as_attachment=True)
    else:
        return jsonify({"error": result}), 500


# Script Manager API

@app.route('/api/script/spawn', methods=['POST'])
def script_spawn():
    """Spawn app and attach script"""
    data = request.get_json()
    device_id = data.get("device_id")
    package_name = data.get("package_name")
    script_code = data.get("script", "")

    success, message = script_manager.spawn_and_attach(device_id, package_name, script_code)
    return jsonify({"success": success, "message": message, "pid": script_manager.current_pid})


@app.route('/api/script/attach', methods=['POST'])
def script_attach():
    """Attach script to running PID"""
    data = request.get_json()
    device_id = data.get("device_id")
    pid = data.get("pid", 0)
    package_name = data.get("package_name", "")
    script_code = data.get("script", "")

    if pid and pid > 0:
        success, message = script_manager.attach_to_pid(device_id, pid, script_code)
    elif package_name:
        success, message = script_manager.attach_to_package(device_id, package_name, script_code)
    else:
        return jsonify({"success": False, "message": "No PID or package specified"}), 400

    return jsonify({"success": success, "message": message, "pid": script_manager.current_pid})


@app.route('/api/script/detach', methods=['POST'])
def script_detach():
    success = script_manager.detach()
    return jsonify({"success": success})


# Class Inspector API

@app.route('/api/classes/<device_id>/<package_name>')
def enumerate_classes(device_id, package_name):
    """Enumerate loaded classes"""
    filter_pattern = request.args.get("filter", "")
    success, result = class_inspector.enumerate_classes(device_id, package_name, filter_pattern)
    if success:
        return jsonify({"classes": result})
    else:
        return jsonify({"error": result}), 500


@app.route('/api/methods/<device_id>/<package_name>')
def enumerate_methods(device_id, package_name):
    """Enumerate methods of a class"""
    class_name = request.args.get("class")
    if not class_name:
        return jsonify({"error": "No class specified"}), 400

    success, result = class_inspector.enumerate_methods(device_id, package_name, class_name)
    if success:
        return jsonify({"methods": result})
    else:
        return jsonify({"error": result}), 500


@app.route('/api/hook/generate', methods=['POST'])
def generate_hook():
    """Generate hookable Frida script for a method"""
    data = request.get_json()
    class_name = data.get("class_name")
    method_info = data.get("method_info")

    if not class_name or not method_info:
        return jsonify({"error": "Missing class_name or method_info"}), 400

    script = ClassInspector.generate_hook_script(class_name, method_info)
    return jsonify({"script": script})


# Logs API

@app.route('/api/logs')
def get_logs():
    return jsonify({"logs": logger.get_logs()})


# SocketIO Events

@socketio.on('connect')
def handle_connect():
    logger.info("Web client connected")
    # Send current devices
    socketio.emit("devices_update", device_manager.get_devices_list())


@socketio.on('disconnect')
def handle_disconnect():
    pass


# Main Entry Point

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════╗
    ║      🔥 Frida Childs Play 🔥            ║
    ║      Automated Frida Management          ║
    ║                                          ║
    ║  Open: http://localhost:5000             ║
    ╚══════════════════════════════════════════╝
    """)

    # Start device monitoring
    device_manager.start_monitoring()

    socketio.run(app, host=config.HOST, port=config.PORT, debug=config.DEBUG)
