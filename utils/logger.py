"""
Logger utility with SocketIO support
"""
import threading
from datetime import datetime
from typing import Callable, Optional


class Logger:
    """Thread-safe logger with SocketIO emission"""

    def __init__(self):
        self.lock = threading.Lock()
        self.log_callback: Optional[Callable] = None
        self.socketio = None
        self.logs = []

    def set_socketio(self, socketio):
        """Set SocketIO instance for real-time log streaming"""
        self.socketio = socketio

    def set_callback(self, callback: Callable):
        """Set callback function"""
        self.log_callback = callback

    def _log(self, level: str, message: str):
        """Internal logging method"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"

        with self.lock:
            self.logs.append(log_entry)
            if self.socketio:
                self.socketio.emit("log", {"level": level, "message": message, "timestamp": timestamp})
            if self.log_callback:
                self.log_callback(log_entry)

        # Also print to console
        print(log_entry)

    def info(self, message: str):
        self._log("INFO", message)

    def warning(self, message: str):
        self._log("WARN", message)

    def error(self, message: str):
        self._log("ERROR", message)

    def get_logs(self):
        with self.lock:
            return self.logs.copy()


# Global logger instance
logger = Logger()
