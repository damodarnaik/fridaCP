"""
Error handler for ART, Java, Frida, and ADB errors
"""
import re
from utils.logger import logger


class ErrorHandler:
    """Centralized error handling for Frida and ADB operations"""

    @staticmethod
    def handle_frida_error(error: Exception) -> str:
        error_str = str(error)

        if "art::" in error_str.lower() or "artmethod" in error_str.lower():
            logger.warning("ART runtime error detected")
            return "ART Runtime Error: Method may be optimized or inlined."

        if "java.lang.classnotfoundexception" in error_str.lower() or "class not found" in error_str.lower():
            match = re.search(r"class[:\s]+([a-zA-Z0-9.$_]+)", error_str, re.IGNORECASE)
            class_name = match.group(1) if match else "unknown"
            return f"Class Not Found: {class_name} is not loaded."

        if "process not found" in error_str.lower() or "failed to spawn" in error_str.lower():
            return "Process Error: Application not found or failed to start."

        if "device not found" in error_str.lower() or "unable to connect" in error_str.lower():
            return "Device Error: Unable to connect. Check USB debugging."

        if "server not running" in error_str.lower():
            return "Frida server is not running on device. Click 'Setup Frida' first."

        if "script error" in error_str.lower() or "syntaxerror" in error_str.lower():
            return "Script Error: Invalid JavaScript syntax."

        if "timed out" in error_str.lower():
            return "Timeout: Operation took too long."

        logger.error(f"Frida error: {error_str[:150]}")
        return f"Error: {error_str[:200]}"

    @staticmethod
    def handle_adb_error(error: Exception) -> str:
        error_str = str(error)

        if "device offline" in error_str.lower():
            return "Device Offline: Reconnect the device."
        if "unauthorized" in error_str.lower():
            return "Device Unauthorized: Accept USB debugging prompt."
        if "no devices" in error_str.lower():
            return "No Devices: Connect an Android device."

        logger.error(f"ADB error: {error_str[:150]}")
        return f"ADB Error: {error_str[:200]}"


error_handler = ErrorHandler()
