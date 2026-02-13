"""
Frida Manager - Handles Frida version checking, installation, and synchronization.
Handles Kali Linux pip quirks, Windows/Linux differences, and version matching.
"""
import subprocess
import re
import os
import sys
import platform
import shutil
import requests
import lzma
import time
from typing import Optional, Tuple
from utils.logger import logger
from utils.error_handler import error_handler
import config


class FridaManager:
    """Manages Frida installation and version synchronization"""

    def __init__(self, device_manager):
        self.device_manager = device_manager
        self.socketio = None

    def set_socketio(self, socketio):
        self.socketio = socketio

    def _emit_progress(self, step: str, detail: str, percent: int = -1):
        """Emit setup progress to frontend"""
        if self.socketio:
            self.socketio.emit("frida_progress", {
                "step": step, "detail": detail, "percent": percent
            })

    # ─── Host Frida Detection ───────────────────────────────────────────

    def check_host_frida(self) -> Optional[str]:
        """Check Frida version installed on host machine"""
        # Method 1: Try python import
        try:
            import frida
            version = frida.__version__
            logger.info(f"Host Frida version (python): {version}")
            return version
        except ImportError:
            pass

        # Method 2: Try CLI
        try:
            result = subprocess.run(
                ["frida", "--version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Host Frida version (cli): {version}")
                return version
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        logger.warning("Frida not found on host")
        return None

    def get_host_frida_version_exact(self) -> Optional[str]:
        """Get exact frida python package version"""
        try:
            import frida
            return frida.__version__
        except ImportError:
            return None

    # ─── Host Frida Installation ────────────────────────────────────────

    def _detect_pip_command(self) -> list:
        """Detect the correct pip command for the current system"""
        system = platform.system().lower()

        # Try multiple pip variants
        pip_candidates = [
            [sys.executable, "-m", "pip"],
            ["pip3"],
            ["pip"],
        ]

        for pip_cmd in pip_candidates:
            try:
                result = subprocess.run(
                    pip_cmd + ["--version"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return pip_cmd
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return [sys.executable, "-m", "pip"]  # fallback

    def _is_kali_or_externally_managed(self) -> bool:
        """Check if we're on Kali Linux or a system with externally managed Python"""
        # Check for externally-managed marker (PEP 668)
        try:
            import sysconfig
            stdlib = sysconfig.get_path("stdlib")
            marker = os.path.join(stdlib, "EXTERNALLY-MANAGED")
            if os.path.exists(marker):
                return True
        except:
            pass

        # Check /etc/os-release for Kali
        try:
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    content = f.read().lower()
                    if "kali" in content:
                        return True
        except:
            pass

        return False

    def _needs_sudo(self) -> bool:
        """Check if sudo is needed for pip install"""
        system = platform.system().lower()
        if system == "windows":
            return False
        # On Linux, check if we can write to site-packages
        try:
            import site
            site_packages = site.getsitepackages()
            for sp in site_packages:
                if os.path.exists(sp) and not os.access(sp, os.W_OK):
                    return True
        except:
            pass
        return False

    def install_frida_host(self, version: Optional[str] = None, sudo_password: Optional[str] = None) -> Tuple[bool, str]:
        """
        Install Frida on host machine.
        Handles Kali Linux (--break-system-packages), sudo, Windows, etc.
        """
        try:
            self._emit_progress("host_install", "Detecting pip configuration...", 10)

            pip_cmd = self._detect_pip_command()
            install_args = ["install"]

            # Add specific version if requested
            if version:
                install_args += [f"frida=={version}", f"frida-tools"]
            else:
                install_args += ["frida", "frida-tools"]

            # Handle Kali / externally managed Python
            if self._is_kali_or_externally_managed():
                install_args.append("--break-system-packages")
                logger.info("Detected externally-managed Python (Kali/Debian). Using --break-system-packages")
                self._emit_progress("host_install", "Kali Linux detected, using --break-system-packages", 15)

            full_cmd = pip_cmd + install_args

            # Handle sudo on Linux
            system = platform.system().lower()
            if system != "windows" and self._needs_sudo():
                if sudo_password:
                    # Use sudo with password via stdin
                    sudo_cmd = ["sudo", "-S"] + full_cmd
                    logger.info("Installing Frida with sudo...")
                    self._emit_progress("host_install", "Installing with sudo...", 20)
                    result = subprocess.run(
                        sudo_cmd,
                        input=sudo_password + "\n",
                        capture_output=True, text=True, timeout=300
                    )
                else:
                    # Try without sudo first, then report need for sudo
                    logger.info("Trying pip install without sudo...")
                    self._emit_progress("host_install", "Trying install without elevated privileges...", 20)
                    result = subprocess.run(
                        full_cmd,
                        capture_output=True, text=True, timeout=300
                    )
                    if result.returncode != 0 and ("permission" in result.stderr.lower() or "denied" in result.stderr.lower()):
                        return False, "SUDO_REQUIRED"
            else:
                logger.info(f"Installing Frida: {' '.join(full_cmd)}")
                self._emit_progress("host_install", f"Running pip install...", 20)
                result = subprocess.run(
                    full_cmd,
                    capture_output=True, text=True, timeout=300
                )

            if result.returncode == 0:
                # Verify installation
                installed_version = self.check_host_frida()
                if installed_version:
                    logger.info(f"Frida {installed_version} installed on host")
                    self._emit_progress("host_install", f"Frida {installed_version} installed!", 100)
                    return True, installed_version
                else:
                    return False, "Install appeared to succeed but frida not importable"
            else:
                error_output = result.stderr[:300] if result.stderr else result.stdout[:300]
                logger.error(f"Pip install failed: {error_output}")
                return False, f"Install failed: {error_output}"

        except subprocess.TimeoutExpired:
            return False, "Installation timed out (>5 min). Check network connection."
        except Exception as e:
            logger.error(f"Host install error: {str(e)[:100]}")
            return False, str(e)[:200]

    # ─── Device Frida Server ────────────────────────────────────────────

    def check_device_frida(self, device_id: str) -> Optional[str]:
        """Check Frida server on device - returns version or None"""
        try:
            # Check if frida-server binary exists
            success, output = self.device_manager.execute_adb_command(
                device_id, ["shell", "su", "-c", f"ls {config.FRIDA_SERVER_PATH}"]
            )
            if not success or "No such file" in output:
                logger.info("Frida server not found on device")
                return None

            # Try to get version from binary
            success, output = self.device_manager.execute_adb_command(
                device_id, ["shell", "su", "-c", f"{config.FRIDA_SERVER_PATH} --version"],
                timeout=5
            )
            if success and output.strip():
                version = output.strip().split('\n')[0].strip()
                # Validate it looks like a version
                if re.match(r'^\d+\.\d+\.\d+', version):
                    logger.info(f"Device Frida server version: {version}")
                    return version

            # Binary exists but couldn't get version
            logger.info("Frida server binary found, version unknown")
            return "unknown"

        except Exception as e:
            logger.error(f"Error checking device Frida: {str(e)[:80]}")
            return None

    def is_frida_server_running(self, device_id: str) -> bool:
        """Check if frida-server process is running"""
        try:
            success, output = self.device_manager.execute_adb_command(
                device_id, ["shell", "su", "-c", "ps -ef | grep frida-server | grep -v grep"]
            )
            return success and "frida-server" in output
        except:
            return False

    def start_frida_server(self, device_id: str) -> bool:
        """Start Frida server on device using su"""
        try:
            # Kill existing
            self.device_manager.execute_adb_command(
                device_id, ["shell", "su", "-c", "killall frida-server 2>/dev/null"]
            )
            time.sleep(0.5)

            # Start in background
            logger.info("Starting Frida server...")
            self._emit_progress("server_start", "Starting Frida server on device...", 90)

            # Use nohup to keep server running
            self.device_manager.execute_adb_command(
                device_id,
                ["shell", "su", "-c", f"nohup {config.FRIDA_SERVER_PATH} -D &"],
                timeout=3
            )

            # Wait and verify
            time.sleep(2)
            if self.is_frida_server_running(device_id):
                logger.info("Frida server started successfully")
                return True

            # Try alternate start method
            self.device_manager.execute_adb_command(
                device_id,
                ["shell", "su", "-c", f"{config.FRIDA_SERVER_PATH} -D &"],
                timeout=3
            )
            time.sleep(2)
            return self.is_frida_server_running(device_id)

        except Exception as e:
            logger.error(f"Error starting Frida server: {str(e)[:80]}")
            return False

    def install_frida_device(self, device_id: str, version: str) -> bool:
        """Download and install Frida server on device"""
        try:
            arch = self.device_manager.get_device_architecture(device_id)
            url = config.FRIDA_DOWNLOAD_URL.format(version=version, arch=arch)

            self._emit_progress("device_install", f"Downloading frida-server {version} ({arch})...", 40)
            logger.info(f"Downloading: {url}")

            response = requests.get(url, timeout=120, stream=True)
            if response.status_code != 200:
                logger.error(f"Download failed: HTTP {response.status_code}")
                return False

            # Download content
            content = response.content
            self._emit_progress("device_install", "Decompressing...", 60)

            # Decompress XZ
            frida_server_data = lzma.decompress(content)

            # Save temp file
            temp_path = os.path.join(config.DOWNLOAD_DIRECTORY, "frida-server-temp")
            with open(temp_path, "wb") as f:
                f.write(frida_server_data)

            # Push to device
            self._emit_progress("device_install", "Pushing to device...", 70)
            success, output = self.device_manager.execute_adb_command(
                device_id,
                ["push", temp_path, config.FRIDA_SERVER_PATH],
                timeout=60
            )

            # Cleanup temp
            try:
                os.remove(temp_path)
            except:
                pass

            if not success:
                logger.error(f"Push failed: {output[:100]}")
                return False

            # Make executable
            self._emit_progress("device_install", "Setting permissions...", 80)
            self.device_manager.execute_adb_command(
                device_id, ["shell", "su", "-c", f"chmod 755 {config.FRIDA_SERVER_PATH}"]
            )

            logger.info(f"Frida server {version} installed on device")
            self._emit_progress("device_install", f"Frida server {version} installed!", 85)
            return True

        except Exception as e:
            logger.error(f"Device install error: {str(e)[:100]}")
            return False

    # ─── Version Resolution ─────────────────────────────────────────────

    def _get_latest_frida_version(self) -> Optional[str]:
        """Get latest Frida release version from GitHub"""
        try:
            response = requests.get(config.FRIDA_GITHUB_API, timeout=10)
            if response.status_code == 200:
                data = response.json()
                version = data["tag_name"]
                logger.info(f"Latest Frida version: {version}")
                return version
        except Exception as e:
            logger.warning(f"GitHub API failed: {str(e)[:50]}")

        # Fallback: PyPI
        try:
            response = requests.get("https://pypi.org/pypi/frida/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data["info"]["version"]
        except:
            pass

        return None

    # ─── Main Sync Operation ────────────────────────────────────────────

    def sync_versions(self, device_id: str, sudo_password: Optional[str] = None) -> Tuple[bool, str]:
        """
        Full synchronization: ensure both host and device have matching Frida versions.
        Flow:
        1. Check host frida
        2. Check device frida-server
        3. Install/upgrade as needed to match versions
        4. Start frida-server
        """
        try:
            self._emit_progress("check", "Checking host Frida...", 5)
            host_version = self.check_host_frida()

            self._emit_progress("check", "Checking device Frida server...", 10)
            device_version = self.check_device_frida(device_id)

            # ── Case 1: Both missing ──
            if not host_version and not device_version:
                logger.info("Frida missing on both host and device")

                # Get latest version
                target_version = self._get_latest_frida_version()
                if not target_version:
                    return False, "Cannot determine latest Frida version. Check internet."

                self._emit_progress("install", f"Installing Frida {target_version} on host...", 15)
                success, result = self.install_frida_host(version=target_version, sudo_password=sudo_password)
                if not success:
                    return False, f"Host install failed: {result}"

                host_version = result  # now we have host version

                self._emit_progress("install", f"Installing Frida server {target_version} on device...", 35)
                if not self.install_frida_device(device_id, target_version):
                    return False, "Failed to install Frida server on device"

                self.start_frida_server(device_id)
                return True, f"Frida {target_version} installed on both host and device"

            # ── Case 2: Host exists, device missing ──
            elif host_version and not device_version:
                logger.info(f"Installing Frida server {host_version} on device...")
                self._emit_progress("install", f"Installing Frida server {host_version} on device...", 30)

                if not self.install_frida_device(device_id, host_version):
                    return False, "Failed to install Frida server on device"

                self.start_frida_server(device_id)
                return True, f"Frida server {host_version} installed on device (matching host)"

            # ── Case 3: Device exists, host missing ──
            elif not host_version and device_version:
                # Install host frida matching device version
                target = device_version if device_version != "unknown" else self._get_latest_frida_version()
                if not target:
                    return False, "Cannot determine version. Check internet."

                self._emit_progress("install", f"Installing Frida {target} on host...", 20)
                success, result = self.install_frida_host(version=target, sudo_password=sudo_password)
                if not success:
                    return False, f"Host install failed: {result}"

                # Start server if not running
                if not self.is_frida_server_running(device_id):
                    self.start_frida_server(device_id)

                return True, f"Frida {target} installed on host (matching device)"

            # ── Case 4: Both present ──
            else:
                # Check version match
                if device_version != "unknown" and host_version != device_version:
                    logger.warning(f"Version mismatch: host={host_version}, device={device_version}")
                    self._emit_progress("install",
                        f"Version mismatch: host={host_version} vs device={device_version}. Reinstalling device server...", 30)

                    # Reinstall device to match host
                    if not self.install_frida_device(device_id, host_version):
                        return False, "Failed to update Frida server on device"

                    self.start_frida_server(device_id)
                    return True, f"Frida server updated to {host_version} on device"

                # Versions match (or device version unknown), just start server
                if not self.is_frida_server_running(device_id):
                    self.start_frida_server(device_id)

                self._emit_progress("ready", "Frida ready!", 100)
                return True, f"Frida {host_version} ready (host and device in sync)"

        except Exception as e:
            error_msg = f"Sync error: {str(e)[:150]}"
            logger.error(error_msg)
            return False, error_msg
