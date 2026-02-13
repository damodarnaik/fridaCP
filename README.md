# Android Pentest Tool

A comprehensive Python-based Android penetration testing tool with device management, Frida integration, application analysis, and runtime monitoring capabilities.

## Features

- **Device Management**: Real-time detection and monitoring of connected Android devices
- **Frida Integration**: Automatic version checking and synchronization between host and device
- **Application Analysis**: List and analyze installed applications
- **Script Injection**: 
  - Spawn mode: Kill and restart app with Frida script
  - Hot-load mode: Attach to running app without restart
- **File Management**: Browse, view, and download application files
- **Runtime Monitoring**: Trace method calls, parameters, and return values in real-time

## Requirements

- Python 3.7+
- Android SDK Platform Tools (ADB)
- USB Debugging enabled on Android device
- Root access on device (recommended for full functionality)

## Installation

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure ADB is in your system PATH

## Usage

1. Connect your Android device via USB with USB debugging enabled

2. Run the application:
```bash
python main.py
```

3. Select your device from the dropdown

4. Click "Check/Install Frida" to ensure Frida is properly installed

5. Select an application from the list

6. Use the three tabs:
   - **Scripting**: Write and inject Frida scripts
   - **Files**: Browse and download app files
   - **Runtime**: Monitor method calls in real-time

## Tabs Overview

### Scripting Tab
- Write custom Frida scripts
- **Spawn**: Kill existing process and spawn new one with script attached
- **Hot Load**: Attach to running process without restart
- View script output in real-time

### Files Tab
- Navigate application file system
- View text file contents
- Download files to local machine

### Runtime Tab
- Monitor method calls with parameters and return values
- Filter by class name pattern
- Real-time trace display

## Error Handling

The tool gracefully handles:
- ART (Android Runtime) errors
- Java class not found errors
- Device disconnections
- Frida server issues

All errors are logged with user-friendly messages in the log view.

## Notes

- Root access is required for full file system access
- Some system apps may not be hookable
- Frida server must match the host Frida version (handled automatically)

## License

This tool is for educational and authorized testing purposes only.
