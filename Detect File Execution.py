import wmi
import socket
import time
import json

# === CONFIG ===
EXECUTABLE_EXTENSIONS = [".exe", ".bat", ".ps1"]

def is_suspicious_exec(command_line):
    # Basic check: only flag executables
    return any(command_line.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS)

def log_event(event_type, details):
    event = {
        "event_type": event_type,
        "details": details,
        "timestamp": time.time(),
        "hostname": socket.gethostname()
    }
    print(json.dumps(event))

def monitor_processes():
    c = wmi.WMI()
    process_watcher = c.Win32_Process.watch_for("creation")

    print("Monitoring for executable file launches...")
    while True:
        new_process = process_watcher()
        command_line = new_process.CommandLine or new_process.Name

        if command_line and is_suspicious_exec(command_line):
            log_event("file_executed", command_line)

if __name__ == "__main__":
    monitor_processes()
