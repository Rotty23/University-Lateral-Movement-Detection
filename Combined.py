import os
import time
import socket
import json
import shutil
import wmi
import sqlite3
import threading
import pythoncom  # Needed to initialize COM in threads
from datetime import datetime, timedelta

# === CONFIG ===
EXECUTABLE_EXTENSIONS = [".exe", ".bat", ".ps1"]
CHROME_HISTORY_PATH = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History")
TEMP_HISTORY_COPY = "temp_chrome_history"
MALICIOUS_DOMAINS = ["badsite.com", "malware.test", "phishingsite.net"]  # Add your own domains

# === COMMON EVENT LOGGER ===
def log_event(event_type, data):
    event = {
        "event_type": event_type,
        "data": data,
        "timestamp": time.time(),
        "hostname": socket.gethostname()
    }
    print(json.dumps(event))
    # Future: send to Kafka or REST endpoint

# === PROCESS MONITORING (FILE EXECUTION) ===
def is_suspicious_exec(command_line):
    if command_line:
        return any(command_line.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS)
    return False

def monitor_process_execution():
    pythoncom.CoInitialize()  # ✅ FIX: Initialize COM in this thread
    c = wmi.WMI()
    watcher = c.Win32_Process.watch_for("creation")
    print("[Process Monitor] Monitoring for executable launches...")

    while True:
        try:
            new_proc = watcher()
            command = new_proc.CommandLine or new_proc.Name
            if is_suspicious_exec(command):
                log_event("file_executed", {"command": command})
        except Exception as e:
            print(f"[Process Monitor] Error: {e}")
            time.sleep(2)

# === BROWSER HISTORY MONITORING (SUSPICIOUS URLS) ===
def scan_browser_history():
    print("[URL Scanner] Started scanning Chrome history every 30 seconds...")
    while True:
        try:
            # Copy history file (Chrome locks the original)
            shutil.copy2(CHROME_HISTORY_PATH, TEMP_HISTORY_COPY)
            conn = sqlite3.connect(TEMP_HISTORY_COPY)
            cursor = conn.cursor()

            # Get recent history (last 2 minutes)
            chrome_time_cutoff = (datetime.now() - timedelta(minutes=2)).timestamp() * 1_000_000
            cursor.execute("SELECT url FROM urls WHERE last_visit_time > ?", (int(chrome_time_cutoff),))

            for (url,) in cursor.fetchall():
                if any(domain in url for domain in MALICIOUS_DOMAINS):
                    log_event("suspicious_url", {"url": url})

            conn.close()
            os.remove(TEMP_HISTORY_COPY)
        except Exception as e:
            print(f"[URL Scanner] Error: {e}")

        time.sleep(30)

# === MAIN ===
if __name__ == "__main__":
    print("[Agent] Starting combined agent...")

    # Thread 1: Monitor file execution
    process_thread = threading.Thread(target=monitor_process_execution, daemon=True)
    process_thread.start()

    # Thread 2: Monitor browser history
    browser_thread = threading.Thread(target=scan_browser_history, daemon=True)
    browser_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Agent] Shutting down.")
