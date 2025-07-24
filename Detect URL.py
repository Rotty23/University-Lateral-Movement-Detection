import os
import time
import shutil
import sqlite3
import socket
import json
from datetime import datetime, timedelta

# === CONFIG ===
CHROME_HISTORY_PATH = os.path.expandvars(r"C:\Users\Lachlan\AppData\Local\Google\Chrome\User Data\Default\History")
TEMP_COPY_PATH = "temp_history"
MALICIOUS_DOMAINS = ["amazon.com", "malware.test", "phishingsite.net"]

def log_event(event_type, url):
    event = {
        "event_type": event_type,
        "url": url,
        "timestamp": time.time(),
        "hostname": socket.gethostname()
    }
    print(json.dumps(event))

def scan_history():
    try:
        shutil.copy2(CHROME_HISTORY_PATH, TEMP_COPY_PATH)
        conn = sqlite3.connect(TEMP_COPY_PATH)
        cursor = conn.cursor()

        time_threshold = (datetime.now() - timedelta(minutes=2)).timestamp() * 1000000  # Chrome time is in microseconds
        cursor.execute("SELECT url FROM urls WHERE last_visit_time > ?", (int(time_threshold),))

        for (url,) in cursor.fetchall():
            if any(domain in url for domain in MALICIOUS_DOMAINS):
                log_event("suspicious_url", url)

        conn.close()
        os.remove(TEMP_COPY_PATH)

    except Exception as e:
        print(f"[!] Failed to scan history: {e}")

if __name__ == "__main__":
    print("Scanning browser history for suspicious URLs every 5 seconds...")
    while True:
        scan_history()
        time.sleep(5)
