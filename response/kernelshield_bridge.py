#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import time


ALERT_FILE = "/tmp/kernelshield-alerts.jsonl"
DETECTION_FILE = "detection.json"


def process_alert(alert):
    """
    Convert KernelShield's native alert schema into
    the response engine's input format.
    """

    detection = {
        "schema_version":
            alert.get("schema_version", 1),

        "timestamp_ns":
            alert.get("timestamp_ns", 0),

        "pid":
            alert.get("pid", 0),

        "ppid":
            alert.get("ppid", 0),

        "uid":
            alert.get("uid", 0),

        "gid":
            alert.get("gid", 0),

        "process_name":
            alert.get("process_name", ""),

        "parent_name":
            alert.get("parent_name", ""),

        "attack_type":
            alert.get("attack_type", "unknown"),

        "alert_type":
            alert.get("alert_type", "unknown"),

        "severity":
            alert.get("severity", "unknown"),

        "reason":
            alert.get("reason", ""),

        "mitre_technique":
            alert.get("mitre_technique", ""),

        "has_network":
            alert.get("has_network", 0),

        "destination_ip":
            alert.get("destination_ip", ""),

        "destination_port":
            alert.get("destination_port", 0),

        "event_count":
            alert.get("event_count", 0),
    }

    with open(
        DETECTION_FILE,
        "w"
    ) as file:

        json.dump(
            detection,
            file,
            indent=2
        )

    print()
    print("[BRIDGE] KernelShield detection received.")
    print(
        f"[BRIDGE] PID={detection['pid']} "
        f"attack={detection['attack_type']} "
        f"severity={detection['severity']}"
    )

    subprocess.run(
        [
            sys.executable,
            os.path.join(os.path.dirname(__file__), "response_engine.py"),
            DETECTION_FILE,
        ],
        check=False,
    )


def follow_alerts():

    print("============================================")
    print(" KernelShield Response Bridge")
    print("============================================")
    print(f"Alert source : {ALERT_FILE}")
    print("Mode         : continuous")
    print()

    while not os.path.exists(ALERT_FILE):

        print(
            "[BRIDGE] Waiting for KernelShield alerts..."
        )

        time.sleep(1)

    with open(
        ALERT_FILE,
        "r"
    ) as file:

        # Existing alerts are not replayed.
        file.seek(0, os.SEEK_END)

        while True:

            line = file.readline()

            if not line:

                time.sleep(0.2)
                continue

            line = line.strip()

            if not line:
                continue

            try:

                alert = json.loads(line)

                process_alert(alert)

            except json.JSONDecodeError:

                print(
                    "[BRIDGE] Invalid JSON alert ignored."
                )

            except Exception as exc:

                print(
                    f"[BRIDGE] Processing error: {exc}"
                )


if __name__ == "__main__":

    try:
        follow_alerts()

    except KeyboardInterrupt:

        print()
        print("[BRIDGE] Stopped.")
