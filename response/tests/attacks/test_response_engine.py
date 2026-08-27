import subprocess
import json
import os
import sys


RESPONSE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

sys.path.insert(0, RESPONSE_DIR)

TEST_IP = "203.0.113.10"
DETECTION_FILE = os.path.join(RESPONSE_DIR, "detection.json")


def run_test():

    print("==============================================")
    print(" KernelShield End-to-End Response Test")
    print("==============================================")

    # Create a harmless controlled test process.
    process = subprocess.Popen(["sleep", "60"])
    pid = process.pid

    print(f"Test Process PID : {pid}")

    # Use the same alert type that the production detector
    # uses for automatic containment.
    detection = {
        "schema_version": 1,
        "pid": pid,
        "ppid": os.getpid(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "process_name": "sleep",
        "parent_name": "python3",
        "attack_type": "multi_stage_attack",
        "alert_type": "correlation",
        "severity": "CRITICAL",
        "reason": "Controlled multi-stage correlation test",
        "mitre_technique": "T1059",
        "has_network": 1,
        "destination_ip": TEST_IP,
        "destination_port": 4444,
        "event_count": 3
    }

    with open(DETECTION_FILE, "w") as file:
        json.dump(detection, file, indent=4)

    # Run the actual production response engine
    # using its documented interface.
    result = subprocess.run(
        [
            "python3",
            os.path.join(RESPONSE_DIR, "response_engine.py"),
            DETECTION_FILE
        ],
        cwd=RESPONSE_DIR,
        capture_output=True,
        text=True
    )

    print(result.stdout)

    # Reap the controlled test process after the response
    # engine terminates it. The response engine is a separate
    # process, so ps(1) may briefly observe a zombie entry.
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process_terminated = False
    else:
        process_terminated = process.returncode is not None

    # Verify firewall containment.
    firewall_check = subprocess.run(
        ["sudo", "iptables", "-L", "OUTPUT", "-n"],
        capture_output=True,
        text=True
    )

    firewall_blocked = TEST_IP in firewall_check.stdout

    # Cleanup firewall rule.
    subprocess.run(
        [
            "sudo",
            "iptables",
            "-D",
            "OUTPUT",
            "-d",
            TEST_IP,
            "-j",
            "DROP"
        ],
        check=False
    )

    # Remove temporary detection file.
    try:
        os.remove(DETECTION_FILE)
    except FileNotFoundError:
        pass

    if process_terminated and firewall_blocked:

        print("Expected Result : Process terminated + IP blocked")
        print("Actual Result   : Process terminated + IP blocked")
        print("TEST RESULT     : PASS")

    else:

        print("Expected Result : Process terminated + IP blocked")
        print(
            "Actual Result   : "
            f"Process terminated = {process_terminated}, "
            f"IP blocked = {firewall_blocked}"
        )
        print("TEST RESULT     : FAIL")

    print("==============================================")


if __name__ == "__main__":
    run_test()
