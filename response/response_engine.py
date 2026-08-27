import json
import os

from process_killer import terminate_process
from logger import write_log
from config import PROTECTED_PIDS, AUTO_RESPONSE_SEVERITIES
from firewall import block_ip


def decide_response(detection):
    """
    Determine response from the KernelShield alert.

    Detection is evidence produced by the native detector.
    """

    attack_type = detection.get("attack_type", "")
    severity = detection.get("severity", "").lower()

    # Strong multi-stage correlation.
    if (
        attack_type == "multi_stage_attack"
        and severity in AUTO_RESPONSE_SEVERITIES
    ):
        return "Terminate Process + Block IP"

    # A shell spawned from a server is suspicious, but
    # should not automatically kill the process by itself.
    if attack_type == "server_to_shell":
        return "Alert Only"

    # Shell network activity alone is evidence, not
    # sufficient proof for destructive response.
    if attack_type == "shell_network_activity":
        return "Alert Only"

    return "No Action"


def receive_detection(detection):
    """
    Process one KernelShield detection.
    """

    attack_type = detection.get("attack_type", "unknown")
    severity = detection.get("severity", "unknown").lower()

    pid = int(detection.get("pid", 0))

    has_network = int(
        detection.get("has_network", 0)
    )

    destination_ip = detection.get(
        "destination_ip", ""
    )

    destination_port = int(
        detection.get("destination_port", 0)
    )

    action = decide_response(detection)

    print()
    print("========== KernelShield Response ==========")
    print(f"Attack Type : {attack_type}")
    print(f"Severity    : {severity}")
    print(f"PID         : {pid}")
    print(f"Action      : {action}")

    status = "NOT_EXECUTED"

    if pid <= 0:

        status = "INVALID_PID"

    elif pid in PROTECTED_PIDS:

        print("[SAFETY] Protected system process.")
        print("[SAFETY] Response cancelled.")

        status = "BLOCKED"

    elif action.startswith("Terminate"):

        if pid == os.getpid():

            print("[SAFETY] Refusing to terminate response engine.")
            status = "BLOCKED"

        else:

            success = terminate_process(pid)

            if success:
                status = "SUCCESS"
            else:
                status = "FAILED"

    elif action == "Alert Only":

        status = "ALERT_ONLY"

    else:

        status = "NO_ACTION"

    # Network containment is only performed when the
    # detector explicitly associates an IP with the alert.
    if (
        has_network
        and destination_ip
        and action == "Terminate Process + Block IP"
    ):

        print(
            f"[NETWORK] Destination: "
            f"{destination_ip}:{destination_port}"
        )

        firewall_success = block_ip(
            destination_ip
        )

        if firewall_success:
            print(
                "[NETWORK] IP containment: SUCCESS"
            )
        else:
            print(
                "[NETWORK] IP containment: FAILED"
            )

    write_log(
        attack_type,
        pid,
        action,
        status
    )

    print(f"Status      : {status}")
    print("============================================")


def main():

    import sys

    if len(sys.argv) != 2:

        print(
            "Usage: python3 response_engine.py "
            "<detection.json>"
        )

        raise SystemExit(1)

    detection_file = sys.argv[1]

    with open(detection_file, "r") as file:

        detection = json.load(file)

    receive_detection(detection)


if __name__ == "__main__":
    main()
