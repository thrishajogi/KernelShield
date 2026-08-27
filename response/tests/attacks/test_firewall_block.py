import subprocess
import sys
import os

RESPONSE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

sys.path.insert(0, RESPONSE_DIR)

from firewall import block_ip


TEST_IP = "203.0.113.10"


def rule_exists():

    result = subprocess.run(
        ["sudo", "iptables", "-L", "OUTPUT", "-n"],
        capture_output=True,
        text=True
    )

    return TEST_IP in result.stdout


def run_test():

    print("========== Firewall Block Test ==========")
    print(f"Test Destination : {TEST_IP}")

    # Add firewall rule
    success = block_ip(TEST_IP)

    if not success:
        print("Expected Result : IP blocked")
        print("Actual Result   : Failed to add firewall rule")
        print("TEST RESULT     : FAIL")
        return

    # Verify rule
    if rule_exists():
        print("Expected Result : Firewall rule exists")
        print("Actual Result   : Firewall rule exists")
        print("TEST RESULT     : PASS")
    else:
        print("Expected Result : Firewall rule exists")
        print("Actual Result   : Firewall rule not found")
        print("TEST RESULT     : FAIL")

    # Cleanup test rule
    subprocess.run(
        ["sudo", "iptables", "-D", "OUTPUT", "-d", TEST_IP, "-j", "DROP"],
        check=False
    )

    print("Test firewall rule removed.")
    print("=========================================")


if __name__ == "__main__":
    run_test()
