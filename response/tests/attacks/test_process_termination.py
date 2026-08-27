import subprocess
import time
import sys
import os

RESPONSE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

sys.path.insert(0, RESPONSE_DIR)

from process_killer import terminate_process


def run_test():

    process = subprocess.Popen(["sleep", "60"])

    pid = process.pid

    print("========== Process Termination Test ==========")
    print(f"Test Process PID : {pid}")

    time.sleep(1)

    success = terminate_process(pid)

    if success:
        print("Expected Result : Process terminated")
        print("Actual Result   : Process terminated")
        print("TEST RESULT     : PASS")
    else:
        print("Expected Result : Process terminated")
        print("Actual Result   : Process still running")
        print("TEST RESULT     : FAIL")

    print("==============================================")


if __name__ == "__main__":
    run_test()
