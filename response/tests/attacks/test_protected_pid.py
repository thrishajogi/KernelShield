import sys
import os

RESPONSE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

sys.path.insert(0, RESPONSE_DIR)

from config import PROTECTED_PIDS


def run_test():

    test_pid = 1

    print("========== Protected PID Test ==========")
    print(f"Test PID : {test_pid}")

    if test_pid in PROTECTED_PIDS:
        print("Expected Result : Response blocked")
        print("Actual Result   : Response blocked")
        print("TEST RESULT     : PASS")
    else:
        print("Expected Result : Response blocked")
        print("Actual Result   : Response allowed")
        print("TEST RESULT     : FAIL")

    print("========================================")


if __name__ == "__main__":
    run_test()
