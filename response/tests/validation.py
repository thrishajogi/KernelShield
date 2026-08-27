import subprocess
import sys
import os


TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


TEST_FILES = [
    ("Process Termination", "attacks/test_process_termination.py"),
    ("Protected PID Safety", "attacks/test_protected_pid.py"),
    ("Firewall Blocking", "attacks/test_firewall_block.py"),
    ("Benign Process", "benign/test_benign_process.py"),
    ("End-to-End Response", "attacks/test_response_engine.py")
]


def run_test(name, file_path):

    print(f"\n--- Running: {name} ---")

    result = subprocess.run(
        ["python3", os.path.join(TESTS_DIR, file_path)],
        capture_output=True,
        text=True
    )

    print(result.stdout)

    if "TEST RESULT     : PASS" in result.stdout:
        return True

    return False


def main():

    print("==============================================")
    print(" KernelShield Response Validation")
    print("==============================================")

    passed = 0
    failed = 0

    for name, file_path in TEST_FILES:

        if run_test(name, file_path):
            passed += 1
        else:
            failed += 1

    total = passed + failed

    print("\n==============================================")
    print(" Validation Summary")
    print("==============================================")
    print(f"Tests Passed : {passed}")
    print(f"Tests Failed : {failed}")
    print(f"Total Tests  : {total}")

    if failed == 0:
        print("Result       : ALL TESTS PASSED")
    else:
        print("Result       : SOME TESTS FAILED")

    print("==============================================")


if __name__ == "__main__":
    main()
