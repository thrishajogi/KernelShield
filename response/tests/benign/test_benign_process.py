import subprocess
import time


def run_test():

    process = subprocess.Popen(["sleep", "30"])

    pid = process.pid

    print("========== Benign Process Test ==========")
    print(f"Test Process PID : {pid}")

    time.sleep(1)

    if process.poll() is None:
        print("Expected Result : Process remains running")
        print("Actual Result   : Process remains running")
        print("TEST RESULT     : PASS")

        process.terminate()
        process.wait()

    else:
        print("Expected Result : Process remains running")
        print("Actual Result   : Process was terminated")
        print("TEST RESULT     : FAIL")

    print("==========================================")


if __name__ == "__main__":
    run_test()
