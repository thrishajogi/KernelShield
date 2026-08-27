import os
import signal


def terminate_process(pid):

    try:

        os.kill(pid, signal.SIGTERM)

        print(f"[SUCCESS] Process {pid} terminated.")

        return True

    except ProcessLookupError:

        print(f"[ERROR] Process {pid} does not exist.")

        return False

    except PermissionError:

        print("[ERROR] Permission denied.")

        return False

    except Exception as e:

        print(e)

        return False
