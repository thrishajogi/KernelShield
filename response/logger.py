from datetime import datetime


def write_log(attack_type, pid, action, status):

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("response.log", "a") as log:

        log.write(f"Time   : {current_time}\n")
        log.write(f"Attack : {attack_type}\n")
        log.write(f"PID    : {pid}\n")
        log.write(f"Action : {action}\n")
        log.write(f"Status : {status}\n")
        log.write("-" * 40 + "\n")
