import subprocess


def _run_iptables(args):
    """
    Execute iptables directly when already running as root.
    Otherwise invoke it through sudo.
    """

    command = ["iptables"] + args

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if result.returncode == 0:
            return True

        # Fall back to sudo when the process isn't root.
        result = subprocess.run(
            ["sudo"] + command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        return result.returncode == 0

    except OSError:
        return False


def block_ip(ip):
    if not ip:
        return False

    # Check whether the rule already exists.
    if _run_iptables([
        "-C",
        "OUTPUT",
        "-d",
        ip,
        "-j",
        "DROP",
    ]):
        print(f"[FIREWALL] Already blocked: {ip}")
        return True

    # Add the rule.
    if _run_iptables([
        "-A",
        "OUTPUT",
        "-d",
        ip,
        "-j",
        "DROP",
    ]):
        print(f"[FIREWALL] Blocked connection to {ip}")
        return True

    print(f"[FIREWALL] Failed to block {ip}")
    return False
