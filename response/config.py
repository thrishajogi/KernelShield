"""
KernelShield Response Configuration
"""

# Never terminate critical system processes.
PROTECTED_PIDS = {
    1,   # systemd/init
    2,   # kthreadd
}

# KernelShield detection types.
SUPPORTED_ATTACKS = {
    "server_to_shell",
    "multi_stage_attack",
    "shell_network_activity",
}

# Only critical correlated behavior is automatically terminated.
# High-severity detections are logged for investigation.
AUTO_RESPONSE_SEVERITIES = {
    "critical",
}
