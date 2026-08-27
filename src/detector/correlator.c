#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "detector.h"
#include "rules.h"
#include "state.h"
#include "process_table.h"
#include "ks_alert.h"
static void add_risk(ks_process *process, int points)
{
    if (!process)
        return;

    process->risk_score += points;

    if (process->risk_score > 100)
        process->risk_score = 100;
}
static void emit_detection_alert(
    const struct ks_event *event,
    const char *attack_type,
    const char *alert_type,
    const char *severity,
    const char *action_taken,
    const char *reason,
    const char *mitre,
    uint8_t has_network,
    const char *destination_ip,
    uint16_t destination_port,
    uint32_t event_count)
{
    ks_alert alert;

    memset(&alert, 0, sizeof(alert));

    alert.schema_version =
        KS_ALERT_SCHEMA_VERSION;

    alert.timestamp_ns =
        event->timestamp_ns;

    alert.pid =
        event->pid;

    alert.ppid =
        event->ppid;

    alert.uid =
        event->uid;

    alert.gid =
        event->gid;

    strncpy(
        alert.process_name,
        event->comm,
        sizeof(alert.process_name) - 1
    );

    /*
     * Resolve parent process name from the existing
     * process table.
     */
    ks_process *parent =
        ks_process_find(event->ppid);

    if (parent) {

        strncpy(
            alert.parent_name,
            parent->comm,
            sizeof(alert.parent_name) - 1
        );
    } else {

        strncpy(
            alert.parent_name,
            "unknown",
            sizeof(alert.parent_name) - 1
        );
    }

    strncpy(
        alert.attack_type,
        attack_type,
        sizeof(alert.attack_type) - 1
    );

    strncpy(
        alert.alert_type,
        alert_type,
        sizeof(alert.alert_type) - 1
    );

    strncpy(
        alert.severity,
        severity,
        sizeof(alert.severity) - 1
    );

    strncpy(
        alert.action_taken,
        action_taken,
        sizeof(alert.action_taken) - 1
    );

    strncpy(
        alert.reason,
        reason,
        sizeof(alert.reason) - 1
    );

    strncpy(
        alert.mitre_technique,
        mitre,
        sizeof(alert.mitre_technique) - 1
    );

    alert.has_network =
        has_network;

    if (has_network && destination_ip) {

        strncpy(
            alert.destination_ip,
            destination_ip,
            sizeof(alert.destination_ip) - 1
        );

        alert.destination_port =
            destination_port;
    }

    alert.event_count =
        event_count;

    if (ks_alert_write(&alert) != 0) {

        fprintf(
            stderr,
            "[KernelShield] Failed to write detection alert\n"
        );
    }
}
void ks_detector_init(void)
{
    ks_state_init();

    if (ks_alert_init() != 0) {

        fprintf(
            stderr,
            "[KernelShield] WARNING: "
            "Failed to initialize alert output: "
            "/tmp/kernelshield-alerts.jsonl\n"
        );
    }
}
void ks_detector_process_event(const struct ks_event *event)
{
    /*
     * ------------------------------------------------------
     * EXEC EVENT
     * ------------------------------------------------------
     */
    if (event->type == KS_EVENT_EXEC) {

        /*
         * Add/update the process before evaluating it.
         */
        ks_process_add(event);

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        process->last_activity_ns =
            event->timestamp_ns;

        /*
         * Execution transition:
         *
         * Example:
         *   bash -> curl
         *
         * Keep the transition as behavioural context.
         */
        if (process->exec_count > 1 &&
            process->previous_comm[0] != '\0') {

            printf("\n");
            printf("============================================\n");
            printf("[INFO] Process Execution Transition\n");
            printf("PID      : %u\n", process->pid);
            printf("Previous : %s\n", process->previous_comm);
            printf("Current  : %s\n", process->comm);
            printf("Execs    : %u\n", process->exec_count);
            printf("============================================\n\n");
        }

        /*
         * Check whether this process was created by
         * a server process and is now a shell.
         */
        if (ks_rule_shell_from_server(event)) {

            process->spawned_shell = true;

            /*
             * Server -> shell is a strong behavioural signal.
             */
            add_risk(process, 40);

            emit_detection_alert(
                event,
                "server_to_shell",
                "behavioral",
                "high",
                "A server process spawned a shell",
                "Alert Generated",
                "T1059",
                0,
                NULL,
                0,
                1
            );

            printf("\n");
            printf("============================================\n");
            printf("[HIGH] Suspicious Server-to-Shell Execution\n");
            printf("Process : %s (%u)\n",
                   process->comm,
                   process->pid);
            printf("Parent  : %u\n",
                   process->ppid);
            printf("Risk    : %d/100\n",
                   process->risk_score);
            printf("Reason  : Server process spawned a shell\n");
            printf("MITRE   : T1059 Command and Scripting Interpreter\n");
            printf("============================================\n\n");
        }

        return;
    }

    /*
     * ------------------------------------------------------
     * NETWORK EVENT
     * ------------------------------------------------------
     */
    if (event->type == KS_EVENT_NETWORK) {

        /*
         * Store network history.
         */
        ks_state_add_network(event);

        /*
         * Find the process responsible for the connection.
         */
        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        process->last_activity_ns =
            event->timestamp_ns;

        process->made_network_connection = true;
        process->network_count++;

        /*
         * --------------------------------------------------
         * MULTI-STAGE ATTACK CHAIN
         * --------------------------------------------------
         *
         * This check MUST happen for ANY network process,
         * not only shells.
         *
         * Example:
         *
         *     python3 -> bash -> curl -> network
         *
         * curl itself is not a shell, but its ancestor
         * bash was spawned by a server process.
         */
        if (!process->attack_chain_detected &&
            ks_rule_attack_chain(process->pid)) {

            process->attack_chain_detected = true;

            /*
             * Strong correlation signal.
             */
            add_risk(process, 40);

            char chain_ip[INET_ADDRSTRLEN] = "unknown";

            inet_ntop(
                AF_INET,
                &event->dst_ipv4,
                chain_ip,
                sizeof(chain_ip)
            );

            emit_detection_alert(
                event,
                "multi_stage_attack",
                "correlation",
                "critical",
                "Process Terminated",
                "Correlated server-to-shell-to-network behavior detected",
                "T1059",
                1,
                chain_ip,
                ntohs(event->dst_port),
                3
            );

            printf("\n");
            printf("============================================\n");
            printf("[CRITICAL] Multi-Stage Attack Chain Detected\n");
            printf("Process : %s (%u)\n",
                   process->comm,
                   process->pid);
            printf("Parent  : %u\n",
                   process->ppid);
            printf("Risk    : %d/100\n",
                   process->risk_score);
            printf("Chain   : server -> shell -> network process\n");
            printf("Signals : server-to-shell + network activity\n");
            printf("MITRE   : T1059 Command and Scripting Interpreter\n");
            printf("============================================\n\n");
        }

        /*
         * --------------------------------------------------
         * SHELL NETWORK ACTIVITY
         * --------------------------------------------------
         *
         * This is a separate signal.
         */
        if (ks_rule_network_from_shell(event)) {

            add_risk(process, 20);

            char ip[INET_ADDRSTRLEN];

            inet_ntop(AF_INET,
                      &event->dst_ipv4,
                      ip,
                      sizeof(ip));

            emit_detection_alert(
                event,
                "shell_network_activity",
                "network",
                "high",
                "Process Terminated",
                "Shell process generated outbound network activity",
                "T1059",
                1,
                ip,
                ntohs(event->dst_port),
                2
            );

            printf("\n");
            printf("============================================\n");
            printf("[INFO] Shell Network Activity\n");
            printf("Process : %s (%u)\n",
                   process->comm,
                   process->pid);
            printf("Target  : %s:%u\n",
                   ip,
                   ntohs(event->dst_port));
            printf("Network : %u connections\n",
                   process->network_count);
            printf("Risk    : %d/100\n",
                   process->risk_score);
            printf("============================================\n\n");
        }

        /*
         * Multiple connections from the same process
         * add another behavioural signal.
         */
        if (process->network_count == 3) {
            add_risk(process, 10);
        }

        return;
    }

    /*
     * ------------------------------------------------------
     * EXIT EVENT
     * ------------------------------------------------------
     */
    if (event->type == KS_EVENT_EXIT) {

        ks_process *process =
            ks_process_find(event->pid);

        if (process) {

            process->last_activity_ns =
                event->timestamp_ns;

            /*
             * Only remove the process after we have
             * finished using its state.
             */
            ks_process_remove(event);
        }

        return;
    }
}
void ks_detector_shutdown(void)
{
    ks_alert_close();
}
