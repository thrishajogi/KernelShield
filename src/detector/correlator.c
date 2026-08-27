#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "detector.h"
#include "rules.h"
#include "state.h"
#include "process_table.h"
#include "evidence_graph.h"
#include "ks_alert.h"
#include "attack_episode.h"

/*
 * Temporal correlation window.
 *
 * Events occurring within this window are considered part
 * of the same behavioral episode.
 *
 * 30 seconds gives enough room for multi-stage activity
 * without correlating unrelated activity indefinitely.
 */
#define KS_BEHAVIOR_WINDOW_NS 30000000000ULL

/*
 * Add behavioral evidence to the current episode.
 *
 * The score is bounded to 100 so a noisy process cannot
 * accumulate an unlimited risk value.
 */
static void add_behavior_score(
    ks_process *process,
    int points)
{
    if (!process || points <= 0)
        return;

    process->episode_score +=
        (uint32_t)points;

    if (process->episode_score > 100)
        process->episode_score = 100;

    process->behavioral_score =
        (int)process->episode_score;
}

/*
 * Check whether two timestamps belong to the same
 * behavioral episode.
 */
static bool within_window(
    uint64_t current,
    uint64_t previous)
{
    if (previous == 0)
        return false;

    if (current < previous)
        return false;

    return (current - previous) <=
           KS_BEHAVIOR_WINDOW_NS;
}

/*
 * Ensure that the process has a valid behavioral episode.
 *
 * Activity separated by more than the correlation window
 * starts a new episode and clears the previous score.
 */
static void ensure_episode(
    ks_process *process,
    uint64_t timestamp_ns)
{
    if (!process)
        return;

    /*
     * First event for an episode.
     */
    if (process->episode_start_ns == 0) {

        process->episode_id = 1;

        process->episode_start_ns =
            timestamp_ns;

        process->episode_last_event_ns =
            timestamp_ns;

        process->episode_event_count = 1;

        process->episode_score = 0;

        process->behavioral_score = 0;

        return;
    }

    /*
     * Activity outside the temporal window starts
     * a new independent behavioral episode.
     */
    if (!within_window(
            timestamp_ns,
            process->episode_last_event_ns)) {

        process->episode_id++;

        process->episode_start_ns =
            timestamp_ns;

        process->episode_event_count = 0;

        process->episode_score = 0;

        process->behavioral_score = 0;
    }

    process->episode_last_event_ns =
        timestamp_ns;

    process->episode_event_count++;
}

/*
 * Convert accumulated behavioral evidence into severity.
 *
 * These thresholds describe the strength of correlated
 * evidence, not a probability of compromise.
 */
static const char *severity_for_score(int score)
{
    if (score >= 85)
        return "critical";

    if (score >= 70)
        return "high";

    if (score >= 50)
        return "medium";

    return "low";
}

/*
 * Convert accumulated evidence into a deterministic
 * confidence value.
 */
static uint16_t confidence_for_score(int score)
{
    if (score >= 85)
        return 95;

    if (score >= 70)
        return 85;

    if (score >= 50)
        return 70;

    if (score >= 30)
        return 50;

    return 25;
}

/*
 * Generate standardized ks_alert.
 */
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
    if (!event)
        return;

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

    alert.has_network = has_network;

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

    /*
     * Attach the current behavioral episode assessment.
     */
    ks_process *assessment_process =
        ks_process_find(event->pid);

    if (assessment_process) {

        alert.risk_score =
            (uint16_t)assessment_process->episode_score;

        alert.confidence =
            confidence_for_score(
                assessment_process->episode_score
            );
    }

    if (ks_alert_write(&alert) != 0) {

        fprintf(
            stderr,
            "[KernelShield] Failed to write ks_alert\n"
        );
    }
}

void ks_detector_init(void)
{
    ks_attack_episode_init();
    ks_state_init();
    ks_process_table_init();

    if (ks_alert_init() != 0) {

        fprintf(
            stderr,
            "[KernelShield] WARNING: "
            "ks_alert initialization failed\n"
        );
    }
}

void ks_detector_process_event(
    const struct ks_event *event)
{
    if (!event)
        return;

    /*
     * High-level attack episode reconstruction.
     *
     * Every event observed by KernelShield is also evaluated
     * as part of a multi-stage attack episode.
     */
    ks_attack_episode *attack_episode =
        ks_attack_episode_process_event(event);

    if (attack_episode) {

        static uint32_t last_episode_id = 0;
        static int last_score = -1;
        static ks_attack_stage last_stage = KS_STAGE_UNKNOWN;

        /*
         * Only show an attack update when the episode contains
         * meaningful suspicious behavior.
         */
        bool suspicious =
            attack_episode->score >= 20 ||
            attack_episode->current_stage >=
                KS_STAGE_SUSPICIOUS_SPAWN;

        if (suspicious) {

            bool meaningful_change = false;

            if (attack_episode->id != last_episode_id)
                meaningful_change = true;

            if (attack_episode->current_stage != last_stage)
                meaningful_change = true;

            if ((attack_episode->score / 10) !=
                (last_score / 10))
                meaningful_change = true;

            if (meaningful_change) {

                printf(
                    "\n"
                    "========== KERNELSHIELD ATTACK UPDATE ==========\n"
                    "Episode ID       : KS-%06u\n"
                    "Root PID         : %u\n"
                    "Process          : %s\n"
                    "Events Seen      : %u\n"
                    "Risk Score       : %d/100\n"
                    "Current Stage    : %s\n"
                    "Predicted Next   : %s\n"
                    "Containment      : %s\n"
                    "================================================\n\n",

                    attack_episode->id,
                    attack_episode->root_pid,
                    attack_episode->last_process,
                    attack_episode->event_count,
                    attack_episode->score > 100 ?
                        100 : attack_episode->score,
                    ks_attack_stage_name(
                        attack_episode->current_stage
                    ),
                    ks_attack_stage_name(
                        attack_episode->predicted_next_stage
                    ),
                    attack_episode->containment_recommended ?
                        "RECOMMENDED" : "MONITOR"
                );

                last_episode_id = attack_episode->id;
                last_score = attack_episode->score;
                last_stage = attack_episode->current_stage;
            }
        }
    }

    /*
     * ======================================================
     * EXECUTION
     * ======================================================
     */
    if (event->type == KS_EVENT_EXEC) {

        ks_process_add(event);

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        ensure_episode(
            process,
            event->timestamp_ns
        );

        ks_evidence_add(
            &process->evidence_graph,
            KS_EVIDENCE_EXECUTION,
            event->timestamp_ns
        );

        process->last_activity_ns =
            event->timestamp_ns;

        /*
         * Existing process transition is itself evidence.
         *
         * Example:
         *
         * application -> interpreter
         * interpreter -> network utility
         */
        if (process->exec_count > 1) {

            add_behavior_score(process, 5);

            printf(
                "[BEHAVIOR] PID=%u transition %s -> %s\n",
                process->pid,
                process->previous_comm,
                process->comm
            );
        }

        /*
         * Server -> shell remains a useful semantic signal,
         * but it is now only ONE component of the behavioral
         * score rather than the entire detection mechanism.
         */
        if (ks_rule_shell_from_server(event)) {

            process->spawned_shell = true;

            ks_evidence_add(
                &process->evidence_graph,
                KS_EVIDENCE_SHELL,
                event->timestamp_ns
            );

            /*
             * Server -> shell is suspicious evidence,
             * not sufficient proof by itself.
             */
            add_behavior_score(process, 25);

            printf(
                "[BEHAVIOR] PID=%u server-to-shell evidence "
                "score=%u episode=%u\\n",
                process->pid,
                process->episode_score,
                process->episode_id
            );
        }

        return;
    }

    /*
     * ======================================================
     * NETWORK
     * ======================================================
     */
    if (event->type == KS_EVENT_NETWORK) {

        ks_state_add_network(event);

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        ensure_episode(
            process,
            event->timestamp_ns
        );

        ks_evidence_add(
            &process->evidence_graph,
            KS_EVIDENCE_NETWORK,
            event->timestamp_ns
        );

        process->last_activity_ns =
            event->timestamp_ns;

        process->network_count++;
        process->made_network_connection = true;
        process->last_network_ns =
            event->timestamp_ns;

        /*
         * Network activity immediately after an execution
         * transition is stronger evidence than an isolated
         * connection.
         */
        if (within_window(
                event->timestamp_ns,
                process->last_exec_ns)) {

            add_behavior_score(process, 15);
        }

        /*
         * Repeated network activity increases evidence.
         */
        if (process->network_count >= 3) {

            add_behavior_score(process, 10);
        }

        char ip[INET_ADDRSTRLEN] = "unknown";

        inet_ntop(
            AF_INET,
            &event->dst_ipv4,
            ip,
            sizeof(ip)
        );

        /*
         * Multi-stage correlation:
         *
         * process
         *    ↓
         * shell ancestor
         *    ↓
         * network
         */
        if (!process->attack_chain_detected &&
            !process->chain_alert_emitted &&
            ks_rule_attack_chain(process->pid)) {

            process->attack_chain_detected = true;
            process->chain_alert_emitted = true;

            ks_evidence_add(
                &process->evidence_graph,
                KS_EVIDENCE_CHAIN,
                event->timestamp_ns
            );

            add_behavior_score(process, 40);

            emit_detection_alert(
                event,
                "multi_stage_attack",
                "correlation",
                "critical",
                "Process Terminated",
                "Execution and network behavior formed a correlated multi-stage process chain",
                "T1059",
                1,
                ip,
                ntohs(event->dst_port),
                process->exec_count +
                process->network_count
            );

            return;
        }

        /*
         * Shell network activity is another behavioral signal.
         */
        if (!process->network_alert_emitted &&
            ks_rule_network_from_shell(event)) {

            process->network_alert_emitted = true;

            add_behavior_score(process, 20);

            emit_detection_alert(
                event,
                "shell_network_activity",
                "network",
                severity_for_score(
                    process->behavioral_score
                ),
                "Process Terminated",
                "Shell process generated outbound network activity",
                "T1059",
                1,
                ip,
                ntohs(event->dst_port),
                process->network_count
            );
        }

        return;
    }

    /*
     * ======================================================
     * FILE ACTIVITY
     * ======================================================
     */
    if (event->type == KS_EVENT_FILE) {

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        ensure_episode(
            process,
            event->timestamp_ns
        );

        /*
         * File evidence is recorded independently from scoring.
         * Repeated writes do not increase evidence diversity.
         */
        ks_evidence_add(
            &process->evidence_graph,
            KS_EVIDENCE_FILE,
            event->timestamp_ns
        );

        process->last_activity_ns =
            event->timestamp_ns;

        switch (event->file_operation) {

        case KS_FILE_OPEN:

            process->file_open_count++;
            break;

        case KS_FILE_WRITE:

            process->file_write_count++;
            process->wrote_file = true;
            process->last_file_write_ns =
                event->timestamp_ns;

            /*
             * Track modification of the same temporary file
             * created during this process episode.
             */
            if (process->temporary_file_created &&
                process->tracked_file_path[0] != '\0' &&
                strcmp(
                    event->file_path,
                    process->tracked_file_path
                ) == 0) {

                process->temporary_file_written = true;
                process->temporary_file_write_ns =
                    event->timestamp_ns;
            }

            /*
             * File modification following execution/network
             * behavior is stronger than an isolated write.
             */
            if (within_window(
                    event->timestamp_ns,
                    process->last_exec_ns) ||
                within_window(
                    event->timestamp_ns,
                    process->last_network_ns)) {

                add_behavior_score(process, 10);
            }

            break;

        case KS_FILE_CREATE:

            process->file_create_count++;
            process->created_file = true;

            if (within_window(
                    event->timestamp_ns,
                    process->last_network_ns)) {

                add_behavior_score(process, 15);
            }

            /*
             * Track temporary-file creation as evidence only.
             *
             * Creating a file in /tmp is normal on Linux and
             * must never generate an alert by itself.
             */
            if (strstr(event->file_path, "/tmp/") != NULL) {

                process->temporary_file_created = true;
                process->temporary_file_create_ns =
                    event->timestamp_ns;

                snprintf(
                    process->tracked_file_path,
                    sizeof(process->tracked_file_path),
                    "%s",
                    event->file_path
                );
            }

            break;

        default:
            break;
        }

        /*
         * Production file-chain correlation.
         *
         * Require multiple independent pieces of evidence:
         *
         *   network / shell / privilege
         *            +
         *   temporary file creation
         *            +
         *   modification of that same file
         *
         * This prevents ordinary /tmp activity from becoming
         * an alert by itself.
         */
        /*
         * Alert eligibility requires independent evidence.
         *
         * FILE evidence alone is never enough.
         *
         * Require:
         *
         *   FILE
         *     +
         *   at least two independent evidence categories
         *
         * This prevents repeated activity of one type from
         * artificially satisfying a correlation threshold.
         */
        if (!process->file_alert_emitted &&
            process->temporary_file_created &&
            process->temporary_file_written &&
            ks_evidence_has_all(
                &process->evidence_graph,
                KS_EVIDENCE_FILE
            ) &&
            ks_evidence_meets_minimum(
                &process->evidence_graph,
                3
            ) &&
            process->episode_score >= 50) {

            process->file_alert_emitted = true;

            emit_detection_alert(
                event,
                "correlated_file_drop",
                "correlation",
                severity_for_score(
                    process->episode_score
                ),
                "Alert Generated",
                "Temporary file creation and modification correlated with independent suspicious process behavior",
                "T1105",
                process->made_network_connection ? 1 : 0,
                "",
                0,
                process->episode_event_count
            );
        }

        return;
    }

    /*
     * ======================================================
     * PRIVILEGE
     * ======================================================
     */
    if (event->type == KS_EVENT_PRIVILEGE) {

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        ensure_episode(
            process,
            event->timestamp_ns
        );

        ks_evidence_add(
            &process->evidence_graph,
            KS_EVIDENCE_PRIVILEGE,
            event->timestamp_ns
        );

        process->last_activity_ns =
            event->timestamp_ns;

        process->privilege_event_count++;
        process->privilege_transition = true;
        process->last_privilege_ns =
            event->timestamp_ns;

        /*
         * Production privilege-escalation correlation.
         *
         * A privilege transition is common for legitimate tools
         * such as sudo, package managers, cron jobs and services.
         *
         * FILE evidence is deliberately NOT sufficient because
         * privileged programs normally access and create files.
         *
         * Require:
         *
         *     PRIVILEGE
         *        +
         *     NETWORK or SHELL or CHAIN
         *
         * and at least three independent evidence categories.
         */

        bool strong_privilege_context =
            ks_evidence_has(
                &process->evidence_graph,
                KS_EVIDENCE_NETWORK
            ) ||
            ks_evidence_has(
                &process->evidence_graph,
                KS_EVIDENCE_SHELL
            ) ||
            ks_evidence_has(
                &process->evidence_graph,
                KS_EVIDENCE_CHAIN
            );

        if (strong_privilege_context) {

            add_behavior_score(process, 25);
        }

        if (!process->privilege_alert_emitted &&
            strong_privilege_context &&
            ks_evidence_has_all(
                &process->evidence_graph,
                KS_EVIDENCE_PRIVILEGE
            ) &&
            ks_evidence_meets_minimum(
                &process->evidence_graph,
                3
            ) &&
            process->episode_score >= 70) {

            process->privilege_alert_emitted = true;

            emit_detection_alert(
                event,
                "privilege_transition",
                "behavioral",
                severity_for_score(
                    process->episode_score
                ),
                "Alert Generated",
                "Privilege transition correlated with independent network, shell, or multi-stage evidence",
                "T1548",
                process->made_network_connection ? 1 : 0,
                "",
                0,
                process->episode_event_count
            );
        }

        return;
    }

    /*
     * ======================================================
     * EXIT
     * ======================================================
     */
    if (event->type == KS_EVENT_EXIT) {

        ks_process *process =
            ks_process_find(event->pid);

        if (process) {

            process->last_activity_ns =
                event->timestamp_ns;

            ks_process_remove(event);
        }

        return;
    }
}

void ks_detector_shutdown(void)
{
    ks_alert_close();
}
