#include <stdio.h>
#include <string.h>

#include "attack_episode.h"
#include "process_table.h"

#define KS_EPISODE_WINDOW_NS (60ULL * 1000000000ULL)

#define EVIDENCE_EXEC       (1U << 0)
#define EVIDENCE_NETWORK    (1U << 1)
#define EVIDENCE_FILE       (1U << 2)
#define EVIDENCE_PRIVILEGE  (1U << 3)
#define EVIDENCE_SHELL      (1U << 4)

static ks_attack_episode episodes[KS_MAX_ATTACK_EPISODES];
static uint32_t next_episode_id = 1;


static bool is_shell(const char *comm)
{
    return strcmp(comm, "bash") == 0 ||
           strcmp(comm, "sh") == 0 ||
           strcmp(comm, "dash") == 0 ||
           strcmp(comm, "zsh") == 0;
}


const char *ks_attack_stage_name(
    ks_attack_stage stage
)
{
    switch (stage) {

    case KS_STAGE_INITIAL_EXECUTION:
        return "initial_execution";

    case KS_STAGE_SUSPICIOUS_SPAWN:
        return "suspicious_spawn";

    case KS_STAGE_COMMAND_EXECUTION:
        return "command_execution";

    case KS_STAGE_NETWORK_ACTIVITY:
        return "network_activity";

    case KS_STAGE_PAYLOAD_ACTIVITY:
        return "payload_activity";

    case KS_STAGE_PRIVILEGE_ESCALATION:
        return "privilege_escalation";

    case KS_STAGE_IMPACT:
        return "impact";

    default:
        return "unknown";
    }
}


static ks_attack_episode *find_episode(
    uint32_t pid,
    uint32_t ppid,
    uint64_t timestamp
)
{
    /*
     * First check direct process continuation and
     * direct parent-child relationship using the
     * event's PPID.
     */
    for (int i = 0; i < KS_MAX_ATTACK_EPISODES; i++) {

        ks_attack_episode *episode =
            &episodes[i];

        if (!episode->active ||
            episode->closed)
            continue;

        if (timestamp >
            episode->last_event_ns +
            KS_EPISODE_WINDOW_NS)
            continue;

        /*
         * Same process continues the episode.
         */
        if (episode->last_pid == pid ||
            episode->root_pid == pid)
            return episode;

        /*
         * Direct child of the episode's current
         * or root process.
         */
        if (ppid != 0 &&
            (episode->last_pid == ppid ||
             episode->root_pid == ppid))
            return episode;
    }

    /*
     * If no direct relationship was found, walk the
     * known process lineage for deeper descendants.
     */
    ks_process *process =
        ks_process_find(pid);

    int depth = 0;

    while (process && depth < 8) {

        for (int i = 0;
             i < KS_MAX_ATTACK_EPISODES;
             i++) {

            ks_attack_episode *episode =
                &episodes[i];

            if (!episode->active ||
                episode->closed)
                continue;

            if (timestamp >
                episode->last_event_ns +
                KS_EPISODE_WINDOW_NS)
                continue;

            if (process->pid ==
                episode->root_pid ||
                process->ppid ==
                episode->root_pid) {

                return episode;
            }
        }

        process =
            ks_process_find(process->ppid);

        depth++;
    }

    return NULL;
}


static ks_attack_episode *create_episode(
    const struct ks_event *event
)
{
    for (int i = 0;
         i < KS_MAX_ATTACK_EPISODES;
         i++) {

        if (episodes[i].active)
            continue;

        ks_attack_episode *episode =
            &episodes[i];

        memset(
            episode,
            0,
            sizeof(*episode)
        );

        episode->active = true;

        episode->id =
            next_episode_id++;

        /*
         * The episode root is the process that generated
         * the first relevant event.
         *
         * Do NOT automatically use PPID as the root.
         * Otherwise unrelated system processes sharing a
         * common ancestor such as PID 1 can collapse into
         * one giant episode.
         */
        episode->root_pid =
            event->pid;

        episode->last_pid =
            event->pid;

        episode->start_ns =
            event->timestamp_ns;

        episode->last_event_ns =
            event->timestamp_ns;

        episode->current_stage =
            KS_STAGE_INITIAL_EXECUTION;

        strncpy(
            episode->root_process,
            event->comm,
            TASK_COMM_LEN - 1
        );

        return episode;
    }

    return NULL;
}


static void update_stage(
    ks_attack_episode *episode,
    ks_attack_stage stage,
    uint64_t timestamp
)
{
    if (stage <= episode->current_stage)
        return;

    episode->previous_stage_ns =
        episode->last_event_ns;

    episode->current_stage =
        stage;

    if (episode->previous_stage_ns > 0 &&
        timestamp >
        episode->previous_stage_ns) {

        episode->escalation_velocity_ns =
            timestamp -
            episode->previous_stage_ns;
    }
}


static void predict_next_stage(
    ks_attack_episode *episode
)
{
    switch (episode->current_stage) {

    case KS_STAGE_SUSPICIOUS_SPAWN:
        episode->predicted_next_stage =
            KS_STAGE_COMMAND_EXECUTION;
        break;

    case KS_STAGE_COMMAND_EXECUTION:
        episode->predicted_next_stage =
            KS_STAGE_NETWORK_ACTIVITY;
        break;

    case KS_STAGE_NETWORK_ACTIVITY:
        episode->predicted_next_stage =
            KS_STAGE_PAYLOAD_ACTIVITY;
        break;

    case KS_STAGE_PAYLOAD_ACTIVITY:
        episode->predicted_next_stage =
            KS_STAGE_PRIVILEGE_ESCALATION;
        break;

    case KS_STAGE_PRIVILEGE_ESCALATION:
        episode->predicted_next_stage =
            KS_STAGE_IMPACT;
        break;

    default:
        episode->predicted_next_stage =
            KS_STAGE_UNKNOWN;
        break;
    }
}


static void apply_event(
    ks_attack_episode *episode,
    const struct ks_event *event
)
{
    episode->event_count++;

    episode->last_pid =
        event->pid;

    episode->last_event_ns =
        event->timestamp_ns;

    strncpy(
        episode->last_process,
        event->comm,
        TASK_COMM_LEN - 1
    );

    switch (event->type) {

    case KS_EVENT_EXEC:

        episode->evidence_mask |=
            EVIDENCE_EXEC;

        episode->score += 5;

        if (episode->score > 100)
            episode->score = 100;

        if (is_shell(event->comm)) {

            episode->evidence_mask |=
                EVIDENCE_SHELL;

            episode->score += 15;

            update_stage(
                episode,
                KS_STAGE_COMMAND_EXECUTION,
                event->timestamp_ns
            );

        } else {

            update_stage(
                episode,
                KS_STAGE_SUSPICIOUS_SPAWN,
                event->timestamp_ns
            );
        }

        break;


    case KS_EVENT_NETWORK:

        /*
         * Network activity is common for browsers, DNS resolvers
         * and other normal applications. Count network evidence
         * once per episode so repeated connections cannot inflate
         * the risk score indefinitely.
         */
        if (!(episode->evidence_mask & EVIDENCE_NETWORK)) {

            episode->evidence_mask |=
                EVIDENCE_NETWORK;

            episode->score += 20;
        }

        update_stage(
            episode,
            KS_STAGE_NETWORK_ACTIVITY,
            event->timestamp_ns
        );

        break;


    case KS_EVENT_FILE:

        /*
         * File activity alone is common during normal application
         * behavior. Treat it as payload evidence only when the
         * episode already contains shell or network activity.
         *
         * Count this evidence once per episode so browser caches,
         * databases and repeated application writes cannot push
         * the risk score to 100.
         */
        if (event->file_operation ==
                KS_FILE_WRITE ||
            event->file_operation ==
                KS_FILE_CREATE ||
            event->file_operation ==
                KS_FILE_RENAME ||
            event->file_operation ==
                KS_FILE_DELETE) {

            if ((episode->evidence_mask &
                    (EVIDENCE_SHELL |
                     EVIDENCE_NETWORK)) &&
                !(episode->evidence_mask &
                    EVIDENCE_FILE)) {

                episode->evidence_mask |=
                    EVIDENCE_FILE;

                episode->score += 10;

                update_stage(
                    episode,
                    KS_STAGE_PAYLOAD_ACTIVITY,
                    event->timestamp_ns
                );
            }
        }

        break;

    case KS_EVENT_PRIVILEGE:

        /*
         * Privilege activity can occur repeatedly during normal
         * service and authentication behavior. Count privilege
         * evidence only once per episode, just like network and
         * file evidence, so repeated events cannot independently
         * drive an episode to critical severity.
         */
        if (!(episode->evidence_mask & EVIDENCE_PRIVILEGE)) {

            episode->evidence_mask |=
                EVIDENCE_PRIVILEGE;

            episode->score += 30;

            update_stage(
                episode,
                KS_STAGE_PRIVILEGE_ESCALATION,
                event->timestamp_ns
            );
        }

        break;


    default:
        break;
    }

    /*
     * High-confidence destructive behavior.
     */
    if ((episode->evidence_mask &
            EVIDENCE_FILE) &&
        (event->file_operation ==
            KS_FILE_RENAME ||
         event->file_operation ==
            KS_FILE_DELETE)) {

        update_stage(
            episode,
            KS_STAGE_IMPACT,
            event->timestamp_ns
        );

        episode->score += 25;
    }

    /*
     * Episode score is bounded so repetitive activity cannot
     * inflate risk indefinitely.
     */
    if (episode->score > 100)
        episode->score = 100;

    if (episode->score >= 70 ||
        episode->current_stage ==
            KS_STAGE_PRIVILEGE_ESCALATION ||
        episode->current_stage ==
            KS_STAGE_IMPACT) {

        episode->containment_recommended =
            true;
    }

    if (episode->score > 100)
        episode->score = 100;

    predict_next_stage(episode);
}


void ks_attack_episode_init(void)
{
    memset(
        episodes,
        0,
        sizeof(episodes)
    );

    next_episode_id = 1;
}



/*
 * Episode admission control.
 *
 * Not every kernel event represents suspicious activity. File and
 * network activity are extremely common during normal application
 * execution, so they must not independently create an attack episode.
 *
 * An episode is admitted only when there is an initial execution or
 * privilege-related signal with sufficient security relevance.
 */
static bool should_start_episode(
    const struct ks_event *event
)
{
    if (!event)
        return false;

    switch (event->type) {

    case KS_EVENT_EXEC:

        /*
         * A shell represents an execution context capable of launching
         * a command chain. Allow it to establish an episode root.
         */
        if (is_shell(event->comm))
            return true;

        /*
         * Processes spawned from an already tracked lineage will be
         * correlated later by find_episode(). For standalone processes,
         * only admit commands already classified as suspicious by the
         * existing rule/correlation layer.
         *
         * The current implementation uses common command-line utilities
         * as low-confidence execution signals.
         */
        if (strcmp(event->comm, "curl") == 0 ||
            strcmp(event->comm, "wget") == 0 ||
            strcmp(event->comm, "nc") == 0 ||
            strcmp(event->comm, "ncat") == 0 ||
            strcmp(event->comm, "python") == 0 ||
            strcmp(event->comm, "python3") == 0)
            return true;

        return false;

    case KS_EVENT_PRIVILEGE:

        /*
         * A privilege event alone must not automatically create an
         * attack episode. Legitimate sudo and authentication activity
         * would otherwise create false positives.
         *
         * Privilege escalation can still contribute evidence to an
         * already-established suspicious process lineage.
         */
        return false;

    /*
     * Network and file events are evidence, not episode roots.
     * They can strengthen an existing correlated episode but cannot
     * create one by themselves.
     */
    case KS_EVENT_NETWORK:
    case KS_EVENT_FILE:
    case KS_EVENT_EXIT:
    default:
        return false;
    }
}


ks_attack_episode *ks_attack_episode_process_event(
    const struct ks_event *event
)
{
    if (!event)
        return NULL;

    /*
     * Exit events provide lifecycle information only.
     * They must never create or extend an attack episode.
     */
    if (event->type == KS_EVENT_EXIT)
        return NULL;

    /*
     * First attempt to correlate the event with an existing episode.
     *
     * This allows file and network activity from child processes to
     * contribute evidence without independently creating episodes.
     */
    ks_attack_episode *episode =
        find_episode(
            event->pid,
            event->ppid,
            event->timestamp_ns
        );

    /*
     * No existing lineage was found.
     *
     * Apply admission control before allocating a new attack episode.
     * This prevents ordinary browser, system and application activity
     * from polluting the attack correlation engine.
     */
    if (!episode) {

        if (!should_start_episode(event))
            return NULL;

        episode = create_episode(event);

        if (!episode)
            return NULL;
    }

    apply_event(
        episode,
        event
    );

    return episode;
}


void ks_attack_episode_print(
    const ks_attack_episode *episode
)
{
    if (!episode)
        return;

    /*
     * Ignore harmless low-risk activity.
     */
    if (episode->score < 20 &&
        episode->current_stage ==
        KS_STAGE_INITIAL_EXECUTION) {
        return;
    }

    printf(
        "\n"
        "========== KERNELSHIELD ATTACK UPDATE ==========\n"
        "Episode ID       : KS-%06u\n"
        "Root PID         : %u\n"
        "Current PID      : %u\n"
        "Events Seen      : %u\n"
        "Risk Score       : %d/100\n"
        "Current Stage    : %s\n"
        "Predicted Next   : %s\n"
        "Containment      : %s\n"
        "================================================\n\n",

        episode->id,
        episode->root_pid,
        episode->last_pid,
        episode->event_count,
        episode->score,

        ks_attack_stage_name(
            episode->current_stage
        ),

        ks_attack_stage_name(
            episode->predicted_next_stage
        ),

        episode->containment_recommended ?
        "RECOMMENDED" :
        "MONITOR"
    );
}
