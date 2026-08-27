#include <stdio.h>
#include <string.h>

#include "process_table.h"

static ks_process process_table[KS_MAX_PROCESSES];

static int find_slot(uint32_t pid)
{
    for (int i = 0; i < KS_MAX_PROCESSES; i++) {

        if (process_table[i].active &&
            process_table[i].pid == pid) {

            return i;
        }
    }

    return -1;
}

static int find_free_slot(void)
{
    for (int i = 0; i < KS_MAX_PROCESSES; i++) {

        if (!process_table[i].active)
            return i;
    }

    return -1;
}

void ks_process_table_init(void)
{
    memset(process_table, 0, sizeof(process_table));
}

void ks_process_add(const struct ks_event *event)
{
    if (!event)
        return;

    int slot = find_slot(event->pid);

    /*
     * Existing PID means the process performed another exec().
     *
     * Preserve the previous executable so the detector can
     * reason about execution transitions.
     */
    if (slot >= 0) {

        ks_process *p = &process_table[slot];

        strncpy(
            p->previous_comm,
            p->comm,
            sizeof(p->previous_comm) - 1
        );

        p->previous_comm[
            sizeof(p->previous_comm) - 1
        ] = '\0';

        strncpy(
            p->previous_filename,
            p->filename,
            sizeof(p->previous_filename) - 1
        );

        p->previous_filename[
            sizeof(p->previous_filename) - 1
        ] = '\0';

        p->exec_count++;

        /*
         * Continue the current behavioral episode.
         * Episode rollover is handled by the correlator when
         * activity falls outside the temporal window.
         */
        p->episode_last_event_ns = event->timestamp_ns;
        p->episode_event_count++;

        p->ppid = event->ppid;
        p->uid = event->uid;
        p->gid = event->gid;

        p->last_activity_ns = event->timestamp_ns;
        p->last_exec_ns = event->timestamp_ns;

        strncpy(
            p->comm,
            event->comm,
            sizeof(p->comm) - 1
        );

        p->comm[sizeof(p->comm) - 1] = '\0';

        if (event->filename[0] != '\0') {

            strncpy(
                p->filename,
                event->filename,
                sizeof(p->filename) - 1
            );

            p->filename[
                sizeof(p->filename) - 1
            ] = '\0';
        }

        return;
    }

    /*
     * New process.
     */
    slot = find_free_slot();

    if (slot < 0)
        return;

    ks_process *p = &process_table[slot];

    memset(p, 0, sizeof(*p));

    p->active = true;

    p->pid = event->pid;
    p->ppid = event->ppid;

    p->uid = event->uid;
    p->gid = event->gid;

    p->start_time_ns = event->timestamp_ns;
    p->last_activity_ns = event->timestamp_ns;
    p->last_exec_ns = event->timestamp_ns;

    p->exec_count = 1;

    /*
     * Start the first behavioral episode with the process.
     */
    p->episode_id = 1;
    p->episode_start_ns = event->timestamp_ns;
    p->episode_last_event_ns = event->timestamp_ns;
    p->episode_event_count = 1;
    p->episode_score = 0;

    strncpy(
        p->comm,
        event->comm,
        sizeof(p->comm) - 1
    );

    p->comm[sizeof(p->comm) - 1] = '\0';

    strncpy(
        p->filename,
        event->filename,
        sizeof(p->filename) - 1
    );

    p->filename[sizeof(p->filename) - 1] = '\0';
}

void ks_process_remove(const struct ks_event *event)
{
    if (!event)
        return;

    int slot = find_slot(event->pid);

    if (slot < 0)
        return;

    process_table[slot].end_time_ns =
        event->timestamp_ns;

    process_table[slot].last_activity_ns =
        event->timestamp_ns;

    process_table[slot].active = false;
}

ks_process *ks_process_find(uint32_t pid)
{
    int slot = find_slot(pid);

    if (slot < 0)
        return NULL;

    return &process_table[slot];
}

void ks_process_table_print(void)
{
    printf("\n");
    printf("========== KernelShield Behavioral State ==========\n");

    for (int i = 0; i < KS_MAX_PROCESSES; i++) {

        ks_process *p = &process_table[i];

        if (!p->active)
            continue;

        printf(
            "PID=%u PPID=%u COMM=%s "
            "EXEC=%u NET=%u WRITE=%u CREATE=%u PRIV=%u "
            "SCORE=%d\n",
            p->pid,
            p->ppid,
            p->comm,
            p->exec_count,
            p->network_count,
            p->file_write_count,
            p->file_create_count,
            p->privilege_event_count,
            p->behavioral_score
        );
    }

    printf("===================================================\n");
}
