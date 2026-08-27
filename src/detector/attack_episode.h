#ifndef KS_ATTACK_EPISODE_H
#define KS_ATTACK_EPISODE_H

#include <stdbool.h>
#include <stdint.h>

#include "../../include/ks_event.h"

#define KS_MAX_ATTACK_EPISODES 256

typedef enum {
    KS_STAGE_UNKNOWN = 0,
    KS_STAGE_INITIAL_EXECUTION,
    KS_STAGE_SUSPICIOUS_SPAWN,
    KS_STAGE_COMMAND_EXECUTION,
    KS_STAGE_NETWORK_ACTIVITY,
    KS_STAGE_PAYLOAD_ACTIVITY,
    KS_STAGE_PRIVILEGE_ESCALATION,
    KS_STAGE_IMPACT
} ks_attack_stage;

typedef struct {
    bool active;

    uint32_t id;

    uint32_t root_pid;
    uint32_t last_pid;

    uint64_t start_ns;
    uint64_t last_event_ns;

    uint32_t event_count;

    uint32_t evidence_mask;
    int score;

    ks_attack_stage current_stage;
    ks_attack_stage predicted_next_stage;

    uint64_t previous_stage_ns;
    uint64_t escalation_velocity_ns;

    bool containment_recommended;
    bool containment_announced;
    bool closed;

    char root_process[TASK_COMM_LEN];
    char last_process[TASK_COMM_LEN];

} ks_attack_episode;

void ks_attack_episode_init(void);

ks_attack_episode *ks_attack_episode_process_event(
    const struct ks_event *event
);

void ks_attack_episode_print(
    const ks_attack_episode *episode
);

const char *ks_attack_stage_name(
    ks_attack_stage stage
);

#endif
