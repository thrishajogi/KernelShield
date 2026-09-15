#ifndef KS_ALERT_H
#define KS_ALERT_H

#include <stdint.h>

#define KS_ALERT_SCHEMA_VERSION 2

#define KS_ALERT_PROCESS_LEN 64
#define KS_ALERT_ATTACK_TYPE_LEN 64
#define KS_ALERT_ALERT_TYPE_LEN 32
#define KS_ALERT_SEVERITY_LEN 16
#define KS_ALERT_REASON_LEN 256
#define KS_ALERT_MITRE_LEN 32
#define KS_ALERT_IP_LEN 46

typedef struct ks_alert {

    uint32_t schema_version;

    uint64_t timestamp_ns;

    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;

    char process_name[KS_ALERT_PROCESS_LEN];
    char parent_name[KS_ALERT_PROCESS_LEN];

    char attack_type[KS_ALERT_ATTACK_TYPE_LEN];
    char alert_type[KS_ALERT_ALERT_TYPE_LEN];
    char severity[KS_ALERT_SEVERITY_LEN];
    char action_taken[32];

    char reason[KS_ALERT_REASON_LEN];

    char mitre_technique[KS_ALERT_MITRE_LEN];

    uint8_t has_network;

    char destination_ip[KS_ALERT_IP_LEN];

    uint16_t destination_port;

    uint32_t event_count;

    /*
     * Behavioral risk metrics.
     *
     * risk_score:
     *   0-100 accumulated behavioral evidence.
     *
     * confidence:
     *   0-100 confidence derived from correlated evidence.
     */
    uint16_t risk_score;
    uint16_t confidence;

} ks_alert;

int ks_alert_init(void);

void ks_alert_close(void);

int ks_alert_write(const ks_alert *alert);

#endif
