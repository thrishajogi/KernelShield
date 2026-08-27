#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "ks_alert.h"
#include "../response/response.h"

#define KS_ALERT_JSONL_PATH "/var/log/kernelshield/alerts.jsonl"

/*
 * Final alert deduplication window.
 *
 * This is a defense-in-depth barrier against duplicate delivery
 * of the same detection event. It does not replace behavioral
 * correlation guards.
 */
#define KS_ALERT_DEDUP_WINDOW_NS 1000000000ULL

typedef struct {
    uint32_t pid;
    uint64_t timestamp_ns;
    char attack_type[KS_ALERT_ATTACK_TYPE_LEN];
    char reason[KS_ALERT_REASON_LEN];
    bool valid;
} ks_alert_dedup_entry;

static FILE *alert_fp = NULL;
static ks_alert_dedup_entry last_alert;

int ks_alert_init(void)
{
    if (alert_fp)
        return 0;

    alert_fp = fopen(KS_ALERT_JSONL_PATH, "a");

    if (!alert_fp)
        return -1;

    setvbuf(alert_fp, NULL, _IOLBF, 0);

    return 0;
}

void ks_alert_close(void)
{
    if (!alert_fp)
        return;

    fflush(alert_fp);
    fclose(alert_fp);

    alert_fp = NULL;
}

static void json_escape(
    const char *src,
    char *dst,
    size_t dst_size)
{
    size_t j = 0;

    if (!src || !dst || dst_size == 0)
        return;

    for (size_t i = 0;
         src[i] != '\0' && j + 2 < dst_size;
         i++) {

        unsigned char c =
            (unsigned char)src[i];

        switch (c) {

        case '"':
            dst[j++] = '\\';
            dst[j++] = '"';
            break;

        case '\\':
            dst[j++] = '\\';
            dst[j++] = '\\';
            break;

        case '\n':
            dst[j++] = '\\';
            dst[j++] = 'n';
            break;

        case '\r':
            dst[j++] = '\\';
            dst[j++] = 'r';
            break;

        case '\t':
            dst[j++] = '\\';
            dst[j++] = 't';
            break;

        default:
            if (c >= 0x20)
                dst[j++] = c;
            break;
        }
    }

    dst[j] = '\0';
}

static bool ks_alert_is_duplicate(
    const ks_alert *alert)
{
    if (!alert || !last_alert.valid)
        return false;

    if (alert->pid != last_alert.pid)
        return false;

    if (strcmp(
            alert->attack_type,
            last_alert.attack_type
        ) != 0)
        return false;

    if (strcmp(
            alert->reason,
            last_alert.reason
        ) != 0)
        return false;

    if (alert->timestamp_ns <
        last_alert.timestamp_ns)
        return false;

    return (alert->timestamp_ns -
            last_alert.timestamp_ns)
        <= KS_ALERT_DEDUP_WINDOW_NS;
}

static void ks_alert_remember(
    const ks_alert *alert)
{
    if (!alert)
        return;

    last_alert.pid =
        alert->pid;

    last_alert.timestamp_ns =
        alert->timestamp_ns;

    strncpy(
        last_alert.attack_type,
        alert->attack_type,
        sizeof(last_alert.attack_type) - 1
    );

    last_alert.attack_type[
        sizeof(last_alert.attack_type) - 1
    ] = '\0';

    strncpy(
        last_alert.reason,
        alert->reason,
        sizeof(last_alert.reason) - 1
    );

    last_alert.reason[
        sizeof(last_alert.reason) - 1
    ] = '\0';

    last_alert.valid = true;
}

int ks_alert_write(const ks_alert *alert)
{
    if (!alert)
        return -1;

    if (ks_alert_is_duplicate(alert))
        return 0;

    if (!alert_fp) {
        if (ks_alert_init() != 0)
            return -1;
    }

    char process_name[KS_ALERT_PROCESS_LEN * 2];
    char parent_name[KS_ALERT_PROCESS_LEN * 2];
    char attack_type[KS_ALERT_ATTACK_TYPE_LEN * 2];
    char alert_type[KS_ALERT_ALERT_TYPE_LEN * 2];
    char severity[KS_ALERT_SEVERITY_LEN * 2];
    char action_taken[64];
    char reason[KS_ALERT_REASON_LEN * 2];
    char mitre[KS_ALERT_MITRE_LEN * 2];
    char destination_ip[KS_ALERT_IP_LEN * 2];

    json_escape(alert->process_name,
                process_name,
                sizeof(process_name));

    json_escape(alert->parent_name,
                parent_name,
                sizeof(parent_name));

    json_escape(alert->attack_type,
                attack_type,
                sizeof(attack_type));

    json_escape(alert->alert_type,
                alert_type,
                sizeof(alert_type));

    json_escape(alert->severity,
                severity,
                sizeof(severity));

    json_escape(alert->action_taken,
            action_taken,
            sizeof(action_taken));

    json_escape(alert->reason,
                reason,
                sizeof(reason));

    json_escape(alert->mitre_technique,
                mitre,
                sizeof(mitre));

    json_escape(alert->destination_ip,
                destination_ip,
                sizeof(destination_ip));

    fprintf(
        alert_fp,
        "{"
        "\"schema_version\":%u,"
        "\"timestamp_ns\":%llu,"
        "\"pid\":%u,"
        "\"ppid\":%u,"
        "\"uid\":%u,"
        "\"gid\":%u,"
        "\"process_name\":\"%s\","
        "\"parent_name\":\"%s\","
        "\"attack_type\":\"%s\","
        "\"alert_type\":\"%s\","
        "\"severity\":\"%s\","
        "\"action_taken\":\"%s\","
        "\"reason\":\"%s\","
        "\"mitre_technique\":\"%s\","
        "\"has_network\":%u,"
        "\"destination_ip\":\"%s\","
        "\"destination_port\":%u,"
        "\"event_count\":%u,"
        "\"risk_score\":%u,"
        "\"confidence\":%u"
        "}\n",

        alert->schema_version,
        (unsigned long long)alert->timestamp_ns,

        alert->pid,
        alert->ppid,
        alert->uid,
        alert->gid,

        process_name,
        parent_name,

        attack_type,
        alert_type,
        severity,
        action_taken,

        reason,
        mitre,

        alert->has_network,
        destination_ip,
        alert->destination_port,

        alert->event_count,
        alert->risk_score,
        alert->confidence
    );

    fflush(alert_fp);

    if (ferror(alert_fp))
        return -1;

    /*
     * Remember only successfully persisted alerts.
     */
    ks_alert_remember(alert);

    /*
     * Automated response is intentionally executed only
     * after the detection alert has been successfully
     * persisted.
     *
     * This preserves the forensic record even if the
     * containment action changes process state.
     */
    ks_response_action action =
        ks_response_decide(
            alert->risk_score,
            alert->confidence,
            alert->severity
        );

    if (action != KS_RESPONSE_NONE) {

        ks_response_execute(
            alert->pid,
            action,
            alert->risk_score,
            alert->confidence,
            alert->reason
        );
    }

    return 0;
}
