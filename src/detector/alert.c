#include <stdio.h>
#include <string.h>

#include "ks_alert.h"

#define KS_ALERT_JSONL_PATH "/tmp/kernelshield-alerts.jsonl"

static FILE *alert_fp = NULL;

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

int ks_alert_write(const ks_alert *alert)
{
    if (!alert)
        return -1;

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
        "\"event_count\":%u"
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

        alert->event_count
    );

    fflush(alert_fp);

    return ferror(alert_fp) ? -1 : 0;
}
