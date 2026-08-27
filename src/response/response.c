#include "response.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#define KS_RESPONSE_LOG_PATH \
    "/var/log/kernelshield/responses.jsonl"

/*
 * Processes that must never be automatically terminated.
 */
static bool
ks_response_is_protected(uint32_t pid)
{
    if (pid == 0 || pid == 1)
        return true;

    /*
     * Protect the current KernelShield process.
     */
    if (pid == (uint32_t)getpid())
        return true;

    return false;
}

ks_response_action
ks_response_decide(
    uint32_t risk_score,
    uint32_t confidence,
    const char *severity
)
{
    if (!severity)
        return KS_RESPONSE_LOG;

    /*
     * Automatic containment is reserved for
     * high-confidence critical detections.
     */
    if (strcmp(severity, "critical") == 0 &&
        risk_score >= 85 &&
        confidence >= 85) {

        return KS_RESPONSE_TERMINATE;
    }

    return KS_RESPONSE_LOG;
}

void
ks_response_log(
    uint32_t pid,
    const char *action,
    uint32_t risk_score,
    uint32_t confidence,
    const char *reason,
    const char *result
)
{
    FILE *fp;
    struct timespec ts;

    fp = fopen(
        KS_RESPONSE_LOG_PATH,
        "a"
    );

    if (!fp)
        return;

    clock_gettime(
        CLOCK_REALTIME,
        &ts
    );

    fprintf(
        fp,
        "{\"timestamp_ns\":%lld,"
        "\"pid\":%u,"
        "\"action\":\"%s\","
        "\"risk_score\":%u,"
        "\"confidence\":%u,"
        "\"reason\":\"%s\","
        "\"result\":\"%s\"}\n",
        (long long)ts.tv_sec * 1000000000LL +
            ts.tv_nsec,
        pid,
        action ? action : "unknown",
        risk_score,
        confidence,
        reason ? reason : "unknown",
        result ? result : "unknown"
    );

    fclose(fp);
}

bool
ks_response_execute(
    uint32_t pid,
    ks_response_action action,
    uint32_t risk_score,
    uint32_t confidence,
    const char *reason
)
{
    if (action == KS_RESPONSE_NONE)
        return true;

    if (action == KS_RESPONSE_LOG) {

        ks_response_log(
            pid,
            "log",
            risk_score,
            confidence,
            reason,
            "recorded"
        );

        return true;
    }

    if (action == KS_RESPONSE_TERMINATE) {

        if (ks_response_is_protected(pid)) {

            ks_response_log(
                pid,
                "terminate",
                risk_score,
                confidence,
                reason,
                "blocked_protected_process"
            );

            return false;
        }

        /*
         * Graceful termination first.
         */
        if (kill(
                (pid_t)pid,
                SIGTERM
            ) == 0) {

            ks_response_log(
                pid,
                "terminate",
                risk_score,
                confidence,
                reason,
                "SIGTERM_sent"
            );

            return true;
        }

        ks_response_log(
            pid,
            "terminate",
            risk_score,
            confidence,
            reason,
            strerror(errno)
        );

        return false;
    }

    return false;
}
