#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

#include "ks_alert.h"

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(
        CLOCK_REALTIME,
        &ts
    );

    return
        (uint64_t)ts.tv_sec *
        1000000000ULL +
        (uint64_t)ts.tv_nsec;
}

int main(void)
{
    printf(
        "[TEST] KernelShield alert -> response integration\n"
    );

    /*
     * Spawn a completely harmless process that can safely
     * be used to validate automated containment.
     */
    pid_t child = fork();

    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {

        execl(
            "/bin/sleep",
            "sleep",
            "60",
            NULL
        );

        perror("execl");
        return 1;
    }

    printf(
        "[TEST] harmless child PID=%d\n",
        child
    );

    sleep(1);

    ks_alert alert;

    memset(
        &alert,
        0,
        sizeof(alert)
    );

    alert.schema_version =
        KS_ALERT_SCHEMA_VERSION;

    alert.timestamp_ns =
        now_ns();

    alert.pid =
        (uint32_t)child;

    alert.ppid =
        (uint32_t)getpid();

    alert.uid =
        (uint32_t)getuid();

    alert.gid =
        (uint32_t)getgid();

    strncpy(
        alert.process_name,
        "sleep",
        sizeof(alert.process_name) - 1
    );

    strncpy(
        alert.parent_name,
        "alert_response_test",
        sizeof(alert.parent_name) - 1
    );

    strncpy(
        alert.attack_type,
        "integration_test",
        sizeof(alert.attack_type) - 1
    );

    strncpy(
        alert.alert_type,
        "behavioral",
        sizeof(alert.alert_type) - 1
    );

    strncpy(
        alert.severity,
        "critical",
        sizeof(alert.severity) - 1
    );

    strncpy(
        alert.reason,
        "controlled alert-response integration validation",
        sizeof(alert.reason) - 1
    );

    strncpy(
        alert.mitre_technique,
        "TEST",
        sizeof(alert.mitre_technique) - 1
    );

    alert.has_network = 0;

    alert.event_count = 5;

    /*
     * These values intentionally cross the automated
     * containment threshold:
     *
     * critical
     * risk >= 85
     * confidence >= 85
     */
    alert.risk_score = 90;
    alert.confidence = 95;

    printf(
        "[TEST] writing critical alert "
        "(risk=%u confidence=%u)\n",
        alert.risk_score,
        alert.confidence
    );

    if (ks_alert_write(&alert) != 0) {

        fprintf(
            stderr,
            "[FAIL] ks_alert_write failed\n"
        );

        kill(
            child,
            SIGTERM
        );

        return 1;
    }

    ks_alert_close();

    int status;

    if (waitpid(
            child,
            &status,
            0
        ) < 0) {

        perror("waitpid");
        return 1;
    }

    if (WIFSIGNALED(status)) {

        printf(
            "[PASS] automated response "
            "terminated child with signal %d\n",
            WTERMSIG(status)
        );

    } else {

        printf(
            "[FAIL] child was not terminated "
            "by automated response\n"
        );

        return 1;
    }

    printf(
        "[RESULT] full alert -> response "
        "integration test passed\n"
    );

    return 0;
}
