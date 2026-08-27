#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include "response.h"

int main(void)
{
    /*
     * TEST 1:
     * Medium-confidence detection.
     * Must choose LOG only.
     */
    ks_response_action action1 =
        ks_response_decide(
            70,
            70,
            "high"
        );

    printf(
        "[TEST 1] action=%d (expected %d = LOG)\n",
        action1,
        KS_RESPONSE_LOG
    );

    ks_response_execute(
        999999,
        action1,
        70,
        70,
        "response self-test log-only"
    );

    /*
     * TEST 2:
     * Spawn a harmless child process.
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
        "[TEST 2] harmless child PID=%d\n",
        child
    );

    sleep(1);

    /*
     * High-confidence critical detection.
     * Must choose TERMINATE.
     */
    ks_response_action action2 =
        ks_response_decide(
            90,
            95,
            "critical"
        );

    printf(
        "[TEST 2] action=%d (expected %d = TERMINATE)\n",
        action2,
        KS_RESPONSE_TERMINATE
    );

    bool result =
        ks_response_execute(
            (uint32_t)child,
            action2,
            90,
            95,
            "response self-test containment"
        );

    printf(
        "[TEST 2] containment result=%s\n",
        result ? "success" : "failure"
    );

    int status;

    waitpid(
        child,
        &status,
        0
    );

    if (WIFSIGNALED(status)) {

        printf(
            "[TEST 2] child terminated by signal %d\n",
            WTERMSIG(status)
        );
    }

    printf(
        "[RESULT] automated response self-test completed\n"
    );

    return 0;
}
