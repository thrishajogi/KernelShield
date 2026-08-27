#include <stdio.h>
#include <stdbool.h>

#include "response.h"

int main(void)
{
    ks_response_action action =
        ks_response_decide(
            90,
            95,
            "critical"
        );

    printf(
        "[TEST] action=%d (expected %d = TERMINATE)\n",
        action,
        KS_RESPONSE_TERMINATE
    );

    bool result =
        ks_response_execute(
            1,
            action,
            90,
            95,
            "protected process safety validation"
        );

    printf(
        "[TEST] protected PID=1 result=%s\n",
        result ? "unexpected_success" : "blocked"
    );

    if (!result) {
        printf(
            "[PASS] protected process was not terminated\n"
        );
        return 0;
    }

    printf(
        "[FAIL] protected process safety failed\n"
    );

    return 1;
}
