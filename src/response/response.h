#ifndef KS_RESPONSE_H
#define KS_RESPONSE_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    KS_RESPONSE_NONE = 0,
    KS_RESPONSE_LOG,
    KS_RESPONSE_TERMINATE
} ks_response_action;

/*
 * Decide whether a detection is strong enough for
 * automated containment.
 */
ks_response_action
ks_response_decide(
    uint32_t risk_score,
    uint32_t confidence,
    const char *severity
);

/*
 * Execute a response against a process.
 *
 * Returns true when the requested response succeeds.
 */
bool
ks_response_execute(
    uint32_t pid,
    ks_response_action action,
    uint32_t risk_score,
    uint32_t confidence,
    const char *reason
);

/*
 * Write an auditable response event.
 */
void
ks_response_log(
    uint32_t pid,
    const char *action,
    uint32_t risk_score,
    uint32_t confidence,
    const char *reason,
    const char *result
);

#endif
