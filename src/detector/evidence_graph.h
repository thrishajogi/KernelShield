#ifndef KERNELSHIELD_EVIDENCE_GRAPH_H
#define KERNELSHIELD_EVIDENCE_GRAPH_H

#include <stdint.h>
#include <stdbool.h>

/*
 * Independent behavioral evidence observed during a process
 * episode.
 *
 * This is intentionally separate from the risk score.
 * The score answers "how severe".
 * Evidence diversity answers "how much independent proof".
 */
typedef enum {
    KS_EVIDENCE_NONE       = 0,
    KS_EVIDENCE_EXECUTION  = 1 << 0,
    KS_EVIDENCE_NETWORK    = 1 << 1,
    KS_EVIDENCE_FILE       = 1 << 2,
    KS_EVIDENCE_SHELL      = 1 << 3,
    KS_EVIDENCE_PRIVILEGE  = 1 << 4,
    KS_EVIDENCE_CHAIN      = 1 << 5
} ks_evidence_type;

/*
 * Compact evidence state.
 *
 * Stored per process episode.
 */
typedef struct {
    uint32_t mask;

    uint64_t first_evidence_ns;
    uint64_t last_evidence_ns;

    uint32_t evidence_events;
} ks_evidence_graph;

/*
 * Add evidence to the current process episode.
 */
void ks_evidence_add(
    ks_evidence_graph *graph,
    ks_evidence_type evidence,
    uint64_t timestamp_ns
);

/*
 * Reset evidence when a new process episode begins.
 */
void ks_evidence_reset(
    ks_evidence_graph *graph
);

/*
 * Number of independent evidence categories.
 */
uint32_t ks_evidence_diversity(
    const ks_evidence_graph *graph
);

/*
 * Calculate confidence from independent evidence diversity.
 *
 * Confidence is deliberately separate from risk scoring.
 */
uint32_t ks_evidence_confidence(
    const ks_evidence_graph *graph,
    uint32_t episode_score
);

/*
 * Check whether an evidence category exists.
 */
bool ks_evidence_has(
    const ks_evidence_graph *graph,
    ks_evidence_type evidence
);


/*
 * Check whether all required evidence categories exist.
 */
bool ks_evidence_has_all(
    const ks_evidence_graph *graph,
    uint32_t required_mask
);

/*
 * Check whether the evidence graph contains at least
 * `minimum` independent evidence categories.
 */
bool ks_evidence_meets_minimum(
    const ks_evidence_graph *graph,
    unsigned int minimum
);

#endif
