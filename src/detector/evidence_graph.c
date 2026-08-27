#include "evidence_graph.h"

#include <string.h>

static uint32_t bit_count(uint32_t value)
{
    uint32_t count = 0;

    while (value) {
        count += value & 1U;
        value >>= 1;
    }

    return count;
}

void ks_evidence_reset(
    ks_evidence_graph *graph
)
{
    if (!graph)
        return;

    memset(graph, 0, sizeof(*graph));
}

void ks_evidence_add(
    ks_evidence_graph *graph,
    ks_evidence_type evidence,
    uint64_t timestamp_ns
)
{
    if (!graph || evidence == KS_EVIDENCE_NONE)
        return;

    if (graph->first_evidence_ns == 0)
        graph->first_evidence_ns = timestamp_ns;

    graph->last_evidence_ns = timestamp_ns;

    /*
     * Count every observation, while diversity is derived
     * independently from the bitmask.
     */
    graph->evidence_events++;

    graph->mask |= (uint32_t)evidence;
}

uint32_t ks_evidence_diversity(
    const ks_evidence_graph *graph
)
{
    if (!graph)
        return 0;

    return bit_count(graph->mask);
}

bool ks_evidence_has(
    const ks_evidence_graph *graph,
    ks_evidence_type evidence
)
{
    if (!graph)
        return false;

    return
        (graph->mask & (uint32_t)evidence) != 0;
}

uint32_t ks_evidence_confidence(
    const ks_evidence_graph *graph,
    uint32_t episode_score
)
{
    uint32_t diversity;
    uint32_t confidence = 0;

    if (!graph)
        return 0;

    diversity = ks_evidence_diversity(graph);

    /*
     * Independent evidence categories contribute more strongly
     * than repeated events of the same category.
     *
     * This prevents:
     *
     *   500 ordinary file events
     *
     * from being treated like:
     *
     *   execution + network + file + privilege
     */
    switch (diversity) {

    case 0:
        confidence = 0;
        break;

    case 1:
        confidence = 20;
        break;

    case 2:
        confidence = 45;
        break;

    case 3:
        confidence = 70;
        break;

    case 4:
        confidence = 85;
        break;

    default:
        confidence = 95;
        break;
    }

    /*
     * Strong episode evidence can slightly reinforce confidence,
     * but cannot replace evidence diversity.
     */
    if (episode_score >= 80 && confidence < 95)
        confidence += 5;

    if (confidence > 95)
        confidence = 95;

    return confidence;
}


/*
 * Check whether every required evidence category exists.
 */
bool
ks_evidence_has_all(
    const ks_evidence_graph *graph,
    uint32_t required_mask
)
{
    if (!graph)
        return false;

    return
        (graph->mask & required_mask)
        == required_mask;
}


/*
 * Check whether the episode contains enough independent
 * evidence categories for correlation eligibility.
 */
bool
ks_evidence_meets_minimum(
    const ks_evidence_graph *graph,
    unsigned int minimum
)
{
    if (!graph)
        return false;

    return ks_evidence_diversity(graph) >= minimum;
}
