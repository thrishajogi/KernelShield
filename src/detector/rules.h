#ifndef KS_RULES_H
#define KS_RULES_H

#include <stdint.h>

#include "../../include/ks_event.h"

int ks_rule_shell_from_server(const struct ks_event *event);

int ks_rule_network_from_shell(const struct ks_event *event);

int ks_rule_correlated_behavior(uint32_t pid);

int ks_rule_attack_chain(uint32_t pid);

int ks_rule_suspicious_network_utility(const struct ks_event *event);

#endif
