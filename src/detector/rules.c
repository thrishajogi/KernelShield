#include <string.h>
#include <stdint.h>

#include "../../include/ks_event.h"
#include "rules.h"
#include "process_table.h"

static int is_server_process(const char *comm)
{
    return strcmp(comm, "nginx") == 0 ||
           strcmp(comm, "apache2") == 0 ||
           strcmp(comm, "httpd") == 0 ||
           strcmp(comm, "python3") == 0 ||
           strcmp(comm, "php-fpm") == 0;
}

static int is_shell(const char *comm)
{
    return strcmp(comm, "bash") == 0 ||
           strcmp(comm, "sh") == 0 ||
           strcmp(comm, "dash") == 0 ||
           strcmp(comm, "zsh") == 0;
}

/*
 * Rule 1:
 * A server process spawning a shell is suspicious.
 */
int ks_rule_shell_from_server(const struct ks_event *event)
{
    if (event->type != KS_EVENT_EXEC)
        return 0;

    ks_process *parent = ks_process_find(event->ppid);

    if (!parent)
        return 0;

    if (is_server_process(parent->comm) &&
        is_shell(event->comm))
        return 1;

    return 0;
}

/*
 * Rule 2:
 * A shell making an outbound network connection
 * is interesting, but not automatically malicious.
 */
int ks_rule_network_from_shell(const struct ks_event *event)
{
    if (event->type != KS_EVENT_NETWORK)
        return 0;

    ks_process *process = ks_process_find(event->pid);

    if (!process)
        return 0;

    if (is_shell(process->comm))
        return 1;

    return 0;
}

/*
 * Rule 3:
 * Existing simple correlation.
 */
int ks_rule_correlated_behavior(uint32_t pid)
{
    ks_process *process = ks_process_find(pid);

    if (!process)
        return 0;

    return process->spawned_shell &&
           process->made_network_connection;
}

/*
 * Rule 4:
 * Multi-stage attack chain.
 *
 * Example:
 *
 *     python3
 *        |
 *       bash
 *        |
 *       curl
 *        |
 *      network
 *
 * The network event belongs to curl, so we walk its
 * parent chain looking for a shell that was spawned
 * by a server process.
 */
int ks_rule_attack_chain(uint32_t pid)
{
    ks_process *process = ks_process_find(pid);

    if (!process)
        return 0;

    /*
     * A shell may exec() into another program such as curl,
     * keeping the same PID. In that case the suspicious shell
     * is preserved in previous_comm rather than the parent chain.
     */
    if (process->spawned_shell ||
        is_shell(process->previous_comm))
        return 1;

    /*
     * Walk up to three ancestors looking for a process that was
     * identified as a shell spawned by a server.
     */
    for (int depth = 0; depth < 4; depth++) {

        if (process->ppid == 0)
            break;

        ks_process *parent =
            ks_process_find(process->ppid);

        if (!parent)
            break;

        if (parent->spawned_shell)
            return 1;

        process = parent;
    }

    return 0;
}
