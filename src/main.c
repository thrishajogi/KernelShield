// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdlib.h>
#include <argp.h>
#include <signal.h>

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "../include/ks_event.h"
#include "detector/detector.h"
#include "logger.h"
#include "process_exec.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "KernelShield 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF KernelShield demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./KernelShield [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;


static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct ks_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	(void)ctx;
	(void)data_sz;

	/* Structured telemetry */
	ks_logger_event(e);

	/* Detection and correlation */
	ks_detector_process_event(e);
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	/* ------------------------------------------------------ */
	/* EXEC event                                              */
	/* ------------------------------------------------------ */

	if (e->type == KS_EVENT_EXEC) {

		printf("%-8s %-6s %-6u %-6u %-6u %-6u %-16s %s\n",
		       ts,
		       "EXEC",
		       e->pid,
		       e->ppid,
		       e->uid,
		       e->gid,
		       e->comm,
		       e->filename);
	}

	/* ------------------------------------------------------ */
	/* EXIT event                                              */
	/* ------------------------------------------------------ */

	else if (e->type == KS_EVENT_EXIT) {

		printf("%-8s %-6s %-6u %-6u %-6u %-6u %-16s code=%d duration=%lums\n",
		       ts,
		       "EXIT",
		       e->pid,
		       e->ppid,
		       e->uid,
		       e->gid,
		       e->comm,
		       e->exit_code,
		       e->duration_ns / 1000000UL);

	}

	/* ------------------------------------------------------ */
	/* NETWORK event                                           */
	/* ------------------------------------------------------ */

	else if (e->type == KS_EVENT_NETWORK) {

		char dst_ip[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET,
		              &e->dst_ipv4,
		              dst_ip,
		              sizeof(dst_ip)) == NULL) {
			strncpy(dst_ip, "unknown", sizeof(dst_ip));
			dst_ip[sizeof(dst_ip) - 1] = '\0';
		}

		printf("%-8s %-7s PID=%-6u COMM=%-16s DEST=%s:%u\n",
		       ts,
		       "NETWORK",
		       e->pid,
		       e->comm,
		       dst_ip,
		       ntohs(e->dst_port));
	}


	else if (e->type == KS_EVENT_FILE) {

		const char *operation = "UNKNOWN";
		const char *path = e->file_path;

		switch (e->file_operation) {
		case KS_FILE_OPEN:
			operation = "OPEN";
			break;
		case KS_FILE_WRITE:
			operation = "WRITE";
			break;
		case KS_FILE_CREATE:
			operation = "CREATE";
			break;
		case KS_FILE_RENAME:
			operation = "RENAME";
			break;
		case KS_FILE_DELETE:
			operation = "DELETE";
			break;
		case KS_FILE_EXECUTE:
			operation = "EXECUTE";
			break;
		default:
			break;
		}

		/*
		 * Console presentation filter.
		 *
		 * IMPORTANT:
		 * This does NOT suppress telemetry or detection.
		 * Every event has already been logged and passed to
		 * the detection/correlation engine above.
		 *
		 * Only high-value or potentially suspicious file
		 * activity is displayed on the interactive console.
		 */
		bool noisy_path =
			strstr(path, "/.cache/") ||
			strstr(path, "/cache2/") ||
			strstr(path, "/mozilla/") ||
			strstr(path, "/fontconfig/") ||
			strstr(path, "/mesa_shader_cache/") ||
			strstr(path, "/fonts/") ||
			strstr(path, "/snap/firefox/") ||
			strstr(path, ".sqlite") ||
			strstr(path, ".sqlite-wal") ||
			strstr(path, ".sqlite-journal") ||
			strstr(path, ".cache-");

		bool destructive_operation =
			e->file_operation == KS_FILE_RENAME ||
			e->file_operation == KS_FILE_DELETE;

		bool executable_activity =
			e->file_operation == KS_FILE_EXECUTE;

		bool sensitive_path =
			strstr(path, "/etc/") ||
			strstr(path, "/usr/bin/") ||
			strstr(path, "/usr/sbin/") ||
			strstr(path, "/bin/") ||
			strstr(path, "/sbin/") ||
			strstr(path, "/var/tmp/") ||
			strstr(path, "/tmp/");

		bool user_writable_activity =
			strstr(path, "/home/") &&
			!noisy_path;

		if (destructive_operation ||
		    executable_activity ||
		    sensitive_path ||
		    user_writable_activity) {

			printf("%-8s %-7s PID=%-6u COMM=%-16s OP=%-8s PATH=%s\n",
			       ts,
			       "FILE",
			       e->pid,
			       e->comm,
			       operation,
			       path);
		}
	}

	fflush(stdout);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct process_exec_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	ks_detector_init();

const char *log_path = getenv("KERNELSHIELD_LOG_PATH");

if (!log_path || log_path[0] == '\0') {
    log_path = "/var/log/kernelshield/kernelshield-events.jsonl";
}

printf("KernelShield logger: %s\n", log_path);

if (ks_logger_init(log_path) != 0) {
    fprintf(stderr, "Failed to initialize KernelShield logger\n");
    return 1;
}
	skel = process_exec_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = process_exec_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = process_exec_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-6s %-6s %-6s %-6s %-6s %-16s %s\n",
       "TIME",
       "EVENT",
       "PID",
       "PPID",
       "UID",
       "GID",
       "COMM",
       "FILE");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	process_exec_bpf__destroy(skel);
	ks_detector_shutdown();
	ks_logger_close();

	return err < 0 ? -err : 0;
}
