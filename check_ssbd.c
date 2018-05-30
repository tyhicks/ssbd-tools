/*
 * check-ssbd.c: Read the Speculative Store Bypass Disable status after using prctl/seccomp
 * Copyright (C) 2018 Canonical LTD.
 * Author: Tyler Hicks <tyhicks@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cpu.h"
#include "msr.h"
#include "prctl.h"
#include "seccomp.h"
#include "ssbd.h"

/* Waits for the child to exit and exits with the same return value
 *
 * Exits using the child's exit status if the child exited normally. Exits
 * non-zero on error or if child died unexpectedly.
 */
static int exit_after_child(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "ERROR: Couldn't wait for child to exit: %m\n");
		exit(EXIT_FAILURE);
	}

	if (!WIFEXITED(status))
		exit(EXIT_FAILURE);

	exit(WEXITSTATUS(status));
}

/* Execute prog with argv as the arguments
 *
 * Doesn't return on success. Returns -1 on error.
 */
static int exec(const char *prog, char **argv)
{
	execvp(prog, argv);
	fprintf(stderr, "ERROR: Couldn't execute %s: %m\n", prog);
	return -1;
}

/* Fork, verify the SSBD bit, and exec a program in the child process
 *
 * If verify is false, msr_fd and expected are ignored.
 *
 * The parent returns the pid of the child process on success. The parent
 * returns -1 on error. The child executes the program prog or exits non-zero
 * on error.
 */
static pid_t fork_verify_exec(bool verify, int msr_fd, cpu_id cpu_id,
			      bool expected, const char *prog, char **argv)
{
	int pid = fork();

	if (pid < 0) {
		fprintf(stderr, "ERROR: Couldn't fork a new process: %m\n");
		return -1;
	} else if (!pid) {
		/* Do a single SSBD verification in the child after forking */
		if (verify &&
		    verify_ssbd_bit(msr_fd, cpu_id, expected, (time_t) -1))
			exit(EXIT_FAILURE);
		exec(prog, argv);
		exit(EXIT_FAILURE);
	}

	/* The parent continues on */
	return pid;
}

/* Prints the usage and exits with an error */
static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options] [-- ...]\n\n"
		"Valid options are:\n"
		"  -c CPUNUM     Pin the process to the CPUNUM cpu. The default is 0.\n"
		"  -q            Don't print the string represenation of the prctl value\n"
		"  -p VALUE      Use PR_SET_SPECULATION_CTRL with the specified value. Valid\n"
		"                values for VALUE are:\n"
		"                 \"enable\" for PR_SPEC_ENABLE\n"
		"                 \"disable\" for PR_SPEC_DISABLE\n"
		"                 \"force-disable\" for PR_SPEC_FORCE_DISABLE\n"
		"  -s FLAGS      Use a permissive seccomp filter with the specified flags. Valid\n"
	        "                values for FLAGS are:\n"
		"                 \"empty\" for 0\n"
		"                 \"spec-allow\" for SECCOMP_FILTER_FLAG_SPEC_ALLOW\n"
		"  -e VAL[:SECS] Verify that the SSBD bit in the IA32_SPEC_CTRL MSR is equal to VAL.\n"
		"                By default, a single read of the MSR is performed. If :SECS is\n"
		"                specified, the MSR is reread and verified in a loop for SECS\n"
		"                seconds of wall time. If SECS is 0, the loop is doesn't end until\n"
	        "                the program is interrupted.\n"
		"                Unless the -n option is in use, a single SSBD bit verification is\n"
		"                performed prior to forking off a child process and another in\n"
		"                the child after forking. Once the parent returns from the call\n"
		"                to fork(), SSBD bit verification is performed according to the\n"
		"                specified SECS.\n"
		"  -n            Do NOT fork before executing another program. This option is only\n"
		"                valid when \"--\" is present.\n"
		"\nIf \"--\" is encountered, execv() will be called using the following argument\n"
		"as the program to execute and passing it all of the arguments following the\n"
		"program name.\n", prog);
	exit(EXIT_FAILURE);
}

struct options {
	bool prctl;			/* Whether to use the spec prctl */
	unsigned long prctl_value;	/* The prctl's value */

	bool seccomp;			/* Whether to load a seccomp filter */
	unsigned int seccomp_flags;	/* The seccomp filter flags */

	bool verify_ssbd;	/* Whether to verify the SSBD bit with rdmsr */
	bool ssbd;		/* Expected ssbd */
	time_t seconds;		/* Seconds to verify ssbd (wall time) */

	bool fork;		/* True if fork() should happen before exec() */
	const char *exec;	/* Program to exec */
	char **exec_argv;	/* Arguments to pass to program */

	int cpu_num;		/* CPU number to restrict the process to */

	bool quiet;		/* Whether to print the prctl value */
};

/* Parses the command line options and stores the results in opts */
static void parse_opts(int argc, char **argv, struct options *opts)
{
	const char *prog = argv[0];
	int o;

	memset(opts, 0, sizeof(*opts));
	opts->seconds = (time_t) -1;
	opts->fork = true;
	opts->cpu_num = DEFAULT_CPU_NUM;

	while ((o = getopt(argc, argv, "c:e:np:qs:")) != -1) {
		char *secs = NULL;

		switch(o) {
		case 'c': /* CPU number */
			opts->cpu_num = atoi(optarg);
			break;
		case 'e': /* expected ssbd */
			opts->verify_ssbd = true;
			secs = optarg;
			optarg = strsep(&secs, ":");

			if (!strcmp(optarg, "0"))
				opts->ssbd = false;
			else if (!strcmp(optarg, "1"))
				opts->ssbd = true;
			else
				usage(prog);

			if (secs)
				opts->seconds = atol(secs);

			break;
		case 'n': /* no fork */
			opts->fork = false;
			break;
		case 'p': /* prctl */
			opts->prctl = true;
			if (!strcmp(optarg, "enable"))
				opts->prctl_value = PR_SPEC_ENABLE;
			else if (!strcmp(optarg, "disable"))
				opts->prctl_value = PR_SPEC_DISABLE;
			else if (!strcmp(optarg, "force-disable"))
				opts->prctl_value = PR_SPEC_FORCE_DISABLE;
			else
				usage(prog);
			break;
		case 'q': /* quiet */
			opts->quiet = true;
			break;
		case 's': /* seccomp */
			opts->seccomp = true;
			if (!strcmp(optarg, "empty"))
				opts->seccomp_flags = 0;
			else if (!strcmp(optarg, "spec-allow"))
				opts->seccomp_flags = SECCOMP_FILTER_FLAG_SPEC_ALLOW;
			else
				usage(prog);
			break;
		default:
			usage(prog);
		}
	}

	if (optind < argc) {
		/* Ensure that the first non-option is "--" */
		if (optind == 0 || strcmp("--", argv[optind - 1]))
			usage(prog);

		opts->exec = argv[optind];
		opts->exec_argv = &argv[optind];
	} else if (!opts->fork) {
		fprintf(stderr, "-n is only valid with \"-- ...\"\n");
		usage(prog);
	}

	if (!opts->verify_ssbd)
		fprintf(stderr, "WARNING: Not verifying the SSBD bit with rdmsr (-e) may result in an incomplete test\n");
}

int main(int argc, char **argv)
{
	struct options opts;
	int msr_fd;
	cpu_id cpu_id;
	int prctl_value;
	pid_t pid;

	parse_opts(argc, argv, &opts);

	if (restrict_to_cpu(opts.cpu_num))
		exit(EXIT_FAILURE);

	msr_fd = open_msr_fd(opts.cpu_num);
	if (msr_fd < 0)
		exit(EXIT_FAILURE);

	if (identify_cpu(&cpu_id, msr_fd))
		exit(EXIT_FAILURE);

	if (cpu_id == CPU_SSBD_UNSUPPORTED) {
		fprintf(stderr, "FAIL: SSBD is unsupported by this CPU\n");
		exit(EXIT_FAILURE);
	} else if (cpu_id == CPU_SSB_UNAFFECTED) {
		printf("This CPU is not affected by Speculative Store Bypass\n");
		exit(EXIT_SUCCESS);
	}

	if (opts.prctl && set_prctl(opts.prctl_value))
		exit(EXIT_FAILURE);

	if (opts.seccomp && load_seccomp_filter(opts.seccomp_flags))
		exit(EXIT_FAILURE);

	prctl_value = get_prctl();
	if (prctl_value < 0)
		exit(EXIT_FAILURE);

	if (!opts.quiet)
		print_ssbd_prctl(prctl_value);

	/* Verify that the returned prctl value matches with the MSR */
	if (opts.verify_ssbd && verify_ssbd_prctl(msr_fd, cpu_id, prctl_value))
		exit(EXIT_FAILURE);

	if (opts.exec && opts.fork) {
		/* Do a single SSBD verification prior to forking */
		if (opts.verify_ssbd &&
		    verify_ssbd_bit(msr_fd, cpu_id, opts.ssbd, (time_t) -1))
			exit(EXIT_FAILURE);

		/* This will do a single SSBD verification after forking */
		pid = fork_verify_exec(opts.verify_ssbd, msr_fd, cpu_id,
				       opts.ssbd, opts.exec, opts.exec_argv);
		if (pid < 0)
			exit(EXIT_FAILURE);
	}

	if (opts.verify_ssbd &&
	    verify_ssbd_bit(msr_fd, cpu_id, opts.ssbd, opts.seconds))
		exit(EXIT_FAILURE);

	if (opts.exec && opts.fork)
		exit_after_child(pid);
	else if (opts.exec && exec(opts.exec, opts.exec_argv))
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
