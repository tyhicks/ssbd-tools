/*
 * ssbd-exec.c: Execute programs after manipulating the Speculative Store Bypass
 *              Disable status
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
#include "prctl.h"
#include "seccomp.h"

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

/* Prints the usage and exits with an error */
static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options] [-- prog args ...]\n\n"
		"Valid options are:\n"
		"  -c CPUNUM     Pin the process to the CPUNUM cpu. The default is to\n"
		"                not pin the process.\n"
		"  -p VALUE      Use PR_SET_SPECULATION_CTRL with the specified value. Valid\n"
		"                values for VALUE are:\n"
		"                 \"enable\" for PR_SPEC_ENABLE\n"
		"                 \"disable\" for PR_SPEC_DISABLE\n"
		"                 \"force-disable\" for PR_SPEC_FORCE_DISABLE\n"
		"  -s FLAGS      Use a permissive seccomp filter with the specified flags. Valid\n"
	        "                values for FLAGS are:\n"
		"                 \"empty\" for 0\n"
		"                 \"spec-allow\" for SECCOMP_FILTER_FLAG_SPEC_ALLOW\n"
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

	bool cpu;		/* Whether to restrict the process to a CPU */
	int cpu_num;		/* CPU number to restrict the process to */

	const char *exec;	/* Program to exec */
	char **exec_argv;	/* Arguments to pass to program */
};

/* Parses the command line options and stores the results in opts */
static void parse_opts(int argc, char **argv, struct options *opts)
{
	const char *prog = argv[0];
	int o;

	memset(opts, 0, sizeof(*opts));

	while ((o = getopt(argc, argv, "c:p:s:")) != -1) {
		char *secs = NULL;

		switch(o) {
		case 'c': /* CPU number */
			opts->cpu = true;
			opts->cpu_num = atoi(optarg);
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
	}
}

int main(int argc, char **argv)
{
	struct options opts;
	int prctl_value;

	parse_opts(argc, argv, &opts);

	if (opts.cpu && restrict_to_cpu(opts.cpu_num))
		exit(EXIT_FAILURE);

	if (opts.prctl && set_prctl(opts.prctl_value))
		exit(EXIT_FAILURE);

	if (opts.seccomp && load_seccomp_filter(opts.seccomp_flags))
		exit(EXIT_FAILURE);

	prctl_value = get_prctl();
	if (prctl_value < 0)
		exit(EXIT_FAILURE);

	if (opts.exec && exec(opts.exec, opts.exec_argv))
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
