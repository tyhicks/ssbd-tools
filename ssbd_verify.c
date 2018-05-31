/*
 * ssbd_verify.c: Verify the Speculative Store Bypass Disable status
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
#include "ssbd.h"

/* Verify that the prctl value and actual SSBD bit match the expected values
 *
 * Returns 0 on success. -1 on error. 1 on a failed verification.
 */
static int verify_prctl(int msr_fd, cpu_id cpu_id, int expected)
{
	int actual = get_prctl();
	int adjusted;

	if (actual < 0)
		return -1;

	adjusted = actual;
	adjusted &= ~PR_SPEC_PRCTL;
	if (expected != adjusted) {
		fprintf(stderr,
			"FAIL: Expected SSBD prctl value (0x%x) does not match the actual value (0x%x)\n",
			expected, adjusted);

		return 1;
	}

	return verify_ssbd_prctl(msr_fd, cpu_id, actual);
}

/* Prints the usage and exits with an error */
static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options] VALUE\n\n"
		"Valid options are:\n"
		"  -c CPUNUM     Pin the process to the CPUNUM cpu. The default is 0.\n"
		"  -p VALUE      Verify PR_SET_SPECULATION_CTRL with the specified value. Valid\n"
		"                values for VALUE are:\n"
		"                 \"enable\" for PR_SPEC_ENABLE\n"
		"                 \"disable\" for PR_SPEC_DISABLE\n"
		"                 \"force-disable\" for PR_SPEC_FORCE_DISABLE\n"
		"  -t SECONDS    Verify the SSBD bit repeatedly for SECONDS of wall time.\n"
		"                If SECS is 0, the loop is doesn't end until the program\n"
		"                is interrupted.\n"
		"\n"
		"                This program detects which X86 MSR is to be used for\n"
		"                the SSBD bit, according to the current processor, and\n"
		"                verifies that the SSBD bit matches VALUE. By default,\n"
		"                a single read of the MSR is performed. If the -t option\n"
		"                is specified, the MSR is reread and verified in a loop.\n",
		prog);
	exit(EXIT_FAILURE);
}

struct options {
	bool verify_prctl;	/* Whether to verify the spec prctl */
	int prctl_value;	/* The prctl's value */

	bool ssbd;		/* Expected ssbd */
	time_t seconds;		/* Seconds to verify ssbd (wall time) */

	int cpu_num;		/* CPU number to restrict the process to */
};

/* Parses the command line options and stores the results in opts */
static void parse_opts(int argc, char **argv, struct options *opts)
{
	const char *prog = argv[0];
	int o;

	if (argc <= 1)
		usage(prog);

	memset(opts, 0, sizeof(*opts));
	opts->seconds = (time_t) -1;
	opts->cpu_num = DEFAULT_CPU_NUM;

	while ((o = getopt(argc, argv, "c:p:t:")) != -1) {
		switch(o) {
		case 'c': /* CPU number */
			opts->cpu_num = atoi(optarg);
			break;
		case 'p': /* prctl */
			opts->verify_prctl = true;
			if (!strcmp(optarg, "enable"))
				opts->prctl_value = PR_SPEC_ENABLE;
			else if (!strcmp(optarg, "disable"))
				opts->prctl_value = PR_SPEC_DISABLE;
			else if (!strcmp(optarg, "force-disable"))
				opts->prctl_value = PR_SPEC_FORCE_DISABLE;
			else
				usage(prog);
			break;
		case 't': /* time */
			opts->seconds = atol(optarg);
			break;
		default:
			usage(prog);
		}
	}

	if (optind != argc - 1)
		usage(prog);

	if (!strcmp(argv[optind], "0"))
		opts->ssbd = false;
	else if (!strcmp(argv[optind], "1"))
		opts->ssbd = true;
	else
		usage(prog);
}

int main(int argc, char **argv)
{
	struct options opts;
	int msr_fd;
	cpu_id cpu_id;

	parse_opts(argc, argv, &opts);

	if (restrict_to_cpu(opts.cpu_num))
		exit(EXIT_FAILURE);

	msr_fd = open_msr_fd(opts.cpu_num, false);
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

	if (opts.verify_prctl && verify_prctl(msr_fd, cpu_id, opts.prctl_value))
		exit(EXIT_FAILURE);

	if (verify_ssbd_bit(msr_fd, cpu_id, opts.ssbd, opts.seconds))
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
