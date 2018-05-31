/*
 * ssbd_toggle.c: Toggle the Speculative Store Bypass Disable status
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cpu.h"
#include "ssbd.h"

/* Prints the usage and exits with an error */
static int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n\n"
		"Valid options are:\n"
		"  -c CPUNUM     Pin the process to the CPUNUM cpu. The default is 0.\n",
		prog);
	exit(EXIT_FAILURE);
}

struct options {
	int cpu_num;		/* CPU number to restrict the process to */
};

/* Parses the command line options and stores the results in opts */
static void parse_opts(int argc, char **argv, struct options *opts)
{
	const char *prog = argv[0];
	int o;

	if (argc < 1)
		usage(prog);

	memset(opts, 0, sizeof(*opts));
	opts->cpu_num = DEFAULT_CPU_NUM;

	while ((o = getopt(argc, argv, "c:")) != -1) {
		switch(o) {
		case 'c': /* CPU number */
			opts->cpu_num = atoi(optarg);
			break;
		default:
			usage(prog);
		}
	}

	if (optind != argc)
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

	msr_fd = open_msr_fd(opts.cpu_num, true);
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

	if (toggle_ssbd(msr_fd, cpu_id))
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
