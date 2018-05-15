/*
 * read-ssb.c: Read the Speculative Store Bypass status after using prctl/seccomp
 * Copyright (C) 2018 Canonical LTD.
 * Author: Tyler Hicks <tyhicks@canonical.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifndef PR_GET_SPECULATION_CTRL
#define PR_GET_SPECULATION_CTRL 52
#endif

#ifndef PR_SET_SPECULATION_CTRL
#define PR_SET_SPECULATION_CTRL 53
#endif

/* Speculation control variants */
#ifndef PR_SPEC_STORE_BYPASS
# define PR_SPEC_STORE_BYPASS	0
#endif
/* Return and control values for PR_SET/GET_SPECULATION_CTRL */
# define PR_SPEC_NOT_AFFECTED	0
# define PR_SPEC_PRCTL		(1UL << 0)
# define PR_SPEC_ENABLE		(1UL << 1)
# define PR_SPEC_DISABLE	(1UL << 2)
# define PR_SPEC_FORCE_DISABLE	(1UL << 3)

int get_prctl(void)
{
	int rc = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);

	if (rc < 0)
		if (errno == EINVAL)
			fprintf(stderr, "This kernel does not support per-process speculation control\n");
		else
			perror("prctl PR_GET_SPECULATION_CTRL");

	return rc;
}

int set_prctl(void)
{
	int rc;

	rc = get_prctl();
	if (rc < 0) {
		return rc;
	} else if (!(rc & PR_SPEC_PRCTL)) {
		fprintf(stderr, "Speculation cannot be controlled via prctl\n");
		return -EOPNOTSUPP;
	}

	rc = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
		   PR_SPEC_DISABLE, 0, 0);
	if (rc < 0)
		perror("prctl PR_SET_SPECULATION_CTRL");

	return rc;
}

int print_prctl(void)
{
	int rc = get_prctl();

	if (rc < 0)
		return rc;

	switch (rc) {
	case PR_SPEC_NOT_AFFECTED:
		printf("not vulnerable\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
		printf("thread mitigated\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
		printf("thread mitigated (force)\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		printf("thread vulnerable\n");
		break;
	case PR_SPEC_DISABLE:
	case PR_SPEC_FORCE_DISABLE:
		printf("globally mitigated\n");
		break;
	default:
		printf("vulnerable\n");
		break;
	}

	return 0;
}

int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(SYS_seccomp, operation, flags, args);
}

int load_seccomp_filter(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS,
			offsetof(struct seccomp_data, nr)),
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};
	int rc;

	rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (rc < 0) {
		perror("prctl PR_SET_NO_NEW_PRIVS");
		return rc;
	}

	rc = seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
	if (rc < 0) {
		perror("seccomp");
		return rc;
	}

	return 0;
}

int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [-p|-s]\n\n", prog);
	fprintf(stderr, "  -p		Use PR_SET_SPECULATION_CTRL\n");
	fprintf(stderr, "  -s		Use a permissive seccomp filter\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int use_prctl = 0;
	int use_seccomp = 0;
	int rc;

	if (argc == 2) {
		if (!strcmp(argv[1], "-p"))
			use_prctl = 1;
		else if (!strcmp(argv[1], "-s"))
			use_seccomp = 1;
		else
			usage(argv[0]);
	} else if (argc != 1) {
		usage(argv[0]);
	}

	if (use_prctl)
		rc = set_prctl();
	else if (use_seccomp)
		rc = load_seccomp_filter();
	else
		rc = 0;

	if (rc != 0 || print_prctl() < 0)
		exit(1);

	exit(0);
}
