/*
 * check-ssbd.c: Read the Speculative Store Bypass Disable status after using prctl/seccomp
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
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

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

#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1UL << 2)
#endif

#define IA32_SPEC_CTRL_MSR	0x48

int exec(const char *prog, char **argv)
{
	execvp(prog, argv);
	perror("execv");
	return -1;
}

int do_fork()
{
	int pid = fork();

	if (pid < 0) {
		perror("fork");
		exit(1);
	} else if (pid) {
		int status;

		/* The parent waits for the child and exits */
		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
			exit(1);
		}

		if (WIFEXITED(status))
			exit(WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			exit(WTERMSIG(status));

		exit(1);
	}

	/* The child continues on */
	return 0;
}

int verify_prctl(int cpu, int ssbd)
{
	char msr_path[64];
	uint64_t value;
	int msr_fd;
	int rc;

	rc = snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%d/msr", cpu);
	if (rc < 0 || rc >= sizeof(msr_path) ){
		fprintf(stderr, "%s: Failed to construct MSR path", __func__);
		return -1;
	}

	msr_fd = open(msr_path, O_RDONLY | O_CLOEXEC);
	if (msr_fd < 0) {
		if (errno == ENOENT) {
			fprintf(stderr, "Please load the msr module and try again\n");
		} else if (errno == EACCES) {
			fprintf(stderr, "WARNING: Skipping verification of the SPEC_CTRL MSR; run as root to perform verification\n");
			return 0;
		} else {
			perror("open");
		}
		return -1;
	}

	rc = pread(msr_fd, &value, sizeof(value), IA32_SPEC_CTRL_MSR);
	if (rc < 0) {
		perror("pread");
		return -1;
	} else if (rc != sizeof(value)) {
		fprintf(stderr, "%s: short read of the MSR\n", __func__);
		return -1;
	}

	switch (ssbd) {
	case PR_SPEC_NOT_AFFECTED:
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		if (value & 0x4) {
			fprintf(stderr, "Bit 2 of IA32_SPEC_CTRL MSR is unexpectedly set");
			return -1;
		}
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
	case PR_SPEC_DISABLE:
		if (!(value & 0x4)) {
			fprintf(stderr, "Bit 2 of IA32_SPEC_CTRL MSR is unexpectedly clear");
			return -1;
		}
		break;
	default:
		fprintf(stderr,
			"Unknown SSBD status (0x%x); can't verify MSR\n", ssbd);
		return -1;
	}

	return 0;
}

int get_prctl(void)
{
	int rc = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);

	if (rc < 0) {
		if (errno == EINVAL)
			fprintf(stderr, "This kernel does not support per-process speculation control\n");
		else
			perror("prctl PR_GET_SPECULATION_CTRL");
	} else if (!(rc & PR_SPEC_PRCTL)) {
		fprintf(stderr, "Speculation cannot be controlled via prctl\n");
		rc = -1;
	}

	return rc;
}

int set_prctl(unsigned long value)
{
	int rc;

	rc = get_prctl();
	if (rc < 0)
		return rc;

	rc = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
		   value, 0, 0);
	if (rc < 0)
		perror("prctl PR_SET_SPECULATION_CTRL");

	return rc;
}

void print_prctl(int ssbd)
{
	/* The printed strings should match what's in the kernel's
	 * task_seccomp() function
	 */
	switch (ssbd) {
	case PR_SPEC_NOT_AFFECTED:
		printf("not vulnerable\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
		printf("thread mitigated\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
		printf("thread force mitigated\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		printf("thread vulnerable\n");
		break;
	case PR_SPEC_DISABLE:
		printf("globally mitigated\n");
		break;
	default:
		printf("vulnerable\n");
		break;
	}
}

int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(SYS_seccomp, operation, flags, args);
}

int load_seccomp_filter(unsigned int flags)
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

	rc = seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog);
	if (rc < 0) {
		perror("seccomp");
		return rc;
	}

	return 0;
}

int restrict_to_cpu(int cpu)
{
	cpu_set_t set;
	int rc;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	rc = sched_setaffinity(0, sizeof(set), &set);
	if (rc < 0)
		perror("sched_setaffinity");

	return rc;
}

int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options] [-- ... [-- ...]]\n\n", prog);
	fprintf(stderr, "  -p VALUE     Use PR_SET_SPECULATION_CTRL with the specified value. Valid\n"
			"               values for VALUE are:\n"
			"                \"enable\" for PR_SPEC_ENABLE\n"
			"                \"disable\" for PR_SPEC_DISABLE\n"
			"                \"force-disable\" for PR_SPEC_FORCE_DISABLE\n");
	fprintf(stderr, "  -s FLAGS     Use a permissive seccomp filter with the specified flags. Valid\n"
		        "               values for FLAGS are:\n"
			"                \"empty\" for 0\n"
			"                \"spec-allow\" for SECCOMP_FILTER_FLAG_SPEC_ALLOW\n");
	fprintf(stderr, "  -f           Fork before executing another program. This option is only\n"
			"               valid when \"--\" is present.");
	fprintf(stderr, "\nIf \"--\" is encountered, execv() will be called using the following argument\n"
			"as the program to execute and passing it all of the arguments following the\n"
			"program name.\n");
	exit(1);
}

struct options {
	bool fork;
	bool prctl;
	unsigned long prctl_value;
	bool seccomp;
	unsigned int seccomp_flags;
	const char *exec;
	char **exec_argv;
};

void parse_opts(int argc, char **argv, struct options *opts)
{
	const char *prog = argv[0];
	int o;

	memset(opts, 0, sizeof(*opts));
	while ((o = getopt(argc, argv, "fp:s:")) != -1) {
		switch(o) {
		case 'f': /* fork */
			opts->fork = true;
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
	} else if (opts->fork) {
		fprintf(stderr, "-f is only valid with \"-- ...\"\n");
		usage(prog);
	}
}

int main(int argc, char **argv)
{
	struct options opts;
	int ssbd;

	parse_opts(argc, argv, &opts);

	if (restrict_to_cpu(0))
		exit(1);

	if (opts.prctl && set_prctl(opts.prctl_value))
		exit(1);

	if (opts.seccomp && load_seccomp_filter(opts.seccomp_flags))
		exit(1);

	ssbd = get_prctl();
	if (ssbd < 0)
		exit(1);

	print_prctl(ssbd);
	if (verify_prctl(0, ssbd) < 0)
		exit(1);

	if (opts.fork && do_fork())
		exit(1);

	if (opts.exec && exec(opts.exec, opts.exec_argv))
		exit(1);

	exit(0);
}
