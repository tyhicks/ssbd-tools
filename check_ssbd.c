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
#include <time.h>
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
#define PR_SPEC_STORE_BYPASS	0
#endif

/* Return and control values for PR_SET/GET_SPECULATION_CTRL */
#ifndef PR_SPEC_NOT_AFFECTED
#define PR_SPEC_NOT_AFFECTED	0
#endif

#ifndef PR_SPEC_PRCTL
#define PR_SPEC_PRCTL		(1UL << 0)
#endif

#ifndef PR_SPEC_ENABLE
#define PR_SPEC_ENABLE		(1UL << 1)
#endif

#ifndef PR_SPEC_DISABLE
#define PR_SPEC_DISABLE		(1UL << 2)
#endif

#ifndef PR_SPEC_FORCE_DISABLE
#define PR_SPEC_FORCE_DISABLE	(1UL << 3)
#endif

#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1UL << 2)
#endif

#define IA32_SPEC_CTRL_MSR	0x48
#define DEFAULT_CPU		0

/* Waits for the child to exit and exits with the same return value
 *
 * Exits using the child's exit status if the child exited normally. Exits
 * non-zero on error or if child died unexpectedly.
 */
int exit_after_child(pid_t pid)
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
int exec(const char *prog, char **argv)
{
	execvp(prog, argv);
	fprintf(stderr, "ERROR: Couldn't execute %s: %m\n", prog);
	return -1;
}

/* Open the /dev/cpu/CPUNUM/msr file where CPUNUM is specified by cpu
 *
 * Returns a valid file descriptor, open for reading, on success. -1 on error.
 */
int open_msr_fd(int cpu)
{
	char msr_path[64];
	int msr_fd;
	int rc;

	rc = snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%d/msr", cpu);
	if (rc < 0 || rc >= sizeof(msr_path) ){
		fprintf(stderr, "ERROR: Couldn't construct the MSR path\n");
		return -1;
	}

	msr_fd = open(msr_path, O_RDONLY | O_CLOEXEC);
	if (msr_fd < 0) {
		if (errno == ENOENT) {
			fprintf(stderr, "ERROR: The msr kernel module is not loaded\n");
		} else {
			fprintf(stderr, "ERROR: Couldn't open MSR file (%s): %m\n",
				msr_path);
		}
		return -1;
	}

	return msr_fd;
}

/* Read the SSBD bit from the IA32_SPEC_CTRL MSR
 *
 * Sets *ssbd to true if the bit is 1, false if the bit is 0.
 *
 * Returns 0 on success. -1 on error.
 */
int read_ssbd_from_msr(int msr_fd, bool *ssbd)
{
	uint64_t value;
	int rc;

	rc = pread(msr_fd, &value, sizeof(value), IA32_SPEC_CTRL_MSR);
	if (rc < 0) {
		fprintf(stderr, "ERROR: Couldn't read MSR file: %m\n");
		return -1;
	} else if (rc != sizeof(value)) {
		fprintf(stderr, "ERROR: Short read of the MSR file\n");
		return -1;
	}

	*ssbd = !!(value & 0x4);
	return 0;
}

/* Reads the SSBD bit from the IA32_SPEC_CTRL MSR and verifies its value
 *
 * The expected argument should be true if the bit is expected to be 1. False
 * if it is expected to be 0.
 *
 * If seconds is 0, loop until the user interrupts the loop. If seconds is
 * (time_t) -1, only verify once. Otherwise, loop until the time at the
 * function entry time added to the number in the seconds argument is reached.
 *
 * Return 0 on success. -1 on error. 1 on a failed verification.
 */
int verify_ssbd(int msr_fd, bool expected, time_t seconds)
{
	time_t cur, stop;
	int rc;

	stop = time(NULL);
	if (stop == (time_t) -1) {
		fprintf(stderr, "ERROR: Couldn't initialize the stop timer: %m\n");
		return -1;
	}

	stop += seconds;
	do {
		bool actual;
		int rc = read_ssbd_from_msr(msr_fd, &actual);

		if (rc) {
			fprintf(stderr, "ERROR: Couldn't perform SSBD bit verification\n");
			return -1;
		}

		if (actual != expected) {
			rc = 1;
			fprintf(stderr, "FAIL: SSBD bit verification failed (expected %d, got %d)\n",
				expected, actual);
			return 1;
		}

		cur = time(NULL);
		if (cur == (time_t) -1) {
			fprintf(stderr, "ERROR: Couldn't get the current time: %m\n");
			return -1;
		}
	} while (seconds == 0 ||
		 (seconds != ((time_t) -1) && cur < stop));

	return 0;
}

/* Fork, verify the SSBD bit, and exec a program in the child process
 *
 * If verify is false, msr_fd and expected are ignored.
 *
 * The parent returns the pid of the child process on success. The parent
 * returns -1 on error. The child executes the program prog or exits non-zero
 * on error.
 */
pid_t fork_verify_exec(bool verify, int msr_fd, bool expected,
		       const char *prog, char **argv)
{
	int pid = fork();

	if (pid < 0) {
		fprintf(stderr, "ERROR: Couldn't fork a new process: %m\n");
		return -1;
	} else if (!pid) {
		/* Do a single SSBD verification in the child after forking */
		if (verify && verify_ssbd(msr_fd, expected, (time_t) -1))
			exit(EXIT_FAILURE);
		exec(prog, argv);
		exit(EXIT_FAILURE);
	}

	/* The parent continues on */
	return pid;
}

/* Verify that the prctl value matches the SSBD bit from the IA32_SPEC_CTRL MSR
 *
 * Returns 0 on success. -1 on error. 1 on a failed verification.
 */
int verify_prctl(int msr_fd, int prctl_value)
{
	bool ssbd;

	if (read_ssbd_from_msr(msr_fd, &ssbd)) {
		fprintf(stderr, "ERROR: Couldn't perofrm prctl value verification\n");
		return -1;
	}

	switch (prctl_value) {
	case PR_SPEC_NOT_AFFECTED:
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		if (ssbd) {
			fprintf(stderr, "FAIL: SSBD bit of the IA32_SPEC_CTRL MSR is unexpectedly set\n");
			return 1;
		}
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
	case PR_SPEC_DISABLE:
		if (!ssbd) {
			fprintf(stderr, "FAIL: SSBD bit of the IA32_SPEC_CTRL MSR is unexpectedly clear\n");
			return 1;
		}
		break;
	default:
		fprintf(stderr, "ERROR: Couldn't verify Unknown prctl value (0x%x)\n",
			prctl_value);
		return -1;
	}

	return 0;
}

/* Get the value of the PR_SPEC_STORE_BYPASS prctl
 *
 * Returns the value on success. -1 on error.
 */
int get_prctl(void)
{
	int rc = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);

	if (rc < 0) {
		if (errno == EINVAL)
			fprintf(stderr, "ERROR: This kernel does not support per-process speculation control\n");
		else
			fprintf(stderr, "ERROR: Couldn't get the value of the PR_SPEC_STORE_BYPASS prctl: %m\n");
		return -1;
	} else if (!(rc & PR_SPEC_PRCTL)) {
		fprintf(stderr, "ERROR: Speculation cannot be controlled via prctl\n");
		return -1;
	}

	return rc;
}

/* Set the value of the PR_SPEC_STORE_BYPASS prctl
 *
 * Returns 0 on success. -1 on error.
 */
int set_prctl(unsigned long value)
{
	int rc;

	rc = get_prctl();
	if (rc < 0) {
		fprintf(stderr, "ERROR: Couldn't get the value of the PR_SPEC_STORE_BYPASS prctl and, therefore, cannot set it\n");
		return -1;
	}

	rc = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, value, 0, 0);
	if (rc < 0) {
		fprintf(stderr, "ERROR: Couldn't set the value of the PR_SPEC_STORE_BYPASS prctl: %m\n");
		return -1;
	}

	return 0;
}

/* Prints a string representation of the PR_SPEC_STORE_BYPASS prctl value */
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

/* seccomp(2) wrapper
 *
 * See the seccomp(2) man page for details.
 */
int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall(SYS_seccomp, operation, flags, args);
}

/* Loads a permissive seccomp filter with the specificied filter flags
 *
 * Returns 0 on success. -1 on error.
 */
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

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		fprintf(stderr, "ERROR: Couldn't set no new privs: %m\n");
		return -1;
	}

	if (seccomp(SECCOMP_SET_MODE_FILTER, flags, &prog) < 0) {
		fprintf(stderr, "ERROR: Couldn't load the seccomp filter: %m\n");
		return -1;
	}

	return 0;
}

/* Restricts the current process to only run on the specified CPU
 *
 * Returns 0 on success. -1 on error.
 */
int restrict_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) < 0) {
		fprintf(stderr, "ERROR: Couldn't set the CPU affinity mask: %m\n");
		return -1;
	}

	return 0;
}

/* Prints the usage and exits with an error */
int usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options] [-- ...]\n\n"
		"Valid options are:\n"
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
		"                If the -f option is in use, a single SSBD bit verification is\n"
		"                performed prior to forking off a child process and another in\n"
		"                the child after forking. Once the parent returns from the call\n"
		"                to fork(), SSBD bit verification is performed according to the\n"
		"                specified SECS.\n"
		"  -f            Fork before executing another program. This option is only\n"
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
};

/* Parses the command line options and stores the results in opts */
void parse_opts(int argc, char **argv, struct options *opts)
{
	const char *prog = argv[0];
	int o;

	memset(opts, 0, sizeof(*opts));
	opts->seconds = (time_t) -1;

	while ((o = getopt(argc, argv, "e:fp:s:")) != -1) {
		char *secs = NULL;

		switch(o) {
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
	int msr_fd;
	int prctl_value;
	pid_t pid;

	parse_opts(argc, argv, &opts);

	if (restrict_to_cpu(DEFAULT_CPU))
		exit(EXIT_FAILURE);

	msr_fd = open_msr_fd(DEFAULT_CPU);
	if (msr_fd < 0)
		exit(EXIT_FAILURE);

	if (opts.prctl && set_prctl(opts.prctl_value))
		exit(EXIT_FAILURE);

	if (opts.seccomp && load_seccomp_filter(opts.seccomp_flags))
		exit(EXIT_FAILURE);

	prctl_value = get_prctl();
	if (prctl_value < 0)
		exit(EXIT_FAILURE);

	print_prctl(prctl_value);
	if (verify_prctl(msr_fd, prctl_value))
		exit(EXIT_FAILURE);

	if (opts.fork) {
		/* Do a single SSBD verification prior to forking */
		if (opts.verify_ssbd &&
		    verify_ssbd(msr_fd, opts.ssbd, (time_t) -1))
			exit(EXIT_FAILURE);

		/* This will do a single SSBD verification after forking */
		pid = fork_verify_exec(opts.verify_ssbd, msr_fd, opts.ssbd,
				       opts.exec, opts.exec_argv);
		if (pid < 0)
			exit(EXIT_FAILURE);
	}

	if (opts.verify_ssbd && verify_ssbd(msr_fd, opts.ssbd, opts.seconds))
		exit(EXIT_FAILURE);

	if (opts.fork)
		exit_after_child(pid);
	else if (opts.exec && exec(opts.exec, opts.exec_argv))
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}
