/*
 * msr.c: Helper functions for interacting with MSRs
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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/* Open the /dev/cpu/CPUNUM/msr file where CPUNUM is specified by cpu_num
 *
 * Returns a valid file descriptor, open for reading, on success. -1 on error.
 */
int open_msr_fd(int cpu_num)
{
	char msr_path[64];
	int msr_fd;
	int rc;

	rc = snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%d/msr", cpu_num);
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

/* Read the value from the MSR
 *
 * Returns 0 on success. -1 on error.
 */
int read_msr(uint64_t *value, int msr_fd, off_t msr)
{
	int rc;

	rc = pread(msr_fd, value, sizeof(*value), msr);
	if (rc < 0) {
		fprintf(stderr, "ERROR: Couldn't read MSR file: %m\n");
		return -1;
	} else if (rc != sizeof(value)) {
		fprintf(stderr, "ERROR: Short read of the MSR file\n");
		return -1;
	}

	return 0;
}
