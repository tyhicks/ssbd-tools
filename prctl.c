/*
 * prctl.c: Helper functions for interacting with prctl()
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
#include <stdbool.h>
#include <stdio.h>
#include <sys/prctl.h>


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
