/*
 * ssbd.h: Helper functions for interacting with the SSBD bit
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

#ifndef __SSBD_H
#define __SSBD_H

#include <time.h>

#include "cpu.h"

int verify_ssbd_bit(int msr_fd, cpu_id cpu_id, bool expected, time_t seconds);
int verify_ssbd_prctl(int msr_fd, cpu_id cpu_id, int prctl_value);
void print_ssbd_prctl(int ssbd);

#endif
