# Tools for exercising Speculative Store Bypass Disable

The [ssbd-tools](https://github.com/tyhicks/ssbd-tools/) project is a
collection of programs that makes use of the Speculative Store Bypass Disable
(SSBD) functionality provided in x86 processors. SSBD is a processor based
mitigation for the Speculative Store Bypass attack that is referred to as
_Variant 4_ and assigned CVE-2018-3639. The Linux kernel introduced per-process
controls for making use of SSBD and these tools can be used to utilize those
controls and help verify their correctness.

## Per-process SSBD controls

The Linux kernel provides several different modes of operation, which can be
selected at boot time with the `spec_store_bypass_disable` kernel parameter,
for SSBD on x86 system. The [kernel parameters documentation](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)
describes them well. Here's a snippet from that document describing the
options:

```
  on      - Unconditionally disable Speculative Store Bypass
  off     - Unconditionally enable Speculative Store Bypass
  auto    - Kernel detects whether the CPU model contains an
            implementation of Speculative Store Bypass and
            picks the most appropriate mitigation. If the
            CPU is not vulnerable, "off" is selected. If the
            CPU is vulnerable the default mitigation is
            architecture and Kconfig dependent. See below.
  prctl   - Control Speculative Store Bypass per thread
            via prctl. Speculative Store Bypass is enabled
            for a process by default. The state of the control
            is inherited on fork.
  seccomp - Same as "prctl" above, but all seccomp threads
            will disable SSB unless they explicitly opt out.

  Not specifying this option is equivalent to
  spec_store_bypass_disable=auto.

  Default mitigations:
  X86:    If CONFIG_SECCOMP=y "seccomp", otherwise "prctl"
```

## CPU-specific details

The SSBD functionality is enabled/disabled by setting a single bit in a
model-specific register (MSR) of the processor. The exact MSR and bit location
inside of the MSR differs across CPU vendors, amongst CPU families from a
single vendor, and whether or not the kernel is running under a hypervisor.
These tools follow the guidelines published by
[Intel](https://software.intel.com/sites/default/files/managed/c5/63/336996-Speculative-Execution-Side-Channel-Mitigations.pdf)
and
[AMD](https://developer.amd.com/wp-content/resources/124441_AMD64_SpeculativeStoreBypassDisable_Whitepaper_final.pdf)
to decide where the SSBD bit is located for the current execution environment.

## Why SSBD may not be available

Some systems may not have SSBD support available. This could be due to a number
of reasons:

* Your processor requires updated microcode. This is the case for Intel
  processors. You may be able to access updated microcode via a firmware update
  or by installing your Linux distribution's microcode packages
  (`intel-microcode` and `amd64-microcode` for Debian/Ubuntu). AMD family 15h,
  16h, and 17h processors do not require updated microcode.
* Your kernel has not been updated to support SSBD. Many Linux OS vendors have
  issued updates so please look for details regarding your vendors at
  CERT's [Variant 4 page](https://www.kb.cert.org/vuls/id/180049).
* You're using a virtual machine and your hypervisor has not been updated to
  support SSBD. If you have control of the host environment, see the CERT page
  above for information on updating the relevant hypervisor software.

## Summary of programs in ssbd-tools

### ssbd-exec

The ssbd-exec program makes use of the per-process SSBD controls before
executing another program. It can use the `PR_SET_SPECULATION_CTRL` prctl to
allow speculation (`-p enable` to use `PR_SPEC_ENABLE`), disallow
speculation via SSBD (`-p disable` to use `PR_SPEC_DISABLE`), or permanently
disallow speculation in all future children processes via SSBD (`-p
force-disable` to use `PR_SPEC_FORCE_DISABLE`).

It can also load a permissive seccomp filter (`-s empty`) which, by default on
x86, opts the process into SSBD mitigation. There's also an option (`-s
spec-allow`) to load a permissive filter which doesn't opt the process into
SSBD.

#### Using ssbd-exec

* View /proc/PID/status to show that tasks don't use SSBD by default
```
 $ ./ssbd-exec -- grep Spec /proc/self/status
 Speculation_Store_Bypass:	thread vulnerable
```

* View /proc/PID/status when using SSBD via the prctl
```
 $ ./ssbd-exec -p disable -- grep -e Spec -e Seccomp /proc/self/status
 Seccomp:        0
 Speculation_Store_Bypass:       thread mitigated
```

* View /proc/PID/status when running with a permissive seccomp filter that opts
  the process into SSBD
```
 $ ./ssbd-exec -s empty -- grep -e Spec -e Seccomp /proc/self/status
 Seccomp:        2
 Speculation_Store_Bypass:       thread force mitigated
```

### ssbd-verify

The ssbd-verify program validates that the actual SSBD bit, in the MSR and bit
offset specific to your processor, is the expected value. _0_ means that SSBD
is not in use while _1_ means that it is in use.

The program can also be used to validate the task's `PR_GET_SPECULATION_CTRL`
prctl value is set to allow speculation (`-p enable` to verify
`PR_SPEC_ENABLE`), disallow speculation via SSBD (`-p disable` to verify
`PR_SPEC_DISABLE`), or permanently disallow speculation in all future children
processes via SSBD (`-p force-disable` to verify `PR_SPEC_FORCE_DISABLE`).

The program can be configured to repeatedly verify the SSBD bit's value using
the `-t SECONDS` options. If `SECONDS` is `0`, the program endlessly loops
while verifying the SSBD bit. A non-zero value for `SECONDS` results in the
program verifying the SSBD bit for the specified amount of time.

This program requires that the msr kernel module is loaded and that the user
has root privileges to read the SSBD bit from the appropriate MSR. 

#### Using ssbd-verify

* Verify that SSBD is not set by default
```
 $ sudo ./ssbd-verify 0
 $ sudo ./ssbd-verify 1
 FAIL: SSBD bit verification failed (expected 1, got 0)
```

* Verify that SSBD is set when using the prctl to disable speculation
```
 $ ./ssbd-exec -p disable -- sudo ./ssbd-verify 1
```

* Verify that SSBD is set when loading a seccomp filter
```
 $ sudo ./ssbd-exec -s empty -- ./ssbd-verify 1
```

**Note**: The command above requires sudo to be used on ssbd-exec because the
`NO_NEW_PRIVS` is used before loading the seccomp filter. sudo would not be
able to elevate privileges if used after `NO_NEW_PRIVS` is set.

### ssbd-toggle

The ssbd-toggle program simply toggles the SSBD bit on and off in an endless
loop until the program is terminated. It can be used in conjunction with
ssbd-verify to ensure that the ssbd-verify process always has the expected SSBD
bit value when the kernel is switches to its task.

This program requires that the msr kernel module is loaded and that the user
has root privileges to read from and write to the appropriate MSR.

#### Using ssbd-toggle

* Toggle the SSBD bit of processor 0 until the process is interrupted
```
 $ sudo ./ssbd-toggle
 ^C
```

## Building the tools

To build the tools, run make:

```
 $ make
```

## Test your system

To run some basic automated tests to ensure that SSBD is working as expected on
your system, run the check target as root:

```
 $ sudo make check
 PASS
```
