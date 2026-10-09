# Validation record

## Milestone 0: user-reported Android execution

The device owner reported **23 tests passed / OK** after updating to the
`getconf` portability fix, commit `441843de50ff71041de9ec6ce6b3d199a944f5e1`.
They supplied the following device-info output. The report did not capture a
commit hash, so association with that commit follows the update instructions;
it is not independently measured from the phone.

| Property | Reported value |
| --- | --- |
| Report timestamp | 2026-10-09T16:18:35Z |
| Device | Poco F3 / M2012K11AG |
| Architecture | aarch64 |
| Android / SDK | 17 / 37 |
| Kernel | 4.19.325-cip136-st20-perf-gac2a025a05e6 |
| Page size | 4096 bytes |
| Compiler | Clang 21.1.8 |
| Compiler target | aarch64-unknown-linux-android24 |
| Execution | Termux device test script, native ARM64 |

This establishes user-reported success of the milestone-0 tests on this
configuration. The agent did not control the phone or inspect its processes.
It does not establish other-device/16 KiB compatibility or arbitrary Debian
application support. The complete test log has not been supplied.

## Next experiment: a separately compiled C executable

`build/file-scan` is a freestanding C program with ordinary Linux syscalls and
no imports from LinuxNative. It accepts a pathname argument, obtains metadata,
seeks, reads the file, and prints JSON with metadata and an FNV-1a fingerprint
(a non-cryptographic content check).

The expanded suite runs the **same executable** directly and under LinuxNative,
then compares both outputs with independently calculated Python/host results.
Cases include empty and multi-buffer binary files, Unicode/spaces in paths,
missing arguments/files, directories, invalid FDs, null fstat buffers, negative
and 64-bit offsets, and unchanged input ELF files. On x86_64 both ARM64 runs use
QEMU; on ARM64 they run directly. No performance conclusion follows from this.

This is still a custom-linked freestanding executable, not an ordinary
libc-linked or stripped Debian binary. It retains the milestone-0 ELF contract.
The expanded **32-test suite** requires a new Android run; the previous 23-test
report does not validate these changes.
