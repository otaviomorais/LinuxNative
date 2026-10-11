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

## Milestone 1, 2, 3, 4 & 5: Android native validation (39 tests passed)

On the target Poco F3 (Android 17 / SDK 37, Linux kernel 4.19, Clang 21.1.8 in Termux),
the expanded test suite has been built and executed natively via `tools/test-termux.sh`.

| Milestone | Scope | Result | Execution time |
| --- | --- | --- | --- |
| Milestone 0 | Assembly probe (SVC rewriting, register preservation, basic file I/O) | 23 / 23 passed | ~0.28s |
| Milestone 1 | Freestanding C file inspector, 64-bit seek, metadata marshalling | 32 / 32 passed | ~0.68s |
| Milestone 2 | Virtual memory ABI (`mmap`, `munmap`, `mprotect`, `brk`), `uname`, W^X | 34 / 34 passed | ~0.40s |
| Milestone 3 | Credentials (`get*id`), Directory I/O (`getdents64`), Micro-libc & `mini-ls` | 36 / 36 passed | ~0.39s |
| Milestone 4 | Writable FS (`mkdirat`, `unlinkat`, `openat` write/create flags, `fs-mut`) | 38 / 38 passed | ~0.42s |
| Milestone 5 | Static PIE (`ET_DYN`) relocatable loading, `load_bias`, `pie-abi` | **39 / 39 passed** | **~0.44s** |

All tests pass without root, ptrace, or signal traps. Build outputs, device metadata,
and execution logs are recorded in `build/device-info.txt`, `build/device-build.log`,
and `build/device-test.log`.
