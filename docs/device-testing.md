# Test on the Poco F3 using Termux

The target device is a Poco F3 with Android 17 as reported by its owner. The
device report records the actual release/SDK at test time. USB ADB on a personal
computer is not automatically accessible from the cloud workspace.

## Get the source directly in Termux

Use the project's GitHub repository; no chat attachment, USB transfer, or
shared-storage permission is needed. Run inside Termux:

```sh
pkg install git clang make python
git clone --branch main https://github.com/otaviomorais/LinuxNative.git ~/LinuxNative
cd ~/LinuxNative
sh tools/test-termux.sh
```

If `~/LinuxNative` already exists, preserve it and choose a new destination
directory for the clone. If the repository is private, use your own authorized
GitHub access on the phone; do not paste credentials into chat. Keep the checkout
in Termux's app-private home, not shared storage such as `/sdcard`.

## Report results

The expected result is 23 passing tests. Copy the final summary or the actual
failure output into chat. Build and test errors are recorded separately:

```sh
cat build/device-info.txt
cat build/device-build.log
cat build/device-test.log
```

Only read logs that exist if an earlier step failed. The device script checks
tool availability and rebuilds generated targets for Android; it does not alter
the phone's system configuration or require root.

If executable-memory permissions or fixed mappings are denied, retain the exact
error. Do not disable SELinux or seccomp and do not root the device to force the
test to pass: those restrictions are part of the intended target.
