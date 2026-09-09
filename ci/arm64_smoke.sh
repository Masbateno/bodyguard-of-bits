#!/bin/sh
# Runs inside the arm64 container. Mirrors the smoke contract the other
# distros are held to, plus the assertions that only mean something on ARM.
set -e

# --- Negative control, first and non-negotiable ------------------------------
# If QEMU registration failed or --platform was ignored, this container is
# x86_64 and every assertion below would pass for the wrong reason. A green
# job that never ran on ARM is worse than no job.
ARCH=$(uname -m)
echo "uname -m: $ARCH"
if [ "$ARCH" != "aarch64" ]; then
  echo "FAIL: expected aarch64, got '$ARCH' — emulation did not take effect"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 python3-venv ca-certificates >/dev/null

python3 -m venv /opt/bobenv
/opt/bobenv/bin/pip install --quiet . 
PATH="/opt/bobenv/bin:$PATH"; export PATH

echo "=== smoke ==="
bob --version
bob --help > /dev/null
bob --explain firewall.inactive > /dev/null

echo "=== audit hors ligne ==="
set +e
bob --offline -v > audit.txt 2>&1
rc=$?
set -e
echo "BOB exit code: $rc"
if [ "$rc" -gt 3 ]; then
  echo "FAIL: exit $rc (expected 0-3)"; tail -n 80 audit.txt; exit 1
fi
if grep -nE '\[[a-z_]+(\.[a-z_]+)+\]' audit.txt; then
  echo "FAIL: locale sentinel keys in output"; exit 1
fi
if grep -qE '^Traceback \(most recent call last\)' audit.txt; then
  echo "FAIL: Python traceback"; grep -A 40 -nE '^Traceback' audit.txt | head -n 60; exit 1
fi

echo "=== ce qui ne vaut que sur ARM ==="
# x86 firmware concepts must degrade, not deduct.
if ! grep -qi "no microcode package required" audit.txt; then
  echo "FAIL: microcode did not degrade on ARM"; grep -i microcode audit.txt; exit 1
fi
# The v0.17.0 fix: absent UEFI must not be *asserted* to be a BIOS this board
# does not have. The generic detail still says "on a PC this usually means
# legacy BIOS boot; on other hardware it may simply be how the machine boots",
# which is a hedge and stays — so the two assertive forms are pinned by name
# rather than the word pair, which would forbid the honest sentence too.
for claim in "Legacy BIOS detected" "This system uses a legacy BIOS"; do
  if grep -qF "$claim" audit.txt; then
    echo "FAIL: '$claim' — asserted on a board that has no BIOS"; exit 1
  fi
done
if ! grep -qi "No UEFI firmware found" audit.txt; then
  echo "FAIL: the no-UEFI message is missing or reworded"; grep -i uefi audit.txt; exit 1
fi

echo "=== Raspberry Pi simulé sur ARM réel ==="
mkdir -p /fakedt /boot/firmware
printf 'Raspberry Pi 4 Model B Rev 1.5\0' > /fakedt/model
printf 'arm_64bit=1\n' > /boot/firmware/config.txt
printf 'pi:$y$j9T$abcdefgh$0123456789abcdefghijklmnopqrstuvwxyz\n' > /boot/firmware/userconf.txt
touch /boot/firmware/ssh
cat > /tmp/pi_run.py <<'PY_EOF'
from pathlib import Path
import bob.platform as p
p._DEVICE_TREE_MODEL = Path("/fakedt/model")
import runpy
runpy.run_module("bob", run_name="__main__")
PY_EOF
set +e
python3 /tmp/pi_run.py --offline -v --check raspberry_pi > pi.txt 2>&1
rc=$?
set -e
echo "BOB exit code (pi): $rc"
for needle in "Raspberry Pi 4 Model B" "userconf.txt" "aarch64"; do
  if ! grep -q "$needle" pi.txt; then
    echo "FAIL: '$needle' missing from the Raspberry Pi section"
    tail -n 40 pi.txt; exit 1
  fi
done
if grep -nE '\[[a-z_]+(\.[a-z_]+)+\]' pi.txt; then
  echo "FAIL: locale sentinel in the Raspberry Pi section"; exit 1
fi
echo "OK — arm64 + Raspberry Pi section verified"
