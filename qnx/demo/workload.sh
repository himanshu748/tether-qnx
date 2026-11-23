#!/bin/sh
# Normal workload: what telemetryd legitimately does. Run on the target while
# secpolgenerate is observing.
set -e
printf 'LOG boot self-test\n'     > /var/telemetry/ctl
printf 'READ serial\n'            > /var/telemetry/ctl
printf 'READ calibration\n'       > /var/telemetry/ctl
printf 'LOG cycle complete\n'     > /var/telemetry/ctl
