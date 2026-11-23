#!/bin/sh
set -e
printf 'QX-0042\n'                > /var/telemetry/serial
printf 'gain=1.02 offset=-3\n'    > /var/telemetry/calibration
printf 'LOG boot self-test\n'     > /var/telemetry/ctl
printf 'READ serial\n'            > /var/telemetry/ctl
printf 'READ calibration\n'       > /var/telemetry/ctl
printf 'LOG cycle complete\n'     > /var/telemetry/ctl
