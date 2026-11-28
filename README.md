# Tether

Least-privilege QNX security policies, written from what your app actually does.

Tether runs an application on QNX OS 8.0 (in QEMU) under `secpolgenerate`, records
the abilities, channels and path attachments it really uses, and writes a security
policy for that one type and nothing else. It then reboots QNX with that policy enforced, reruns the app
with an injected exploit, and shows in a report what QNX refused.

```
observe ──────────► tighten ──────► enforce ────────────► attack ──► report
boot --secpol=open   one type,      secpolcompile, reboot   workload   report.html
secpolgenerate       minus unused   --secpol=secure         + exploit  run.json
```

[Open the archived QNX 8.0 report](https://tether-qnx.vercel.app/report.html).
It records three granted abilities, 26 withheld entries from Tether's reference
list, and one application-reported denial. The enforced log contains the same
five normal-workload lines as the observed log. The archived run predates
workload exit-code capture. See the [judge evidence and replay scope](docs/DEVPOST.md#evidence-of-the-qnx-connection).

## Use

Needs QNX SDP 8.0 (free non-commercial licence), `qemu-system-x86_64`, and an ssh key.

```sh
pip install -e .
source ~/qnx800/qnxsdp-env.sh
make -C qnx/demo                     # builds telemetryd with qcc

# observe, tighten, enforce and attack on a fresh QEMU image (~1 minute with KVM)
tether run qnx/demo/telemetryd --type telemetry_t \
  --workload qnx/demo/workload.sh --exploit qnx/demo/exploit.sh --out runs/telemetryd

# offline: tighten a policy captured from /dev/secpolgenerate/policy
tether tighten observed.secpol --type telemetry_t --unused unused.secpol \
  -o telemetry_t.secpol --json run.json          # --system for the whole bootable policy
```

`tether run` exits 0 only when both workload scripts exit 0 and the run records
a denial. Both workload exit codes and the recorded verification state are in
`run.json`. Your app needs a workload
script that drives its normal behaviour and an exploit script; anything the workload
does not exercise is denied later, so make the workload complete.

## Layout

| Path | What it is |
|---|---|
| `tether/secpol.py` | Parser/writer for the policy language `secpolgenerate` emits |
| `tether/tighten.py` | Extracts one type's rules, drops unused ones, ranks risk |
| `tether/target.py` | ssh/scp to the QNX target |
| `tether/qemu.py` | Builds and boots `mkqnximage` images, pins their sshd keys |
| `tether/pipeline.py` | The observe → tighten → enforce → attack loop |
| `tether/report.py` | Self-contained HTML report |
| `qnx/demo/` | `telemetryd`, a small QNX service with a deliberate bug, plus workload and exploit |

## Tests

```sh
python -m pytest
```

## License

Apache-2.0
