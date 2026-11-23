# Tether

Least-privilege QNX security policies, written from what your app actually does.

Tether runs an application on QNX OS 8.0 (in QEMU) under `secpolgenerate`, records
the abilities, channels and path attachments it really uses, and writes a security
policy for that one type and nothing else. It then pushes the policy, reruns the app
with an injected exploit, and shows in a report what QNX refused.

```
observe ──► tighten ──► enforce ──► attack ──► report
secpolgenerate  tether     secpolcompile  exploit   report.html
                           secpolpush     payload   + run.json
```

## Use

```sh
pip install -e .
# offline: tighten a policy captured from /dev/secpolgenerate/policy
tether tighten observed.secpol --type telemetry_t --unused unused.secpol \
  -o telemetry_t.secpol --json run.json
```

## Layout

| Path | What it is |
|---|---|
| `tether/secpol.py` | Parser/writer for the policy language `secpolgenerate` emits |
| `tether/tighten.py` | Extracts one type's rules, drops unused ones, ranks risk |
| `tether/target.py` | ssh/scp commands for a `mkqnximage` QEMU target |
| `tether/pipeline.py` | The observe → enforce → attack loop |
| `tether/report.py` | Self-contained HTML report |
| `qnx/demo/` | `telemetryd`, a small QNX service with a deliberate bug, plus workload and exploit |

## Tests

```sh
python -m pytest
```

## License

Apache-2.0
