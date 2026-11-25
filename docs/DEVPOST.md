# Tether — Devpost submission draft

**Tagline:** Least-privilege QNX security policies, written from what your app actually does — then proven against a live exploit.

**Category:** Developer Tooling & Host Tools

## Inspiration

QNX ships one of the few mainstream capability-based security models in embedded systems — yet almost nobody writes secpolicies, because writing one by hand means enumerating every ability, channel and path attachment your process needs. We wanted the policy to write itself: watch what the application really does, and deny everything else.

## What it does

Tether is a host-based pipeline for QNX 8.0 targets:

```
observe ──► tighten ──► enforce ──► attack ──► report
```

1. **Observe:** boots QNX 8.0 in QEMU with `--secpol=open` and runs your app under `secpolgenerate`, recording the abilities, channels and path attachments it really uses.
2. **Tighten:** computes a least-privilege policy for that one type — everything unobserved is removed.
3. **Enforce:** recompiles the policy (`secpolcompile`) and reboots QNX with `--secpol=secure`.
4. **Attack:** reruns the app's normal workload — it must keep working — and then runs an injected exploit.
5. **Report:** writes `report.html` and `run.json` showing exactly what QNX refused. `tether run` exits 0 only when the exploit was refused.

On the committed demo run: `telemetryd` keeps working under its generated policy, while the injected `EXEC /bin/sh` fails with `Operation not permitted` — because `spawn` was never observed during normal behaviour.

## How we built it

Python host CLI (parser, tightening engine, runner, report generator) driving QEMU over ssh with the QNX SDP 8.0 toolchain. The demo target is a small C daemon built with `qcc`. The pipeline is the product: point it at your own app with a workload script and an exploit script.

## Evidence of the QNX connection

Everything in the pipeline is QNX-specific: `secpolgenerate`/`secpolcompile` are QNX 8.0 security-policy tools, the policy language is QNX's type/ability model, boot flags are QNX image options, and the attack proof is QNX's own refusal (`EPERM` on disallowed abilities). Unit-tested parser/CLI/report on the host; the on-target pipeline requires a QNX SDP host — this is disclosed plainly in the repository, including what has and has not been executed on target.

## Challenges

- secpolgenerate output is unstructured and version-specific — the parser had to be written against real observed output, not documentation.
- Anything the workload doesn't exercise is denied later: designing workloads that cover legitimate behaviour is the real usability problem of least-privilege, and Tether surfaces it instead of hiding it.

## Accomplishments

The honest end-to-end shape: not "we generated a policy" but "we enforced it, reran the workload, attacked it, and show you the refusal." Most security-tooling demos stop at generation.

## What's next

Running the full pipeline on a QNX SDP host (the repository documents exactly what remains unverified), multi-type policies, and CI integration so a policy diff is reviewable like code.

## Built with

`python` `qnx` `qnx-8.0` `security` `secpol` `least-privilege` `qemu` `embedded`

## Links

- Repository: https://github.com/himanshu748/tether-qnx
- Report sample: https://github.com/himanshu748/tether-qnx/blob/main/web/report.html
- Video: `YOUTUBE_URL_HERE`
