# Tether Devpost submission draft

**Tagline** Turn an observed QNX workload into a reviewable, least-privilege policy and check normal behavior on a secure QNX boot.

**Category** Developer Tooling & Host Tools

## Inspiration

Embedded teams have to keep process abilities, channel connections, and path
attachments aligned with their applications as they change. Tether gives a
QNX developer a reviewable starting point based on the normal workload they
actually exercised.

## What it does

Tether is a host-based pipeline for QNX 8.0 targets:

```
observe ──► tighten ──► enforce ──► attack ──► report
```

1. **Observe:** boots QNX 8.0 in QEMU with `--secpol=open` and runs your app under `secpolgenerate`, recording the abilities, channels and path attachments it really uses.
2. **Tighten:** computes a least-privilege policy for that one type — everything unobserved is removed.
3. **Enforce:** recompiles the policy (`secpolcompile`) and reboots QNX with `--secpol=secure`.
4. **Verify** reruns the app's normal workload under the policy and captures
   the application output.
5. **Report** writes `report.html` and `run.json`. A passing run requires
   a zero workload exit code in both boots and a recorded denial.

The [archived report](https://tether-qnx.vercel.app/report.html) shows
`telemetryd` with three granted abilities and one recorded denial. Five
normal-workload lines appear in both output logs. The archived run predates
exit-code capture.

## How we built it

The Python CLI drives an x86-64 QEMU target over SSH. The QNX SDP 8.0
toolchain builds the demo service with `qcc`. The host can also narrow a
previously exported policy offline.

## Evidence of the QNX connection

Tether reads QNX 8.0 `secpolgenerate` output, narrows rules for a chosen
process type, compiles the policy with `secpolcompile`, and builds a secure
QNX image. The [build and run guide](../README.md#use) names the target and
toolchain.

The hosted report renders the captured logs from the repository. Host tests
cover the result and exit-code logic. A fresh QNX boot with the updated
verdict still needs to be recorded.

## Challenges

- The parser has to preserve the parts of the emitted policy that remain
  relevant to the narrowed application type.
- Anything the workload doesn't exercise is denied later: designing workloads that cover legitimate behaviour is the real usability problem of least-privilege, and Tether surfaces it instead of hiding it.

## Accomplishments

The report puts the generated policy, normal-workload evidence and recorded
denials next to each other, so a reviewer can trace the effect of narrowing
the application's abilities.

## What's next

Record an updated QNX run with both workload exit codes. Multi-type policies
and automated review of generated policy diffs are future work.

## Built with

`python` `qnx` `qnx-8.0` `security` `secpol` `least-privilege` `qemu` `embedded`

## Links

- Repository: https://github.com/himanshu748/tether-qnx
- Rendered report: https://tether-qnx.vercel.app/report.html
- Public YouTube walkthrough: pending

## Video shot list

| Time | Show |
| --- | --- |
| 0:00–0:20 | Developer selects an application type and a normal workload. |
| 0:20–1:00 | QNX SDP 8.0 and the x86-64 guest, with the observe and policy compilation stages visible. |
| 1:00–1:45 | Secure boot and the normal workload result. Keep both exit codes legible. |
| 1:45–2:25 | Open the generated report. Show the granted abilities, the recorded denial and the scope of the workload used. |
