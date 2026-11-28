import json
import re

import pytest

from tether.report import Run, render
from tether.tighten import Grant


def test_render_embeds_run_safely():
    run = Run(app="telemetryd", type_name="telemetry_t", policy="type telemetry_t;</script>",
              grants=[Grant("ability", "spawn", "any", 2)], withheld=["setuid"], blocked=True)
    page = render(run)
    blob = re.search(r'id="run">(.*?)</script>', page, re.S).group(1)
    data = json.loads(blob)
    assert data["policy"].endswith("</script>") and data["grants"][0]["name"] == "spawn"
    assert "__RUN_DATA__" not in page


@pytest.mark.parametrize(
    ("observed", "enforced", "denial", "expected"),
    [
        (0, 0, True, "denial-recorded"),
        (0, 0, False, "denial-unconfirmed"),
        (1, 0, True, "workload-failed"),
        (0, 1, True, "workload-failed"),
        (None, 1, True, "workload-failed"),
        (None, None, True, "workload-unrecorded"),
    ],
)
def test_workload_status_is_required_before_passing(observed, enforced, denial, expected):
    run = Run(app="service", type_name="service_t", blocked=denial,
              observed_workload_exit=observed, enforced_workload_exit=enforced)
    encoded = json.loads(run.to_json())
    assert encoded["verification"] == expected
    assert encoded["observed_workload_exit"] == observed
    assert encoded["enforced_workload_exit"] == enforced
