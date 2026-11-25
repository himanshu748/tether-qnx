import json
import re

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
