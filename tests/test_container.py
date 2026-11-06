"""Opt-in integration check for the real Docker termination boundary."""

import os
import unittest

from cs263_sandbox import harness


@unittest.skipUnless(
    os.environ.get("CS263_DOCKER_TESTS") == "1", "Set CS263_DOCKER_TESTS=1."
)
class ContainerIntegrationTest(unittest.TestCase):
    """Requires the built evaluation image and an available Docker daemon."""

    def test_deadline_stops_running_reference_and_cleans_up(self):
        settings = harness.Settings(wall_seconds=1.5)
        image_id = harness.resolve_image(settings.image)
        case = {
            "id": "external_deadline_check",
            "category": "resource",
            "code": "import time\ntime.sleep(2)\n0",
            "expected": {"status": "wall_timeout"},
        }
        record = harness.run_case(
            case, "reference", image_id, settings, "integration-test"
        )
        self.assertEqual(record["observed"]["status"], "wall_timeout")
        self.assertFalse(record["container"]["running"])
        self.assertTrue(record["cleanup_ok"])
        self.assertEqual(record["controller_errors"], [])


if __name__ == "__main__":
    unittest.main()
