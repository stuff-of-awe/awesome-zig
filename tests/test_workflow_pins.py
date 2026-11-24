# SPDX-License-Identifier: MPL-2.0
"""Check the governance and Hypatia workflow pins against actions.lock.

With PyYAML installed, run: python3 -B -m unittest discover -s tests -p test_workflow_pins.py
The transitive coverage test reads the public callee files at their pinned SHAs.
"""

import re
import unittest
from pathlib import Path
from urllib.request import urlopen

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ".github/workflows"
STANDARDS = "hyperpolymath/standards"
CALLERS = {
    "governance.yml": ("governance", "governance-reusable.yml"),
    "hypatia-scan.yml": ("hypatia", "hypatia-scan-reusable.yml"),
}
SHA = re.compile(r"[0-9a-f]{40}")


def step_actions(workflow):
    """Return lockfile dependency keys for external actions called in steps."""
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if uses.startswith(("./", "docker://")) or "@" not in uses:
                continue
            action, _, ref = uses.rpartition("@")
            # The manifest locks the action repository, even for a subdirectory.
            yield f"{'/'.join(action.split('/')[:2])}@{ref}"


class WorkflowPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (ROOT / WORKFLOWS / "actions.lock").open(encoding="utf-8") as file:
            cls.lock = yaml.load(file, Loader=yaml.BaseLoader)

    def read_workflow(self, filename):
        with (ROOT / WORKFLOWS / filename).open(encoding="utf-8") as file:
            return yaml.load(file, Loader=yaml.BaseLoader)

    def caller_pin(self, filename, job, callee):
        caller = self.read_workflow(filename)
        target, _, ref = caller["jobs"][job]["uses"].rpartition("@")
        self.assertEqual(target, f"{STANDARDS}/{WORKFLOWS}/{callee}")
        self.assertIsNotNone(SHA.fullmatch(ref), f"{filename} must use an immutable pin")
        return ref

    def test_callers_are_pinned_to_the_same_standards_revision(self):
        pins = {self.caller_pin(filename, *call) for filename, call in CALLERS.items()}
        self.assertEqual(len(pins), 1, f"Standards pins drifted apart: {sorted(pins)}")

    def test_reusable_callers_are_registered_in_the_lockfile(self):
        for filename in CALLERS:
            with self.subTest(workflow=filename):
                self.assertIn(f"{WORKFLOWS}/{filename}", self.lock["workflows"])

    def test_pruning_preserves_direct_action_pins(self):
        for filename in ("action.yml", "runtime-policy.yml"):
            with self.subTest(workflow=filename):
                actions = set(step_actions(self.read_workflow(filename)))
                self.assertTrue(actions, f"{filename} should use external actions")
                self.assertLessEqual(actions, set(self.lock["workflows"][f"{WORKFLOWS}/{filename}"]))
                for action in sorted(actions):
                    with self.subTest(action=action):
                        entry = self.lock["dependencies"][action]
                        self.assertRegex(entry["commit"], r"\Asha1-[0-9a-f]{40}\Z")

    def test_pinned_reusable_workflow_step_actions_remain_locked(self):
        for filename, (job, callee_filename) in CALLERS.items():
            with self.subTest(workflow=filename):
                ref = self.caller_pin(filename, job, callee_filename)
                url = (
                    f"https://raw.githubusercontent.com/{STANDARDS}/{ref}/"
                    f"{WORKFLOWS}/{callee_filename}"
                )
                with urlopen(url, timeout=10) as response:
                    callee = yaml.load(response, Loader=yaml.BaseLoader)
                self.assertIn("workflow_call", callee["on"])
                actions = set(step_actions(callee))
                self.assertTrue(actions, f"{callee_filename} should use external actions")
                missing = actions - self.lock["dependencies"].keys()
                self.assertFalse(
                    missing,
                    f"actions.lock is missing dependencies for {job}@{ref}: {sorted(missing)}",
                )
                for action in sorted(actions):
                    with self.subTest(action=action):
                        pin = action.rpartition("@")[2]
                        if SHA.fullmatch(pin):
                            self.assertEqual(
                                self.lock["dependencies"][action]["commit"], f"sha1-{pin}"
                            )


if __name__ == "__main__":
    unittest.main()
