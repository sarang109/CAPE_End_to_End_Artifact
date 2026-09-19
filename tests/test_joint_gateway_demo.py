import unittest

from cape_artifact.joint_gateway_demo import demo


class JointGatewayDemoTests(unittest.TestCase):
    def test_joint_planning_saves_over_independent_planning(self):
        result = demo(fault_budget=1)
        self.assertIsNotNone(result["joint_plan_cost"])
        self.assertIsNotNone(result["independent_sum_cost"])
        self.assertLess(result["joint_plan_cost"], result["independent_sum_cost"])
        self.assertEqual(result["savings_from_joint_planning"], result["shared_source_cost"])

    def test_shared_source_is_used_in_the_joint_plan(self):
        result = demo(fault_budget=1)
        self.assertIn("merchant-payee-directory", result["joint_plan_sources"])


if __name__ == "__main__":
    unittest.main()
