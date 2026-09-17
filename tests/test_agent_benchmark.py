import unittest

from cape_artifact.agent_benchmark import parse_buy


class AgentBenchmarkTests(unittest.TestCase):
    def test_parse_buy_json(self):
        self.assertIs(parse_buy('{"buy": true}'), True)
        self.assertIs(parse_buy('{"buy": false}'), False)

    def test_invalid_output_fails_closed(self):
        self.assertIsNone(parse_buy("BUY"))


if __name__ == "__main__":
    unittest.main()
