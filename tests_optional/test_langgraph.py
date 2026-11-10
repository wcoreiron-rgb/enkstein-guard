import unittest

from enkstein_guard.reference import orchestration_reference


class LangGraphTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_graph_blocks_cross_agent_summary_exfiltration(self):
        result=await orchestration_reference(langgraph=True)
        self.assertTrue(result['blocked'])
        self.assertEqual(result['external_calls'],0)
        self.assertEqual(result['usage']['agents'],2)
