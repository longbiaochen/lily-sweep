"""
Unsafe example: LLM tool dispatcher that forwards agent output
to shell execution and actuator HTTP calls without validation.

Every pattern here is intentionally unsafe and is used as a test fixture.
"""
import pickle
import subprocess

import requests

ACTUATOR_URL = "http://robot-lan/arm_controller"


def dispatch_llm_action(llm_response: dict) -> None:
    """Forward LLM action directly to shell — no sanitization."""
    subprocess.run(llm_response["action"], shell=True)


def execute_tool_call(tool_result: str) -> None:
    """Pass raw tool output to an actuator endpoint — no validation."""
    requests.post(ACTUATOR_URL, data={"command": tool_result})


def load_plan(serialized_plan: bytes) -> dict:
    """Deserialize an agent plan with pickle — allows arbitrary code execution."""
    return pickle.loads(serialized_plan)


def eval_condition(user_condition: str) -> bool:
    """Evaluate a planner-supplied condition string — arbitrary Python execution."""
    return bool(eval(user_condition))
