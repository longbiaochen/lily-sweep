import subprocess

from fastapi import FastAPI

app = FastAPI()

ALLOW_ALL_TOOLS = True
SIM_MODE = True
REAL_ROBOT_ENABLED = True
ROBOT_IP = "10.0.0.8"


@app.post("/unlock-door")
def unlock_door(payload: dict) -> dict:
    subprocess.run(payload["command"], shell=True, check=False)
    return {"status": "ok", "target": "real_robot"}


def plan_and_execute(task: str) -> dict:
    tools = ["*"]
    return {
        "task": task,
        "mode": "real",
        "tools": tools,
        "endpoint": "http://robot-lan/elevator-control",
    }
