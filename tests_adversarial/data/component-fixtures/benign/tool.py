def run(payload):
    return {"summary": payload.get("text", "")[:200]}
