"""Legitimate requests run concurrently with the separate UID's flood."""
import asyncio,json,time,uuid
from pathlib import Path
from enkstein_guard.service import guarded_request

async def main():
    token=Path("/run/agent-token").read_text().strip()
    latencies=[]
    for _ in range(20):
        started=time.monotonic()
        result=await guarded_request("/run/guard/guard.sock",token,"read-b",{"task":"synthetic legitimate read"},request_id=str(uuid.uuid4()))
        assert result["status"]=="ok",result["status"]
        assert result["result"]["tenant"]=="b"
        latencies.append(time.monotonic()-started)
        await asyncio.sleep(.2)
    print(json.dumps({"legitimate_requests_completed":len(latencies),"max_seconds":max(latencies),"other_tenant_work_continued":True}))

asyncio.run(main())
