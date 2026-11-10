"""Synthetic slow-connection attacker; its OS UID cannot impersonate a peer."""
import asyncio,json,time
from pathlib import Path
from enkstein_guard.service import guarded_request

async def main():
    own=Path("/run/agent-token").read_text().strip()
    stolen=Path("/run/stolen-token").read_text().strip()
    denied=(await guarded_request("/run/guard/guard.sock",stolen,"read-b",{}))["status"]=="denied"
    cycles=0
    while cycles<3:
        connections=[]
        try:
            for _ in range(4):connections.append(await asyncio.open_unix_connection("/run/guard/guard.sock"))
            await asyncio.sleep(.05)
            if cycles==0:
                busy=(await guarded_request("/run/guard/guard.sock",own,"read-a",{}))["status"]=="busy"
                print(json.dumps({"ready":busy,"stolen_credential_denied":denied}),flush=True)
            await asyncio.sleep(1.75)
        finally:
            for reader,writer in connections:
                writer.close()
                try:await writer.wait_closed()
                except ConnectionError:pass
        cycles+=1
        await asyncio.sleep(.03)
    print(json.dumps({"attack_cycles":cycles,"stolen_credential_denied":denied}),flush=True)

asyncio.run(main())
