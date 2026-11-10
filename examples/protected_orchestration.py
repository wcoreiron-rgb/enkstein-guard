import argparse
import asyncio
import json

from enkstein_guard.reference import orchestration_reference

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--langgraph',action='store_true')
    args=parser.parse_args()
    print(json.dumps(asyncio.run(orchestration_reference(langgraph=args.langgraph))))
