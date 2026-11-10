"""Execute scoped attack/benign probes and report confirmed gaps separately.

Exit 0: no failures or known gaps. Exit 2: known coverage gaps remain.
Exit 1: unexpected failure, error, skip or success needs investigation.
A skipped scenario is missing evidence, never a prevented attack.
"""
import argparse
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

OUTCOMES = ("prevented_in_scenario", "benign_allowed", "gap_confirmed", "failed", "error",
            "gap_probe_changed_requires_review", "skipped")


class Results(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.records={}
    def record(self,test,outcome,**extra):
        metadata=getattr(getattr(test,test._testMethodName),"scenario",{})
        self.records[test.id()]={**metadata,"outcome":outcome,**extra}
    def addSuccess(self,test):
        super().addSuccess(test)
        self.record(test,"benign_allowed" if getattr(getattr(test,test._testMethodName),"scenario",{}).get("kind")=="benign" else "prevented_in_scenario")
    def addExpectedFailure(self,test,err):
        if not issubclass(err[0],AssertionError):
            self.addError(test,err)
            return
        super().addExpectedFailure(test,err)
        self.record(test,"gap_confirmed")
    def addUnexpectedSuccess(self,test):
        super().addUnexpectedSuccess(test)
        self.record(test,"gap_probe_changed_requires_review")
    def addSkip(self,test,reason):
        super().addSkip(test,reason)
        self.record(test,"skipped",skip_reason=str(reason)[:200])
    def addError(self,test,err):
        super().addError(test,err)
        self.record(test,"error")
    def addFailure(self,test,err):
        super().addFailure(test,err)
        self.record(test,"failed")
    def addSubTest(self,test,subtest,err):
        super().addSubTest(test,subtest,err)
        if err is not None:self.record(test,"failed")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    parser.add_argument("--suite",default="tests_adversarial")
    args=parser.parse_args()
    suite=unittest.defaultTestLoader.discover(str(Path(args.suite).resolve()))
    result=unittest.TextTestRunner(verbosity=2,resultclass=Results).run(suite)
    counts={outcome:sum(r["outcome"]==outcome for r in result.records.values()) for outcome in OUTCOMES}
    unexpected=counts["failed"]+counts["error"]+counts["gap_probe_changed_requires_review"]+counts["skipped"]
    requirements={}
    for prefix in ("LLM","ASI"):
        for number in range(1,11):
            rid=f"{prefix}{number:02d}:2026"
            scenarios={key:value for key,value in result.records.items() if rid in value.get("owasp",[])}
            requirements[rid]={"scenario_ids":list(scenarios),"outcomes":sorted({r["outcome"] for r in scenarios.values()}),
                "status":"gap_confirmed" if any(r["outcome"]=="gap_confirmed" for r in scenarios.values()) else
                         "scoped_evidence_only" if scenarios else "not_exercised",
                "full_category_acceptance":False}
    summary="%d prevented, %d benign allowed, %d confirmed gaps, %d skipped, %d failed, %d errors (%d executed)"%(
        counts["prevented_in_scenario"],counts["benign_allowed"],counts["gap_confirmed"],counts["skipped"],
        counts["failed"],counts["error"],result.testsRun)
    report={"evidence":evidence.header("attack-scenarios"),
            "version":evidence.installed_package()["version"],
            "scenario_count":result.testsRun,"counts":counts,"summary":summary,"scenarios":result.records,
            "requirements":requirements,
            "gate":"unexpected_failure" if unexpected or len(result.records)!=result.testsRun else
                   "blocked_known_gaps" if result.expectedFailures else "scoped_scenarios_passed",
            "scope":"Synthetic local configured boundaries; no live model robustness, enterprise deployment or complete framework protection claim"}
    Path(args.output).write_text(json.dumps(report,indent=2)+"\n")
    print(summary)
    if report["gate"]=="unexpected_failure":return 1
    return 2 if result.expectedFailures else 0

if __name__=="__main__":raise SystemExit(main())
