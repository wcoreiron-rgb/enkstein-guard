"""Record actual unittest outcomes and check technique-to-test references.

Run with an installed wheel (no PYTHONPATH=src) for release evidence. The
report states passed, skipped (with reasons), failed and errored tests
separately: executed is not the same as passed.
"""
import argparse
from importlib.resources import files
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402


class Results(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.records={}
        self.skip_reasons={}
    def addSuccess(self,test):
        super().addSuccess(test)
        self.records.setdefault(test.id(),"passed")
    def addSkip(self,test,reason):
        super().addSkip(test,reason)
        self.records[test.id()]="skipped"
        self.skip_reasons[test.id()]=str(reason)[:200]
    def addFailure(self,test,err):
        super().addFailure(test,err)
        self.records[test.id()]="failed"
    def addError(self,test,err):
        super().addError(test,err)
        self.records[test.id()]="error"
    def addExpectedFailure(self,test,err):
        super().addExpectedFailure(test,err)
        self.records[test.id()]="expected_failure"
    def addUnexpectedSuccess(self,test):
        super().addUnexpectedSuccess(test)
        self.records[test.id()]="unexpected_success"
    def addSubTest(self,test,subtest,err):
        super().addSubTest(test,subtest,err)
        if err is not None:
            self.records[test.id()]="failed"


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--suite",default="tests")
    parser.add_argument("--output",required=True)
    parser.add_argument("--report",default="core-tests")
    args=parser.parse_args()
    suite=unittest.defaultTestLoader.discover(str(Path(args.suite).resolve()))
    result=unittest.TextTestRunner(verbosity=2,resultclass=Results).run(suite)
    atlas=json.loads(files("enkstein_guard").joinpath("atlas-evidence.json").read_text())
    mappings=[]
    for row in atlas["techniques"]:
        statuses={name:result.records.get(name,"not_executed") for name in row["tests"]}
        # A technique without component tests has no component result (null),
        # not a vacuous pass.
        mappings.append({"id":row["id"],"name":row["name"],"scope":"component_scenarios_only", "tests":statuses,
                         "referenced_tests":len(statuses),
                         "all_referenced_tests_passed":all(s=="passed" for s in statuses.values()) if statuses else None})
    counted=evidence.test_counts(result.records,result.skip_reasons)
    record={"evidence":evidence.header(args.report),
            "version":evidence.installed_package()["version"],
            "tests_run":result.testsRun,**counted,
            "successful":result.wasSuccessful(),
            "successful_meaning":"no failures or errors; skipped tests are not passes (see counts.skipped)",
            "tests":result.records,
            "atlas_source_sha256":atlas["sha256"],"atlas_component_evidence":mappings}
    if result.testsRun!=len(result.records):
        record["unrecorded_tests"]=result.testsRun-len(result.records)
        record["successful"]=False
    Path(args.output).write_text(json.dumps(record,indent=2)+"\n")
    print(counted["counts"]["summary"])
    return 0 if record["successful"] else 1

if __name__=="__main__":
    raise SystemExit(main())
