"""Evaluate unlabelled-confidential-data detection on the versioned corpus.

Reports true/false positives and negatives for the heuristic detector, the
declared-context matcher and their combination, listing every miss and false
positive. Results describe this synthetic corpus only; they are not a general
detection rate and do not show that arbitrary confidential text is recognized.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

from enkstein_guard import __version__
from enkstein_guard.sensitivity import DeclaredContext, DeclaredEntry, heuristic_findings


def metrics(results, key):
    tp = [r["id"] for r in results if r["expected"] == "detect" and r[key]]
    fn = [r["id"] for r in results if r["expected"] == "detect" and not r[key]]
    fp = [r["id"] for r in results if r["expected"] == "no_detect" and r[key]]
    tn = [r["id"] for r in results if r["expected"] == "no_detect" and not r[key]]
    precision = len(tp) / (len(tp) + len(fp)) if tp or fp else None
    recall = len(tp) / (len(tp) + len(fn)) if tp or fn else None
    return {"true_positive": len(tp), "false_negative": len(fn), "false_positive": len(fp), "true_negative": len(tn),
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "missed_ids": fn, "false_positive_ids": fp}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default="tests_adversarial/data/unlabelled-corpus-v1.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    raw = Path(args.corpus).read_bytes()
    corpus = json.loads(raw)
    declared = DeclaredContext([DeclaredEntry(e["name"], e["level"], e["text"], e.get("canary", False))
                                for e in corpus["declared_context"]])
    results = []
    for case in corpus["cases"]:
        rules = sorted({rule for rule, _ in heuristic_findings(case["text"])})
        level, names = declared.match(case["text"])
        results.append({"id": case["id"], "category": case["category"], "expected": case["expected"],
                        "heuristic": bool(rules), "heuristic_rules": rules,
                        "declared": level is not None, "declared_entries": list(names),
                        "combined": bool(rules) or level is not None})
    report = {"evidence": evidence.header("unlabelled-detection-evaluation"),
              "version": __version__, "python": platform.python_version(), "corpus": corpus["name"],
              "corpus_sha256": hashlib.sha256(raw).hexdigest(), "cases": len(results),
              "adversarial": sum(r["category"] == "adversarial" for r in results),
              "benign": sum(r["category"] == "benign" for r in results),
              "detectors": {name: metrics(results, name) for name in ("heuristic", "declared", "combined")},
              "results": results,
              "interpretation": ("Synthetic corpus only. Declared-context matching recognizes verbatim and lightly "
                                 "obfuscated reuse of declared text; heuristics recognize explicit confidentiality "
                                 "markers. Paraphrase, translation, reversal and undeclared facts are missed. "
                                 "Heuristics are monitor-only by default because of the false positives listed.")}
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    for name, values in report["detectors"].items():
        print(name, {k: v for k, v in values.items() if not k.endswith("_ids")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
