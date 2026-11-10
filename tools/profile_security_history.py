#!/usr/bin/env python3
"""Plan or run a bounded synthetic SecurityHistoryStore component profile.

This diagnostic creates only a fresh temporary store.  It is not deployment,
capacity, or production-acceptance evidence.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import cProfile
from dataclasses import dataclass
import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import pstats
import sqlite3
import sys
import tempfile
import time

import enkstein_guard
from enkstein_guard.contracts import Action, SecurityContext
from enkstein_guard.runtime import Operation
from enkstein_guard.security_assessment import SecurityAssessment
from enkstein_guard.security_context import SecurityHistoryStore
import enkstein_guard.security_context as security_context_module


PLAN_SCHEMA = "enkstein-guard.security-history-component-profile-plan/v1"
RESULT_SCHEMA = "enkstein-guard.security-history-component-profile-result/v1"
DEFAULT_OUTPUT = Path("verification/history-component-profiler/run")
PROFILE_NAME = "history-component.prof"
REPORT_NAME = "history-component.json"
TTL_SECONDS = 3_600
RECENT_LIMIT = 64
SYNTHETIC_NOW = 2_000_000_000.0


@dataclass(frozen=True)
class ProfileParameters:
    actors: int = 8
    per_actor_history: int = 256
    iterations: int = 1
    bulk_seed: bool = False

    def __post_init__(self) -> None:
        if type(self.actors) is not int or not 1 <= self.actors <= 16:
            raise ValueError("actors_must_be_between_1_and_16")
        if (type(self.per_actor_history) is not int
                or not 16 <= self.per_actor_history <= 256):
            raise ValueError("per_actor_history_must_be_between_16_and_256")
        if type(self.iterations) is not int or not 1 <= self.iterations <= 100:
            raise ValueError("iterations_must_be_between_1_and_100")
        if self.history_records > 4_096:
            raise ValueError("history_records_must_not_exceed_4096")
        if type(self.bulk_seed) is not bool:
            raise ValueError("bulk_seed_must_be_boolean")

    @property
    def history_records(self) -> int:
        return self.actors * self.per_actor_history

    @property
    def recent_calls(self) -> int:
        return self.actors * self.iterations

    @property
    def record_calls(self) -> int:
        return self.actors * self.iterations


# Descriptive public name while retaining the concise name used by early callers.
HistoryProfileParameters = ProfileParameters


def _arguments(parameters: ProfileParameters, output_dir: Path) -> list[str]:
    values = [
        "--actors", str(parameters.actors),
        "--per-actor-history", str(parameters.per_actor_history),
        "--iterations", str(parameters.iterations),
        "--output-dir", str(output_dir),
    ]
    if parameters.bulk_seed:
        values.append("--bulk-seed")
    return values


def build_plan(parameters: ProfileParameters, output_dir: Path) -> dict[str, object]:
    """Return a serializable plan without creating a store or output path."""
    output_dir = Path(output_dir)
    return {
        "schema": PLAN_SCHEMA,
        "mode": "plan",
        "evidence_class": "synthetic_component_diagnostic_only",
        "acceptance_eligible": False,
        "arguments": _arguments(parameters, output_dir),
        "parameters": {
            "actors": parameters.actors,
            "per_actor_history": parameters.per_actor_history,
            "history_records": parameters.history_records,
            "iterations": parameters.iterations,
            "recent_limit": min(RECENT_LIMIT, parameters.per_actor_history),
            "bulk_seed": parameters.bulk_seed,
        },
        "request_counts": {
            "recent": parameters.recent_calls,
            "record": parameters.record_calls,
            "total": parameters.recent_calls + parameters.record_calls,
        },
        "fixture": {
            "rows": parameters.history_records,
            "construction": (
                "authenticated_sqlite_bulk_seed"
                if parameters.bulk_seed else "public_record_calls"
            ),
            "complete_verification_required_before_timing": True,
            "temporary_store_only": True,
        },
        "scope_limits": {
            "actors": [1, 16],
            "per_actor_history": [16, 256],
            "history_records_maximum": 4_096,
            "iterations": [1, 100],
            "network": False,
            "subprocess": False,
            "deployment": False,
            "live_api": False,
        },
        "outputs": {
            "exclusive_directory": str(output_dir),
            "profile": PROFILE_NAME,
            "report": REPORT_NAME,
        },
        "side_effects_performed": {
            "temporary_store_created": False,
            "output_created": False,
        },
    }


def _synthetic_clock() -> float:
    return SYNTHETIC_NOW


def _operation(actor_number: int, record_number: int) -> Operation:
    tenant_number = actor_number // 4
    context = SecurityContext(
        f"synthetic-tenant-{tenant_number}",
        f"synthetic-principal-{actor_number}",
        f"synthetic-agent-{actor_number}",
        "synthetic-workflow",
        f"synthetic-operation-{actor_number}-{record_number}",
        "synthetic.inspect",
        "synthetic-policy-v1",
    )
    payload = "{}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return Operation(
        context,
        "synthetic.inspect",
        "synthetic-resource",
        "synthetic-local",
        payload,
        digest,
    )


def _assessment(number: int) -> SecurityAssessment:
    digest = hashlib.sha256(f"synthetic-assessment-{number}".encode("utf-8")).hexdigest()
    return SecurityAssessment(1, digest, "allow", "low", 1.0, ())


def _public_fixture(store: SecurityHistoryStore, parameters: ProfileParameters) -> None:
    number = 0
    for actor in range(parameters.actors):
        for record in range(parameters.per_actor_history):
            store.record(_operation(actor, record), _assessment(number), Action.ALLOW)
            number += 1


def _bulk_fixture(store: SecurityHistoryStore, parameters: ProfileParameters) -> None:
    """Seed authenticated synthetic rows using the store's encoding and keys.

    This intentionally uses private codec/key attributes for a diagnostic-only
    fast fixture.  Every resulting row is authenticated by ``verify`` before it
    can be included in the timed profile.
    """
    for actor in range(parameters.actors):
        store.record(_operation(actor, 0), _assessment(actor), Action.ALLOW)

    with closing(sqlite3.connect(store.database)) as connection:
        rows = connection.execute(
            "SELECT id,actor,tenant,created,expires,record FROM history ORDER BY id"
        ).fetchall()
        if len(rows) != parameters.actors:
            raise RuntimeError("synthetic_fixture_seed_count_mismatch")
        for actor, row in enumerate(rows):
            for record in range(1, parameters.per_actor_history):
                value = store._decrypt(row[-1])
                value["operation_id"] = f"synthetic-operation-{actor}-{record}"
                value["action_digest"] = hashlib.sha256(
                    f"synthetic-assessment-{actor}-{record}".encode("utf-8")
                ).hexdigest()
                encrypted = store._cipher.encrypt(store._encode(value))
                connection.execute(
                    "INSERT INTO history(actor,tenant,created,expires,record) "
                    "VALUES (?,?,?,?,?)",
                    (*row[1:5], encrypted),
                )
        connection.commit()


def _package_digest(package_root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in package_root.rglob("*.py") if path.is_file())
    for path in files:
        relative = path.relative_to(package_root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _distribution_version() -> str | None:
    try:
        return metadata.version("enkstein-guard")
    except metadata.PackageNotFoundError:
        return None


def _source_metadata() -> dict[str, object]:
    module_path = Path(security_context_module.__file__).resolve()
    package_root = Path(enkstein_guard.__file__).resolve().parent
    location_kind = (
        "installed_distribution"
        if any(part in {"site-packages", "dist-packages"} for part in package_root.parts)
        else "source_tree"
    )
    return {
        "location_kind": location_kind,
        "package_root": str(package_root),
        "security_context_path": str(module_path),
        "security_context_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
        "python_package_sha256": _package_digest(package_root),
        "reported_package_version": enkstein_guard.__version__,
        "installed_distribution_version": _distribution_version(),
    }


def _top_functions(profiler: cProfile.Profile, limit: int = 25) -> list[dict[str, object]]:
    rows = []
    for (filename, line, function), values in pstats.Stats(profiler).stats.items():
        primitive_calls, total_calls, total_seconds, cumulative_seconds, _ = values
        rows.append({
            "file": filename,
            "line": line,
            "function": function,
            "primitive_calls": primitive_calls,
            "total_calls": total_calls,
            "total_seconds": total_seconds,
            "cumulative_seconds": cumulative_seconds,
        })
    rows.sort(key=lambda row: (
        -row["cumulative_seconds"], -row["total_seconds"],
        row["file"], row["line"], row["function"],
    ))
    return rows[:limit]


def _profile_calls(
    store: SecurityHistoryStore,
    parameters: ProfileParameters,
    operations: tuple[Operation, ...],
) -> tuple[cProfile.Profile, float]:
    profiler = cProfile.Profile()
    started = time.perf_counter()
    profiler.enable()
    try:
        for iteration in range(parameters.iterations):
            for operation in operations:
                records = store.recent(
                    operation, min(RECENT_LIMIT, parameters.per_actor_history)
                )
                if len(records) != min(RECENT_LIMIT, parameters.per_actor_history):
                    raise RuntimeError("synthetic_fixture_recent_count_mismatch")
            for actor, operation in enumerate(operations):
                assessment_number = parameters.history_records + (
                    iteration * parameters.actors
                ) + actor
                store.record(operation, _assessment(assessment_number), Action.ALLOW)
    finally:
        profiler.disable()
    return profiler, time.perf_counter() - started


def execute(parameters: ProfileParameters, output_dir: Path) -> dict[str, object]:
    """Run the diagnostic and write an exclusive two-file result directory."""
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise FileExistsError(f"profile_output_already_exists:{output_dir}")

    plan = build_plan(parameters, output_dir)
    source_metadata = _source_metadata()
    with tempfile.TemporaryDirectory(prefix="enkstein-history-profile-") as temporary:
        temporary_root = Path(temporary)
        store = SecurityHistoryStore.initialize(
            temporary_root / "state" / "history.sqlite3",
            temporary_root / "keys" / "history.key",
            capacity=parameters.history_records,
            ttl_seconds=TTL_SECONDS,
            per_actor_capacity=parameters.per_actor_history,
            clock=_synthetic_clock,
        )
        if parameters.bulk_seed:
            _bulk_fixture(store, parameters)
        else:
            _public_fixture(store, parameters)

        fixture_verification = store.verify()
        if fixture_verification != {
            "status": "verified", "records": parameters.history_records
        }:
            raise RuntimeError("synthetic_fixture_verification_failed")

        operations = tuple(_operation(actor, parameters.per_actor_history)
                           for actor in range(parameters.actors))
        profiler, elapsed = _profile_calls(store, parameters, operations)
        final_verification = store.verify()
        if final_verification != fixture_verification:
            raise RuntimeError("synthetic_fixture_final_verification_failed")
        if _source_metadata() != source_metadata:
            raise RuntimeError("profile_source_changed_during_run")

        report = {
            "schema": RESULT_SCHEMA,
            "evidence_class": "synthetic_component_diagnostic_only",
            "acceptance_eligible": False,
            "plan": plan,
            "fixture_verification": fixture_verification,
            "final_verification": final_verification,
            "elapsed_seconds": elapsed,
            "profiled_request_counts": {
                "recent": parameters.recent_calls,
                "record": parameters.record_calls,
                "total": parameters.recent_calls + parameters.record_calls,
            },
            "runtime": {
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "python_executable": sys.executable,
                "platform": platform.platform(),
            },
            "source": source_metadata,
            "artifacts": {
                "output_directory": str(output_dir.resolve()),
                "profile": str((output_dir / PROFILE_NAME).resolve()),
                "report": str((output_dir / REPORT_NAME).resolve()),
            },
            "top_functions": _top_functions(profiler),
        }

        output_dir.parent.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(mode=0o700, exist_ok=False)
        profiler.dump_stats(str(output_dir / PROFILE_NAME))
        with (output_dir / REPORT_NAME).open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="execute the synthetic profile; otherwise print only the plan")
    parser.add_argument("--actors", type=int, default=8)
    parser.add_argument("--per-actor-history", type=int, default=256)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--bulk-seed", action="store_true",
                        help="use authenticated synthetic SQLite seeding before verification")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    parameters = ProfileParameters(
        actors=arguments.actors,
        per_actor_history=arguments.per_actor_history,
        iterations=arguments.iterations,
        bulk_seed=arguments.bulk_seed,
    )
    if not arguments.run:
        print(json.dumps(build_plan(parameters, arguments.output_dir), indent=2, sort_keys=True))
        return 0
    report = execute(parameters, arguments.output_dir)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
