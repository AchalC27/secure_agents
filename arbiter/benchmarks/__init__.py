"""
Arbiter Benchmarks Package

Comprehensive evaluation framework for measuring security effectiveness,
performance, and comparative metrics for IEEE publication results.

Modules:
    - attacks: Attack simulation suite with AdvBench/HarmBench patterns
    - latency: Latency and throughput benchmarks
    - security: Security effectiveness metrics (TPR/FPR/MTTD/MTTR)
    - revocation: Revocation propagation benchmarks
    - ablation: Ablation study framework
    - runner: Main benchmark orchestration
    - report: JSON/CSV report generation
"""

from arbiter.benchmarks.attacks import AttackSuite, AttackCategory, CWECategory
from arbiter.benchmarks.latency import LatencyBenchmark, ThroughputBenchmark
from arbiter.benchmarks.security import SecurityBenchmark
from arbiter.benchmarks.ablation import AblationBenchmark
from arbiter.benchmarks.revocation import RevocationBenchmark
from arbiter.benchmarks.runner import BenchmarkRunner
from arbiter.benchmarks.report import BenchmarkReport

__all__ = [
    "AttackSuite",
    "AttackCategory",
    "CWECategory",
    "LatencyBenchmark",
    "ThroughputBenchmark",
    "SecurityBenchmark",
    "AblationBenchmark",
    "RevocationBenchmark",
    "BenchmarkRunner",
    "BenchmarkReport",
]
