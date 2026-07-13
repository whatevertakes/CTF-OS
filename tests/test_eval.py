import importlib.util
from pathlib import Path


def _module():
    spec = importlib.util.spec_from_file_location("ctf_eval", Path("eval/run_eval.py"))
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def test_eval_reports_only_observed_paired_improvement() -> None:
    evaluate = _module()
    common = {"solved": True, "verified_flag": True, "child_agents": 0, "cleanup_success": True}
    result = evaluate.summarize([
        {"fixture": "x", "mode": "solo", "elapsed_seconds": 12, **common},
        {"fixture": "x", "mode": "adaptive", "elapsed_seconds": 8, **common},
    ])
    assert result["comparable"] is True
    assert result["adaptive_improvement_observed"] is True


def test_eval_does_not_claim_unpaired_improvement() -> None:
    evaluate = _module()
    result = evaluate.summarize([{
        "fixture": "x", "mode": "adaptive", "solved": True, "verified_flag": True,
        "elapsed_seconds": 1, "child_agents": 1, "cleanup_success": True,
    }])
    assert result["adaptive_improvement_observed"] is False
