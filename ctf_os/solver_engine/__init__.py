"""Solver backends and orchestration helpers."""

from .backend import SolverBackend
from .category_planner import CategoryPlanner, ExecutionContract, PlanParseError, SolvePlan, SolvePlanParser
from .context import ChallengeContext, ChallengeContextBuilder
from .knowledge import KnowledgeChunk, KnowledgeIndex, PlaybookSelector
from .loop_detector import LoopDetector, LoopSignal
from .mock_backend import MockBackend
from .parser import ActionObservationParser
from .prompt import PromptRenderer
from .race_plan import ATTEMPT_PROFILES, AttemptProfile, RaceAttempt, RacePlan
from .strategy_reranker import StrategyReranker
from .types import BackendResult, SolverEvent
from .verifier import VerificationResult, Verifier

__all__ = [
    "ATTEMPT_PROFILES",
    "ActionObservationParser",
    "AttemptProfile",
    "BackendResult",
    "ChallengeContext",
    "ChallengeContextBuilder",
    "CategoryPlanner",
    "ExecutionContract",
    "PlanParseError",
    "SolvePlan",
    "SolvePlanParser",
    "KnowledgeChunk",
    "KnowledgeIndex",
    "LoopDetector",
    "LoopSignal",
    "MockBackend",
    "PlaybookSelector",
    "PromptRenderer",
    "RaceAttempt",
    "RacePlan",
    "SolverBackend",
    "StrategyReranker",
    "SolverEvent",
    "VerificationResult",
    "Verifier",
]
