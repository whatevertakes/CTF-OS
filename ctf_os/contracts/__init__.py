"""Versioned, standard-library-only deterministic engine contracts.

Contract modules are append-only once their records may have been persisted.
New behavior belongs in a new versioned module rather than rewriting an older
module's fingerprint or semantic validator.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable

from .rev_inventory_v1 import (
    REV_INVENTORY_V1_CONTRACT_FINGERPRINT,
    REV_INVENTORY_V1_CONTRACT_ID,
    REV_INVENTORY_V1_CONTRACT_VERSION,
    RevInventoryV1Result,
    evaluate_rev_inventory_v1,
    evaluate_rev_inventory_v1_artifact_size,
)
from .rev_inventory_v2 import (
    REV_INVENTORY_V2_CONTRACT_FINGERPRINT,
    REV_INVENTORY_V2_CONTRACT_ID,
    REV_INVENTORY_V2_CONTRACT_VERSION,
    RevInventoryV2Result,
    evaluate_rev_inventory_v2,
    evaluate_rev_inventory_v2_artifact_size,
)


@dataclass(frozen=True, slots=True)
class RevInventoryContract:
    """One exact immutable parser selected by its full persisted identity."""

    oracle_id: str
    oracle_version: int
    contract_fingerprint: str
    evaluate: Callable[..., RevInventoryV1Result | RevInventoryV2Result]
    evaluate_artifact_size: Callable[
        ...,
        RevInventoryV1Result | RevInventoryV2Result | None,
    ]

    @property
    def identity(self) -> tuple[str, int, str]:
        return (
            self.oracle_id,
            self.oracle_version,
            self.contract_fingerprint,
        )


_REV_INVENTORY_CONTRACTS = (
    RevInventoryContract(
        oracle_id=REV_INVENTORY_V1_CONTRACT_ID,
        oracle_version=REV_INVENTORY_V1_CONTRACT_VERSION,
        contract_fingerprint=REV_INVENTORY_V1_CONTRACT_FINGERPRINT,
        evaluate=evaluate_rev_inventory_v1,
        evaluate_artifact_size=evaluate_rev_inventory_v1_artifact_size,
    ),
    RevInventoryContract(
        oracle_id=REV_INVENTORY_V2_CONTRACT_ID,
        oracle_version=REV_INVENTORY_V2_CONTRACT_VERSION,
        contract_fingerprint=REV_INVENTORY_V2_CONTRACT_FINGERPRINT,
        evaluate=evaluate_rev_inventory_v2,
        evaluate_artifact_size=evaluate_rev_inventory_v2_artifact_size,
    ),
)
REV_INVENTORY_CONTRACT_REGISTRY = MappingProxyType(
    {contract.identity: contract for contract in _REV_INVENTORY_CONTRACTS}
)
REV_INVENTORY_CONTRACT_FINGERPRINTS = MappingProxyType(
    {
        REV_INVENTORY_V1_CONTRACT_VERSION: (
            REV_INVENTORY_V1_CONTRACT_FINGERPRINT
        ),
        REV_INVENTORY_V2_CONTRACT_VERSION: (
            REV_INVENTORY_V2_CONTRACT_FINGERPRINT
        ),
    }
)


def resolve_rev_inventory_contract(
    oracle_id: object,
    oracle_version: object,
    contract_fingerprint: object,
) -> RevInventoryContract | None:
    """Resolve only an exact id/version/fingerprint triple."""

    if (
        type(oracle_id) is not str
        or type(oracle_version) is not int
        or type(contract_fingerprint) is not str
    ):
        return None
    return REV_INVENTORY_CONTRACT_REGISTRY.get(
        (oracle_id, oracle_version, contract_fingerprint)
    )


__all__ = [
    "REV_INVENTORY_CONTRACT_REGISTRY",
    "REV_INVENTORY_CONTRACT_FINGERPRINTS",
    "REV_INVENTORY_V1_CONTRACT_FINGERPRINT",
    "REV_INVENTORY_V1_CONTRACT_ID",
    "REV_INVENTORY_V1_CONTRACT_VERSION",
    "REV_INVENTORY_V2_CONTRACT_FINGERPRINT",
    "REV_INVENTORY_V2_CONTRACT_ID",
    "REV_INVENTORY_V2_CONTRACT_VERSION",
    "RevInventoryContract",
    "resolve_rev_inventory_contract",
]
