"""Typed host resource requests used by the CTF-OS lease broker.

Logical Codex roles deliberately do not appear here.  These values describe
host resources consumed by sandboxed tools only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class ResourceKind(str, Enum):
    CPU = "cpu"
    MEMORY_MIB = "memory_mib"
    GPU = "gpu"
    KVM = "kvm"
    NETWORK = "network"

    def __str__(self) -> str:
        return self.value


_FIELDS: Mapping[ResourceKind, str] = MappingProxyType(
    {
        ResourceKind.CPU: "cpu",
        ResourceKind.MEMORY_MIB: "memory_mib",
        ResourceKind.GPU: "gpu",
        ResourceKind.KVM: "kvm",
        ResourceKind.NETWORK: "network",
    }
)


@dataclass(frozen=True, slots=True)
class ResourceVector:
    """An integer resource vector.

    Memory uses MiB so comparisons and persisted lease records remain exact.
    A zero value means the resource is not requested.
    """

    cpu: int = 0
    memory_mib: int = 0
    gpu: int = 0
    kvm: int = 0
    network: int = 0

    def __post_init__(self) -> None:
        for field_name in _FIELDS.values():
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")

    @classmethod
    def one(cls, kind: ResourceKind | str, count: int = 1) -> ResourceVector:
        resource_kind = ResourceKind(kind)
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError("count must be a positive integer")
        return cls(**{_FIELDS[resource_kind]: count})

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> ResourceVector:
        if not isinstance(values, Mapping):
            raise ValueError("resource vector must be an object")
        unknown = set(values).difference(kind.value for kind in ResourceKind)
        if unknown:
            raise ValueError(f"unknown resource kinds: {sorted(unknown)}")
        return cls(
            **{
                _FIELDS[kind]: values.get(kind.value, 0)
                for kind in ResourceKind
            }
        )

    def as_dict(self) -> dict[str, int]:
        return {
            kind.value: getattr(self, field_name)
            for kind, field_name in _FIELDS.items()
        }

    def nonzero(self) -> dict[ResourceKind, int]:
        return {
            kind: getattr(self, field_name)
            for kind, field_name in _FIELDS.items()
            if getattr(self, field_name)
        }

    def is_empty(self) -> bool:
        return not self.nonzero()

    def fits_within(self, other: ResourceVector) -> bool:
        return all(
            getattr(self, field_name) <= getattr(other, field_name)
            for field_name in _FIELDS.values()
        )

    def overlaps(self, other: ResourceVector) -> bool:
        return any(
            getattr(self, field_name) and getattr(other, field_name)
            for field_name in _FIELDS.values()
        )

    def __add__(self, other: ResourceVector) -> ResourceVector:
        return ResourceVector(
            **{
                field_name: getattr(self, field_name) + getattr(other, field_name)
                for field_name in _FIELDS.values()
            }
        )

    def __sub__(self, other: ResourceVector) -> ResourceVector:
        values = {
            field_name: getattr(self, field_name) - getattr(other, field_name)
            for field_name in _FIELDS.values()
        }
        if any(value < 0 for value in values.values()):
            raise ValueError("resource vector subtraction would be negative")
        return ResourceVector(**values)

    def partial_for(self, available: ResourceVector) -> ResourceVector:
        """Return a partial single-kind allocation.

        Partial bundle allocation creates deadlock-prone resource fragments and
        is intentionally rejected.  Callers needing a tool bundle wait for the
        complete vector.
        """

        nonzero = self.nonzero()
        if len(nonzero) != 1:
            raise ValueError("partial allocation is supported for one kind only")
        kind, requested = next(iter(nonzero.items()))
        granted = min(requested, available.nonzero().get(kind, 0))
        return ResourceVector.one(kind, granted) if granted else ResourceVector()


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Global host-tool capacity.

    Defaults match the conservative baseline in the implementation report.
    They can only be changed by constructing a broker with explicit limits.
    """

    cpu: int = 8
    memory_mib: int = 18 * 1024
    gpu: int = 1
    kvm: int = 1
    network: int = 2

    def __post_init__(self) -> None:
        ResourceVector(
            cpu=self.cpu,
            memory_mib=self.memory_mib,
            gpu=self.gpu,
            kvm=self.kvm,
            network=self.network,
        )

    def as_vector(self) -> ResourceVector:
        return ResourceVector(
            cpu=self.cpu,
            memory_mib=self.memory_mib,
            gpu=self.gpu,
            kvm=self.kvm,
            network=self.network,
        )


TOOL_PROFILES: Mapping[str, ResourceVector] = MappingProxyType(
    {
        "light": ResourceVector(cpu=1, memory_mib=2 * 1024),
        "standard": ResourceVector(cpu=2, memory_mib=4 * 1024),
        "heavy": ResourceVector(cpu=4, memory_mib=8 * 1024),
        "gpu": ResourceVector(
            cpu=4,
            memory_mib=10 * 1024,
            gpu=1,
        ),
    }
)


def tool_profile(name: str, *, needs_kvm: bool = False, network: bool = False) -> ResourceVector:
    """Return a copy of a named tool profile with optional device resources."""

    try:
        base = TOOL_PROFILES[name]
    except KeyError as error:
        raise ValueError(f"unknown tool resource profile: {name}") from error
    return ResourceVector(
        cpu=base.cpu,
        memory_mib=base.memory_mib,
        gpu=base.gpu,
        kvm=1 if needs_kvm else 0,
        network=1 if network else 0,
    )


ToolResourceRequest = ResourceVector
