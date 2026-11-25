"""Agent framework: role definitions, capability-restricted tool broker, audited execution.

Every specialised agent declares the capabilities it needs. The ToolBroker hands
out only those services; anything else raises CapabilityDenied and is audited.
Capabilities that would change the system (file modification, quarantine,
approval issuing, keystore access) do not exist in the broker at all, so no
agent can obtain them, by design.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from ..util import dumps, new_id, utcnow_iso

if TYPE_CHECKING:
    from ..engine import Engine

# capabilities that are never grantable; requesting them is logged as a policy violation
FORBIDDEN = {"fs.modify", "fs.delete", "quarantine.write", "approval.issue", "keystore.read", "executor.run", "process.kill"}


class CapabilityDenied(PermissionError):
    pass


class ReadOnlyEvidence:
    def __init__(self, em):
        self._em = em

    def __iter__(self):
        return iter(self._em)

    def __len__(self):
        return len(self._em)

    def get(self, key):
        return self._em.get(key)

    def by_path(self, path, target_type="file"):
        return self._em.by_path(path, target_type)


def _service_table() -> dict[str, Callable[["Engine", dict], Any]]:
    from ..behavioral import network, processes
    from ..malware import pe_analysis
    from ..remediation import repair
    from ..verification import verifier
    from ..vulnerability import config_checks, dependencies, tools
    from .. import persistence, scope

    return {
        "scope.read": lambda e, c: scope,
        "fs.analyze": lambda e, c: c["analyzer"],
        "detect.clamav": lambda e, c: e.clamav,
        "detect.defender": lambda e, c: e.defender,
        "authenticode.read": lambda e, c: pe_analysis.authenticode_status,
        "proc.read": lambda e, c: processes,
        "net.read": lambda e, c: network,
        "persist.read": lambda e, c: persistence,
        "config.read": lambda e, c: config_checks,
        "vuln.deps": lambda e, c: dependencies,
        "vuln.tools": lambda e, c: tools,
        "intel.online": lambda e, c: e.intel,
        "evidence.read": lambda e, c: ReadOnlyEvidence(c["evidence"]),
        "evidence.write": lambda e, c: c["evidence"],
        "plan.write": lambda e, c: repair,
        "verify.read": lambda e, c: verifier,
        "recovery.inspect": lambda e, c: e.recovery,
        "store.read": lambda e, c: e.store,
    }


class ToolBroker:
    def __init__(self, engine: "Engine", agent: "Agent", ctx: dict[str, Any], run_id: str):
        self.engine = engine
        self.agent = agent
        self.ctx = ctx
        self.run_id = run_id
        self.used: set[str] = set()
        self.denied: list[str] = []
        self._table = _service_table()

    def use(self, capability: str) -> Any:
        if capability in FORBIDDEN or capability not in self.agent.capabilities or capability not in self._table:
            self.denied.append(capability)
            self.engine.audit.append("agent.capability_denied", f"agent:{self.agent.name}",
                                     {"capability": capability, "run_id": self.run_id})
            raise CapabilityDenied(f"Agent '{self.agent.name}' is not allowed to use '{capability}'.")
        self.used.add(capability)
        return self._table[capability](self.engine, self.ctx)

    def can(self, capability: str) -> bool:
        return capability in self.agent.capabilities and capability in self._table and capability not in FORBIDDEN


@dataclass
class Agent:
    name: str = "agent"
    role: str = ""
    responsibility: str = ""
    capabilities: frozenset[str] = field(default_factory=frozenset)
    inputs: str = ""
    outputs: str = ""

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role, "responsibility": self.responsibility,
                "capabilities": sorted(self.capabilities), "inputs": self.inputs, "outputs": self.outputs,
                "can_modify_system": False}

    def run(self, broker: ToolBroker, ctx: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError


def run_agent(engine: "Engine", agent: Agent, ctx: dict[str, Any], scan_id: str | None) -> dict[str, Any]:
    """Execute an agent with a fresh broker; record an auditable run history."""
    run_id = new_id("AR")
    started = time.time()
    engine.store.execute("INSERT INTO agent_runs(id, scan_id, agent, started_at, status, capabilities) VALUES (?,?,?,?,?,?)",
                         (run_id, scan_id, agent.name, utcnow_iso(), "running", dumps(sorted(agent.capabilities))))
    broker = ToolBroker(engine, agent, ctx, run_id)
    status, summary = "completed", {}
    try:
        summary = agent.run(broker, ctx) or {}
    except CapabilityDenied as exc:
        status, summary = "denied", {"error": str(exc)}
    except Exception as exc:  # an agent failure must not abort the whole scan
        status, summary = "failed", {"error": f"{type(exc).__name__}: {exc}"[:500]}
    summary["duration_s"] = round(time.time() - started, 2)
    engine.store.execute("UPDATE agent_runs SET finished_at=?, status=?, tools_used=?, denied=?, summary=? WHERE id=?",
                         (utcnow_iso(), status, dumps(sorted(broker.used)), dumps(broker.denied), dumps(summary), run_id))
    engine.audit.append("agent.run", f"agent:{agent.name}", {"run_id": run_id, "scan_id": scan_id, "status": status,
                                                            "tools_used": sorted(broker.used), "denied": broker.denied})
    return {"agent": agent.name, "run_id": run_id, "status": status, "summary": summary}
