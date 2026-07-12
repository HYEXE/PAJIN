"""Typed multi-agent execution graph and lifecycle contracts."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest


class AgentRole(StrEnum):
    SUPERVISOR = "supervisor"
    PLANNER = "planner"
    SPECIALIST = "specialist"
    VALIDATOR = "validator"
    REPORTER = "reporter"


class AgentStatus(StrEnum):
    SPAWNED = "spawned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(StrEnum):
    WAITING = "waiting"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentNode(StrictModel):
    agent_id: str = Field(default_factory=lambda: f"agent:{uuid4().hex}")
    role: AgentRole
    parent_agent_id: str | None = None
    depth: int = Field(ge=0)
    capability_grant_id: str
    status: AgentStatus = AgentStatus.SPAWNED
    error: str | None = None


class TaskNode(StrictModel):
    task_id: str = Field(default_factory=lambda: f"task_{uuid4().hex}")
    title: str
    assigned_agent_id: str | None = None
    depends_on: set[str] = Field(default_factory=set)
    status: TaskStatus = TaskStatus.WAITING
    request: ToolRequest | None = None
    attempts: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=1, ge=1, le=10)
    error: str | None = None


class TaskGraph(StrictModel):
    tasks: dict[str, TaskNode] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_dependencies(self) -> TaskGraph:
        task_ids = set(self.tasks)
        for task in self.tasks.values():
            unknown = task.depends_on - task_ids
            if unknown:
                raise ValueError(f"task depends on unknown tasks: {sorted(unknown)}")
            if task.task_id in task.depends_on:
                raise ValueError("task cannot depend on itself")
        self._assert_acyclic()
        return self

    def add(self, task: TaskNode) -> None:
        if task.task_id in self.tasks:
            raise ValueError(f"duplicate task ID: {task.task_id}")
        unknown = task.depends_on - set(self.tasks)
        if unknown:
            raise ValueError(f"task depends on unknown tasks: {sorted(unknown)}")
        self.tasks[task.task_id] = task
        try:
            self._assert_acyclic()
        except ValueError:
            del self.tasks[task.task_id]
            raise

    def ready(self) -> list[TaskNode]:
        return [
            task
            for task in self.tasks.values()
            if task.status is TaskStatus.WAITING
            and all(
                self.tasks[item].status
                in {TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.SKIPPED}
                for item in task.depends_on
            )
        ]

    def transition(self, task_id: str, status: TaskStatus, *, error: str | None = None) -> None:
        task = self.tasks[task_id]
        allowed = {
            TaskStatus.WAITING: {TaskStatus.RUNNING, TaskStatus.CANCELLED, TaskStatus.SKIPPED},
            TaskStatus.RUNNING: {
                TaskStatus.WAITING,
                TaskStatus.SUCCEEDED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
            },
        }
        if status not in allowed.get(task.status, set()):
            raise ValueError(f"invalid task transition: {task.status} -> {status}")
        task.status = status
        task.error = error

    def cancel_pending(self, reason: str) -> list[str]:
        cancelled: list[str] = []
        for task in self.tasks.values():
            if task.status in {TaskStatus.WAITING, TaskStatus.RUNNING}:
                task.status = TaskStatus.CANCELLED
                task.error = reason
                cancelled.append(task.task_id)
        return cancelled

    def _assert_acyclic(self) -> None:
        visited: set[str] = set()
        visiting: set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visiting:
                raise ValueError("task graph contains a dependency cycle")
            if task_id in visited:
                return
            visiting.add(task_id)
            for dependency in self.tasks[task_id].depends_on:
                visit(dependency)
            visiting.remove(task_id)
            visited.add(task_id)

        for task_id in self.tasks:
            visit(task_id)
