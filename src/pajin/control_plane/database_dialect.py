"""Dialect-specific schema signatures, validation, and SQL generation.

This module is read-only with respect to database state: validators inspect
managed schema and SQL builders return deterministic strings. Migration
transactions and DDL installation remain in database_migrations.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.engine import Connection

from pajin.control_plane.database_schema import (
    _JOB_JSON_STORAGE_MAX_BYTES,
    _RUN_JSON_STORAGE_MAX_BYTES,
    _V7_METADATA,
    COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
    Base,
    JobRecord,
    RunRecord,
    SchemaInitializationError,
    SchemaVersionRecord,
    _lower_hex_check,
)
from pajin.control_plane.models import (
    CONTROL_PLANE_STORED_JSON_POLICY,
    SUBMIT_RUN_INPUT_JSON_POLICY,
)


def _strict_json_object(value: str, *, allow_null: bool) -> dict[str, Any] | None:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        for key, item in pairs:
            if key in decoded:
                raise ValueError("duplicate JSON object key")
            decoded[key] = item
        return decoded

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    decoded = json.loads(
        value,
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )
    if decoded is None and allow_null:
        return None
    if not isinstance(decoded, dict):
        raise ValueError("JSON authority must be an object")
    return decoded


def _validate_sqlite_datetime_columns(connection: Connection, table: Table) -> None:
    """Require the exact SQLAlchemy SQLite DATETIME storage representation."""

    for column in table.columns:
        if not isinstance(column.type, DateTime):
            continue
        invalid = int(
            connection.scalar(
                text(
                    f'SELECT count(*) FROM "{table.name}" '
                    f'WHERE "{column.name}" IS NOT NULL AND '
                    f"({_sqlite_datetime_is_invalid_sql(f'{column.name}')})"
                )
            )
            or 0
        )
        if invalid:
            raise SchemaInitializationError(
                f"{table.name}.{column.name} contains invalid datetime authority rows"
            )


def _is_managed_postgres_sequence_default(
    connection: Connection,
    *,
    table_name: str,
    column_name: str,
    value: object,
) -> bool:
    """Accept only SQLAlchemy's one intentional PostgreSQL SERIAL default."""

    if (
        connection.dialect.name != "postgresql"
        or table_name != SchemaVersionRecord.__tablename__
        or column_name != "version"
    ):
        return False
    current_schema = str(connection.scalar(text("SELECT current_schema()")))
    normalized = str(value).replace('"', "")
    return normalized in {
        "nextval('cp_schema_version_version_seq'::regclass)",
        f"nextval('{current_schema}.cp_schema_version_version_seq'::regclass)",
    }


def _column_type_family(column_type: Any) -> str:
    if isinstance(column_type, JSON):
        return "json"
    if isinstance(column_type, DateTime):
        return "datetime"
    if isinstance(column_type, Integer):
        return "integer"
    if isinstance(column_type, LargeBinary):
        return "binary"
    if isinstance(column_type, Text):
        return "text"
    if isinstance(column_type, String):
        return "string"
    return type(column_type).__name__.lower()


def _validate_unique_constraints(inspector: Any, table_name: str, expected: Any) -> None:
    from sqlalchemy import UniqueConstraint as SqlAlchemyUniqueConstraint

    expected_sets = Counter(
        tuple(column.name for column in constraint.columns)
        for constraint in expected.constraints
        if isinstance(constraint, SqlAlchemyUniqueConstraint)
    )
    inspected_constraints = inspector.get_unique_constraints(table_name)
    if any(
        bool((constraint.get("dialect_options") or {}).get("postgresql_nulls_not_distinct"))
        or bool(constraint.get("include_columns"))
        for constraint in inspected_constraints
    ):
        raise SchemaInitializationError(
            f"{table_name} has a unique constraint with unmanaged options"
        )
    actual_sets = Counter(
        tuple(constraint.get("column_names") or ()) for constraint in inspected_constraints
    )
    if expected_sets != actual_sets:
        raise SchemaInitializationError(
            f"{table_name} unique constraints do not match managed schema "
            f"(actual={sorted(actual_sets.elements())!r}, "
            f"expected={sorted(expected_sets.elements())!r})"
        )


def _validate_foreign_keys(inspector: Any, table_name: str, expected: Any) -> None:
    expected_fks = Counter(
        (
            tuple(element.parent.name for element in constraint.elements),
            str(constraint.referred_table.schema or ""),
            constraint.referred_table.name,
            tuple(element.column.name for element in constraint.elements),
            str(constraint.ondelete or "").upper(),
            str(constraint.onupdate or "").upper(),
            bool(constraint.deferrable),
            str(constraint.initially or "").upper(),
            str(constraint.match or "").upper(),
        )
        for constraint in expected.foreign_key_constraints
    )
    actual_fks = Counter(
        (
            tuple(constraint.get("constrained_columns") or ()),
            str(constraint.get("referred_schema") or ""),
            str(constraint.get("referred_table")),
            tuple(constraint.get("referred_columns") or ()),
            str((constraint.get("options") or {}).get("ondelete") or "").upper(),
            str((constraint.get("options") or {}).get("onupdate") or "").upper(),
            bool((constraint.get("options") or {}).get("deferrable")),
            str((constraint.get("options") or {}).get("initially") or "").upper(),
            str((constraint.get("options") or {}).get("match") or "").upper(),
        )
        for constraint in inspector.get_foreign_keys(table_name)
    )
    if expected_fks != actual_fks:
        raise SchemaInitializationError(f"{table_name} foreign keys do not match managed schema")


def _validate_check_constraints(
    connection: Connection, inspector: Any, table_name: str, expected: Any
) -> None:
    from sqlalchemy import CheckConstraint as SqlAlchemyCheckConstraint

    expected_constraints = {
        str(constraint.name): str(constraint.sqltext)
        for constraint in expected.constraints
        if isinstance(constraint, SqlAlchemyCheckConstraint)
    }
    inspected_constraints = inspector.get_check_constraints(table_name)
    if any(
        bool((constraint.get("dialect_options") or {}).get("postgresql_not_valid"))
        or bool((constraint.get("dialect_options") or {}).get("postgresql_no_inherit"))
        for constraint in inspected_constraints
    ):
        raise SchemaInitializationError(
            f"{table_name} has a check constraint with unmanaged options"
        )
    if any(constraint.get("name") is None for constraint in inspected_constraints):
        raise SchemaInitializationError(f"{table_name} has an unmanaged unnamed check constraint")
    actual_constraints = {
        str(constraint["name"]): str(constraint.get("sqltext") or "")
        for constraint in inspected_constraints
    }
    if len(actual_constraints) != len(inspected_constraints) or set(expected_constraints) != set(
        actual_constraints
    ):
        raise SchemaInitializationError(
            f"{table_name} check constraint set does not match managed schema "
            f"(actual={sorted(actual_constraints)!r}, "
            f"expected={sorted(expected_constraints)!r})"
        )
    for name, expected_sql in expected_constraints.items():
        actual_sql = actual_constraints[name]
        if connection.dialect.name == "sqlite":
            matches = _normalize_check_sql(actual_sql) == _normalize_check_sql(expected_sql)
        else:
            matches = _postgres_check_signature(actual_sql, expected_sql, expected)
        if not matches:
            matches = _matches_frozen_parser_deep_check(
                connection,
                table_name=table_name,
                constraint_name=name,
                actual_sql=actual_sql,
                expected_sql=expected_sql,
            )
        if not matches:
            raise SchemaInitializationError(
                f"{table_name} check constraint {name} does not match managed schema"
            )


_PARSER_SAFE_CHECK_NAMES = frozenset(
    {
        "ck_cp_artifacts_sealed_run_id",
        "ck_cp_artifacts_media_type",
        "ck_cp_artifacts_schema_kind",
        "ck_cp_replay_execution_contexts_executor_profile",
    }
)


def _matches_frozen_parser_deep_check(
    connection: Connection,
    *,
    table_name: str,
    constraint_name: str,
    actual_sql: str,
    expected_sql: str,
) -> bool:
    """Accept only the exact semantically equivalent v1-v8 rendering after v9."""

    if constraint_name not in _PARSER_SAFE_CHECK_NAMES:
        return False
    current_table = Base.metadata.tables.get(table_name)
    legacy_table = _V7_METADATA.tables.get(table_name)
    if current_table is None or legacy_table is None:
        return False
    current = next(
        (
            item
            for item in current_table.constraints
            if isinstance(item, CheckConstraint) and item.name == constraint_name
        ),
        None,
    )
    legacy = next(
        (
            item
            for item in legacy_table.constraints
            if isinstance(item, CheckConstraint) and item.name == constraint_name
        ),
        None,
    )
    if current is None or legacy is None:
        return False
    current_sql = str(current.sqltext)
    legacy_sql = str(legacy.sqltext)
    expected = _normalize_check_sql(expected_sql)
    current_normalized = _normalize_check_sql(current_sql)
    legacy_normalized = _normalize_check_sql(legacy_sql)
    if connection.dialect.name == "sqlite":
        actual = _normalize_check_sql(actual_sql)
        return (expected, actual) in {
            (current_normalized, legacy_normalized),
            (legacy_normalized, current_normalized),
        }
    if expected == current_normalized:
        return _postgres_check_signature(actual_sql, legacy_sql, legacy_table)
    if expected == legacy_normalized:
        return _postgres_check_signature(actual_sql, current_sql, current_table)
    return False


def _validate_postgres_constraint_flags(connection: Connection, table_name: str) -> None:
    """Reject constraint states omitted by SQLAlchemy's PostgreSQL inspector."""

    rows = connection.execute(
        text(
            "SELECT managed_constraint.conname AS constraint_name, "
            "managed_constraint.contype AS constraint_type, "
            "managed_constraint.convalidated AS is_validated, "
            "managed_constraint.connoinherit AS no_inherit, "
            "managed_constraint.condeferrable AS is_deferrable, "
            "managed_constraint.condeferred AS is_initially_deferred "
            "FROM pg_constraint AS managed_constraint "
            "JOIN pg_class AS relation "
            "ON relation.oid = managed_constraint.conrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = current_schema() "
            "AND relation.relname = :table_name "
            "AND managed_constraint.contype IN ('c', 'f', 'u')"
        ),
        {"table_name": table_name},
    ).all()
    invalid = [
        str(row.constraint_name)
        for row in rows
        if not bool(row.is_validated)
        or (str(row.constraint_type) == "c" and bool(row.no_inherit))
        or bool(row.is_deferrable)
        or bool(row.is_initially_deferred)
    ]
    if invalid:
        raise SchemaInitializationError(
            f"{table_name} has constraints with unmanaged catalog flags: {sorted(invalid)!r}"
        )


def _validate_postgres_relation_catalog(connection: Connection, table_name: str) -> None:
    """Validate PostgreSQL relation properties and semantic hook inventory."""

    relation_rows = connection.execute(
        text(
            "SELECT relation.relkind AS relation_kind, "
            "relation.relpersistence AS relation_persistence, "
            "relation.relrowsecurity AS row_security, "
            "relation.relforcerowsecurity AS force_row_security, "
            "EXISTS ("
            "SELECT 1 FROM pg_inherits AS inheritance "
            "WHERE inheritance.inhparent = relation.oid "
            "OR inheritance.inhrelid = relation.oid"
            ") AS has_inheritance "
            "FROM pg_class AS relation "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = current_schema() "
            "AND relation.relname = :table_name"
        ),
        {"table_name": table_name},
    ).all()
    if len(relation_rows) != 1:
        raise SchemaInitializationError(
            f"{table_name} relation catalog does not match managed schema"
        )
    relation = relation_rows[0]
    if str(relation.relation_kind) != "r":
        raise SchemaInitializationError(f"{table_name} relation kind does not match managed schema")
    if str(relation.relation_persistence) != "p":
        raise SchemaInitializationError(
            f"{table_name} relation persistence does not match managed schema"
        )
    if bool(relation.has_inheritance):
        raise SchemaInitializationError(
            f"{table_name} inheritance inventory does not match managed schema"
        )
    if bool(relation.row_security) or bool(relation.force_row_security):
        raise SchemaInitializationError(f"{table_name} row security does not match managed schema")

    policy_rows = connection.execute(
        text(
            "SELECT policy.polname AS policy_name "
            "FROM pg_policy AS policy "
            "JOIN pg_class AS relation ON relation.oid = policy.polrelid "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = current_schema() "
            "AND relation.relname = :table_name"
        ),
        {"table_name": table_name},
    ).all()
    if policy_rows:
        raise SchemaInitializationError(
            f"{table_name} row security policy inventory does not match managed schema: "
            f"{sorted(str(row.policy_name) for row in policy_rows)!r}"
        )

    rows = connection.execute(
        text(
            "SELECT rewrite.rulename AS rule_name "
            "FROM pg_rewrite AS rewrite "
            "JOIN pg_class AS relation ON relation.oid = rewrite.ev_class "
            "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "WHERE namespace.nspname = current_schema() "
            "AND relation.relname = :table_name"
        ),
        {"table_name": table_name},
    ).all()
    if rows:
        raise SchemaInitializationError(
            f"{table_name} rewrite rule inventory does not match managed schema: "
            f"{sorted(str(row.rule_name) for row in rows)!r}"
        )


def _normalize_check_sql(value: str) -> str:
    normalized = re.sub(r"\s+", "", value.lower().replace('"', "").replace("`", ""))
    while normalized.startswith("(") and normalized.endswith(")"):
        depth = 0
        encloses_all = True
        for index, character in enumerate(normalized):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and index != len(normalized) - 1:
                    encloses_all = False
                    break
        if not encloses_all:
            break
        normalized = normalized[1:-1]
    return normalized


def _postgres_check_signature(actual_sql: str, expected_sql: str, table: Any) -> bool:
    """Compare repository-owned CHECK structure, tolerating only PostgreSQL rendering.

    PostgreSQL renders ``IN`` as ``= ANY (ARRAY[...])`` and adds casts and
    parentheses.  Token-count signatures cannot distinguish operand or range
    reordering, so both forms are parsed into a small AST covering every CHECK
    expression declared by this module.  Unknown syntax fails closed.
    """

    allowed_columns = frozenset(column.name.lower() for column in table.columns)
    textual_columns = frozenset(
        column.name.lower() for column in table.columns if isinstance(column.type, (String, Text))
    )
    try:
        actual = _PostgresCheckParser(actual_sql, allowed_columns, textual_columns).parse()
        expected = _PostgresCheckParser(expected_sql, allowed_columns, textual_columns).parse()
    except ValueError:
        return False
    return actual == expected


_CHECK_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<string>'(?:''|[^'])*')|"
    r'(?P<quoted>"(?:""|[^"])*")|'
    r"(?P<number>\d+)|"
    r"(?P<arithmetic>[+-])|"
    r"(?P<cast>::)|"
    r"(?P<operator><>|!=|>=|<=|=|>|<)|"
    r"(?P<punct>[(),\[\]])|"
    r"(?P<word>[a-z_][a-z0-9_]*)"
    r")",
    re.IGNORECASE,
)


def _tokenize_postgres_check(value: str) -> list[tuple[str, str]]:
    stripped = value.strip()
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(stripped):
        match = _CHECK_TOKEN_RE.match(stripped, position)
        if match is None:
            raise ValueError("unsupported PostgreSQL CHECK syntax")
        kind = str(match.lastgroup)
        token = match.group(kind)
        if kind == "string":
            token = token[1:-1].replace("''", "'")
        elif kind == "quoted":
            kind = "word"
            token = token[1:-1].replace('""', '"').lower()
        elif kind == "word":
            token = token.lower()
        tokens.append((kind, token))
        position = match.end()
    return tokens


class _PostgresCheckParser:
    """Parser for the deliberately small CHECK grammar owned by this schema."""

    def __init__(
        self,
        value: str,
        allowed_columns: frozenset[str],
        textual_columns: frozenset[str],
    ) -> None:
        self._tokens = _tokenize_postgres_check(value)
        self._position = 0
        self._allowed_columns = allowed_columns
        self._textual_columns = textual_columns

    def parse(self) -> tuple[Any, ...]:
        if self._accept_word("check"):
            self._expect_punct("(")
            result = self._parse_or()
            self._expect_punct(")")
        else:
            result = self._parse_or()
        if self._position != len(self._tokens):
            raise ValueError("trailing PostgreSQL CHECK syntax")
        return result

    def _parse_or(self) -> tuple[Any, ...]:
        parts = [self._parse_and()]
        while self._accept_word("or"):
            parts.append(self._parse_and())
        return parts[0] if len(parts) == 1 else ("or", *parts)

    def _parse_and(self) -> tuple[Any, ...]:
        parts = [self._parse_predicate()]
        while self._accept_word("and"):
            parts.append(self._parse_predicate())
        return parts[0] if len(parts) == 1 else ("and", *parts)

    def _parse_predicate(self) -> tuple[Any, ...]:
        if self._peek() == ("punct", "(") and not self._leading_parenthesis_is_operand():
            self._position += 1
            expression = self._parse_or()
            self._expect_punct(")")
            return expression

        left = self._parse_operand()
        if self._accept_word("is"):
            negated = self._accept_word("not")
            self._expect_word("null")
            return ("is-null", left, negated)

        negated = self._accept_word("not")
        if self._accept_word("in"):
            values = self._parse_parenthesized_values(array=False)
            return ("in", left, values, negated)
        if negated:
            raise ValueError("NOT must qualify IN or NULL")

        operator = self._expect_kind("operator")
        if operator == "=" and self._accept_word("any"):
            values = self._parse_parenthesized_values(array=True)
            return ("in", left, values, False)
        right = self._parse_operand()
        return ("compare", operator, left, right)

    def _parse_operand(self) -> tuple[Any, ...]:
        value = self._parse_primary()
        while (token := self._peek()) is not None and token[0] == "arithmetic":
            operator = self._expect_kind("arithmetic")
            value = ("arithmetic", operator, value, self._parse_primary())
        return value

    def _parse_primary(self) -> tuple[Any, ...]:
        if self._accept_punct("("):
            value = self._parse_operand()
            self._expect_punct(")")
        else:
            token = self._peek()
            if token is None:
                raise ValueError("missing CHECK operand")
            kind, token_value = token
            if kind == "number":
                self._position += 1
                value = ("number", int(token_value))
            elif kind == "string":
                self._position += 1
                value = ("string", token_value)
            elif kind != "word":
                raise ValueError("unsupported CHECK operand")
            else:
                self._position += 1
                if self._accept_punct("("):
                    if token_value == "length":
                        arguments = [self._parse_operand()]
                    elif token_value in {"replace", "substr"}:
                        arguments = [self._parse_operand()]
                        self._expect_punct(",")
                        arguments.append(self._parse_operand())
                        self._expect_punct(",")
                        arguments.append(self._parse_operand())
                    else:
                        raise ValueError("unsupported CHECK function")
                    self._expect_punct(")")
                    value = ("function", token_value, *arguments)
                else:
                    if token_value not in self._allowed_columns:
                        raise ValueError("CHECK references an unmanaged identifier")
                    value = ("column", token_value)
        return self._consume_text_casts(value, array=False)

    def _parse_parenthesized_values(self, *, array: bool) -> tuple[tuple[Any, ...], ...]:
        self._expect_punct("(")
        nested = self._accept_punct("(")
        if array:
            self._expect_word("array")
            self._expect_punct("[")
            closing = "]"
        else:
            closing = ")"
        values = [self._parse_operand()]
        while self._accept_punct(","):
            values.append(self._parse_operand())
        self._expect_punct(closing)
        if nested:
            self._expect_punct(")")
        self._consume_text_casts(("array",), array=True)
        if array:
            self._expect_punct(")")
        if any(value[0] not in {"string", "number"} for value in values):
            raise ValueError("unsupported CHECK membership value")
        return tuple(values)

    def _leading_parenthesis_is_operand(self) -> bool:
        depth = 0
        for position in range(self._position, len(self._tokens)):
            token = self._tokens[position]
            if token == ("punct", "("):
                depth += 1
            elif token == ("punct", ")"):
                depth -= 1
                if depth == 0:
                    following = (
                        self._tokens[position + 1] if position + 1 < len(self._tokens) else None
                    )
                    return following is not None and (
                        following[0] in {"operator", "cast", "arithmetic"}
                        or following
                        in {
                            ("word", "is"),
                            ("word", "in"),
                            ("word", "not"),
                        }
                    )
        raise ValueError("unbalanced PostgreSQL CHECK parentheses")

    def _consume_text_casts(self, value: tuple[Any, ...], *, array: bool) -> tuple[Any, ...]:
        while self._peek() == ("cast", "::"):
            self._position += 1
            cast_name = self._expect_kind("word")
            if cast_name == "character":
                self._expect_word("varying")
            elif cast_name not in {"text", "varchar"}:
                raise ValueError("unsupported PostgreSQL CHECK cast")
            has_array_suffix = self._accept_punct("[")
            if has_array_suffix:
                self._expect_punct("]")
            if has_array_suffix != array:
                raise ValueError("CHECK cast shape does not match its operand")
            if not array and not (
                value[0] == "string"
                or (value[0] == "column" and value[1] in self._textual_columns)
                or (value[0] == "function" and value[1] in {"replace", "substr"})
            ):
                raise ValueError("text cast is not a PostgreSQL rendering cast")
        return value

    def _peek(self) -> tuple[str, str] | None:
        if self._position == len(self._tokens):
            return None
        return self._tokens[self._position]

    def _accept_word(self, value: str) -> bool:
        if self._peek() == ("word", value):
            self._position += 1
            return True
        return False

    def _expect_word(self, value: str) -> None:
        if not self._accept_word(value):
            raise ValueError(f"expected CHECK keyword {value}")

    def _accept_punct(self, value: str) -> bool:
        if self._peek() == ("punct", value):
            self._position += 1
            return True
        return False

    def _expect_punct(self, value: str) -> None:
        if not self._accept_punct(value):
            raise ValueError(f"expected CHECK punctuation {value}")

    def _expect_kind(self, kind: str) -> str:
        token = self._peek()
        if token is None or token[0] != kind:
            raise ValueError(f"expected CHECK token kind {kind}")
        self._position += 1
        return token[1]


def _validate_indexes(
    inspector: Any,
    table_name: str,
    expected: Any,
    *,
    allow_missing_v2_job_index: bool,
) -> None:
    expected_indexes = {
        (index.name, tuple(column.name for column in index.columns), bool(index.unique))
        for index in expected.indexes
    }
    if allow_missing_v2_job_index and table_name == "cp_jobs":
        expected_indexes = {index for index in expected_indexes if index[0] != "ux_cp_jobs_job_run"}
    inspected_indexes = [
        index
        for index in inspector.get_indexes(table_name)
        if not index.get("duplicates_constraint")
    ]
    for index in inspected_indexes:
        dialect_options = index.get("dialect_options") or {}
        if (
            any(column is None for column in (index.get("column_names") or ()))
            or bool(index.get("column_sorting"))
            or bool(index.get("include_columns"))
            or dialect_options.get("postgresql_where") is not None
            or dialect_options.get("sqlite_where") is not None
            or bool(dialect_options.get("postgresql_include"))
        ):
            raise SchemaInitializationError(
                f"{table_name} index {index.get('name')!r} has unmanaged options"
            )
    actual_indexes = {
        (
            index.get("name"),
            tuple(index.get("column_names") or ()),
            bool(index.get("unique")),
        )
        for index in inspected_indexes
    }
    if expected_indexes != actual_indexes:
        raise SchemaInitializationError(
            f"{table_name} indexes do not match managed schema "
            f"(actual={sorted(actual_indexes)!r}, expected={sorted(expected_indexes)!r})"
        )


_SUBMISSION_AUTHORITY_TRIGGER_NAME = "cp_runs_submission_authority_guard"
_SUBMISSION_AUTHORITY_FUNCTION_NAME = "pajin_cp_enforce_run_submission_authority"
_LEASE_AUTHORITY_TRIGGER_NAME = "cp_jobs_lease_authority_guard"
_LEASE_AUTHORITY_FUNCTION_NAME = "pajin_cp_enforce_job_lease_authority"
_AUTHORITY_GUARD_TABLES = frozenset({"cp_runs", "cp_jobs"})
_MANAGED_RUN_STATES = (
    "queued",
    "running",
    "awaiting-approval",
    "completed",
    "failed",
    "cancelled",
)
_MANAGED_JOB_STATES = (
    "queued",
    "leased",
    "succeeded",
    "failed",
    "dead-letter",
    "cancelled",
)
_MANAGED_JOB_KINDS = ("campaign", "tool-loop", "internal-replay")


def _submission_authority_is_valid_sql(prefix: str, *, dialect_name: str) -> str:
    digest = f"{prefix}submission_authority_digest"
    text_type = f"typeof({digest}) = 'text' AND " if dialect_name == "sqlite" else ""
    if dialect_name not in {"sqlite", "postgresql"}:
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {dialect_name}"
        )
    return f"{digest} IS NOT NULL AND {text_type}({_lower_hex_check(digest, 64)})"


def _managed_text_value_is_valid_sql(
    value: str,
    *,
    allowed: tuple[str, ...],
    dialect_name: str,
) -> str:
    text_type = f"typeof({value}) = 'text' AND " if dialect_name == "sqlite" else ""
    if dialect_name not in {"sqlite", "postgresql"}:
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {dialect_name}"
        )
    choices = ", ".join(f"'{item}'" for item in allowed)
    return f"{value} IS NOT NULL AND {text_type}{value} IN ({choices})"


def _json_object_is_valid_sql(
    value: str,
    *,
    dialect_name: str,
    max_storage_bytes: int,
    max_depth: int,
    max_nodes: int,
    max_keys: int,
    allow_json_null: bool = False,
) -> str:
    allowed_types = "('object', 'null')" if allow_json_null else "('object')"
    if dialect_name == "sqlite":
        safe_value = (
            f"CASE WHEN typeof({value}) = 'text' AND json_valid({value}) "
            f"THEN {value} ELSE '{{}}' END"
        )
        return (
            f"typeof({value}) = 'text' AND "
            f"length(CAST({value} AS BLOB)) <= {max_storage_bytes} AND "
            f"CASE WHEN json_valid({value}) "
            f"THEN json_type({value}) IN {allowed_types} ELSE 0 END AND "
            "NOT EXISTS (SELECT 1 FROM json_tree("
            f"{safe_value}) WHERE key IS NOT NULL GROUP BY parent, key HAVING count(*) > 1)"
        )
    if dialect_name == "postgresql":
        recursive_shape = _postgres_json_shape_is_valid_sql(
            value,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_keys=max_keys,
        )
        return (
            f"octet_length({value}::text) <= {max_storage_bytes} AND "
            f"json_typeof({value}) IN {allowed_types} AND "
            f"({recursive_shape})"
        )
    raise SchemaInitializationError(f"unsupported Control Plane database dialect: {dialect_name}")


def _postgres_json_shape_is_valid_sql(
    value: str,
    *,
    max_depth: int,
    max_nodes: int,
    max_keys: int,
) -> str:
    """Render a bounded duplicate-preserving walk over PostgreSQL ``json``.

    Casting to ``jsonb`` would erase duplicate keys before validation.  The
    recursive walk therefore stays on ``json`` and assigns every child an
    ordinal path.  The one-extra depth/node/key rows make every resource limit
    fail closed without allowing an unbounded materialization.
    """

    if any(type(limit) is not int or limit < 1 for limit in (max_depth, max_nodes, max_keys)):
        raise ValueError("PostgreSQL JSON walk limits must be positive integers")
    return f"""
        WITH RECURSIVE pajin_json_walk(path, depth, node_value) AS (
          SELECT ARRAY[]::bigint[], 0, {value}::json
          UNION ALL
          SELECT
            walk.path || child.ordinality,
            walk.depth + 1,
            child.node_value
          FROM pajin_json_walk AS walk
          CROSS JOIN LATERAL (
            SELECT object_child.value, object_child.ordinality
            FROM json_each(
              CASE WHEN json_typeof(walk.node_value) = 'object'
                   THEN walk.node_value ELSE '{{}}'::json END
            ) WITH ORDINALITY AS object_child(key, value, ordinality)
            UNION ALL
            SELECT array_child.value, array_child.ordinality
            FROM json_array_elements(
              CASE WHEN json_typeof(walk.node_value) = 'array'
                   THEN walk.node_value ELSE '[]'::json END
            ) WITH ORDINALITY AS array_child(value, ordinality)
          ) AS child(node_value, ordinality)
          WHERE walk.depth <= {max_depth}
        ),
        pajin_json_nodes AS MATERIALIZED (
          SELECT path, depth, node_value
          FROM pajin_json_walk
          LIMIT {max_nodes + 1}
        ),
        pajin_json_members AS MATERIALIZED (
          SELECT node.path, member.key
          FROM pajin_json_nodes AS node
          CROSS JOIN LATERAL json_each(
            CASE WHEN json_typeof(node.node_value) = 'object'
                 THEN node.node_value ELSE '{{}}'::json END
          ) AS member(key, value)
          LIMIT {max_keys + 1}
        )
        SELECT
          (SELECT count(*) <= {max_nodes} FROM pajin_json_nodes)
          AND NOT EXISTS (
            SELECT 1 FROM pajin_json_nodes WHERE depth > {max_depth}
          )
          AND (SELECT count(*) <= {max_keys} FROM pajin_json_members)
          AND NOT EXISTS (
            SELECT 1
            FROM pajin_json_members
            GROUP BY path, key
            HAVING count(*) > 1
          )
    """


def _run_authority_is_valid_sql(prefix: str, *, dialect_name: str) -> str:
    state_valid = _managed_text_value_is_valid_sql(
        f"{prefix}state",
        allowed=_MANAGED_RUN_STATES,
        dialect_name=dialect_name,
    )
    input_valid = _json_object_is_valid_sql(
        f"{prefix}input",
        dialect_name=dialect_name,
        max_storage_bytes=_RUN_JSON_STORAGE_MAX_BYTES,
        max_depth=SUBMIT_RUN_INPUT_JSON_POLICY.max_depth,
        max_nodes=SUBMIT_RUN_INPUT_JSON_POLICY.max_nodes,
        max_keys=SUBMIT_RUN_INPUT_JSON_POLICY.max_keys,
    )
    return (
        f"({_submission_authority_is_valid_sql(prefix, dialect_name=dialect_name)}) AND "
        f"({state_valid}) AND ({input_valid})"
    )


def _sqlite_datetime_is_invalid_sql(value: str) -> str:
    """Reject SQLite date/time spellings that SQLAlchemy cannot decode as datetime."""

    return (
        f"typeof({value}) <> 'text' OR length({value}) <> 26 OR "
        f"substr({value}, 1, 4) NOT GLOB '[0-9][0-9][0-9][0-9]' OR "
        f"substr({value}, 5, 1) <> '-' OR "
        f"substr({value}, 6, 2) NOT GLOB '[0-9][0-9]' OR "
        f"substr({value}, 8, 1) <> '-' OR "
        f"substr({value}, 9, 2) NOT GLOB '[0-9][0-9]' OR "
        f"substr({value}, 11, 1) <> ' ' OR "
        f"substr({value}, 12, 2) NOT GLOB '[0-9][0-9]' OR "
        f"substr({value}, 14, 1) <> ':' OR "
        f"substr({value}, 15, 2) NOT GLOB '[0-9][0-9]' OR "
        f"substr({value}, 17, 1) <> ':' OR "
        f"substr({value}, 18, 2) NOT GLOB '[0-9][0-9]' OR "
        f"substr({value}, 20, 1) <> '.' OR "
        f"substr({value}, 21, 6) NOT GLOB '[0-9][0-9][0-9][0-9][0-9][0-9]' OR "
        f"CAST(substr({value}, 1, 4) AS INTEGER) < 1 OR "
        f"date(substr({value}, 1, 10)) <> substr({value}, 1, 10) OR "
        f"CAST(substr({value}, 12, 2) AS INTEGER) NOT BETWEEN 0 AND 23 OR "
        f"CAST(substr({value}, 15, 2) AS INTEGER) NOT BETWEEN 0 AND 59 OR "
        f"CAST(substr({value}, 18, 2) AS INTEGER) NOT BETWEEN 0 AND 59"
    )


def _run_state_transition_is_invalid_sql(
    *,
    new_prefix: str,
    old_prefix: str,
    dialect_name: str,
) -> str:
    new_state = f"{new_prefix}state"
    old_state = f"{old_prefix}state"
    changed = (
        f"{new_state} IS NOT {old_state}"
        if dialect_name == "sqlite"
        else f"{new_state} IS DISTINCT FROM {old_state}"
    )
    if dialect_name not in {"sqlite", "postgresql"}:
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {dialect_name}"
        )
    replay_job_exists = (
        "EXISTS (SELECT 1 FROM cp_jobs AS transition_job "
        f"WHERE transition_job.run_id = {old_prefix}run_id "
        "AND transition_job.kind = 'internal-replay')"
    )
    allowed = (
        f"({old_state} = 'queued' AND ("
        f"{new_state} IN ('running', 'cancelled') OR "
        f"({new_state} = 'failed' AND {replay_job_exists}))) OR "
        f"({old_state} = 'running' AND "
        f"{new_state} IN ('queued', 'awaiting-approval', 'completed', 'failed', 'cancelled')) OR "
        f"({old_state} = 'awaiting-approval' AND {new_state} IN ('queued', 'cancelled'))"
    )
    return f"({changed} AND NOT ({allowed}))"


def _job_state_transition_is_invalid_sql(
    *,
    new_prefix: str,
    old_prefix: str,
    dialect_name: str,
) -> str:
    new_state = f"{new_prefix}state"
    old_state = f"{old_prefix}state"
    old_kind = f"{old_prefix}kind"
    changed = (
        f"{new_state} IS NOT {old_state}"
        if dialect_name == "sqlite"
        else f"{new_state} IS DISTINCT FROM {old_state}"
    )
    if dialect_name not in {"sqlite", "postgresql"}:
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {dialect_name}"
        )
    allowed = (
        f"({old_state} = 'queued' AND ("
        f"{new_state} IN ('leased', 'cancelled') OR "
        f"({new_state} = 'failed' AND {old_kind} = 'internal-replay'))) OR "
        f"({old_state} = 'leased' AND "
        f"{new_state} IN ('queued', 'succeeded', 'failed', 'dead-letter', 'cancelled'))"
    )
    return f"({changed} AND NOT ({allowed}))"


def _lease_authority_is_invalid_sql(prefix: str, *, dialect_name: str) -> str:
    state = f"{prefix}state"
    kind = f"{prefix}kind"
    payload = f"{prefix}payload"
    owner = f"{prefix}lease_owner"
    token = f"{prefix}lease_token_hash"
    attempts = f"{prefix}attempts"
    max_attempts = f"{prefix}max_attempts"
    lease_expires = f"{prefix}lease_expires_at"
    lease_deadline = f"{prefix}lease_deadline_at"
    heartbeat = f"{prefix}heartbeat_at"
    event_time = f"{prefix}heartbeat_event_at"
    if dialect_name == "sqlite":
        heartbeat_horizon = f"date(substr({heartbeat}, 1, 10), '+1 day') || substr({heartbeat}, 11)"
        horizon_exceeded = f"{lease_deadline} > ({heartbeat_horizon})"
        expires_after_deadline = f"{lease_expires} > {lease_deadline}"
        heartbeat_after_deadline = f"{heartbeat} > {lease_deadline}"
        event_after_heartbeat = f"{event_time} > {heartbeat}"
        invalid_timestamps = (
            f"({_sqlite_datetime_is_invalid_sql(lease_expires)}) OR "
            f"({_sqlite_datetime_is_invalid_sql(lease_deadline)}) OR "
            f"({_sqlite_datetime_is_invalid_sql(heartbeat)}) OR "
            f"julianday({lease_expires}) IS NULL OR "
            f"julianday({lease_deadline}) IS NULL OR "
            f"julianday({heartbeat}) IS NULL OR "
            f"({event_time} IS NOT NULL AND ({_sqlite_datetime_is_invalid_sql(event_time)} OR "
            f"julianday({event_time}) IS NULL)) OR "
        )
        invalid_types = (
            f"typeof({attempts}) <> 'integer' OR typeof({max_attempts}) <> 'integer' OR "
        )
        invalid_lease_identity = f"typeof({owner}) <> 'text' OR typeof({token}) <> 'text' OR "
    elif dialect_name == "postgresql":
        horizon_exceeded = f"{lease_deadline} > {heartbeat} + INTERVAL '24 hours'"
        expires_after_deadline = f"{lease_expires} > {lease_deadline}"
        heartbeat_after_deadline = f"{heartbeat} > {lease_deadline}"
        event_after_heartbeat = f"{event_time} > {heartbeat}"
        invalid_timestamps = ""
        invalid_types = ""
        invalid_lease_identity = ""
    else:  # pragma: no cover - callers reject unsupported dialects
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {dialect_name}"
        )
    state_valid = _managed_text_value_is_valid_sql(
        state,
        allowed=_MANAGED_JOB_STATES,
        dialect_name=dialect_name,
    )
    kind_valid = _managed_text_value_is_valid_sql(
        kind,
        allowed=_MANAGED_JOB_KINDS,
        dialect_name=dialect_name,
    )
    payload_valid = _json_object_is_valid_sql(
        payload,
        dialect_name=dialect_name,
        max_storage_bytes=_JOB_JSON_STORAGE_MAX_BYTES,
        max_depth=CONTROL_PLANE_STORED_JSON_POLICY.max_depth,
        max_nodes=CONTROL_PLANE_STORED_JSON_POLICY.max_nodes,
        max_keys=CONTROL_PLANE_STORED_JSON_POLICY.max_keys,
    )
    return (
        f"NOT ({_submission_authority_is_valid_sql(prefix, dialect_name=dialect_name)}) OR "
        f"NOT ({state_valid}) OR NOT ({kind_valid}) OR NOT ({payload_valid}) OR "
        f"{invalid_types}"
        f"{attempts} < 0 OR {max_attempts} < 1 OR {max_attempts} > 20 OR "
        f"{attempts} > {max_attempts} OR "
        f"({state} = 'leased' AND ("
        f"{owner} IS NULL OR length({owner}) < 1 OR length({owner}) > 200 OR "
        f"{token} IS NULL OR NOT ({_lower_hex_check(token, 64)}) OR "
        f"{invalid_lease_identity}"
        f"{lease_expires} IS NULL OR {lease_deadline} IS NULL OR {heartbeat} IS NULL OR "
        f"{invalid_timestamps}"
        f"{expires_after_deadline} OR {heartbeat_after_deadline} OR "
        f"{horizon_exceeded} OR "
        f"({event_time} IS NOT NULL AND {event_after_heartbeat}))) OR "
        f"({state} <> 'leased' AND ({lease_deadline} IS NOT NULL OR "
        f"{event_time} IS NOT NULL))"
    )


def _postgres_submission_authority_function_source() -> str:
    invalid_transition = _run_state_transition_is_invalid_sql(
        new_prefix="NEW.",
        old_prefix="OLD.",
        dialect_name="postgresql",
    )
    return f"""
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'cp_runs submission identity cannot be deleted';
          END IF;
          IF NOT ({_run_authority_is_valid_sql("NEW.", dialect_name="postgresql")}) THEN
            RAISE EXCEPTION 'cp_runs submission authority is invalid';
          END IF;
          IF TG_OP = 'UPDATE' AND {invalid_transition} THEN
            RAISE EXCEPTION 'cp_runs state transition authority is invalid';
          END IF;
          IF TG_OP = 'UPDATE' AND (
             NEW.run_id IS DISTINCT FROM OLD.run_id
             OR NEW.submission_authority_digest IS DISTINCT FROM OLD.submission_authority_digest
             OR NEW.campaign_name IS DISTINCT FROM OLD.campaign_name
             OR NEW.input::text IS DISTINCT FROM OLD.input::text
             OR NEW.submission_key IS DISTINCT FROM OLD.submission_key
             OR NEW.created_at IS DISTINCT FROM OLD.created_at) THEN
            RAISE EXCEPTION 'cp_runs submission identity is immutable';
          END IF;
          IF TG_OP = 'UPDATE' AND OLD.state IN ('completed', 'failed', 'cancelled') THEN
            RAISE EXCEPTION 'cp_runs terminal state is immutable';
          END IF;
          RETURN NEW;
        END;
    """


def _postgres_lease_authority_function_source() -> str:
    invalid_transition = _job_state_transition_is_invalid_sql(
        new_prefix="NEW.",
        old_prefix="OLD.",
        dialect_name="postgresql",
    )
    return f"""
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'cp_jobs submission identity cannot be deleted';
          END IF;
          IF {_lease_authority_is_invalid_sql("NEW.", dialect_name="postgresql")} THEN
            RAISE EXCEPTION 'cp_jobs lease authority is invalid';
          END IF;
          IF TG_OP = 'UPDATE' AND {invalid_transition} THEN
            RAISE EXCEPTION 'cp_jobs state transition authority is invalid';
          END IF;
          IF TG_OP = 'INSERT' AND NEW.state = 'leased' THEN
            RAISE EXCEPTION 'cp_jobs leased authority must be claimed from queued state';
          END IF;
          IF TG_OP = 'UPDATE' AND NEW.state = 'leased'
             AND OLD.state NOT IN ('queued', 'leased') THEN
            RAISE EXCEPTION 'cp_jobs leased authority must be claimed from queued state';
          END IF;
          IF TG_OP = 'UPDATE' AND OLD.state = 'queued' AND NEW.state = 'leased'
             AND NEW.attempts IS DISTINCT FROM OLD.attempts + 1 THEN
            RAISE EXCEPTION 'cp_jobs lease attempt authority is invalid';
          END IF;
          IF TG_OP = 'UPDATE' AND NEW.attempts IS DISTINCT FROM OLD.attempts
             AND NOT (OLD.state = 'queued' AND NEW.state = 'leased'
                      AND NEW.attempts = OLD.attempts + 1) THEN
            RAISE EXCEPTION 'cp_jobs attempt authority is immutable outside claim';
          END IF;
          IF TG_OP = 'UPDATE' AND OLD.state = 'leased' AND NEW.state = 'leased'
             AND (NEW.lease_deadline_at > OLD.lease_deadline_at
                  OR NEW.attempts IS DISTINCT FROM OLD.attempts
                  OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
                  OR NEW.lease_token_hash IS DISTINCT FROM OLD.lease_token_hash) THEN
            RAISE EXCEPTION 'cp_jobs active lease authority is immutable';
          END IF;
          IF TG_OP = 'UPDATE' AND (
             NEW.job_id IS DISTINCT FROM OLD.job_id
             OR NEW.submission_authority_digest IS DISTINCT FROM OLD.submission_authority_digest
             OR NEW.run_id IS DISTINCT FROM OLD.run_id
             OR NEW.kind IS DISTINCT FROM OLD.kind
             OR NEW.payload::text IS DISTINCT FROM OLD.payload::text
             OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
             OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
             OR NEW.created_at IS DISTINCT FROM OLD.created_at) THEN
            RAISE EXCEPTION 'cp_jobs submission identity is immutable';
          END IF;
          IF TG_OP = 'UPDATE'
             AND OLD.state IN ('succeeded', 'failed', 'dead-letter', 'cancelled') THEN
            RAISE EXCEPTION 'cp_jobs terminal state is immutable';
          END IF;
          RETURN NEW;
        END;
    """


def _sqlite_submission_authority_trigger_sql(operation: str) -> str:
    invalid_transition = _run_state_transition_is_invalid_sql(
        new_prefix="NEW.",
        old_prefix="OLD.",
        dialect_name="sqlite",
    )
    immutable = (
        " OR NEW.rowid IS NOT OLD.rowid"
        " OR NEW.run_id IS NOT OLD.run_id"
        " OR NEW.submission_authority_digest IS NOT OLD.submission_authority_digest"
        " OR NEW.campaign_name IS NOT OLD.campaign_name"
        " OR NEW.input IS NOT OLD.input"
        " OR NEW.submission_key IS NOT OLD.submission_key"
        " OR NEW.created_at IS NOT OLD.created_at"
        " OR OLD.state IN ('completed', 'failed', 'cancelled')"
        f" OR {invalid_transition}"
        if operation == "UPDATE"
        else ""
    )
    replacement = (
        f" OR ({_sqlite_existing_row_conflict_sql(RunRecord.__tablename__)})"
        if operation == "INSERT"
        else ""
    )
    valid_authority = _run_authority_is_valid_sql("NEW.", dialect_name="sqlite")
    return f"""
        CREATE TRIGGER {_SUBMISSION_AUTHORITY_TRIGGER_NAME}_{operation.lower()}
        BEFORE {operation} ON cp_runs
        WHEN NOT ({valid_authority}){immutable}{replacement}
        BEGIN SELECT RAISE(ABORT, 'cp_runs submission authority is invalid'); END
    """


def _sqlite_lease_authority_trigger_sql(operation: str) -> str:
    invalid_authority = _lease_authority_is_invalid_sql("NEW.", dialect_name="sqlite")
    invalid_transition = _job_state_transition_is_invalid_sql(
        new_prefix="NEW.",
        old_prefix="OLD.",
        dialect_name="sqlite",
    )
    immutable = (
        " OR NEW.rowid IS NOT OLD.rowid"
        " OR (NEW.state = 'leased' AND OLD.state NOT IN ('queued', 'leased'))"
        " OR (OLD.state = 'queued' AND NEW.state = 'leased' "
        "AND NEW.attempts IS NOT OLD.attempts + 1)"
        " OR (NEW.attempts IS NOT OLD.attempts AND NOT "
        "(OLD.state = 'queued' AND NEW.state = 'leased' "
        "AND NEW.attempts = OLD.attempts + 1))"
        " OR (OLD.state = 'leased' AND NEW.state = 'leased' "
        "AND (NEW.lease_deadline_at > OLD.lease_deadline_at"
        " OR NEW.attempts IS NOT OLD.attempts"
        " OR NEW.lease_owner IS NOT OLD.lease_owner"
        " OR NEW.lease_token_hash IS NOT OLD.lease_token_hash))"
        " OR NEW.job_id IS NOT OLD.job_id"
        " OR NEW.submission_authority_digest IS NOT OLD.submission_authority_digest"
        " OR NEW.run_id IS NOT OLD.run_id"
        " OR NEW.kind IS NOT OLD.kind"
        " OR NEW.payload IS NOT OLD.payload"
        " OR NEW.max_attempts IS NOT OLD.max_attempts"
        " OR NEW.idempotency_key IS NOT OLD.idempotency_key"
        " OR NEW.created_at IS NOT OLD.created_at"
        " OR OLD.state IN ('succeeded', 'failed', 'dead-letter', 'cancelled')"
        f" OR {invalid_transition}"
        if operation == "UPDATE"
        else ""
    )
    replacement = (
        f" OR NEW.state = 'leased'"
        f" OR ({_sqlite_existing_row_conflict_sql(JobRecord.__tablename__)})"
        if operation == "INSERT"
        else ""
    )
    return f"""
        CREATE TRIGGER {_LEASE_AUTHORITY_TRIGGER_NAME}_{operation.lower()}
        BEFORE {operation} ON cp_jobs
        WHEN ({invalid_authority}){immutable}{replacement}
        BEGIN SELECT RAISE(ABORT, 'cp_jobs lease authority is invalid'); END
    """


def _sqlite_authority_delete_trigger_sql(table_name: str, trigger_name: str) -> str:
    return f"""
        CREATE TRIGGER {trigger_name}_delete
        BEFORE DELETE ON {table_name}
        BEGIN SELECT RAISE(ABORT, '{table_name} submission identity cannot be deleted'); END
    """


def _sqlite_authority_rowid_trigger_sql(table_name: str, trigger_name: str) -> str:
    return f"""
        CREATE TRIGGER {trigger_name}_rowid
        AFTER INSERT ON {table_name}
        WHEN NEW.rowid <= 0
        BEGIN SELECT RAISE(ABORT, '{table_name} authority rowid is invalid'); END
    """


_APPEND_ONLY_TABLE_SUFFIXES = {
    "cp_events": "event",
    "cp_artifacts": "artifact",
    "cp_replay_compilations": "replay_compilation",
    "cp_replay_execution_contexts": "replay_execution_context",
    "cp_replay_events": "replay_event",
    "cp_replay_tool_permits": "replay_tool_permit",
    "cp_replay_finalizations": "replay_finalization",
    "cp_replay_projections": "replay_projection",
    "cp_replay_retest_sources": "replay_retest_source",
}


def _sqlite_existing_row_conflict_sql(table_name: str) -> str:
    """Detect SQLite REPLACE targets across rowid, primary, and unique identities."""

    table = Base.metadata.tables[table_name]
    primary_key = tuple(column.name for column in table.primary_key.columns)
    unique_keys = {
        tuple(column.name for column in constraint.columns)
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    unique_keys.update(
        tuple(column.name for column in index.columns) for index in table.indexes if index.unique
    )
    keys = {primary_key, *unique_keys}
    conflict_checks = [
        f"(NEW.rowid != -1 AND EXISTS (SELECT 1 FROM {table_name} WHERE rowid = NEW.rowid))"
    ]
    for columns in sorted(keys):
        equality = " AND ".join(f'"{column}" IS NEW."{column}"' for column in columns)
        conflict_checks.append(f"EXISTS (SELECT 1 FROM {table_name} WHERE {equality})")
    return " OR ".join(conflict_checks)


def _sqlite_append_only_conflict_keys(table_name: str) -> tuple[tuple[str, ...], ...]:
    table = Base.metadata.tables[table_name]
    primary_key = tuple(column.name for column in table.primary_key.columns)
    unique_keys = {
        tuple(column.name for column in constraint.columns)
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    unique_keys.update(
        tuple(column.name for column in index.columns) for index in table.indexes if index.unique
    )
    unique_keys.discard(primary_key)
    return (primary_key, *sorted(unique_keys))


def _sqlite_no_replace_trigger_sql(table_name: str) -> str:
    conflict_checks = [f"EXISTS (SELECT 1 FROM {table_name} WHERE rowid = NEW.rowid)"]
    for columns in _sqlite_append_only_conflict_keys(table_name):
        equality = " AND ".join(f'"{column}" = NEW."{column}"' for column in columns)
        conflict_checks.append(f"EXISTS (SELECT 1 FROM {table_name} WHERE {equality})")
    condition = "\n OR ".join(conflict_checks)
    trigger_name = f"{table_name}_no_replace"
    return f"""
        CREATE TRIGGER {trigger_name}
        BEFORE INSERT ON {table_name}
        WHEN {condition}
        BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
    """


def _validate_trigger_inventory(
    connection: Connection,
    table_names: frozenset[str],
    *,
    append_only_guard_version: int,
    require_submission_and_lease_guards: bool,
) -> None:
    for table_name in sorted(table_names):
        if require_submission_and_lease_guards and table_name in _AUTHORITY_GUARD_TABLES:
            _validate_submission_or_lease_authority_trigger(connection, table_name)
        elif table_name in _APPEND_ONLY_TABLE_SUFFIXES:
            _validate_append_only_trigger(
                connection,
                table_name,
                append_only_guard_version=append_only_guard_version,
            )
        else:
            _validate_no_user_triggers(connection, table_name)


def _validate_submission_or_lease_authority_trigger(
    connection: Connection,
    table_name: str,
) -> None:
    """Require the exact v10 fail-closed trigger and no unmanaged peers."""

    if table_name == RunRecord.__tablename__:
        trigger_name = _SUBMISSION_AUTHORITY_TRIGGER_NAME
        function_name = _SUBMISSION_AUTHORITY_FUNCTION_NAME
        function_source = _postgres_submission_authority_function_source()
        sqlite_definition = _sqlite_submission_authority_trigger_sql
        authority_name = "submission authority"
    elif table_name == JobRecord.__tablename__:
        trigger_name = _LEASE_AUTHORITY_TRIGGER_NAME
        function_name = _LEASE_AUTHORITY_FUNCTION_NAME
        function_source = _postgres_lease_authority_function_source()
        sqlite_definition = _sqlite_lease_authority_trigger_sql
        authority_name = "lease authority"
    else:
        raise ValueError(f"unsupported authority-guard table: {table_name}")

    if connection.dialect.name == "sqlite":
        rows = connection.execute(
            text(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'trigger' AND tbl_name = :table_name"
            ),
            {"table_name": table_name},
        ).all()
        definitions = {str(row.name): str(row.sql or "") for row in rows}
        expected_definitions = {
            f"{trigger_name}_{operation.lower()}": sqlite_definition(operation)
            for operation in ("INSERT", "UPDATE")
        }
        expected_definitions[f"{trigger_name}_delete"] = _sqlite_authority_delete_trigger_sql(
            table_name, trigger_name
        )
        expected_definitions[f"{trigger_name}_rowid"] = _sqlite_authority_rowid_trigger_sql(
            table_name, trigger_name
        )
        if set(definitions) != set(expected_definitions) or any(
            _normalize_trigger_sql(definitions[name]) != _normalize_trigger_sql(expected_definition)
            for name, expected_definition in expected_definitions.items()
        ):
            raise SchemaInitializationError(
                f"{table_name} {authority_name} trigger inventory is missing or invalid"
            )
        return

    if connection.dialect.name == "postgresql":
        rows = _postgres_user_trigger_rows(connection, table_name)
        matching = [row for row in rows if str(row.trigger_name) == trigger_name]
        if (
            len(rows) != 1
            or len(matching) != 1
            or not _postgres_authority_trigger_is_valid(
                matching[0],
                function_name=function_name,
                function_source=function_source,
            )
        ):
            raise SchemaInitializationError(
                f"{table_name} {authority_name} trigger inventory is missing or invalid"
            )
        return

    raise SchemaInitializationError(
        f"unsupported Control Plane database dialect: {connection.dialect.name}"
    )


def _postgres_user_trigger_rows(connection: Connection, table_name: str) -> list[Any]:
    return list(
        connection.execute(
            text(
                "SELECT trigger.tgname AS trigger_name, "
                "trigger.tgenabled AS trigger_enabled, "
                "trigger.tgtype AS trigger_type, "
                "trigger.tgattr = ''::int2vector AS no_trigger_columns, "
                "trigger.tgqual IS NOT NULL AS has_when, "
                "octet_length(trigger.tgargs) AS trigger_arguments_length, "
                "procedure.proname AS function_name, "
                "function_namespace.nspname AS function_schema, "
                "current_schema() AS expected_schema, "
                "language.lanname AS function_language, "
                "procedure.pronargs AS function_argument_count, "
                "procedure.prorettype = 'trigger'::regtype AS returns_trigger, "
                "procedure.prokind AS function_kind, "
                "procedure.prosecdef AS security_definer, "
                "procedure.proleakproof AS leakproof, "
                "procedure.provolatile AS volatility, "
                "procedure.proparallel AS parallel_mode, "
                "procedure.proconfig IS NULL AS no_function_config, "
                "procedure.prosrc AS function_source "
                "FROM pg_trigger AS trigger "
                "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "JOIN pg_proc AS procedure ON procedure.oid = trigger.tgfoid "
                "JOIN pg_namespace AS function_namespace "
                "ON function_namespace.oid = procedure.pronamespace "
                "JOIN pg_language AS language ON language.oid = procedure.prolang "
                "WHERE namespace.nspname = current_schema() "
                "AND relation.relname = :table_name AND NOT trigger.tgisinternal"
            ),
            {"table_name": table_name},
        ).all()
    )


def _postgres_authority_trigger_is_valid(
    row: Any,
    *,
    function_name: str,
    function_source: str,
) -> bool:
    # PostgreSQL tgtype bitmask: ROW | BEFORE | INSERT | DELETE | UPDATE.
    expected_trigger_type = 1 | 2 | 4 | 8 | 16
    return (
        int(row.trigger_type) == expected_trigger_type
        and str(row.trigger_enabled) == "O"
        and bool(row.no_trigger_columns)
        and not bool(row.has_when)
        and int(row.trigger_arguments_length) == 0
        and str(row.function_name) == function_name
        and str(row.function_schema) == str(row.expected_schema)
        and str(row.function_language) == "plpgsql"
        and int(row.function_argument_count) == 0
        and bool(row.returns_trigger)
        and str(row.function_kind) == "f"
        and not bool(row.security_definer)
        and not bool(row.leakproof)
        and str(row.volatility) == "v"
        and str(row.parallel_mode) == "u"
        and bool(row.no_function_config)
        and _normalize_trigger_sql(str(row.function_source))
        == _normalize_trigger_sql(function_source)
    )


def _validate_no_user_triggers(connection: Connection, table_name: str) -> None:
    if connection.dialect.name == "sqlite":
        names = connection.scalars(
            text(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = :table_name"
            ),
            {"table_name": table_name},
        ).all()
    elif connection.dialect.name == "postgresql":
        names = connection.scalars(
            text(
                "SELECT trigger.tgname "
                "FROM pg_trigger AS trigger "
                "JOIN pg_class AS relation ON relation.oid = trigger.tgrelid "
                "JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
                "WHERE namespace.nspname = current_schema() "
                "AND relation.relname = :table_name AND NOT trigger.tgisinternal"
            ),
            {"table_name": table_name},
        ).all()
    else:
        raise SchemaInitializationError(
            f"unsupported Control Plane database dialect: {connection.dialect.name}"
        )
    if names:
        raise SchemaInitializationError(
            f"{table_name} user trigger inventory does not match managed schema: "
            f"{sorted(str(name) for name in names)!r}"
        )


def _validate_append_only_trigger(
    connection: Connection,
    table_name: str,
    *,
    append_only_guard_version: int = COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION,
) -> None:
    if connection.dialect.name == "sqlite":
        rows = connection.execute(
            text(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type = 'trigger' AND tbl_name = :table_name"
            ),
            {"table_name": table_name},
        ).all()
        definitions = {str(row.name): str(row.sql or "").upper() for row in rows}
        expected_names: set[str] = set()
        for operation in ("UPDATE", "DELETE"):
            name = f"{table_name}_no_{operation.lower()}"
            expected_names.add(name)
            definition = definitions.get(name, "")
            expected_definition = f"""
                CREATE TRIGGER {name}
                BEFORE {operation} ON {table_name}
                BEGIN SELECT RAISE(ABORT, '{table_name} is append-only'); END
            """
            if _normalize_trigger_sql(definition) != _normalize_trigger_sql(expected_definition):
                raise SchemaInitializationError(
                    f"{table_name} append-only {operation.lower()} trigger is missing or invalid"
                )
        if append_only_guard_version >= COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION:
            name = f"{table_name}_no_replace"
            expected_names.add(name)
            definition = definitions.get(name, "")
            if _normalize_trigger_sql(definition) != _normalize_trigger_sql(
                _sqlite_no_replace_trigger_sql(table_name)
            ):
                raise SchemaInitializationError(
                    f"{table_name} append-only insert trigger is missing or invalid"
                )
        if set(definitions) != expected_names:
            raise SchemaInitializationError(
                f"{table_name} user trigger inventory does not match managed schema: "
                f"{sorted(definitions)!r}"
            )
        return
    if connection.dialect.name == "postgresql":
        rows = _postgres_user_trigger_rows(connection, table_name)
        row_trigger_name = f"{table_name}_append_only"
        row_matching = [row for row in rows if row.trigger_name == row_trigger_name]
        if len(row_matching) != 1:
            raise SchemaInitializationError(
                f"{table_name} append-only trigger is missing or invalid"
            )
        if not _postgres_append_only_trigger_is_valid(row_matching[0], table_name):
            raise SchemaInitializationError(
                f"{table_name} append-only trigger is missing or invalid"
            )
        expected_names = {row_trigger_name}
        if append_only_guard_version >= COMPLETE_APPEND_ONLY_GUARDS_SCHEMA_VERSION:
            truncate_trigger_name = f"{table_name}_no_truncate"
            expected_names.add(truncate_trigger_name)
            truncate_matching = [row for row in rows if row.trigger_name == truncate_trigger_name]
            if len(truncate_matching) != 1 or not _postgres_truncate_trigger_is_valid(
                truncate_matching[0], table_name
            ):
                raise SchemaInitializationError(
                    f"{table_name} append-only truncate trigger is missing or invalid"
                )
        if {str(row.trigger_name) for row in rows} != expected_names:
            raise SchemaInitializationError(
                f"{table_name} user trigger inventory does not match managed schema: "
                f"{sorted(str(row.trigger_name) for row in rows)!r}"
            )
        return
    raise SchemaInitializationError(
        f"unsupported Control Plane database dialect: {connection.dialect.name}"
    )


def _postgres_append_only_trigger_is_valid(row: Any, table_name: str) -> bool:
    # PostgreSQL tgtype bitmask: ROW | BEFORE | DELETE | UPDATE.
    expected_trigger_type = 1 | 2 | 8 | 16
    return int(
        row.trigger_type
    ) == expected_trigger_type and _postgres_append_only_function_is_valid(row, table_name)


def _postgres_truncate_trigger_is_valid(row: Any, table_name: str) -> bool:
    # PostgreSQL tgtype bitmask: BEFORE | TRUNCATE; absence of ROW means statement-level.
    expected_trigger_type = 2 | 32
    return int(
        row.trigger_type
    ) == expected_trigger_type and _postgres_append_only_function_is_valid(row, table_name)


def _postgres_append_only_function_is_valid(row: Any, table_name: str) -> bool:
    suffix = _APPEND_ONLY_TABLE_SUFFIXES.get(table_name)
    if suffix is None:
        return False
    expected_function_source = f"""
        BEGIN
          RAISE EXCEPTION '{table_name} is append-only';
        END;
    """
    return (
        str(row.trigger_enabled) == "O"
        and bool(row.no_trigger_columns)
        and not bool(row.has_when)
        and int(row.trigger_arguments_length) == 0
        and str(row.function_name) == f"pajin_cp_reject_{suffix}_mutation"
        and str(row.function_schema) == str(row.expected_schema)
        and str(row.function_language) == "plpgsql"
        and int(row.function_argument_count) == 0
        and bool(row.returns_trigger)
        and str(row.function_kind) == "f"
        and not bool(row.security_definer)
        and not bool(row.leakproof)
        and str(row.volatility) == "v"
        and str(row.parallel_mode) == "u"
        and bool(row.no_function_config)
        and _normalize_trigger_sql(str(row.function_source))
        == _normalize_trigger_sql(expected_function_source)
    )


def _normalize_trigger_sql(value: str) -> str:
    return re.sub(r"\s+", "", value).rstrip(";").lower()
