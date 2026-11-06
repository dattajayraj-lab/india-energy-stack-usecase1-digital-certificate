"""Vendored IES artefacts: ElectricityCredential v1.2 schema and JSON-LD contexts.

schema.json, context.jsonld and context.inline.jsonld were fetched from
india-energy-stack.github.io/ies-accelerator on 2026-11-05. Vendoring keeps validation
and JSON-LD canonicalisation offline and deterministic.
"""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parent
CONTEXT_BASE = "https://india-energy-stack.github.io/ies-accelerator/schemas/ElectricityCredential/v1.2"
SCHEMA_URL = f"{CONTEXT_BASE}/schema.json"
VC_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
JWS_2020_CONTEXT = "https://w3id.org/security/suites/jws-2020/v1"

CREDENTIAL_CONTEXTS = [
    VC_V2_CONTEXT,
    f"{CONTEXT_BASE}/context.inline.jsonld",  # must precede context.jsonld for DigiLocker
    f"{CONTEXT_BASE}/context.jsonld",
    JWS_2020_CONTEXT,
]


@lru_cache
def credential_schema() -> dict[str, Any]:
    return json.loads((ROOT / "v1.2" / "schema.json").read_text(encoding="utf-8"))


@lru_cache
def jsonld_documents() -> dict[str, dict[str, Any]]:
    def load(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    def load_imported(path: Path) -> dict[str, Any]:
        # PyLD treats @version inside an @import-ed context as a term and rejects it. The
        # importing context already sets 1.1, so dropping it here changes nothing.
        document = load(path)
        document["@context"].pop("@version", None)
        return document

    transitive = json.loads((ROOT / "contexts" / "manifest.json").read_text(encoding="utf-8"))
    return {
        **{url: load_imported(ROOT / "contexts" / name) for url, name in transitive.items()},
        VC_V2_CONTEXT: load(ROOT / "contexts" / "credentials_v2.jsonld"),
        JWS_2020_CONTEXT: load(ROOT / "contexts" / "jws2020.jsonld"),
        f"{CONTEXT_BASE}/context.jsonld": load(ROOT / "v1.2" / "context.jsonld"),
        f"{CONTEXT_BASE}/context.inline.jsonld": load(ROOT / "v1.2" / "context.inline.jsonld"),
    }


def _collect_terms(node: Any, terms: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if not key.startswith("@"):
                terms.add(key)
            _collect_terms(value, terms)


@lru_cache
def jsonld_terms() -> frozenset[str]:
    """Every term the IES contexts define, at any scope."""
    terms: set[str] = set()
    for url, document in jsonld_documents().items():
        if url not in (VC_V2_CONTEXT, JWS_2020_CONTEXT):
            _collect_terms(document["@context"], terms)
    return frozenset(terms)


def prune_for_jsonld(subject: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Drop fields a JSON-LD proof cannot cover, and report them.

    Schema v1.2 defines fields its JSON-LD context does not, such as serialNumber and
    inspection. jws-2020 refuses to sign an undefined term, so these cannot reach DigiLocker
    until IES adds them (docs/DECISIONS.md, D-07). The wallet credential keeps them.
    """
    allowed = jsonld_terms()
    dropped: set[str] = set()

    def walk(node: Any, path: str) -> Any:
        if isinstance(node, list):
            return [walk(item, path) for item in node]
        if not isinstance(node, dict):
            return node
        kept = {}
        for key, value in node.items():
            if key in allowed or key == "id":
                kept[key] = walk(value, f"{path}.{key}" if path else key)
            else:
                dropped.add(f"{path}.{key}" if path else key)
        return kept

    return walk(subject, ""), sorted(dropped)


def _strip_presence_rules(node: Any) -> Any:
    """A hidden field is not a missing one, so presence rules cannot apply to a disclosure."""
    if isinstance(node, dict):
        return {k: _strip_presence_rules(v) for k, v in node.items() if k not in ("required", "minItems")}
    if isinstance(node, list):
        return [_strip_presence_rules(item) for item in node]
    return node


def _subject_root() -> dict[str, Any]:
    schema = credential_schema()
    return {"$defs": schema["$defs"], **copy.deepcopy(schema["properties"]["credentialSubject"])}


@lru_cache
def subject_validator() -> Draft202012Validator:
    """Strict validator for a complete credentialSubject."""
    return Draft202012Validator(_subject_root(), format_checker=FormatChecker())


@lru_cache
def partial_subject_validator() -> Draft202012Validator:
    """For selective disclosure: what is shown must be valid, but hidden fields may be absent."""
    return Draft202012Validator(_strip_presence_rules(_subject_root()), format_checker=FormatChecker())


@lru_cache
def credential_validator() -> Draft202012Validator:
    return Draft202012Validator(credential_schema(), format_checker=FormatChecker())


def schema_errors(validator: Draft202012Validator, document: dict[str, Any]) -> list[str]:
    """Error locations only; messages can echo values, and values can be personal data."""
    return [
        f"{'/'.join(str(p) for p in error.absolute_path) or '<root>'}: {error.validator}"
        for error in validator.iter_errors(document)
    ]
