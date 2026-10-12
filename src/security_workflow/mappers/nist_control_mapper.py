"""Local ACAS/CVE to NIST candidate-control mapper.

Adapted from the supplied ACAS NIST mapper's conservative design: CWE links and text relevance
produce candidates only. They never establish a control deficiency or replace an assessor.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from math import exp, log, sqrt
from pathlib import Path
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from security_workflow.contracts import Finding
from security_workflow.persistence.models import (
    CveIntelligenceRecord,
    NistControlRecord,
    SourceSnapshotRecord,
)


_TOKEN = re.compile(r"[a-z][a-z0-9_-]{2,}")

# Analyst-reviewable weak candidate links from the user-supplied ACAS mapper. They are retrieval
# expansion rules, not an authoritative NIST crosswalk or a finding of noncompliance.
_CWE_CONTROL_CANDIDATES: dict[str, tuple[str, ...]] = {
    "CWE-89": ("SI-10", "SA-11", "SI-2"),
    "CWE-78": ("SI-10", "SA-11", "SI-2"),
    "CWE-77": ("SI-10", "SA-11"),
    "CWE-20": ("SI-10", "SA-11"),
    "CWE-94": ("SI-10", "SA-11"),
    "CWE-502": ("SI-10", "SA-11"),
    "CWE-79": ("SI-10", "SA-11"),
    "CWE-22": ("SI-10", "AC-3", "SA-11"),
    "CWE-287": ("IA-2", "AC-3", "IA-5"),
    "CWE-863": ("AC-3", "AC-6"),
    "CWE-1188": ("CM-6", "IA-5"),
    "CWE-798": ("IA-5", "CM-6", "SA-11"),
    "CWE-269": ("AC-6", "AC-3"),
    "CWE-284": ("AC-3", "AC-6"),
    "CWE-327": ("SC-13", "CM-6"),
}


def _tokens(value: str | None) -> Counter[str]:
    return Counter(_TOKEN.findall((value or "").lower()))


def _english_description(record: CveIntelligenceRecord | None) -> str:
    return record.description if record and record.description else ""


def _cwes(record: CveIntelligenceRecord | None) -> set[str]:
    if not record:
        return set()
    cwes: set[str] = set()
    for weakness in record.raw.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = str(description.get("value", "")).upper()
            if re.fullmatch(r"CWE-\d+", value):
                cwes.add(value)
    return cwes


def _finding_text(finding: Finding, nvd_description: str, cwes: set[str]) -> str:
    # Plugin output is intentionally excluded: it can contain sensitive scanner evidence and is not
    # required for baseline relevance retrieval.
    values = (
        finding.title,
        finding.plugin_name,
        finding.plugin_family,
        finding.synopsis,
        finding.vulnerability_description,
        finding.solution,
        finding.package_name,
        finding.service,
        finding.operating_system,
        nvd_description,
        " ".join(sorted(cwes)),
    )
    return " ".join(str(value) for value in values if value)


def _snapshot(session: Session, snapshot_id: Any) -> dict[str, Any]:
    record = session.get(SourceSnapshotRecord, snapshot_id)
    if not record:
        return {"snapshot_status": "missing"}
    return {
        "source_url": record.source_url,
        "source_version": record.source_version,
        "retrieved_at": record.retrieved_at.isoformat() if record.retrieved_at else None,
        "content_sha256": record.content_sha256,
    }


def _latest_controls(session: Session) -> list[NistControlRecord]:
    records = list(session.scalars(select(NistControlRecord)))
    latest: dict[str, NistControlRecord] = {}
    for record in records:
        current = latest.get(record.control_id)
        if current is None or record.catalog_version > current.catalog_version:
            latest[record.control_id] = record
    return list(latest.values())


def _lexical_scores(query: Counter[str], controls: list[NistControlRecord]) -> dict[str, float]:
    if not query or not controls:
        return {record.control_id: 0.0 for record in controls}
    corpora = [_tokens(f"{record.control_id} {record.title} {record.statement or ''}") for record in controls]
    document_frequency: Counter[str] = Counter()
    for corpus in corpora:
        document_frequency.update(corpus.keys())
    total = len(corpora)
    weighted_query = {token: count * (log((total + 1) / (document_frequency[token] + 1)) + 1) for token, count in query.items()}
    query_norm = sqrt(sum(value * value for value in weighted_query.values())) or 1.0
    scores: dict[str, float] = {}
    for record, corpus in zip(controls, corpora, strict=True):
        weighted_control = {
            token: count * (log((total + 1) / (document_frequency[token] + 1)) + 1)
            for token, count in corpus.items()
        }
        control_norm = sqrt(sum(value * value for value in weighted_control.values())) or 1.0
        dot = sum(weighted_query[token] * weighted_control.get(token, 0.0) for token in weighted_query)
        scores[record.control_id] = dot / (query_norm * control_norm)
    return scores


def _control_passages(controls: list[NistControlRecord], *, chunk_size: int = 1_000) -> tuple[list[str], list[str]]:
    """Create title-anchored passages without persisting any finding text."""
    passages: list[str] = []
    control_ids: list[str] = []
    for control in controls:
        statement = control.statement or control.title
        chunks = [statement[index : index + chunk_size] for index in range(0, len(statement), chunk_size)] or [control.title]
        for chunk in chunks:
            passages.append(f"{control.control_id} {control.title}. Statement: {chunk}")
            control_ids.append(control.control_id)
    return passages, control_ids


def _embedding_cache_path(cache_directory: str | None, model_name: str, passages: list[str]) -> Path | None:
    if not cache_directory:
        return None
    digest = hashlib.sha256(
        json.dumps({"model": model_name, "passages": passages}, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return Path(cache_directory) / f"nist-control-passages-{digest}.npz"


def _semantic_scores(
    query_text: str,
    controls: list[NistControlRecord],
    *,
    embedding_model: str,
    reranker_model: str | None,
    cache_directory: str | None,
    batch_size: int,
    rerank_limit: int,
) -> tuple[dict[str, float], dict[str, float], dict[str, str], list[str]]:
    """Score public catalog passages with locally staged models only.

    The cache contains embeddings of public NIST control passages. The query/finding embedding is
    deliberately held in memory only. `local_files_only` guarantees this function never tries to
    download a model during an air-gapped workflow run.
    """
    import numpy as np
    from sentence_transformers import CrossEncoder, SentenceTransformer

    passages, passage_control_ids = _control_passages(controls)
    if not passages:
        return {}, {}, {}, []
    encoder = SentenceTransformer(embedding_model, trust_remote_code=False, local_files_only=True)
    cache_path = _embedding_cache_path(cache_directory, embedding_model, passages)
    passage_embeddings: Any
    if cache_path and cache_path.exists():
        try:
            with np.load(cache_path, allow_pickle=False) as cached:
                passage_embeddings = cached["embeddings"]
        except (OSError, ValueError, KeyError):
            passage_embeddings = None
    else:
        passage_embeddings = None
    if passage_embeddings is None:
        passage_embeddings = encoder.encode(
            passages,
            batch_size=batch_size,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        if cache_path:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            np.savez_compressed(cache_path, embeddings=passage_embeddings)

    # Do not cache the query embedding: it is derived from scanner/NVD finding context.
    query_embedding = encoder.encode(
        [query_text],
        batch_size=1,
        convert_to_numpy=True,
        normalize_embeddings=True,
        show_progress_bar=False,
    )[0]
    similarity_by_control: dict[str, float] = {}
    best_passage_by_control: dict[str, str] = {}
    for index, score in enumerate(np.asarray(passage_embeddings).dot(query_embedding)):
        control_id = passage_control_ids[index]
        value = float(score)
        if value > similarity_by_control.get(control_id, float("-inf")):
            similarity_by_control[control_id] = value
            best_passage_by_control[control_id] = passages[index]

    cross_scores: dict[str, float] = {}
    warnings: list[str] = []
    if reranker_model:
        try:
            reranker = CrossEncoder(reranker_model, trust_remote_code=False, local_files_only=True)
            top_control_ids = sorted(
                similarity_by_control,
                key=similarity_by_control.__getitem__,
                reverse=True,
            )[:rerank_limit]
            pairs = [(query_text, best_passage_by_control[control_id]) for control_id in top_control_ids]
            raw_scores = reranker.predict(pairs, batch_size=batch_size, show_progress_bar=False)
            for control_id, raw_score in zip(top_control_ids, raw_scores, strict=True):
                # Cross-encoder logits are converted to a bounded ranking feature, not confidence.
                value = float(raw_score)
                cross_scores[control_id] = 1.0 / (1.0 + exp(-max(min(value, 60.0), -60.0)))
        except Exception as error:  # Optional local model must never make candidate mapping unavailable.
            warnings.append(
                f"Optional local cross-encoder reranking was unavailable ({type(error).__name__}); semantic retrieval was retained."
            )
    return similarity_by_control, cross_scores, best_passage_by_control, warnings


def map_finding_to_controls(
    session: Session,
    finding: Finding,
    *,
    limit: int,
    backend: str = "lexical",
    embedding_model: str | None = None,
    reranker_model: str | None = None,
    embedding_cache_dir: str | None = None,
    embedding_batch_size: int = 8,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    cve = session.get(CveIntelligenceRecord, finding.cve_id) if finding.cve_id else None
    controls = _latest_controls(session)
    if not controls:
        return (
            {
                "summary": "NIST mapping cannot run because no approved OSCAL catalog snapshot is loaded.",
                "confidence": 0.0,
                "requires_human_review": True,
                "rationale": "The deterministic mapper requires a local official NIST catalog snapshot.",
                "findings": [],
                "recommendations": ["Run the connected-zone official source refresh before processing findings."],
                "assumptions": [],
            },
            [],
        )

    cwes = _cwes(cve)
    query_text = _finding_text(finding, _english_description(cve), cwes)
    lexical_scores = _lexical_scores(_tokens(query_text), controls)
    scores = lexical_scores
    semantic_scores: dict[str, float] = {}
    cross_scores: dict[str, float] = {}
    best_passages: dict[str, str] = {}
    runtime_warnings: list[str] = []
    mapping_method = "local_lexical_retrieval_with_cwe_candidate_expansion"
    if backend == "transformer":
        if not embedding_model:
            runtime_warnings.append("Transformer retrieval was requested without an embedding model; lexical retrieval was used.")
        else:
            try:
                semantic_scores, cross_scores, best_passages, semantic_warnings = _semantic_scores(
                    query_text,
                    controls,
                    embedding_model=embedding_model,
                    reranker_model=reranker_model,
                    cache_directory=embedding_cache_dir,
                    batch_size=embedding_batch_size,
                    rerank_limit=max(limit * 3, 20),
                )
                runtime_warnings.extend(semantic_warnings)
                scores = semantic_scores
                mapping_method = "local_sentence_transformer_retrieval_with_cwe_candidate_expansion"
                if cross_scores:
                    mapping_method = "local_sentence_transformer_retrieval_with_optional_cross_encoder_reranking"
            except Exception as error:  # Optional local model must never make candidate mapping unavailable.
                runtime_warnings.append(
                    f"Local transformer retrieval was unavailable ({type(error).__name__}); lexical retrieval was used."
                )

    top = sorted(controls, key=lambda record: scores.get(record.control_id, 0.0), reverse=True)[: max(limit * 3, 20)]
    cwe_ids = {control_id for cwe in cwes for control_id in _CWE_CONTROL_CANDIDATES.get(cwe, ())}
    candidates = {record.control_id: record for record in top}
    candidates.update({record.control_id: record for record in controls if record.control_id in cwe_ids})

    def ranking_score(control: NistControlRecord) -> float:
        cwe_boost = 1.0 if control.control_id in cwe_ids else 0.0
        if semantic_scores:
            semantic = semantic_scores.get(control.control_id, 0.0)
            if cross_scores:
                return (0.65 * semantic) + (0.25 * cross_scores.get(control.control_id, 0.0)) + (0.10 * cwe_boost)
            return (0.90 * semantic) + (0.10 * cwe_boost)
        return (0.90 * lexical_scores[control.control_id]) + (0.10 * cwe_boost)

    ranked = sorted(
        candidates.values(),
        key=ranking_score,
        reverse=True,
    )[:limit]

    findings: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for rank, control in enumerate(ranked, 1):
        cwe_match = control.control_id in cwe_ids
        reasons = ["retrieved_by_local_sentence_transformer" if semantic_scores else "retrieved_by_local_lexical_ranker"]
        if cwe_match:
            reasons.append("heuristic_CWE_candidate_rule")
        candidate = {
            "type": "candidate_control_mapping",
            "rank": rank,
            "control_id": control.control_id,
            "control_title": control.title,
            "control_family": control.family,
            "catalog_version": control.catalog_version,
            "ranking_score_not_probability": round(ranking_score(control), 5),
            "lexical_relevance_score_not_probability": round(lexical_scores[control.control_id], 5),
            "cwe_rule_match": cwe_match,
            "candidate_reasons": reasons,
            "supporting_control_text": best_passages.get(control.control_id, control.statement or "")[:1_200],
            "deficiency_status": "UNASSESSED",
            "assessment_status": "candidate_requires_implementation_evidence",
        }
        if semantic_scores:
            candidate["semantic_similarity_not_probability"] = round(semantic_scores.get(control.control_id, 0.0), 5)
        if cross_scores:
            candidate["cross_encoder_score_not_probability"] = round(cross_scores.get(control.control_id, 0.0), 5)
        findings.append(candidate)
        evidence.append(
            {
                "id": f"nist:{control.catalog_version}:{control.control_id}",
                "source": "nist_oscal_snapshot",
                "locator": f"nist_controls/{control.catalog_version}/{control.control_id}",
                "classification": "internal",
                "summary": f"Official NIST catalog snapshot control {control.control_id}",
                "content": {**candidate, "snapshot": _snapshot(session, control.source_snapshot_id)},
            }
        )
    if cve:
        nvd_data = {
            "cve_id": cve.cve_id,
            "cvss_base_score": cve.cvss_base_score,
            "description": cve.description,
            "cwes": sorted(cwes),
            "snapshot": _snapshot(session, cve.source_snapshot_id),
        }
        evidence.insert(
            0,
            {
                "id": f"nvd:{cve.cve_id}",
                "source": "nvd_snapshot",
                "locator": f"cve_intelligence/{cve.cve_id}",
                "classification": "internal",
                "summary": f"Official NVD snapshot for {cve.cve_id}",
                "content": nvd_data,
            },
        )
    response = {
        "summary": f"Deterministic ACAS/CVE-to-NIST candidate mapping produced {len(findings)} control candidate(s) for {finding.cve_id or finding.finding_id}.",
        "confidence": 0.5 if findings else 0.0,
        "requires_human_review": True,
        "rationale": "Candidates were ranked locally using ACAS/NVD text relevance and optional CWE retrieval expansion; neither score nor CWE link establishes a control deficiency.",
        "findings": findings,
        "recommendations": [
            "Validate that the scanner observation applies to the affected asset and installed component.",
            "Assess control implementation evidence before recording a control deficiency or POA&M item.",
        ],
        "assumptions": [
            "Plugin output was not used for ranking.",
            "CWE-to-control links are weak retrieval candidates from the supplied mapper, not an authoritative crosswalk.",
        ],
        "mapping_method": mapping_method,
        "mapping_runtime_warnings": runtime_warnings,
    }
    return response, evidence
