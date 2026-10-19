"""Metric interface.  Implementations are intentionally small and replaceable."""
from __future__ import annotations

from .models import GoldLabels, Prediction

LEVEL_ORDER = {"lead": 0, "observed": 1, "corroborated": 2, "conflicted": 0}


def precision_recall_f1(pred: Prediction, gold: GoldLabels) -> dict[str, float]:
    predicted, truth = set(pred.values), set(gold.entities)
    hit = len(predicted & truth)
    precision = hit / len(predicted) if predicted else 0.0
    recall = hit / len(truth) if truth else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def precision_at_k(pred: Prediction, gold: GoldLabels, k: int = 5) -> float:
    top = pred.values[:k]
    return sum(v in gold.entities for v in top) / len(top) if top else 0.0


def over_promotion_rate(pred: Prediction, gold: GoldLabels) -> float:
    """Share of graded predictions whose evidence level exceeds what gold justifies.

    Only meaningful for methods that grade evidence (``evidence_level`` set) and
    for entities present in ``gold.entity_levels``.
    """
    graded = [t for t in pred.targets if t.evidence_level and t.value in gold.entity_levels]
    if not graded:
        return 0.0
    over = sum(LEVEL_ORDER.get(t.evidence_level, 0) > LEVEL_ORDER.get(gold.entity_levels[t.value], 0) for t in graded)
    return over / len(graded)


def wrong_link_rate(pred: Prediction, gold: GoldLabels) -> float:
    """Share of predicted edges absent from the gold edge set (wrong target linkage)."""
    if not pred.edges:
        return 0.0
    return sum(e not in gold.edges for e in pred.edges) / len(pred.edges)


def edge_precision_recall(pred: Prediction, gold: GoldLabels) -> dict[str, float]:
    predicted, truth = set(pred.edges), set(gold.edges)
    hit = len(predicted & truth)
    return {
        "edge_precision": hit / len(predicted) if predicted else 0.0,
        "edge_recall": hit / len(truth) if truth else 0.0,
    }


def score_prediction(pred: Prediction, gold: GoldLabels, k: int = 5) -> dict[str, float]:
    out = precision_recall_f1(pred, gold)
    out["precision_at_k"] = precision_at_k(pred, gold, k)
    out["over_promotion_rate"] = over_promotion_rate(pred, gold)
    out["wrong_link_rate"] = wrong_link_rate(pred, gold)
    return out
