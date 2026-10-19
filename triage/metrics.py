"""Triage metrics: per-alert outcomes, threshold sweep, confidence intervals, paired tests, re-weighting.

Score: s = the model's probability that an alert is a false positive
       (confidence if the verdict is false_positive, 1 - confidence if it is real).
An alert is auto-closed when s >= t. Harness failures are never closed (they go to a human),
and are also counted separately.
"""

import math

import numpy as np
import pandas as pd
from scipy.stats import binomtest

OUTCOMES = ("kept_real", "closed_real", "closed_fp", "kept_fp", "harness_failure")


def fp_score(df: pd.DataFrame) -> pd.Series:
    """P(false positive) per alert; NaN for harness failures."""
    ok = df.status == "ok"
    s = np.where(df.verdict == "false_positive", df.confidence, 1 - df.confidence)
    return pd.Series(np.where(ok, s, np.nan), index=df.index)


def closed_at(scores: pd.Series, t: float) -> pd.Series:
    return scores.fillna(-np.inf) >= t


def outcomes(df: pd.DataFrame, closed: pd.Series) -> pd.Series:
    real = df.real_vulnerability.astype(bool)
    out = np.where(real, np.where(closed, "closed_real", "kept_real"), np.where(closed, "closed_fp", "kept_fp"))
    return pd.Series(np.where(df.status != "ok", "harness_failure", out), index=df.index)


def rates(real: np.ndarray, closed: np.ndarray, w: np.ndarray | None = None) -> tuple[float, float]:
    """(recall = share of real alerts kept, FP reduction = share of false positives closed); optional weights."""
    w = np.ones(len(real)) if w is None else w
    r, f = real.astype(bool), ~real.astype(bool)
    recall = float((w[r] * ~closed[r]).sum() / w[r].sum())
    fp_red = float((w[f] * closed[f]).sum() / w[f].sum())
    return recall, fp_red


def sweep(real: np.ndarray, scores: np.ndarray) -> pd.DataFrame:
    """Every distinct threshold (plus 'close nothing' = inf), with recall and FP reduction. Vectorised."""
    real = real.astype(bool)
    s = np.nan_to_num(scores.astype(float), nan=-np.inf)
    thresholds = np.concatenate([[np.inf], np.unique(s[np.isfinite(s)])[::-1]])
    rs, fs = np.sort(s[real]), np.sort(s[~real])
    closed_real = len(rs) - np.searchsorted(rs, thresholds, side="left")
    closed_fp = len(fs) - np.searchsorted(fs, thresholds, side="left")
    return pd.DataFrame({"threshold": thresholds, "recall": 1 - closed_real / len(rs),
                         "fp_reduction": closed_fp / len(fs)})


def best_at_recall(real: np.ndarray, scores: np.ndarray, target: float) -> dict:
    """Most-closing threshold whose recall still meets the target (ties: the strictest threshold)."""
    sw = sweep(real, scores)
    ok = sw[sw.recall >= target - 1e-12]
    row = ok[ok.fp_reduction == ok.fp_reduction.max()].sort_values("threshold").iloc[-1]
    return {"threshold": float(row.threshold), "recall": float(row.recall), "fp_reduction": float(row.fp_reduction)}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def bootstrap_fp_reduction(real: np.ndarray, scores: np.ndarray, target: float, n_boot: int = 2000,
                           seed: int = 42) -> tuple[float, float]:
    """95% CI of FP reduction at the recall target, re-picking the threshold in every resample.

    Resamples real and false-positive alerts separately, so each resample keeps the golden set's 50/50 mix.
    """
    rng = np.random.default_rng(seed)
    r_idx, f_idx = np.flatnonzero(real.astype(bool)), np.flatnonzero(~real.astype(bool))
    vals = []
    for _ in range(n_boot):
        idx = np.concatenate([rng.choice(r_idx, len(r_idx)), rng.choice(f_idx, len(f_idx))])
        vals.append(best_at_recall(real[idx], scores[idx], target)["fp_reduction"])
    return float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))


def mcnemar(a: np.ndarray, b: np.ndarray) -> dict:
    """Exact McNemar test on paired binary outcomes (e.g. 'closed this false positive')."""
    a, b = a.astype(bool), b.astype(bool)
    only_a, only_b = int((a & ~b).sum()), int((~a & b).sum())
    p = 1.0 if only_a + only_b == 0 else binomtest(only_a, only_a + only_b, 0.5).pvalue
    return {"only_a": only_a, "only_b": only_b, "p_value": float(p)}


def natural_weights(golden: pd.DataFrame, population: pd.DataFrame) -> pd.Series:
    """Weight per golden alert so (category, label) cells count as often as in the scanner's real output."""
    key = ["category", "real_vulnerability"]
    pop = population.groupby(key).size()
    sample = golden.groupby(key).size()
    w = (pop / sample).rename("w")
    return golden.join(w, on=key)["w"]


def rule_of_three_n(target: float) -> int:
    """Real alerts needed, with zero misses, for the 95% lower bound on recall to reach the target."""
    return math.ceil(3 / (1 - target))
