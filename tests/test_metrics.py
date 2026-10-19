import numpy as np
import pandas as pd
import pytest

from triage import metrics as M


def test_wilson_known_values():
    lo, hi = M.wilson(50, 50)
    assert lo == pytest.approx(0.9287, abs=1e-3) and hi == 1.0
    lo, hi = M.wilson(0, 10)
    assert lo == 0.0 and hi == pytest.approx(0.2775, abs=1e-3)
    lo, hi = M.wilson(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-3) and hi == pytest.approx(0.7634, abs=1e-3)


def test_fp_score_and_harness_failure_never_closed():
    df = pd.DataFrame({"status": ["ok", "ok", "harness_failure"], "verdict": ["false_positive", "real", None],
                       "confidence": [0.9, 0.8, None], "real_vulnerability": [False, True, True]})
    s = M.fp_score(df)
    assert s.iloc[0] == pytest.approx(0.9) and s.iloc[1] == pytest.approx(0.2) and np.isnan(s.iloc[2])
    closed = M.closed_at(s, 0.0)
    assert list(M.outcomes(df, closed)) == ["closed_fp", "closed_real", "harness_failure"]


def test_best_at_recall_picks_most_closing_threshold_that_keeps_recall():
    real = np.array([1, 1, 1, 1, 0, 0, 0, 0], dtype=bool)
    # one real alert looks like a false positive (0.95); false positives at 0.99, 0.9, 0.6, 0.2
    scores = np.array([0.1, 0.05, 0.3, 0.95, 0.99, 0.9, 0.6, 0.2])
    full = M.best_at_recall(real, scores, 1.0)       # may not close the 0.95 real one
    assert full["recall"] == 1.0 and full["fp_reduction"] == 0.25 and full["threshold"] == 0.99
    loose = M.best_at_recall(real, scores, 0.75)     # one miss allowed
    assert loose["recall"] == 0.75 and loose["fp_reduction"] == 0.75


def test_rates_with_weights():
    real = np.array([True, True, False, False])
    closed = np.array([False, True, True, False])
    assert M.rates(real, closed) == (0.5, 0.5)
    assert M.rates(real, closed, np.array([3.0, 1.0, 1.0, 1.0])) == (0.75, 0.5)


def test_mcnemar_and_rule_of_three():
    a = np.array([1, 1, 1, 0, 0], dtype=bool)
    b = np.array([1, 0, 0, 0, 0], dtype=bool)
    r = M.mcnemar(a, b)
    assert (r["only_a"], r["only_b"]) == (2, 0) and r["p_value"] == pytest.approx(0.5)
    assert M.rule_of_three_n(0.98) == 150
