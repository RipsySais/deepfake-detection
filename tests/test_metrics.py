"""Tests des métriques, avec des valeurs calculées à la main."""
import pytest

from metrics import (auc, best_threshold, compute_metrics, confusion_matrix,
                     ratio, sweep)

# 4 fakes et 4 vraies images ; au seuil 0,5 : TP=2, FN=2, FP=1, TN=3.
LABELS = [True, True, True, True, False, False, False, False]
SCORES = [0.9, 0.8, 0.4, 0.3, 0.6, 0.2, 0.1, 0.05]


def test_ratio_handles_zero_denominator():
    """Une division par zéro donne None au lieu d'une erreur."""
    assert ratio(1, 0) is None
    assert ratio(1, 4) == 0.25


def test_confusion_matrix():
    """La matrice compte correctement les quatre cas."""
    predictions = [score >= 0.5 for score in SCORES]
    assert confusion_matrix(LABELS, predictions) == {
        'tp': 2, 'tn': 3, 'fp': 1, 'fn': 2}


def test_metrics_at_threshold():
    """Les métriques correspondent aux calculs faits à la main."""
    m = compute_metrics(LABELS, SCORES, 0.5)
    assert m['sensitivity'] == pytest.approx(0.5)
    assert m['specificity'] == pytest.approx(0.75)
    assert m['precision'] == pytest.approx(2 / 3)
    assert m['accuracy'] == pytest.approx(5 / 8)
    assert m['f1'] == pytest.approx(4 / 7)
    assert m['balanced_accuracy'] == pytest.approx(0.625)


def test_threshold_is_inclusive():
    """Un score égal au seuil est classé fake."""
    m = compute_metrics([True], [0.5], 0.5)
    assert m['tp'] == 1


def test_auc_value():
    """14 paires gagnantes sur 16 donnent 0,875."""
    assert auc(LABELS, SCORES) == pytest.approx(0.875)


def test_auc_perfect_and_tie():
    """Séparation parfaite = 1, scores identiques = 0,5."""
    assert auc([True, False], [0.9, 0.1]) == 1.0
    assert auc([True, False], [0.5, 0.5]) == 0.5


def test_auc_needs_both_classes():
    """Sans les deux classes, l'AUC n'est pas définie."""
    assert auc([True, True], [0.9, 0.8]) is None


def test_metrics_with_single_class():
    """Avec une seule classe, les métriques indéfinies valent None."""
    m = compute_metrics([False, False], [0.1, 0.9], 0.5)
    assert m['sensitivity'] is None
    assert m['balanced_accuracy'] is None
    assert m['specificity'] == pytest.approx(0.5)


def test_sweep_and_best_threshold():
    """Le balayage couvre 19 seuils et trouve un seuil séparant bien."""
    rows = sweep(LABELS, SCORES)
    assert len(rows) == 19
    threshold, metrics = best_threshold(rows)
    assert metrics['balanced_accuracy'] >= 0.625
    assert 0.05 <= threshold <= 0.95
