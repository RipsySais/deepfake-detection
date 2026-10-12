"""Tests des outils d'entraînement (dégradations, échantillonnage, taux)."""
import random

import numpy as np
import pytest
from PIL import Image

from train_utils import (RandomDegrade, balanced_indices, down_up,
                         fixed_degradation, jpeg_roundtrip, lr_factor)


def noisy_image(size=64, seed=0):
    """Image de bruit : les dégradations y sont bien visibles."""
    rng = np.random.default_rng(seed)
    return Image.fromarray(rng.integers(0, 255, (size, size, 3),
                                        dtype=np.uint8))


def mean_difference(first, second):
    """Écart moyen absolu entre deux images de même taille."""
    a = np.asarray(first, dtype=float)
    b = np.asarray(second, dtype=float)
    return float(np.abs(a - b).mean())


def test_jpeg_quality_controls_loss():
    """Une qualité JPEG basse abîme plus l'image qu'une qualité haute."""
    image = noisy_image()
    low = jpeg_roundtrip(image, 25)
    high = jpeg_roundtrip(image, 95)
    assert low.size == high.size == image.size
    assert mean_difference(image, low) > mean_difference(image, high)


def test_down_up_keeps_size_and_loses_detail():
    """La réduction puis l'agrandissement gardent la taille mais lissent."""
    image = noisy_image()
    result = down_up(image, 0.5, Image.Resampling.BILINEAR)
    assert result.size == image.size
    assert mean_difference(image, result) > 5


def test_fixed_degradation_is_deterministic():
    """La dégradation d'évaluation donne toujours le même résultat."""
    image = noisy_image()
    first = np.asarray(fixed_degradation(image))
    second = np.asarray(fixed_degradation(image))
    assert np.array_equal(first, second)
    assert first.shape == (64, 64, 3)


def test_random_degrade_returns_rgb_same_size():
    """Quelle que soit la graine, l'image garde sa taille et ses canaux."""
    for seed in range(20):
        degrade = RandomDegrade(probability=1.0, rng=random.Random(seed))
        result = degrade(noisy_image())
        assert result.mode == 'RGB'
        assert result.size == (64, 64)


def test_random_degrade_changes_images():
    """Avec probabilité 1, la plupart des images sont modifiées."""
    image = noisy_image()
    changed = 0
    for seed in range(20):
        degrade = RandomDegrade(probability=1.0, rng=random.Random(seed))
        original_or_flipped = (
            np.array_equal(np.asarray(degrade(image)), np.asarray(image)))
        changed += 0 if original_or_flipped else 1
    assert changed >= 15


def test_random_degrade_probability_zero_only_flips():
    """Sans dégradation, l'image est identique ou simplement retournée."""
    image = noisy_image()
    mirrored = image.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
    for seed in range(10):
        degrade = RandomDegrade(probability=0.0, rng=random.Random(seed))
        result = np.asarray(degrade(image))
        assert (np.array_equal(result, np.asarray(image))
                or np.array_equal(result, np.asarray(mirrored)))


def test_balanced_indices_is_balanced_and_reproducible():
    """Le tirage a autant d'images par classe, et dépend de la graine."""
    labels = [0] * 50 + [1] * 30
    chosen = balanced_indices(labels, 10, seed=1)
    assert len(chosen) == 20
    assert sum(1 for i in chosen if labels[i] == 0) == 10
    assert sum(1 for i in chosen if labels[i] == 1) == 10
    assert chosen == balanced_indices(labels, 10, seed=1)
    assert chosen != balanced_indices(labels, 10, seed=2)
    assert len(set(chosen)) == 20


def test_balanced_indices_takes_all_when_class_is_small():
    """Une classe plus petite que `per_class` est prise en entier."""
    labels = [0] * 5 + [1] * 50
    chosen = balanced_indices(labels, 10, seed=0)
    assert sum(1 for i in chosen if labels[i] == 0) == 5
    assert sum(1 for i in chosen if labels[i] == 1) == 10


def test_lr_factor_schedule():
    """Montée linéaire jusqu'à 1, puis descente jusqu'à 0."""
    assert lr_factor(0, 10, 100) == pytest.approx(0.1)
    assert lr_factor(9, 10, 100) == pytest.approx(1.0)
    assert lr_factor(10, 10, 100) == pytest.approx(1.0)
    assert lr_factor(55, 10, 100) == pytest.approx(0.5)
    assert lr_factor(100, 10, 100) == 0.0
    assert lr_factor(150, 10, 100) == 0.0
