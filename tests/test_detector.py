"""Tests unitaires du détecteur (sans télécharger de vrai modèle)."""
import cv2
import numpy as np
import pytest
from PIL import Image

from detector import (DeepfakeDetector, DetectorError, crop_face, file_kind,
                      sample_frames, fake_probability_from_scores)
from tests.conftest import fixed_classifier


def make_video(path, frames=30):
    """Écrit une courte vidéo AVI (MJPG) d'images aléatoires."""
    writer = cv2.VideoWriter(
        str(path), cv2.VideoWriter_fourcc(*'MJPG'), 10.0, (64, 64))
    rng = np.random.default_rng(0)
    for _ in range(frames):
        writer.write(rng.integers(0, 255, (64, 64, 3), dtype=np.uint8))
    writer.release()


def make_detector(value, **kwargs):
    """Détecteur avec un classifieur factice."""
    return DeepfakeDetector(
        'test', classifier=fixed_classifier(value), use_face_crop=False,
        **kwargs)


def test_file_kind():
    """L'extension détermine le type de fichier."""
    assert file_kind('a.JPG') == 'image'
    assert file_kind('a.mov') == 'video'
    assert file_kind('a.exe') is None
    assert file_kind('sans_extension') is None


def test_probability_with_real_fake_labels():
    """Les labels Real/Fake donnent la probabilité du label Fake."""
    scores = [{'label': 'Real', 'score': 0.2},
              {'label': 'Fake', 'score': 0.8}]
    assert fake_probability_from_scores(scores) == pytest.approx(0.8)


def test_probability_with_realism_deepfake_labels():
    """Les labels Realism/Deepfake sont aussi compris."""
    scores = [{'label': 'Realism', 'score': 0.7},
              {'label': 'Deepfake', 'score': 0.3}]
    assert fake_probability_from_scores(scores) == pytest.approx(0.3)


def test_probability_without_fake_label_raises():
    """Un modèle sans label « fake » est signalé clairement."""
    with pytest.raises(DetectorError):
        fake_probability_from_scores([{'label': 'cat', 'score': 1.0}])


def test_image_threshold(tmp_path):
    """Le verdict dépend du seuil."""
    path = tmp_path / 'img.png'
    Image.new('RGB', (32, 32)).save(path)
    assert make_detector(0.9).analyze_image(path).is_deepfake is True
    assert make_detector(0.2).analyze_image(path).is_deepfake is False


def test_corrupted_image_raises(tmp_path):
    """Un fichier image corrompu lève une DetectorError."""
    path = tmp_path / 'bad.png'
    path.write_bytes(b'pas une image')
    with pytest.raises(DetectorError):
        make_detector(0.5).analyze_image(path)


def test_video_samples_limited_number_of_frames(tmp_path):
    """Une vidéo de 30 images est échantillonnée à max_frames images."""
    path = tmp_path / 'clip.avi'
    make_video(path, frames=30)
    verdict = make_detector(0.9, max_frames=8).analyze_video(str(path))
    assert verdict.frames_analyzed == 8
    assert verdict.is_deepfake is True
    assert '8 image(s) suspecte(s) sur 8' in verdict.details


def test_short_video_uses_all_frames(tmp_path):
    """Une vidéo plus courte que max_frames est analysée en entier."""
    path = tmp_path / 'short.avi'
    make_video(path, frames=5)
    assert len(sample_frames(str(path), 16)) == 5


def test_unreadable_video_raises(tmp_path):
    """Un fichier vidéo invalide lève une DetectorError."""
    path = tmp_path / 'bad.mp4'
    path.write_bytes(b'rien')
    with pytest.raises(DetectorError):
        sample_frames(str(path), 8)


def test_crop_face_returns_image_when_no_face():
    """Sans visage, l'image entière est conservée."""
    rng = np.random.default_rng(1)
    noise = Image.fromarray(rng.integers(0, 255, (128, 128, 3),
                                         dtype=np.uint8))
    assert crop_face(noise).size == (128, 128)
