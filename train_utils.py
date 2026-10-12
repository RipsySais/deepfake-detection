"""Outils d'entraînement sans dépendance à torch.

- dégradations d'images (compression JPEG, flou, réduction de taille) pour
  que le modèle apprenne aussi sur des images « WhatsApp », pas seulement
  sur des images propres ;
- tirage d'un sous-ensemble équilibré réel / fake ;
- planning du taux d'apprentissage (montée puis descente linéaires).
"""
import io
import random

from PIL import Image, ImageEnhance, ImageFilter

RESAMPLERS = (Image.Resampling.BILINEAR, Image.Resampling.BICUBIC,
              Image.Resampling.LANCZOS)


def jpeg_roundtrip(image, quality):
    """Compresse l'image en JPEG puis la décompresse (perte de qualité)."""
    buffer = io.BytesIO()
    image.convert('RGB').save(buffer, format='JPEG', quality=quality)
    buffer.seek(0)
    with Image.open(buffer) as compressed:
        return compressed.convert('RGB')


def down_up(image, scale, resample):
    """Réduit l'image puis la ramène à sa taille d'origine (perte de détails).

    Les artefacts fins des images générées disparaissent ainsi en partie,
    comme sur une photo envoyée par messagerie.
    """
    width, height = image.size
    small = image.resize(
        (max(8, int(width * scale)), max(8, int(height * scale))), resample)
    return small.resize((width, height), resample)


def fixed_degradation(image):
    """Dégradation toujours identique, pour une évaluation reproductible."""
    reduced = down_up(image.convert('RGB'), 0.5,
                      Image.Resampling.BILINEAR)
    return jpeg_roundtrip(reduced, 40)


class RandomDegrade:
    """Retourne l'image au hasard puis la dégrade avec une probabilité donnée.

    La même loi de dégradation s'applique aux vraies images et aux fausses :
    sinon le modèle apprendrait « image dégradée = vraie » au lieu de
    regarder le visage.
    """

    def __init__(self, probability=0.8, rng=None):
        """`rng` permet d'imposer un générateur aléatoire (tests)."""
        self.probability = probability
        self.rng = rng if rng is not None else random

    def __call__(self, image):
        """Applique les transformations aléatoires à une image PIL."""
        rng = self.rng
        image = image.convert('RGB')
        if rng.random() < 0.5:
            image = image.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
        if rng.random() >= self.probability:
            return image
        if rng.random() < 0.6:
            image = down_up(image, rng.uniform(0.4, 0.9),
                            rng.choice(RESAMPLERS))
        if rng.random() < 0.4:
            image = image.filter(
                ImageFilter.GaussianBlur(rng.uniform(0.3, 1.5)))
        if rng.random() < 0.3:
            image = ImageEnhance.Brightness(image).enhance(
                rng.uniform(0.7, 1.3))
            image = ImageEnhance.Contrast(image).enhance(
                rng.uniform(0.8, 1.2))
        if rng.random() < 0.8:
            image = jpeg_roundtrip(image, rng.randint(25, 95))
        return image


def balanced_indices(labels, per_class, seed=0):
    """Tire au plus `per_class` indices par classe, puis mélange le tout."""
    rng = random.Random(seed)
    by_class = {}
    for index, label in enumerate(labels):
        by_class.setdefault(int(label), []).append(index)
    chosen = []
    for label in sorted(by_class):
        indices = by_class[label]
        rng.shuffle(indices)
        chosen.extend(indices[:per_class])
    rng.shuffle(chosen)
    return chosen


def lr_factor(step, warmup_steps, total_steps):
    """Facteur du taux d'apprentissage : montée linéaire puis descente à 0."""
    if step < warmup_steps:
        return (step + 1) / max(1, warmup_steps)
    progress = (step - warmup_steps) / max(1, total_steps - warmup_steps)
    return max(0.0, 1.0 - progress)
