"""Détection de deep fakes avec un modèle d'images pré-entraîné.

Principe : un classifieur d'images (Vision Transformer) renvoie, pour chaque
image, une probabilité d'être "fake". Pour une vidéo, on extrait quelques
images réparties dans le temps, on les classe une à une, puis on moyenne.

Le résultat est une estimation, pas une preuve : ces modèles se trompent,
surtout sur des techniques de manipulation absentes de leurs données
d'entraînement.
"""
import logging
import threading
from dataclasses import dataclass
from functools import lru_cache

import cv2
import numpy as np
from PIL import Image

log = logging.getLogger(__name__)

IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}
VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'webm'}
MAX_SCANNED_FRAMES = 900


class DetectorError(Exception):
    """Erreur levée quand un fichier ne peut pas être analysé."""


@dataclass
class Verdict:
    """Résultat d'une analyse."""
    fake_probability: float
    is_deepfake: bool
    frames_analyzed: int
    details: str


def file_kind(filename):
    """Retourne 'image', 'video' ou None selon l'extension du fichier."""
    if '.' not in filename:
        return None
    extension = filename.rsplit('.', 1)[1].lower()
    if extension in IMAGE_EXTENSIONS:
        return 'image'
    if extension in VIDEO_EXTENSIONS:
        return 'video'
    return None


def fake_probability_from_scores(scores):
    """Convertit la sortie d'un classifieur en probabilité de "fake".

    `scores` est une liste de dictionnaires {'label': ..., 'score': ...}.
    Tout label contenant "fake" (Fake, Deepfake...) compte comme faux ; les
    autres (Real, Realism...) comme authentiques.
    """
    fake_total = 0.0
    total = 0.0
    found_fake_label = False
    for item in scores:
        label = str(item['label']).lower()
        value = float(item['score'])
        total += value
        if 'fake' in label:
            fake_total += value
            found_fake_label = True
    if not found_fake_label or total <= 0:
        raise DetectorError(
            "Le modèle choisi n'a pas de label « fake » : "
            "vérifiez la variable DEEPFAKE_MODEL.")
    return fake_total / total


@lru_cache(maxsize=1)
def _face_cascade():
    """Charge (une seule fois) le détecteur de visages d'OpenCV."""
    path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
    cascade = cv2.CascadeClassifier(path)
    if cascade.empty():
        raise DetectorError('Détecteur de visages OpenCV introuvable.')
    return cascade


def crop_face(image):
    """Retourne le plus grand visage de l'image (avec marge), sinon l'image."""
    gray = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2GRAY)
    faces = _face_cascade().detectMultiScale(
        gray, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))
    if len(faces) == 0:
        return image
    x, y, w, h = max(faces, key=lambda face: face[2] * face[3])
    margin = int(0.2 * max(w, h))
    left = max(int(x) - margin, 0)
    top = max(int(y) - margin, 0)
    right = min(int(x + w) + margin, image.width)
    bottom = min(int(y + h) + margin, image.height)
    return image.crop((left, top, right, bottom))


def sample_frames(path, max_frames):
    """Extrait au plus `max_frames` images réparties sur toute la vidéo."""
    capture = cv2.VideoCapture(path)
    if not capture.isOpened():
        raise DetectorError('Vidéo illisible ou format non supporté.')
    frames = []
    try:
        total = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
        if total > 0:
            count = min(max_frames, total)
            indexes = np.linspace(0, total - 1, num=count, dtype=int)
            for index in sorted(set(indexes.tolist())):
                capture.set(cv2.CAP_PROP_POS_FRAMES, index)
                ok, frame = capture.read()
                if ok:
                    frames.append(frame)
        if not frames:
            capture.set(cv2.CAP_PROP_POS_FRAMES, 0)
            scanned = []
            while len(scanned) < MAX_SCANNED_FRAMES:
                ok, frame = capture.read()
                if not ok:
                    break
                scanned.append(frame)
            if scanned:
                count = min(max_frames, len(scanned))
                picks = np.linspace(0, len(scanned) - 1, num=count,
                                    dtype=int)
                frames = [scanned[i] for i in sorted(set(picks.tolist()))]
    finally:
        capture.release()
    if not frames:
        raise DetectorError('Aucune image exploitable dans la vidéo.')
    return [Image.fromarray(cv2.cvtColor(f, cv2.COLOR_BGR2RGB))
            for f in frames]


def build_pipeline_classifier(model_id):
    """Construit un classifieur Hugging Face : images -> probabilités fake."""
    try:
        from transformers import pipeline
    except ImportError as error:
        raise DetectorError(
            'Dépendances manquantes : installez torch et transformers '
            '(voir le README).') from error
    try:
        pipe = pipeline('image-classification', model=model_id, top_k=None)
    except OSError as error:
        raise DetectorError(
            f'Impossible de charger le modèle « {model_id} » '
            '(connexion internet ?).') from error

    def classify(images):
        outputs = pipe(images)
        return [fake_probability_from_scores(scores) for scores in outputs]

    return classify


class DeepfakeDetector:
    """Analyse des images et des vidéos avec un classifieur interchangeable.

    `classifier` est une fonction qui reçoit une liste d'images PIL et
    renvoie une liste de probabilités de "fake". Si elle n'est pas fournie,
    le modèle Hugging Face `model_id` est chargé à la première utilisation.
    """

    def __init__(self, model_id, threshold=0.5, max_frames=16,
                 use_face_crop=True, classifier=None):
        """Initialise le détecteur sans charger le modèle."""
        self.model_id = model_id
        self.threshold = threshold
        self.max_frames = max_frames
        self.use_face_crop = use_face_crop
        self._classifier = classifier
        self._lock = threading.Lock()

    def load(self):
        """Charge le modèle si nécessaire et le retourne."""
        with self._lock:
            if self._classifier is None:
                log.info('Chargement du modèle %s', self.model_id)
                self._classifier = build_pipeline_classifier(self.model_id)
            return self._classifier

    def _prepare(self, image):
        """Recadre sur le visage si l'option est activée."""
        if self.use_face_crop:
            return crop_face(image)
        return image

    def _score(self, images):
        """Retourne la probabilité de fake de chaque image."""
        classifier = self.load()
        prepared = [self._prepare(image) for image in images]
        return [float(p) for p in classifier(prepared)]

    def analyze_image(self, path):
        """Analyse une image."""
        try:
            with Image.open(path) as source:
                image = source.convert('RGB')
        except (OSError, ValueError) as error:
            raise DetectorError('Image illisible ou corrompue.') from error
        probability = self._score([image])[0]
        return Verdict(
            fake_probability=probability,
            is_deepfake=probability >= self.threshold,
            frames_analyzed=1,
            details=f'Probabilité de manipulation : {probability:.0%}')

    def analyze_video(self, path):
        """Analyse une vidéo à partir d'images échantillonnées."""
        frames = sample_frames(path, self.max_frames)
        probabilities = self._score(frames)
        mean = float(np.mean(probabilities))
        suspicious = sum(p >= self.threshold for p in probabilities)
        return Verdict(
            fake_probability=mean,
            is_deepfake=mean >= self.threshold,
            frames_analyzed=len(probabilities),
            details=(f'{suspicious} image(s) suspecte(s) sur '
                     f'{len(probabilities)} analysée(s)'))

    def analyze(self, path, kind):
        """Analyse un fichier selon son type ('image' ou 'video')."""
        if kind == 'image':
            return self.analyze_image(path)
        if kind == 'video':
            return self.analyze_video(path)
        raise DetectorError('Type de fichier non supporté.')
