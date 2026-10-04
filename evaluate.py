"""Évaluation du détecteur sur des images dont on connaît la nature.

Usage :
    python evaluate.py --real data/eval/real --fake data/eval/fake

Le script analyse chaque fichier des deux dossiers, puis affiche la matrice
de confusion, les métriques, l'effet du seuil et la liste des erreurs.
"""
import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path

from config import Config
from detector import DeepfakeDetector, DetectorError, file_kind
from metrics import auc, best_threshold, compute_metrics, sweep

MAX_ERRORS_SHOWN = 10


@dataclass
class Sample:
    """Un fichier analysé, avec sa vraie nature."""
    name: str
    is_fake: bool
    score: float
    faces_found: int
    frames: int


def pct(value):
    """Formate une proportion en pourcentage, ou 'n/a' si elle est vide."""
    if value is None:
        return 'n/a'
    return f'{value * 100:.1f} %'


def list_media(folder):
    """Liste les images et vidéos d'un dossier (sous-dossiers compris)."""
    return sorted(
        path for path in Path(folder).rglob('*')
        if path.is_file() and file_kind(path.name))


def collect(detector, folder, is_fake):
    """Analyse tous les fichiers d'un dossier et retourne des Sample."""
    samples = []
    for path in list_media(folder):
        try:
            verdict = detector.analyze(str(path), file_kind(path.name))
        except DetectorError as error:
            print(f'  ignoré : {path.name} ({error})')
            continue
        samples.append(Sample(
            name=f'{Path(folder).name}/{path.name}',
            is_fake=is_fake,
            score=verdict.fake_probability,
            faces_found=verdict.faces_found,
            frames=verdict.frames_analyzed))
        print(f'  {path.name} : {verdict.fake_probability:.2f}')
    return samples


def format_errors(samples, threshold):
    """Liste les faux positifs et faux négatifs au seuil donné."""
    false_positives = sorted(
        (s for s in samples if not s.is_fake and s.score >= threshold),
        key=lambda s: -s.score)
    false_negatives = sorted(
        (s for s in samples if s.is_fake and s.score < threshold),
        key=lambda s: s.score)
    lines = [f'--- Erreurs au seuil {threshold:.2f} ---']
    if not false_positives and not false_negatives:
        lines.append('Aucune erreur.')
    for label, items in (('FP (vraie image jugée fake)', false_positives),
                         ('FN (fake non détecté)', false_negatives)):
        for sample in items[:MAX_ERRORS_SHOWN]:
            lines.append(f'{label[:2]}  {sample.name}  '
                         f'score={sample.score:.2f}')
    return lines


def format_report(samples, threshold):
    """Construit le rapport complet sous forme de texte."""
    labels = [s.is_fake for s in samples]
    scores = [s.score for s in samples]
    n_fake = sum(labels)
    n_real = len(labels) - n_fake
    no_face = sum(1 for s in samples if s.faces_found == 0)
    m = compute_metrics(labels, scores, threshold)

    lines = [
        f'Échantillon : {n_real} réelle(s), {n_fake} fausse(s), '
        f'{no_face} sans visage détecté',
        '',
        f'--- Résultats au seuil {threshold:.2f} ---',
        '                  prédit réel     prédit fake',
        f"vraie réelle      TN={m['tn']:<10d}  FP={m['fp']}",
        f"vraie fake        FN={m['fn']:<10d}  TP={m['tp']}",
        '',
        f"Sensibilité (fakes détectés)         : {pct(m['sensitivity'])}",
        f"Spécificité (vraies images reconnues): {pct(m['specificity'])}",
        f"Précision (alertes justifiées)       : {pct(m['precision'])}",
        f"Exactitude                           : {pct(m['accuracy'])}",
        f"F1                                   : {pct(m['f1'])}",
        f'AUC (indépendante du seuil)          : '
        f'{auc(labels, scores):.3f}',
        '',
        '--- Effet du seuil ---',
        ' seuil   sensib.   spécif.  exact.éq.      F1',
    ]
    rows = sweep(labels, scores)
    for t, row in rows:
        lines.append(
            f"{t:5.2f}  {pct(row['sensitivity']):>8}  "
            f"{pct(row['specificity']):>8}  "
            f"{pct(row['balanced_accuracy']):>8}  {pct(row['f1']):>8}")
    best = best_threshold(rows)
    if best is not None:
        lines.append('')
        lines.append(f'Meilleur seuil (exactitude équilibrée) : {best[0]:.2f}')
    lines.append('')
    lines.extend(format_errors(samples, threshold))
    lines.append('')
    if no_face:
        lines.append('Les images sans visage sont peu fiables pour ce '
                     'modèle : retirez-les ou ajoutez-en avec visage.')
    lines.append('Attention : sur un petit échantillon, une seule image '
                 'change les pourcentages de plusieurs points.')
    return '\n'.join(lines)


def write_csv(samples, path):
    """Écrit le détail fichier par fichier dans un CSV."""
    with open(path, 'w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle)
        writer.writerow(['fichier', 'vraie_nature', 'score', 'visages'])
        for s in samples:
            writer.writerow([s.name, 'fake' if s.is_fake else 'real',
                             f'{s.score:.4f}', s.faces_found])


def parse_args(argv):
    """Lit les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description='Évalue le détecteur sur des images étiquetées.')
    parser.add_argument('--real', required=True,
                        help='dossier d\'images authentiques')
    parser.add_argument('--fake', required=True,
                        help='dossier d\'images truquées ou générées')
    parser.add_argument('--threshold', type=float,
                        default=Config.FAKE_THRESHOLD,
                        help='seuil de décision (défaut : %(default)s)')
    parser.add_argument('--no-face-crop', action='store_true',
                        help='désactive le recadrage sur le visage')
    parser.add_argument('--csv', help='écrit le détail dans ce fichier CSV')
    return parser.parse_args(argv)


def main(argv=None, detector=None):
    """Point d'entrée ; retourne le code de sortie du programme."""
    args = parse_args(argv)
    for folder in (args.real, args.fake):
        if not Path(folder).is_dir():
            print(f'Dossier introuvable : {folder}')
            return 2
    if detector is None:
        detector = DeepfakeDetector(
            model_id=Config.MODEL_ID,
            threshold=args.threshold,
            max_frames=Config.MAX_VIDEO_FRAMES,
            use_face_crop=Config.USE_FACE_CROP and not args.no_face_crop)
    try:
        detector.load()
    except DetectorError as error:
        print(error)
        return 1

    print('Analyse des images réelles :')
    samples = collect(detector, args.real, False)
    print('Analyse des images fausses :')
    samples += collect(detector, args.fake, True)
    if all(s.is_fake for s in samples) or not any(s.is_fake for s in samples):
        print('Il faut au moins un fichier réel et un fichier faux analysés.')
        return 1

    print()
    print(format_report(samples, args.threshold))
    if args.csv:
        write_csv(samples, args.csv)
        print(f'\nDétail écrit dans {args.csv}')
    return 0


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(errors='replace')
    sys.exit(main())
