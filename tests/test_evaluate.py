"""Test du script d'évaluation avec un faux classifieur."""
from PIL import Image

import evaluate
from detector import DeepfakeDetector


def red_means_fake(images):
    """Faux classifieur : une image rouge est « fake », sinon « réelle »."""
    return [0.9 if image.getpixel((0, 0))[0] > 128 else 0.1
            for image in images]


def make_folder(path, colors):
    """Crée un dossier d'images unies, une par couleur."""
    path.mkdir()
    for index, color in enumerate(colors):
        Image.new('RGB', (64, 64), color).save(path / f'img{index}.png')


def make_detector():
    """Détecteur sans modèle réel."""
    return DeepfakeDetector(
        'test', classifier=red_means_fake, use_face_crop=False)


def test_evaluation_report(tmp_path, capsys):
    """Le rapport affiche la bonne matrice de confusion."""
    blue, red = (0, 0, 255), (255, 0, 0)
    # Un fichier rouge est glissé parmi les vraies images : 1 faux positif.
    make_folder(tmp_path / 'real', [blue, blue, blue, red])
    make_folder(tmp_path / 'fake', [red, red, red])
    csv_path = tmp_path / 'out.csv'
    code = evaluate.main(
        ['--real', str(tmp_path / 'real'), '--fake', str(tmp_path / 'fake'),
         '--csv', str(csv_path)],
        detector=make_detector())
    output = capsys.readouterr().out
    assert code == 0
    for expected in ('TN=3', 'FP=1', 'FN=0', 'TP=3'):
        assert expected in output
    assert 'real/img3.png' in output
    assert 'AUC' in output and '0.875' in output
    assert csv_path.read_text(encoding='utf-8').count('\n') == 8


def test_missing_folder(tmp_path, capsys):
    """Un dossier absent donne le code 2 et un message clair."""
    code = evaluate.main(
        ['--real', str(tmp_path / 'nope'), '--fake', str(tmp_path)],
        detector=make_detector())
    assert code == 2
    assert 'Dossier introuvable' in capsys.readouterr().out


def test_needs_both_classes(tmp_path, capsys):
    """Un dossier vide empêche l'évaluation."""
    make_folder(tmp_path / 'fake', [(255, 0, 0)])
    (tmp_path / 'real').mkdir()
    code = evaluate.main(
        ['--real', str(tmp_path / 'real'), '--fake', str(tmp_path / 'fake')],
        detector=make_detector())
    assert code == 1
    assert 'au moins un fichier réel' in capsys.readouterr().out
