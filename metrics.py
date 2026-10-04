"""Métriques de classification binaire pour évaluer un détecteur.

Convention : la classe « positive » est « fake ». Un deepfake correctement
repéré est un vrai positif (TP) ; une vraie photo jugée fausse est un faux
positif (FP) ; un deepfake raté est un faux négatif (FN).
"""


def ratio(numerator, denominator):
    """Divise deux nombres, ou retourne None si le dénominateur est nul."""
    if denominator == 0:
        return None
    return numerator / denominator


def confusion_matrix(labels, predictions):
    """Compte TP, TN, FP, FN à partir de deux listes de booléens."""
    pairs = list(zip(labels, predictions))
    return {
        'tp': sum(1 for label, pred in pairs if label and pred),
        'tn': sum(1 for label, pred in pairs if not label and not pred),
        'fp': sum(1 for label, pred in pairs if not label and pred),
        'fn': sum(1 for label, pred in pairs if label and not pred),
    }


def compute_metrics(labels, scores, threshold):
    """Calcule la matrice de confusion et les métriques à un seuil donné.

    - sensibilité = TP / (TP + FN) : part des fakes détectés
    - spécificité = TN / (TN + FP) : part des vraies images reconnues
    - précision   = TP / (TP + FP) : parmi les alertes, part de vrais fakes
    - exactitude  = (TP + TN) / total
    - F1          = 2 TP / (2 TP + FP + FN)
    """
    predictions = [score >= threshold for score in scores]
    result = confusion_matrix(labels, predictions)
    tp, tn, fp, fn = result['tp'], result['tn'], result['fp'], result['fn']
    result['sensitivity'] = ratio(tp, tp + fn)
    result['specificity'] = ratio(tn, tn + fp)
    result['precision'] = ratio(tp, tp + fp)
    result['accuracy'] = ratio(tp + tn, tp + tn + fp + fn)
    result['f1'] = ratio(2 * tp, 2 * tp + fp + fn)
    if result['sensitivity'] is None or result['specificity'] is None:
        result['balanced_accuracy'] = None
    else:
        result['balanced_accuracy'] = (
            result['sensitivity'] + result['specificity']) / 2
    return result


def auc(labels, scores):
    """Aire sous la courbe ROC, sans dépendance externe.

    C'est la probabilité qu'un fake tiré au hasard reçoive un score plus
    élevé qu'une vraie image tirée au hasard (égalité = 0,5). Elle ne dépend
    pas du seuil : 1,0 = séparation parfaite, 0,5 = hasard.
    """
    fakes = [s for label, s in zip(labels, scores) if label]
    reals = [s for label, s in zip(labels, scores) if not label]
    if not fakes or not reals:
        return None
    wins = 0.0
    for fake_score in fakes:
        for real_score in reals:
            if fake_score > real_score:
                wins += 1
            elif fake_score == real_score:
                wins += 0.5
    return wins / (len(fakes) * len(reals))


def sweep(labels, scores, thresholds=None):
    """Calcule les métriques pour une liste de seuils (0,05 à 0,95)."""
    if thresholds is None:
        thresholds = [i / 20 for i in range(1, 20)]
    return [(t, compute_metrics(labels, scores, t)) for t in thresholds]


def best_threshold(rows):
    """Retourne la ligne (seuil, métriques) à la meilleure exactitude
    équilibrée ; à égalité, le seuil le plus proche de 0,5."""
    valid = [row for row in rows if row[1]['balanced_accuracy'] is not None]
    if not valid:
        return None
    return max(valid, key=lambda row: (
        row[1]['balanced_accuracy'], -abs(row[0] - 0.5)))
