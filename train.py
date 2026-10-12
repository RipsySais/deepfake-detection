"""Fine-tuning d'un classifieur réel / fake sur le dataset 140k Real and Fake
Faces (Hugging Face).

Principe : on part d'un réseau déjà entraîné à reconnaître des images en
général, on remplace sa dernière couche par une sortie à 2 classes
(Real / Fake) et on le réentraîne sur des visages. Pendant l'entraînement,
les images sont dégradées au hasard (JPEG, flou, réduction) pour imiter des
photos de messagerie.

Le modèle est sauvegardé au format Hugging Face : il se branche dans
l'application en mettant son dossier dans DEEPFAKE_MODEL, sans changer le code.

Usage (sur Colab avec un GPU) :
    python train.py --smoke            # essai de quelques minutes
    python train.py --max-per-class 10000 --epochs 3 --output models/v1
"""
import argparse
import json
import os
import random
import time

import torch
from datasets import load_dataset
from PIL import Image
from torch.utils.data import DataLoader, Dataset
from transformers import (AutoImageProcessor, AutoModelForImageClassification,
                          pipeline)

from metrics import auc, compute_metrics
from train_utils import (RandomDegrade, balanced_indices, fixed_degradation,
                         lr_factor)

DATASET = 'TheKernel01/140k-Real-and-Fake-Faces'
BASE_MODEL = 'facebook/convnext-tiny-224'
ID2LABEL = {0: 'Real', 1: 'Fake'}
LABEL2ID = {'Real': 0, 'Fake': 1}


class FaceDataset(Dataset):
    """Images d'un dataset Hugging Face, avec dégradations selon le mode."""

    def __init__(self, hf_dataset, processor, mode):
        """mode : 'train' (dégradations aléatoires), 'clean' ou 'degraded'."""
        self.data = hf_dataset
        self.processor = processor
        self.mode = mode
        self.random_degrade = RandomDegrade()

    def __len__(self):
        """Nombre d'images."""
        return len(self.data)

    def __getitem__(self, index):
        """Retourne (pixels normalisés, étiquette 0 = réel / 1 = fake)."""
        row = self.data[index]
        image = row['image'].convert('RGB')
        if self.mode == 'train':
            image = self.random_degrade(image)
        elif self.mode == 'degraded':
            image = fixed_degradation(image)
        pixels = self.processor(
            images=image, return_tensors='pt')['pixel_values'][0]
        return pixels, int(row['label'])


@torch.no_grad()
def predict(model, loader, device):
    """Retourne (étiquettes, probabilités de fake) pour tout un loader."""
    model.eval()
    labels, scores = [], []
    for pixels, targets in loader:
        pixels = pixels.to(device)
        with torch.autocast(device_type=device.type,
                            enabled=device.type == 'cuda'):
            logits = model(pixel_values=pixels).logits
        probabilities = torch.softmax(logits.float(), dim=1)[:, 1]
        scores.extend(probabilities.cpu().tolist())
        labels.extend(bool(target) for target in targets.tolist())
    return labels, scores


def evaluate_subset(model, subset, processor, device, args, mode):
    """Mesure exactitude, sensibilité, spécificité et AUC."""
    loader = DataLoader(
        FaceDataset(subset, processor, mode),
        batch_size=args.batch_size * 2, shuffle=False,
        num_workers=args.workers)
    labels, scores = predict(model, loader, device)
    result = compute_metrics(labels, scores, 0.5)
    result['auc'] = auc(labels, scores)
    keep = ('accuracy', 'sensitivity', 'specificity', 'auc')
    return {key: result[key] for key in keep}


def fmt(value):
    """Formate un nombre à 3 décimales, ou 'n/a'."""
    return 'n/a' if value is None else f'{value:.3f}'


def describe(metrics):
    """Résume un dictionnaire de métriques sur une ligne."""
    return (f"exactitude={fmt(metrics['accuracy'])} "
            f"sensibilité={fmt(metrics['sensitivity'])} "
            f"spécificité={fmt(metrics['specificity'])} "
            f"AUC={fmt(metrics['auc'])}")


def make_scaler(use_amp):
    """Crée le GradScaler (précision mixte) selon la version de torch."""
    try:
        return torch.amp.GradScaler('cuda', enabled=use_amp)
    except (AttributeError, TypeError):
        return torch.cuda.amp.GradScaler(enabled=use_amp)


def load_subset(name, split, per_class, seed):
    """Charge un split et en extrait un sous-ensemble équilibré."""
    full = load_dataset(name, split=split)
    indices = balanced_indices(full['label'], per_class, seed)
    return full.select(indices)


def check_saved_model(output):
    """Recharge le modèle sauvegardé comme le fera l'application."""
    classifier = pipeline('image-classification', model=output, top_k=None)
    gray = Image.new('RGB', (256, 256), (128, 128, 128))
    print('Contrôle du modèle sauvegardé :', classifier(gray))


def train(args):
    """Entraîne, garde le meilleur modèle, puis l'évalue sur le split test."""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    if device.type == 'cpu' and not args.smoke:
        raise SystemExit(
            "Aucun GPU détecté. Sur Colab : Exécution > Modifier le type "
            "d'exécution > GPU T4.")
    random.seed(args.seed)
    torch.manual_seed(args.seed)
    print(f'Appareil : {device} | modèle de base : {args.base_model}')

    processor = AutoImageProcessor.from_pretrained(args.base_model)
    model = AutoModelForImageClassification.from_pretrained(
        args.base_model, num_labels=2, id2label=ID2LABEL,
        label2id=LABEL2ID, ignore_mismatched_sizes=True).to(device)

    print('Chargement du dataset (téléchargement de plusieurs Go la '
          'première fois)...')
    train_set = load_subset(args.dataset, 'train', args.max_per_class,
                            args.seed)
    valid_set = load_subset(args.dataset, 'validation', args.val_per_class,
                            args.seed)
    print(f'Entraînement : {len(train_set)} images | '
          f'validation : {len(valid_set)} images')

    loader = DataLoader(
        FaceDataset(train_set, processor, 'train'),
        batch_size=args.batch_size, shuffle=True, num_workers=args.workers,
        pin_memory=device.type == 'cuda', drop_last=True)
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=args.lr, weight_decay=0.05)
    total_steps = args.epochs * len(loader)
    warmup = max(1, int(0.05 * total_steps))
    scheduler = torch.optim.lr_scheduler.LambdaLR(
        optimizer, lambda step: lr_factor(step, warmup, total_steps))
    use_amp = device.type == 'cuda'
    scaler = make_scaler(use_amp)

    os.makedirs(args.output, exist_ok=True)
    best_score = -1.0
    history = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        started = time.time()
        running = 0.0
        for step, (pixels, targets) in enumerate(loader, 1):
            pixels, targets = pixels.to(device), targets.to(device)
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type=device.type, enabled=use_amp):
                logits = model(pixel_values=pixels).logits
            loss = torch.nn.functional.cross_entropy(logits.float(), targets)
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            running += loss.item()
            if step % 50 == 0 or step == len(loader):
                print(f'  epoch {epoch} étape {step}/{len(loader)} '
                      f'perte moyenne={running / step:.4f}', flush=True)

        clean = evaluate_subset(model, valid_set, processor, device, args,
                                'clean')
        degraded = evaluate_subset(model, valid_set, processor, device, args,
                                   'degraded')
        score = ((clean['auc'] or 0.0) + (degraded['auc'] or 0.0)) / 2
        print(f'Epoch {epoch} ({time.time() - started:.0f} s)')
        print('  validation propre   :', describe(clean))
        print('  validation dégradée :', describe(degraded))
        history.append({'epoch': epoch, 'clean': clean,
                        'degraded': degraded})
        if score > best_score:
            best_score = score
            model.save_pretrained(args.output)
            processor.save_pretrained(args.output)
            print(f'  meilleur modèle sauvegardé dans {args.output}')

    best = AutoModelForImageClassification.from_pretrained(
        args.output).to(device)
    test_set = load_subset(args.dataset, 'test', args.test_per_class,
                           args.seed)
    test_clean = evaluate_subset(best, test_set, processor, device, args,
                                 'clean')
    test_degraded = evaluate_subset(best, test_set, processor, device, args,
                                    'degraded')
    print('--- Test final (jamais vu pendant l\'entraînement) ---')
    print('  propre   :', describe(test_clean))
    print('  dégradé  :', describe(test_degraded))
    print('Ce test mesure des visages StyleGAN : il ne dit RIEN sur vos '
          'photos ni sur les générateurs récents. Lancez evaluate.py.')

    report = {'args': vars(args), 'history': history,
              'test_clean': test_clean, 'test_degraded': test_degraded}
    with open(os.path.join(args.output, 'train_report.json'), 'w',
              encoding='utf-8') as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    if args.smoke:
        check_saved_model(args.output)


def parse_args(argv=None):
    """Lit les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description='Fine-tuning réel / fake sur 140k Real and Fake Faces.')
    parser.add_argument('--dataset', default=DATASET)
    parser.add_argument('--base-model', default=BASE_MODEL)
    parser.add_argument('--output', default='models/deepfake_v1')
    parser.add_argument('--max-per-class', type=int, default=10000)
    parser.add_argument('--val-per-class', type=int, default=1000)
    parser.add_argument('--test-per-class', type=int, default=1000)
    parser.add_argument('--epochs', type=int, default=3)
    parser.add_argument('--batch-size', type=int, default=32)
    parser.add_argument('--lr', type=float, default=5e-5)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--smoke', action='store_true',
                        help='essai minuscule pour vérifier toute la chaîne')
    args = parser.parse_args(argv)
    if args.smoke:
        args.max_per_class = args.val_per_class = args.test_per_class = 32
        args.epochs = 1
        args.batch_size = 8
        args.workers = 0
    return args


if __name__ == '__main__':
    train(parse_args())
