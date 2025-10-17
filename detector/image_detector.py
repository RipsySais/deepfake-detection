import cv2
from deepface import DeepFace
import tensorflow as tf
import numpy as np


# Modèle CNN simple (remplacez par MesoNet/Xception si disponible)
model = tf.keras.models.Sequential([
    tf.keras.layers.Conv2D(32, (3,3), activation='relu', input_shape=(224, 224, 3)),
    tf.keras.layers.MaxPooling2D(2,2),
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dense(1, activation='sigmoid')  # 0: réel, 1: fake
])
# Chargez des poids si disponible : model.load_weights('mesonet_weights.h5')


def detect_image(image_path):
    try:
        # Analyse DeepFace pour incohérences
        analysis = DeepFace.analyze(image_path, actions=['emotion', 'age'], enforce_detection=False)
        if not analysis or analysis[0]['age'] < 0:
            return "Potentiellement fake (incohérences détectées)", 90.0

        # Prédiction CNN
        img = cv2.imread(image_path)
        img_resized = cv2.resize(img, (224, 224))
        img_norm = img_resized / 255.0
        score = model.predict(np.expand_dims(img_norm, axis=0))[0][0]
        confidence = score * 100 if score > 0.5 else (1 - score) * 100
        result = "Fake" if score > 0.5 else "Réel"
        return f"{result}", confidence
    except Exception as e:
        return f"Erreur : {str(e)}", 0.0

    