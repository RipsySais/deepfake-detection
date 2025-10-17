import cv2
from moviepy.editor import VideoFileClip
import numpy as np
import tensorflow as tf

# Même modèle que pour images
model = tf.keras.models.Sequential([
    tf.keras.layers.Conv2D(32, (3,3), activation='relu', input_shape=(224, 224, 3)),
    tf.keras.layers.MaxPooling2D(2,2),
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dense(1, activation='sigmoid')
])

def extract_frames(video_path, num_frames=10):
    clip = VideoFileClip(video_path)
    duration = clip.duration
    frames = []
    for t in np.linspace(0, duration, num_frames):
        frame = clip.get_frame(t)
        frames.append(cv2.cvtColor(frame, cv2.COLOR_RGB2BGR))
    return frames

def detect_video(video_path):
    try:
        frames = extract_frames(video_path)
        scores = []
        for frame in frames:
            frame_resized = cv2.resize(frame, (224, 224))
            frame_norm = frame_resized / 255.0
            score = model.predict(np.expand_dims(frame_norm, axis=0))[0][0]
            scores.append(score)
        avg_score = np.mean(scores)
        confidence = avg_score * 100 if avg_score > 0.5 else (1 - avg_score) * 100
        result = "Fake" if avg_score > 0.5 else "Réel"
        return result, confidence
    except Exception as e:
        return f"Erreur : {str(e)}", 0.0
