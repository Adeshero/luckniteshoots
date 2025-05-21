import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, Flatten, Dropout, MaxPooling1D
from tensorflow.keras.optimizers import Adam
import matplotlib.pyplot as plt
import os
import hashlib
import hmac
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class DataIntegrityChecker:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        
    def generate_dataset(self, num_samples=10000, data_size=1024):
        """Generate a dataset of encrypted data with and without tampering"""
        X = []  # Features (encrypted data patterns)
        y = []  # Labels (0 for tampered, 1 for untampered)
        
        # Generate untampered data
        for _ in range(num_samples // 2):
            # Generate random data
            data = get_random_bytes(data_size)
            
            # Encrypt data
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv
            encrypted = cipher.encrypt(pad(data, AES.block_size))
            
            # Calculate HMAC
            hmac_obj = hmac.new(key, encrypted, hashlib.sha256)
            hmac_value = hmac_obj.digest()
            
            # Combine IV, encrypted data, and HMAC
            full_data = iv + encrypted + hmac_value
            
            # Extract features
            features = self._extract_features(full_data)
            X.append(features)
            y.append(1)  # Untampered
            
        # Generate tampered data
        for _ in range(num_samples // 2):
            # Generate random data
            data = get_random_bytes(data_size)
            
            # Encrypt data
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv
            encrypted = cipher.encrypt(pad(data, AES.block_size))
            
            # Calculate HMAC
            hmac_obj = hmac.new(key, encrypted, hashlib.sha256)
            hmac_value = hmac_obj.digest()
            
            # Combine IV, encrypted data, and HMAC
            full_data = iv + encrypted + hmac_value
            
            # Tamper with the data (modify a few bytes)
            tamper_pos = np.random.randint(len(full_data) - len(hmac_value))
            tamper_size = np.random.randint(1, 10)
            for i in range(tamper_size):
                if tamper_pos + i < len(full_data) - len(hmac_value):
                    full_data[tamper_pos + i] = np.random.randint(0, 256)
            
            # Extract features
            features = self._extract_features(full_data)
            X.append(features)
            y.append(0)  # Tampered
            
        return np.array(X), np.array(y)
    
    def _extract_features(self, data):
        """Extract features from data for analysis"""
        # Convert to numpy array
        data_array = np.frombuffer(data, dtype=np.uint8)
        
        # Calculate byte distribution
        hist, _ = np.histogram(data_array, bins=256, range=(0, 256), density=True)
        
        # Calculate entropy
        entropy = -np.sum(hist * np.log2(hist + 1e-10))
        
        # Check for patterns (autocorrelation)
        autocorr = np.correlate(data_array, data_array, mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        autocorr = autocorr / autocorr[0]  # Normalize
        
        # Calculate HMAC verification (simplified)
        # In a real scenario, we would verify the HMAC
        # Here we just check if the last 32 bytes (SHA-256) look like a valid HMAC
        hmac_bytes = data_array[-32:]
        hmac_entropy = -np.sum(np.histogram(hmac_bytes, bins=256, range=(0, 256), density=True)[0] * 
                              np.log2(np.histogram(hmac_bytes, bins=256, range=(0, 256), density=True)[0] + 1e-10))
        
        # Combine features
        features = np.concatenate([hist, [entropy], autocorr[:16], [hmac_entropy]])
        
        return features
    
    def train_model(self, X, y):
        """Train a neural network to detect tampering"""
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)
        
        # Reshape for CNN
        X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
        X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
        
        # Build model
        model = Sequential([
            Conv1D(32, 3, activation='relu', input_shape=(X_train.shape[1], 1)),
            MaxPooling1D(2),
            Conv1D(64, 3, activation='relu'),
            MaxPooling1D(2),
            Flatten(),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(optimizer=Adam(learning_rate=0.001),
                     loss='binary_crossentropy',
                     metrics=['accuracy'])
        
        # Train model
        history = model.fit(X_train, y_train, 
                           epochs=20, 
                           batch_size=64, 
                           validation_data=(X_test, y_test),
                           verbose=1)
        
        self.model = model
        
        # Plot training history
        plt.figure(figsize=(12, 4))
        
        plt.subplot(1, 2, 1)
        plt.plot(history.history['accuracy'])
        plt.plot(history.history['val_accuracy'])
        plt.title('Model Accuracy')
        plt.ylabel('Accuracy')
        plt.xlabel('Epoch')
        plt.legend(['Train', 'Validation'], loc='upper left')
        
        plt.subplot(1, 2, 2)
        plt.plot(history.history['loss'])
        plt.plot(history.history['val_loss'])
        plt.title('Model Loss')
        plt.ylabel('Loss')
        plt.xlabel('Epoch')
        plt.legend(['Train', 'Validation'], loc='upper left')
        
        plt.tight_layout()
        plt.savefig('integrity_training.png')
        
        return model, history
    
    def save_model(self, model_path='integrity_model.keras', scaler_path='integrity_scaler.pkl'):
        """Save the trained model and scaler"""
        if self.model:
            self.model.save(model_path)
            joblib.dump(self.scaler, scaler_path)
            print(f"Model saved to {model_path}")
            print(f"Scaler saved to {scaler_path}")
        else:
            print("No model to save. Train a model first.")
    
    def load_model(self, model_path='integrity_model.keras', scaler_path='integrity_scaler.pkl'):
        """Load a trained model and scaler"""
        try:
            self.model = tf.keras.models.load_model(model_path)
            self.scaler = joblib.load(scaler_path)
            print(f"Model loaded from {model_path}")
            print(f"Scaler loaded from {scaler_path}")
        except Exception as e:
            print(f"Error loading model: {e}")
    
    def check_integrity(self, encrypted_data, hmac_value=None):
        """Check the integrity of encrypted data"""
        if not self.model:
            print("No model loaded. Train or load a model first.")
            return None
        
        # Extract features
        features = self._extract_features(encrypted_data)
        features = features.reshape(1, -1)
        
        # Scale features
        features = self.scaler.transform(features)
        features = features.reshape(features.shape[0], features.shape[1], 1)
        
        # Predict
        prediction = self.model.predict(features)[0][0]
        
        # Calculate entropy
        data = np.frombuffer(encrypted_data, dtype=np.uint8)
        hist, _ = np.histogram(data, bins=256, range=(0, 256), density=True)
        entropy = -np.sum(hist * np.log2(hist + 1e-10))
        
        return {
            'entropy': entropy,
            'tampering_detected': prediction < 0.5,
            'tampering_confidence': abs(prediction - 0.5) * 2,
            'hmac_verification': hmac_value is not None
        }
    
    def encrypt_with_integrity(self, data, key=None):
        """Encrypt data with integrity protection"""
        if key is None:
            key = get_random_bytes(16)
            
        # Encrypt data
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        
        # Calculate HMAC
        hmac_obj = hmac.new(key, encrypted, hashlib.sha256)
        hmac_value = hmac_obj.digest()
        
        # Combine IV, encrypted data, and HMAC
        full_data = iv + encrypted + hmac_value
        
        return full_data, key
    
    def decrypt_with_integrity(self, encrypted_data, key):
        """Decrypt data with integrity verification"""
        # Extract IV, encrypted data, and HMAC
        iv = encrypted_data[:AES.block_size]
        hmac_value = encrypted_data[-32:]
        encrypted = encrypted_data[AES.block_size:-32]
        
        # Verify HMAC
        hmac_obj = hmac.new(key, encrypted, hashlib.sha256)
        expected_hmac = hmac_obj.digest()
        
        if hmac_value != expected_hmac:
            print("HMAC verification failed. Data may have been tampered with.")
            return None
        
        # Decrypt data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        
        return decrypted

def main():
    # Create integrity checker
    integrity_checker = DataIntegrityChecker()
    
    # Generate dataset
    print("Generating dataset...")
    X, y = integrity_checker.generate_dataset(num_samples=5000)
    
    # Train model
    print("Training model...")
    model, history = integrity_checker.train_model(X, y)
    
    # Save model
    integrity_checker.save_model()
    
    # Test with some data
    print("\nTesting with sample data:")
    
    # Generate random data
    data = get_random_bytes(1024)
    
    # Encrypt with integrity
    encrypted, key = integrity_checker.encrypt_with_integrity(data)
    
    # Check integrity
    result = integrity_checker.check_integrity(encrypted)
    print(f"Untampered data:")
    print(f"Entropy: {result['entropy']:.4f}")
    print(f"Tampering detected: {result['tampering_detected']}")
    print(f"Tampering confidence: {result['tampering_confidence']:.4f}")
    
    # Tamper with data
    tampered = bytearray(encrypted)
    tampered[100] = 0  # Modify a byte
    
    # Check integrity of tampered data
    result = integrity_checker.check_integrity(tampered)
    print(f"\nTampered data:")
    print(f"Entropy: {result['entropy']:.4f}")
    print(f"Tampering detected: {result['tampering_detected']}")
    print(f"Tampering confidence: {result['tampering_confidence']:.4f}")
    
    # Try to decrypt tampered data
    try:
        decrypted = integrity_checker.decrypt_with_integrity(tampered, key)
        print(f"Decryption successful: {decrypted is not None}")
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    main() 