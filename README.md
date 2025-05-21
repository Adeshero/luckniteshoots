# LuckniteShoots - AI-Powered Encryption System

LuckniteShoots is a comprehensive encryption system that leverages artificial intelligence to provide state-of-the-art data security. The project combines traditional cryptographic methods with cutting-edge machine learning techniques to optimize encryption, detect vulnerabilities, and ensure data integrity.

## Features

- **AI-Enhanced Cryptanalysis**: Detect weaknesses in ciphers and predict weak keys using machine learning models
- **AI-Powered Key Generation**: Generate cryptographically secure keys using reinforcement learning
- **Multiple Encryption Methods**: Support for AES-256, RSA-2048, and ECC encryption
- **AI-Optimized Method Selection**: Automatically choose the best encryption method based on data characteristics
- **Data Integrity Verification**: Ensure data hasn't been tampered with using AI-based integrity checks
- **Detailed Security Reports**: Get comprehensive reports with visualizations of encryption strength and entropy analysis
- **User-Friendly Web Interface**: Easy-to-use interface for file encryption and decryption

## Project Structure

```
luckniteshoots/
├── phase-1/
│   ├── cryptanalysis.py
│   └── README.md
├── phase-2/
│   ├── aes_key_generation.py
│   ├── validate_keys.py
│   ├── rl_env.py
│   ├── train_password_classifier.py
│   ├── main_pipeline.py
│   └── passwords.csv
├── phase-3/
│   ├── aes.py
│   ├── rsa.py
│   ├── ecc.py
│   ├── ai_optimizer.py
│   ├── benchmark.py
│   ├── train_model.py
│   └── model.keras
├── phase-4/
│   └── data_integrity.py
├── phase-5/
│   ├── app.py
│   └── templates/
│       ├── index.html
│       ├── encrypt.html
│       ├── decrypt.html
│       ├── report.html
│       ├── about.html
│       └── error.html
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/luckniteshoots.git
cd luckniteshoots
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the web interface:
```bash
python phase-5/app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Use the web interface to:
   - Encrypt files with AI-optimized encryption
   - Decrypt files using the provided key
   - View detailed security reports
   - Learn more about the project

## Project Phases

### Phase 1: Research & AI-Powered Cryptanalysis
- Developed AI models to detect weaknesses in ciphers
- Implemented key strength prediction
- Created training datasets for cryptanalysis

### Phase 2: AI-Powered Key Generation
- Implemented reinforcement learning for key generation
- Added NIST test validation
- Created key optimization pipeline

### Phase 3: AI-Optimized Encryption
- Implemented multiple encryption methods (AES, RSA, ECC)
- Created AI model for method selection
- Added benchmarking and performance analysis

### Phase 4: Data Integrity & Authentication
- Implemented AI-assisted integrity verification
- Added HMAC-based authentication
- Created tampering detection system

### Phase 5: Web Interface & Reporting
- Developed Flask web application
- Created user-friendly interface
- Implemented detailed security reporting

## Dependencies

- Flask: Web framework
- TensorFlow: Machine learning framework
- PyCryptoDome: Cryptographic operations
- Gym: Reinforcement learning environment
- NISTRNG: Random number generation testing
- Other dependencies listed in requirements.txt

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- NIST for cryptographic standards
- TensorFlow team for the machine learning framework
- Flask team for the web framework
- All contributors and supporters of the project 