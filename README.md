# Sentinel AI | NextGen Password Security Suite
<p> <img src="https://img.shields.io/badge/Category-Cybersecurity-blueviolet"> <img src="https://img.shields.io/badge/Backend-FastAPI-009688"> <img src="https://img.shields.io/badge/Frontend-HTML%2FJS-blue"> <img src="https://img.shields.io/badge/Security-Attacker--Model-critical"> <img src="https://img.shields.io/badge/Password%20Cracking-PCFG%20%7C%20Entropy-green"> </p>

A password-strength engine built using real attacker modeling.
Detects human-word structures, CamelCase, multi-word passphrases, pronounceable patterns,
keyboard sequences, and PCFG-style guess patterns — even for invented words.

## Overview

▪︎ Human-word structure detection  
▪︎ CamelCase / multi-word splitting  
▪︎ Dictionary + mutation modeling  
▪︎ Entropy + character diversity scoring  
▪︎ Keyboard patterns  
▪︎ Date patterns  
▪︎ PCFG-like structure scoring  
▪︎ Realistic time-to-crack (10M guesses/sec)  


## Features
> Word & Pattern Detection

• Detects invented words (e.g., OrbitSilentRocket)  
• Flags CamelCase  
• Detects multi-word strings  
• Finds pronounceable vowel–consonant patterns  
• Detects keyboard sequences  
• Identifies repetition and date-like segments  


> Attack-Model Scoring

• Shannon entropy  
• Word-rank based guess modeling  
• Mutation and hybrid attack modeling  
• Pattern-based cracking heuristics  
• Conservative caps for human-readable strings  

> Strong Suggestions

• High-entropy random strings  
• Diceware-hybrid passphrases  
• Rare-word + mutation patterns  
• Validated to ≥ 10¹² guesses  


## Tech Stack

| Component    | Technology                           |
|--------------|---------------------------------------|
| Backend      | FastAPI, Uvicorn                     |
| Frontend     | HTML, CSS, JavaScript                |
| Security RNG | Python `secrets`                     |
| Model        | Entropy + Word-pattern + PCFG-style  |

## Project Structure
PRODIGY_CY_03/
├── server.py
├── index.html
└── README.md

## Running the Project
> Backend
- pip install fastapi uvicorn
- uvicorn server:app --reload


> Runs at:
- http://127.0.0.1:8000

> Frontend
- cd web
- python -m http.server 8080


> Open in Browser:
- http://127.0.0.1:8080

## API Usage
POST /check

Request

{
  "password": "Hello@123",
  "leaked": false
}


Response

{
  "score": 42,
  "label": "Fair",
  "entropy_bits": 21.9,
  "guesses_estimate": 43000000,
  "ttc": "4.9 hours",
  "reasons": ["low entropy"],
  "suggestions": [...]
}

## Why This Tool Is Different

| Capability                  | Typical Checkers | This Tool |
|-----------------------------|------------------|-----------|
| Detect invented/human words | No               | Yes       |
| Detect CamelCase            | No               | Yes       |
| Pronounceability detection  | No               | Yes       |
| PCFG-style modeling         | No               | Yes       |
| Realistic crack-time        | No               | Yes       |
| Validated strong suggestions| No               | Yes       |

## Use Cases

• Cybersecurity awareness  
• Password audits  
• Pen-testing tools  
• Enterprise password validation  
• Developer security reviews  
• College / internship projects  


## Final Notes

This project evaluates passwords using attacker-style logic:
structure, patterns, entropy, and guess-modeling — not simple rules.
