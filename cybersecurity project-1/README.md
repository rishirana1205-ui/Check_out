# 🔐 PassGuard — Password Strength Analyzer

A modern, client-side password strength analyzer that evaluates password security in real-time with detailed scoring, actionable suggestions, and password history tracking.

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black)

## ✨ Features

### Password Analysis
- **Real-time strength scoring** — Passwords are evaluated as you type with a 0–100 scoring system
- **Multi-factor analysis** — Evaluates length, complexity, uniqueness, and entropy independently
- **Common password detection** — Checks against a dictionary of frequently breached passwords
- **Keyboard pattern detection** — Identifies common keyboard walks like `qwerty` or `asdfg`
- **Crack time estimation** — Estimates how long it would take to brute-force the password at 10 billion guesses/second

### Smart Suggestions
- Context-aware improvement tips based on specific weaknesses
- Automatically generates a stronger alternative password
- One-click copy for suggested passwords

### Password Generator
- Cryptographically secure random password generation using `crypto.getRandomValues()`
- Configurable length (8–64 characters)
- Toggle character types: uppercase, lowercase, numbers, symbols

### Reuse Prevention (History)
- Stores hashed records of previously analyzed passwords in `localStorage`
- Masked display for privacy (only first and last characters visible)
- Prevents password reuse by tracking past entries
- Clear history option for privacy

## 🔒 Privacy & Security

**All analysis runs entirely in your browser.** No data is ever sent to any server. Password history is stored locally using `localStorage` and passwords are masked — the full plaintext is never persisted.

## 🚀 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/password-strength-analyzer.git
   ```

2. Open `index.html` in your browser — no build step or server required.

   Or use a local server:
   ```bash
   npx serve .
   ```

3. For GitHub Pages deployment, push to the `main` branch and enable Pages in repository settings.

## 📁 Project Structure

```
├── index.html    # Main application markup
├── styles.css    # Styling with dark theme and animations
├── app.js        # Analysis engine, generator, and UI logic
└── README.md     # Documentation
```

## 🧮 Scoring Algorithm

The total score (0–100) is composed of four equally-weighted categories:

| Category     | Max Points | What It Measures                                    |
|-------------|-----------|-----------------------------------------------------|
| Length       | 25        | Password length (8+ recommended, 16+ ideal)        |
| Complexity   | 25        | Character type diversity (uppercase, lowercase, numbers, symbols) |
| Uniqueness   | 25        | Unique character ratio, common password check, pattern detection |
| Entropy      | 25        | Information entropy based on character pool and length |

### Strength Levels

| Score   | Level     |
|---------|-----------|
| 0–24    | Weak      |
| 25–44   | Fair      |
| 45–64   | Good      |
| 65–84   | Strong    |
| 85–100  | Excellent |

## 🛠️ Technologies Used

- **HTML5** — Semantic markup with accessibility attributes
- **CSS3** — Custom properties, glassmorphism, grid layouts, animations
- **Vanilla JavaScript** — Zero dependencies, IIFE pattern, Web Crypto API
- **localStorage** — Client-side password history persistence

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
