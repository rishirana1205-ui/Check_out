// =====================================================
// PassGuard — Password Strength Analyzer
// All analysis is performed client-side for privacy.
// =====================================================

(function () {
    'use strict';

    // ---------- Common weak passwords dictionary ----------
    const COMMON_PASSWORDS = new Set([
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
        'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
        'princess', 'football', 'shadow', 'superman', 'michael', 'letmein',
        'password1', '123456789', '1234567890', 'admin', 'welcome', 'login',
        'hello', 'charlie', 'donald', 'passw0rd', 'qwerty123', 'password123',
        '1q2w3e4r', 'abcdef', 'abcdefg', '654321', '123321', 'access',
        'flower', 'hottie', 'loveme', 'zaq1zaq1', 'mustang', 'test',
        'computer', 'starwars', 'winter', 'summer', 'spring', 'autumn'
    ]);

    // ---------- Keyboard patterns ----------
    const KEYBOARD_PATTERNS = [
        'qwert', 'werty', 'ertyu', 'rtyui', 'tyuio', 'yuiop',
        'asdfg', 'sdfgh', 'dfghj', 'fghjk', 'ghjkl',
        'zxcvb', 'xcvbn', 'cvbnm',
        '12345', '23456', '34567', '45678', '56789', '67890',
        'qazwsx', 'wsxedc'
    ];

    // ---------- DOM Elements ----------
    const els = {
        passwordInput: document.getElementById('password-input'),
        toggleVisibility: document.getElementById('toggle-visibility'),
        meterFill: document.getElementById('meter-fill'),
        strengthLabel: document.getElementById('strength-label'),
        strengthScore: document.getElementById('strength-score'),
        crackTimeDisplay: document.getElementById('crack-time-display'),
        crackTimeValue: document.getElementById('crack-time-value'),
        criteriaLength: document.getElementById('criteria-length'),
        criteriaUppercase: document.getElementById('criteria-uppercase'),
        criteriaLowercase: document.getElementById('criteria-lowercase'),
        criteriaNumber: document.getElementById('criteria-number'),
        criteriaSpecial: document.getElementById('criteria-special'),
        criteriaNoCommon: document.getElementById('criteria-no-common'),
        criteriaNoRepeat: document.getElementById('criteria-no-repeat'),
        suggestionsContent: document.getElementById('suggestions-content'),
        scoreBars: {
            length: { fill: document.getElementById('bar-length'), value: document.getElementById('score-length') },
            complexity: { fill: document.getElementById('bar-complexity'), value: document.getElementById('score-complexity') },
            uniqueness: { fill: document.getElementById('bar-uniqueness'), value: document.getElementById('score-uniqueness') },
            entropy: { fill: document.getElementById('bar-entropy'), value: document.getElementById('score-entropy') }
        },
        genLength: document.getElementById('gen-length'),
        genLengthValue: document.getElementById('gen-length-value'),
        genUppercase: document.getElementById('gen-uppercase'),
        genLowercase: document.getElementById('gen-lowercase'),
        genNumbers: document.getElementById('gen-numbers'),
        genSymbols: document.getElementById('gen-symbols'),
        generatedText: document.getElementById('generated-password-text'),
        btnGenerate: document.getElementById('btn-generate'),
        copyGenerated: document.getElementById('copy-generated'),
        historyList: document.getElementById('history-list'),
        historyEmpty: document.getElementById('history-empty'),
        historyCount: document.getElementById('history-count'),
        btnClearHistory: document.getElementById('btn-clear-history'),
        toast: document.getElementById('toast')
    };

    // ---------- Tab Navigation ----------
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
        });
    });

    // ---------- Toggle Password Visibility ----------
    els.toggleVisibility.addEventListener('click', () => {
        const input = els.passwordInput;
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        els.toggleVisibility.querySelector('.eye-open').style.display = isPassword ? 'none' : 'block';
        els.toggleVisibility.querySelector('.eye-closed').style.display = isPassword ? 'block' : 'none';
    });

    // ---------- Password Analysis Engine ----------
    function analyzePassword(password) {
        if (!password) return null;

        const result = {
            length: password.length,
            hasUppercase: /[A-Z]/.test(password),
            hasLowercase: /[a-z]/.test(password),
            hasNumbers: /[0-9]/.test(password),
            hasSpecial: /[^A-Za-z0-9]/.test(password),
            isCommon: COMMON_PASSWORDS.has(password.toLowerCase()),
            hasExcessiveRepeats: /(.)\1{2,}/.test(password),
            hasKeyboardPattern: false,
            uniqueChars: new Set(password).size,
            scores: { length: 0, complexity: 0, uniqueness: 0, entropy: 0 },
            totalScore: 0,
            level: 'weak',
            crackTime: ''
        };

        // Check keyboard patterns
        const lower = password.toLowerCase();
        result.hasKeyboardPattern = KEYBOARD_PATTERNS.some(p => lower.includes(p));

        // --- Score: Length (max 25) ---
        if (result.length >= 16) result.scores.length = 25;
        else if (result.length >= 12) result.scores.length = 20;
        else if (result.length >= 10) result.scores.length = 15;
        else if (result.length >= 8) result.scores.length = 10;
        else result.scores.length = Math.max(2, result.length);

        // --- Score: Complexity (max 25) ---
        let charTypes = [result.hasUppercase, result.hasLowercase, result.hasNumbers, result.hasSpecial].filter(Boolean).length;
        result.scores.complexity = charTypes * 6;
        if (charTypes === 4) result.scores.complexity = 25;

        // --- Score: Uniqueness (max 25) ---
        const uniqueRatio = result.uniqueChars / Math.max(result.length, 1);
        result.scores.uniqueness = Math.round(uniqueRatio * 25);
        if (result.isCommon) result.scores.uniqueness = Math.max(0, result.scores.uniqueness - 15);
        if (result.hasExcessiveRepeats) result.scores.uniqueness = Math.max(0, result.scores.uniqueness - 8);
        if (result.hasKeyboardPattern) result.scores.uniqueness = Math.max(0, result.scores.uniqueness - 8);

        // --- Score: Entropy (max 25) ---
        let poolSize = 0;
        if (result.hasLowercase) poolSize += 26;
        if (result.hasUppercase) poolSize += 26;
        if (result.hasNumbers) poolSize += 10;
        if (result.hasSpecial) poolSize += 33;
        const entropy = result.length * Math.log2(Math.max(poolSize, 1));
        if (entropy >= 80) result.scores.entropy = 25;
        else if (entropy >= 60) result.scores.entropy = 20;
        else if (entropy >= 40) result.scores.entropy = 15;
        else if (entropy >= 28) result.scores.entropy = 10;
        else result.scores.entropy = Math.round((entropy / 28) * 10);

        // --- Total ---
        result.totalScore = Math.min(100,
            result.scores.length + result.scores.complexity +
            result.scores.uniqueness + result.scores.entropy
        );

        // If common password, cap score
        if (result.isCommon) result.totalScore = Math.min(result.totalScore, 15);

        // --- Level ---
        if (result.totalScore >= 85) result.level = 'excellent';
        else if (result.totalScore >= 65) result.level = 'strong';
        else if (result.totalScore >= 45) result.level = 'good';
        else if (result.totalScore >= 25) result.level = 'fair';
        else result.level = 'weak';

        // --- Crack Time Estimate ---
        const guessesPerSec = 1e10; // 10 billion guesses/sec (modern GPU)
        const totalCombinations = Math.pow(poolSize || 1, result.length);
        const seconds = totalCombinations / guessesPerSec / 2;
        result.crackTime = formatCrackTime(seconds);

        return result;
    }

    function formatCrackTime(seconds) {
        if (!isFinite(seconds) || seconds > 1e15) return 'Centuries+';
        if (seconds < 0.001) return 'Instantly';
        if (seconds < 1) return 'Less than a second';
        if (seconds < 60) return Math.round(seconds) + ' seconds';
        if (seconds < 3600) return Math.round(seconds / 60) + ' minutes';
        if (seconds < 86400) return Math.round(seconds / 3600) + ' hours';
        if (seconds < 2592000) return Math.round(seconds / 86400) + ' days';
        if (seconds < 31536000) return Math.round(seconds / 2592000) + ' months';
        const years = seconds / 31536000;
        if (years < 1000) return Math.round(years) + ' years';
        if (years < 1e6) return Math.round(years / 1000) + ' thousand years';
        if (years < 1e9) return Math.round(years / 1e6) + ' million years';
        return Math.round(years / 1e9) + ' billion years';
    }

    // ---------- UI Update ----------
    const LEVEL_COLORS = {
        weak: 'var(--strength-weak)',
        fair: 'var(--strength-fair)',
        good: 'var(--strength-good)',
        strong: 'var(--strength-strong)',
        excellent: 'var(--strength-excellent)'
    };

    const LEVEL_LABELS = {
        weak: 'Weak', fair: 'Fair', good: 'Good', strong: 'Strong', excellent: 'Excellent'
    };

    function updateUI(result) {
        if (!result) {
            els.meterFill.style.width = '0%';
            els.meterFill.style.background = 'transparent';
            els.strengthLabel.textContent = 'Enter a password';
            els.strengthLabel.style.color = 'var(--text-muted)';
            els.strengthScore.textContent = '';
            els.crackTimeDisplay.style.display = 'none';
            [els.criteriaLength, els.criteriaUppercase, els.criteriaLowercase,
             els.criteriaNumber, els.criteriaSpecial, els.criteriaNoCommon, els.criteriaNoRepeat
            ].forEach(el => el.classList.remove('met'));
            Object.values(els.scoreBars).forEach(bar => {
                bar.fill.style.width = '0%';
                bar.value.textContent = '0';
            });
            els.suggestionsContent.innerHTML = '<p class="suggestions-empty">Enter a password to receive improvement suggestions.</p>';
            return;
        }

        const color = LEVEL_COLORS[result.level];

        // Meter
        els.meterFill.style.width = result.totalScore + '%';
        els.meterFill.style.background = color;
        els.strengthLabel.textContent = LEVEL_LABELS[result.level];
        els.strengthLabel.style.color = color;
        els.strengthScore.textContent = result.totalScore + ' / 100';

        // Crack time
        els.crackTimeDisplay.style.display = 'flex';
        els.crackTimeValue.textContent = result.crackTime;

        // Criteria
        toggleCriteria(els.criteriaLength, result.length >= 8);
        toggleCriteria(els.criteriaUppercase, result.hasUppercase);
        toggleCriteria(els.criteriaLowercase, result.hasLowercase);
        toggleCriteria(els.criteriaNumber, result.hasNumbers);
        toggleCriteria(els.criteriaSpecial, result.hasSpecial);
        toggleCriteria(els.criteriaNoCommon, !result.isCommon);
        toggleCriteria(els.criteriaNoRepeat, !result.hasExcessiveRepeats);

        // Score bars
        updateScoreBar('length', result.scores.length, 25);
        updateScoreBar('complexity', result.scores.complexity, 25);
        updateScoreBar('uniqueness', result.scores.uniqueness, 25);
        updateScoreBar('entropy', result.scores.entropy, 25);

        // Suggestions
        updateSuggestions(result);
    }

    function toggleCriteria(el, met) {
        el.classList.toggle('met', met);
    }

    function updateScoreBar(key, score, max) {
        const pct = Math.round((score / max) * 100);
        els.scoreBars[key].fill.style.width = pct + '%';
        els.scoreBars[key].value.textContent = score + '/' + max;
    }

    // ---------- Suggestions Engine ----------
    function updateSuggestions(result) {
        const tips = [];

        if (result.isCommon) {
            tips.push({ icon: '🚨', text: 'This is an extremely common password and can be cracked instantly. Choose something unique and personal.' });
        }
        if (result.length < 12) {
            tips.push({ icon: '📏', text: 'Increase length to at least 12 characters. Longer passwords are exponentially harder to crack.' });
        }
        if (!result.hasUppercase) {
            tips.push({ icon: '🔠', text: 'Add uppercase letters to increase the character pool and complexity.' });
        }
        if (!result.hasNumbers) {
            tips.push({ icon: '🔢', text: 'Include numbers to add another character class to your password.' });
        }
        if (!result.hasSpecial) {
            tips.push({ icon: '✨', text: 'Add special characters like @, #, $, or ! for significantly better security.' });
        }
        if (result.hasExcessiveRepeats) {
            tips.push({ icon: '🔁', text: 'Avoid repeating characters (e.g., "aaa"). Use varied characters instead.' });
        }
        if (result.hasKeyboardPattern) {
            tips.push({ icon: '⌨️', text: 'Keyboard patterns like "qwerty" or "asdfg" are easily guessed. Avoid sequential key patterns.' });
        }
        if (result.uniqueChars < result.length * 0.6) {
            tips.push({ icon: '🎯', text: 'Use more unique characters. A higher variety makes your password harder to predict.' });
        }

        if (tips.length === 0 && result.level === 'excellent') {
            tips.push({ icon: '🛡️', text: 'Excellent! This password is very strong. Keep it safe and never reuse it across multiple sites.' });
        }

        // Generate a stronger alternative
        let suggestedPw = '';
        if (result.totalScore < 80) {
            suggestedPw = generateStrongerAlternative(els.passwordInput.value);
        }

        let html = tips.map(t =>
            `<div class="suggestion-item"><span class="sug-icon">${t.icon}</span><span>${t.text}</span></div>`
        ).join('');

        if (suggestedPw) {
            html += `<div class="suggested-password" id="suggested-pw" title="Click to copy">
                💡 Suggested: <strong>${escapeHtml(suggestedPw)}</strong>
            </div>`;
        }

        els.suggestionsContent.innerHTML = html;

        // Copy suggested password on click
        const sugEl = document.getElementById('suggested-pw');
        if (sugEl) {
            sugEl.addEventListener('click', () => {
                copyToClipboard(suggestedPw);
                showToast('Suggested password copied!');
            });
        }
    }

    function generateStrongerAlternative(base) {
        const specials = '!@#$%&*?';
        const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        const lower = 'abcdefghjkmnpqrstuvwxyz';
        const digits = '23456789';
        let pw = '';

        // Start with a modified base if available
        if (base && base.length >= 3) {
            const cleaned = base.slice(0, 6);
            pw += cleaned;
        }

        // Pad to 14+ chars with mixed characters
        const allChars = upper + lower + digits + specials;
        while (pw.length < 16) {
            const pool = [upper, lower, digits, specials][pw.length % 4];
            pw += pool[Math.floor(Math.random() * pool.length)];
        }

        // Shuffle the password
        pw = pw.split('').sort(() => Math.random() - 0.5).join('');
        return pw;
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ---------- Input Event ----------
    let debounceTimer;
    els.passwordInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            const password = els.passwordInput.value;
            const result = analyzePassword(password);
            updateUI(result);

            // Save to history if meaningful
            if (password.length >= 4) {
                saveToHistory(password, result);
            }
        }, 150);
    });

    // ---------- Password Generator ----------
    els.genLength.addEventListener('input', () => {
        els.genLengthValue.textContent = els.genLength.value;
    });

    els.btnGenerate.addEventListener('click', () => {
        const length = parseInt(els.genLength.value);
        let charset = '';
        if (els.genUppercase.checked) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (els.genLowercase.checked) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (els.genNumbers.checked) charset += '0123456789';
        if (els.genSymbols.checked) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (!charset) {
            showToast('Please select at least one character type.');
            return;
        }

        let password = '';
        const array = new Uint32Array(length);
        crypto.getRandomValues(array);
        for (let i = 0; i < length; i++) {
            password += charset[array[i] % charset.length];
        }

        els.generatedText.textContent = password;
        els.generatedText.style.color = 'var(--accent-primary)';

        // Add a nice animation
        els.generatedText.style.opacity = '0';
        requestAnimationFrame(() => {
            els.generatedText.style.transition = 'opacity 0.3s';
            els.generatedText.style.opacity = '1';
        });
    });

    els.copyGenerated.addEventListener('click', () => {
        const text = els.generatedText.textContent;
        if (text && !text.startsWith('Click generate')) {
            copyToClipboard(text);
            showToast('Password copied to clipboard!');
        }
    });

    // ---------- Password History (localStorage) ----------
    const HISTORY_KEY = 'passguard_history';
    const MAX_HISTORY = 50;

    function getHistory() {
        try {
            return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
        } catch { return []; }
    }

    function saveToHistory(password, result) {
        const history = getHistory();
        // Hash the password for storage (we don't store plaintext)
        const masked = maskPassword(password);
        const hash = simpleHash(password);

        // Don't add duplicates
        if (history.some(h => h.hash === hash)) return;

        history.unshift({
            masked,
            hash,
            score: result.totalScore,
            level: result.level,
            date: new Date().toISOString()
        });

        if (history.length > MAX_HISTORY) history.pop();
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        renderHistory();
    }

    function maskPassword(pw) {
        if (pw.length <= 3) return '***';
        return pw[0] + '*'.repeat(Math.min(pw.length - 2, 10)) + pw[pw.length - 1];
    }

    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash |= 0;
        }
        return hash.toString(36);
    }

    function renderHistory() {
        const history = getHistory();
        els.historyCount.textContent = history.length + ' password' + (history.length !== 1 ? 's' : '') + ' stored';

        if (history.length === 0) {
            els.historyEmpty.style.display = 'block';
            // Remove any history items
            els.historyList.querySelectorAll('.history-item').forEach(el => el.remove());
            return;
        }

        els.historyEmpty.style.display = 'none';

        let html = '';
        history.forEach(item => {
            const date = new Date(item.date);
            const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            html += `<div class="history-item">
                <span class="history-item-password">${escapeHtml(item.masked)}</span>
                <div class="history-item-meta">
                    <span class="history-item-strength strength-tag-${item.level}">${LEVEL_LABELS[item.level]}</span>
                    <span class="history-item-date">${dateStr}</span>
                </div>
            </div>`;
        });

        // Keep the empty placeholder in DOM but hidden, add items
        const emptyEl = els.historyEmpty;
        els.historyList.innerHTML = html;
        els.historyList.appendChild(emptyEl);
    }

    els.btnClearHistory.addEventListener('click', () => {
        localStorage.removeItem(HISTORY_KEY);
        renderHistory();
        showToast('History cleared.');
    });

    // ---------- Utility ----------
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).catch(() => {
            // Fallback
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        });
    }

    function showToast(message) {
        els.toast.textContent = message;
        els.toast.classList.add('show');
        setTimeout(() => els.toast.classList.remove('show'), 2500);
    }

    // ---------- Init ----------
    renderHistory();
})();
