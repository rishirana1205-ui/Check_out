document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyzeBtn');
    const emailInput = document.getElementById('emailInput');
    const resultsSection = document.getElementById('resultsSection');
    const verdictContainer = document.getElementById('verdictContainer');
    const verdictIcon = document.getElementById('verdictIcon');
    const verdictLabel = document.getElementById('verdictLabel');
    const verdictDesc = document.getElementById('verdictDesc');
    const threatLevelBar = document.getElementById('threatLevelBar');
    const confidenceScore = document.getElementById('confidenceScore');

    analyzeBtn.addEventListener('click', async () => {
        const text = emailInput.value.trim();
        
        if (!text) {
            emailInput.style.borderColor = 'var(--danger-color)';
            setTimeout(() => {
                emailInput.style.borderColor = 'var(--glass-border)';
            }, 800);
            return;
        }

        // Initialize UI Loading State
        document.body.classList.add('loading');
        resultsSection.classList.remove('hidden');
        resultsSection.classList.add('scanning');
        analyzeBtn.querySelector('span').innerText = 'Analyzing Vectors...';
        analyzeBtn.querySelector('i').className = 'fa-solid fa-circle-notch';
        
        // Reset old data visually
        threatLevelBar.style.width = '0%';
        verdictContainer.className = 'verdict-container';
        confidenceScore.innerText = 'Calculating...';

        try {
            const response = await fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ text: text })
            });

            if (!response.ok) {
                throw new Error('Server returned an error.');
            }

            const data = await response.json();
            
            // Simulate deep scanning delay for UX effect
            setTimeout(() => {
                displayResults(data);
            }, 1200);

        } catch (error) {
            console.error('API Error:', error);
            alert("Connection error. Ensure the Flask server is running.");
            resetUI();
        }
    });

    function displayResults(data) {
        document.body.classList.remove('loading');
        resultsSection.classList.remove('scanning');
        analyzeBtn.querySelector('span').innerText = 'Analyze New Email';
        analyzeBtn.querySelector('i').className = 'fa-solid fa-radar';

        const isPhishing = data.prediction === "Phishing";
        const prob = data.probability;
        const confidence = isPhishing ? prob * 100 : (1 - prob) * 100;
        
        confidenceScore.innerText = `${confidence.toFixed(1)}% Confidence`;
        
        // Apply verdict styling
        verdictContainer.className = 'verdict-container';
        threatLevelBar.className = 'progress-fill';

        if (isPhishing) {
            verdictContainer.classList.add('danger');
            verdictIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
            verdictLabel.innerText = 'Threat Detected: Phishing';
            verdictDesc.innerText = 'This email contains malicious links or suspicious keywords designed to manipulate the user or steal information.';
            
            threatLevelBar.classList.add('danger-fill');
            // Slight delay for animation
            setTimeout(() => {
                threatLevelBar.style.width = `${(prob * 100).toFixed(0)}%`;
            }, 50);
        } else {
            verdictContainer.classList.add('safe');
            verdictIcon.innerHTML = '<i class="fa-solid fa-shield-check"></i>';
            verdictLabel.innerText = 'Status: Safe';
            verdictDesc.innerText = 'No malicious intent, phishing patterns, or dangerous URLs detected in the payload.';
            
            threatLevelBar.classList.add('safe-fill');
            // Slight delay for animation
            setTimeout(() => {
                threatLevelBar.style.width = `${((1-prob) * 100).toFixed(0)}%`;
            }, 50);
        }
    }

    function resetUI() {
        document.body.classList.remove('loading');
        resultsSection.classList.add('hidden');
        resultsSection.classList.remove('scanning');
        analyzeBtn.querySelector('span').innerText = 'Initiate Scan';
        analyzeBtn.querySelector('i').className = 'fa-solid fa-radar';
    }
});
