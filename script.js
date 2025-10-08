document.addEventListener('DOMContentLoaded', function() {
    const scanButton = document.querySelector('.scan-button');
    const urlInput = document.querySelector('.url-input');
    const fileInput = document.querySelector('#file-input');
    const fileScanButton = document.querySelector('.file-scan');
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const resultsSection = document.querySelector('.results-section');
    const newScanButton = document.querySelector('.new-scan-button');

    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            this.classList.add('active');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });

    scanButton.addEventListener('click', function() {
        const url = urlInput.value.trim();
        
        if (url === '') {
            alert('Please enter a URL to scan');
            return;
        }
        
        if (!isValidUrl(url)) {
            alert('Please enter a valid URL (e.g., https://example.com)');
            return;
        }
        
        simulateScan(url, 'url');
    });

    fileScanButton.addEventListener('click', function() {
        if (!fileInput.files.length) {
            alert('Please select a file to scan');
            return;
        }
        
        const file = fileInput.files[0];
        const fileName = file.name;
        simulateScan(fileName, 'file');
    });

    fileInput.addEventListener('change', function() {
        const fileLabel = document.querySelector('.file-label span:last-child');
        if (this.files.length) {
            fileLabel.textContent = this.files[0].name;
        } else {
            fileLabel.textContent = 'Choose APK, PDF, or Document';
        }
    });

    newScanButton.addEventListener('click', function() {
        resultsSection.style.display = 'none';
        urlInput.value = '';
        fileInput.value = '';
        document.querySelector('.file-label span:last-child').textContent = 'Choose APK, PDF, or Document';
        
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
        
        document.querySelector('[data-tab="url"]').classList.add('active');
        document.getElementById('url-tab').classList.add('active');
    });

    function simulateScan(target, type) {
        const scanButton = type === 'url' ? document.querySelector('.scan-button') : document.querySelector('.file-scan');
        const originalText = scanButton.textContent;
        
        scanButton.textContent = 'Scanning...';
        scanButton.disabled = true;
        
        setTimeout(() => {
            showResults(target, type);
            scanButton.textContent = originalText;
            scanButton.disabled = false;
        }, 2000);
    }

    function showResults(target, type) {
        document.getElementById('result-url').textContent = target;
        
        const randomScore = Math.floor(Math.random() * 100);
        const riskScore = document.getElementById('risk-score');
        const verdictText = document.getElementById('verdict-text');
        
        riskScore.textContent = `${randomScore}/100`;
        
        if (randomScore < 30) {
            riskScore.className = 'score-value safe';
            verdictText.textContent = 'Safe';
            verdictText.className = 'verdict-safe';
            document.getElementById('malware-detected').textContent = 'No';
            document.getElementById('phishing-risk').textContent = 'Low';
            document.getElementById('suspicious-activity').textContent = 'None';
        } else if (randomScore < 70) {
            riskScore.className = 'score-value warning';
            verdictText.textContent = 'Suspicious';
            verdictText.className = 'verdict-warning';
            document.getElementById('malware-detected').textContent = 'Possible';
            document.getElementById('phishing-risk').textContent = 'Medium';
            document.getElementById('suspicious-activity').textContent = 'Some indicators';
        } else {
            riskScore.className = 'score-value danger';
            verdictText.textContent = 'Malicious';
            verdictText.className = 'verdict-danger';
            document.getElementById('malware-detected').textContent = 'Yes';
            document.getElementById('phishing-risk').textContent = 'High';
            document.getElementById('suspicious-activity').textContent = 'Multiple indicators';
        }
        
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    window.addEventListener('scroll', function() {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 100) {
            navbar.style.background = 'rgba(26, 32, 44, 0.98)';
        } else {
            navbar.style.background = 'rgba(26, 32, 44, 0.95)';
        }
    });
});