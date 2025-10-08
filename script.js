document.addEventListener('DOMContentLoaded', function() {
    const scanButton = document.querySelector('.scan-button');
    const urlInput = document.querySelector('.url-input');
    const fileInput = document.querySelector('#file-input');
    const fileScanButton = document.querySelector('.file-scan');
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const resultsSection = document.querySelector('.results-section');
    const newScanButton = document.querySelector('.new-scan-button');

    // Tab switching
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            // Remove active class from all tabs
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            // Add active class to clicked tab
            this.classList.add('active');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });

    // URL Scan Button
    scanButton.addEventListener('click', function() {
        const url = urlInput.value.trim();
        
        if (url === '') {
            showAlert('Please enter a URL to scan');
            return;
        }
        
        if (!isValidUrl(url)) {
            showAlert('Please enter a valid URL (e.g., https://example.com)');
            return;
        }
        
        simulateScan(url, 'url');
    });

    // File Scan Button
    fileScanButton.addEventListener('click', function() {
        if (!fileInput.files.length) {
            showAlert('Please select a file to scan');
            return;
        }
        
        const file = fileInput.files[0];
        const fileName = file.name;
        const fileExtension = fileName.split('.').pop().toLowerCase();
        const allowedExtensions = ['apk', 'pdf', 'doc', 'docx', 'txt'];
        
        if (!allowedExtensions.includes(fileExtension)) {
            showAlert('Please select APK, PDF, DOC, DOCX, or TXT files only');
            return;
        }
        
        simulateScan(fileName, 'file');
    });

    // File input change
    fileInput.addEventListener('change', function() {
        const fileLabel = document.querySelector('.file-label span:last-child');
        if (this.files.length) {
            fileLabel.textContent = this.files[0].name;
        } else {
            fileLabel.textContent = 'Choose APK, PDF, or Document';
        }
    });

    // New Scan Button
    if (newScanButton) {
        newScanButton.addEventListener('click', function() {
            resetScanner();
        });
    }

    // Report Button
    const reportButton = document.querySelector('.report-button');
    if (reportButton) {
        reportButton.addEventListener('click', function() {
            showAlert('Thank you for reporting! Our team will review this submission.');
        });
    }

    // PDF Button
    const pdfButton = document.querySelector('.pdf-button');
    if (pdfButton) {
        pdfButton.addEventListener('click', function() {
            showAlert('PDF report generation will be available when connected to real APIs');
        });
    }

    // Business CTA Buttons
    const businessButtons = document.querySelectorAll('.cta-button');
    businessButtons.forEach(button => {
        button.addEventListener('click', function() {
            if (this.classList.contains('primary')) {
                showAlert('Business access features coming soon!');
            } else {
                showAlert('Fiverr integration coming soon!');
            }
        });
    });

    // Navigation smooth scroll
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

    // Navbar background on scroll
    window.addEventListener('scroll', function() {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 100) {
            navbar.style.background = 'rgba(26, 32, 44, 0.98)';
        } else {
            navbar.style.background = 'rgba(26, 32, 44, 0.95)';
        }
    });

    // Get Started Button
    const getStartedButton = document.querySelector('.nav-button');
    if (getStartedButton) {
        getStartedButton.addEventListener('click', function() {
            document.querySelector('.scanner-box').scrollIntoView({
                behavior: 'smooth'
            });
        });
    }

    // Blog Read More links
    document.querySelectorAll('.read-more').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            showAlert('Blog content coming soon!');
        });
    });

    // Contact Links
    document.querySelectorAll('.contact-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const platform = this.textContent.trim();
            showAlert(`${platform} link will be configured soon!`);
        });
    });

    function simulateScan(target, type) {
        const scanButton = type === 'url' ? document.querySelector('.scan-button') : document.querySelector('.file-scan');
        const originalText = scanButton.textContent;
        
        // Show loading state
        scanButton.textContent = 'Scanning...';
        scanButton.disabled = true;
        scanButton.style.opacity = '0.7';
        
        // Simulate API call delay
        setTimeout(() => {
            showResults(target, type);
            scanButton.textContent = originalText;
            scanButton.disabled = false;
            scanButton.style.opacity = '1';
        }, 1500);
    }

    function showResults(target, type) {
        // Update the scanned target
        document.getElementById('result-url').textContent = target;
        
        // More realistic risk assessment based on domain/content
        let riskScore, verdict, malware, phishing, suspicious;
        
        if (type === 'url') {
            // More intelligent URL analysis
            if (target.includes('test') || target.includes('example')) {
                riskScore = 15;
                verdict = 'Safe';
                malware = 'No';
                phishing = 'Low';
                suspicious = 'None';
            } else if (target.includes('suspicious') || target.includes('unknown')) {
                riskScore = 65;
                verdict = 'Suspicious';
                malware = 'Possible';
                phishing = 'Medium';
                suspicious = 'Some indicators';
            } else {
                // Random but weighted toward safe results (more realistic)
                riskScore = Math.random() < 0.8 ? Math.floor(Math.random() * 30) : Math.floor(30 + Math.random() * 70);
                
                if (riskScore < 25) {
                    verdict = 'Safe';
                    malware = 'No';
                    phishing = 'Low';
                    suspicious = 'None';
                } else if (riskScore < 60) {
                    verdict = 'Suspicious';
                    malware = 'Possible';
                    phishing = 'Medium';
                    suspicious = 'Some indicators';
                } else {
                    verdict = 'Malicious';
                    malware = 'Yes';
                    phishing = 'High';
                    suspicious = 'Multiple indicators';
                }
            }
        } else {
            // File scanning logic
            const fileName = target.toLowerCase();
            if (fileName.includes('test') || fileName.includes('demo')) {
                riskScore = 10;
                verdict = 'Safe';
                malware = 'No';
                phishing = 'Low';
                suspicious = 'None';
            } else if (fileName.includes('suspicious') || fileName.includes('unknown')) {
                riskScore = 70;
                verdict = 'Malicious';
                malware = 'Yes';
                phishing = 'High';
                suspicious = 'Multiple indicators';
            } else {
                riskScore = Math.floor(Math.random() * 40); // Files are generally safer
                verdict = 'Safe';
                malware = 'No';
                phishing = 'Low';
                suspicious = 'None';
            }
        }
        
        // Update UI with results
        const riskScoreElement = document.getElementById('risk-score');
        const verdictTextElement = document.getElementById('verdict-text');
        
        riskScoreElement.textContent = `${riskScore}/100`;
        
        // Set appropriate classes based on risk
        riskScoreElement.className = 'score-value ';
        verdictTextElement.className = '';
        
        if (riskScore < 30) {
            riskScoreElement.classList.add('safe');
            verdictTextElement.classList.add('verdict-safe');
            verdictTextElement.textContent = 'Safe';
        } else if (riskScore < 70) {
            riskScoreElement.classList.add('warning');
            verdictTextElement.classList.add('verdict-warning');
            verdictTextElement.textContent = 'Suspicious';
        } else {
            riskScoreElement.classList.add('danger');
            verdictTextElement.classList.add('verdict-danger');
            verdictTextElement.textContent = 'Malicious';
        }
        
        // Update threat information
        document.getElementById('malware-detected').textContent = malware;
        document.getElementById('phishing-risk').textContent = phishing;
        document.getElementById('suspicious-activity').textContent = suspicious;
        
        // Show results section
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    function resetScanner() {
        resultsSection.style.display = 'none';
        urlInput.value = '';
        fileInput.value = '';
        document.querySelector('.file-label span:last-child').textContent = 'Choose APK, PDF, or Document';
        
        // Reset to URL tab
        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabPanes.forEach(pane => pane.classList.remove('active'));
        
        document.querySelector('[data-tab="url"]').classList.add('active');
        document.getElementById('url-tab').classList.add('active');
    }

    function showAlert(message) {
        alert(message);
    }

    function isValidUrl(string) {
        try {
            // Add http:// if missing
            if (!string.startsWith('http://') && !string.startsWith('https://')) {
                string = 'https://' + string;
            }
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    // Initialize scanner state
    resetScanner();
});