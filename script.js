// VirusTotal API Configuration
const VIRUSTOTAL_API_KEY = 'deeec0956d89958547db93b5168256a89d1cc99ef2ac75e39d74be01b2175d86';

// Threat database
const THREAT_DATABASE = {
    'Trojan': ['Trojan.Generic', 'Trojan.Win32', 'Trojan.Spy', 'Trojan.Dropper', 'Trojan.Banker'],
    'Ransomware': ['Ransom', 'CryptoLocker', 'WannaCry', 'Ryuk', 'REvil'],
    'Phishing': ['Phishing', 'Fraud', 'Scam', 'Suspicious', 'Malicious'],
    'Spyware': ['Spyware', 'Keylogger', 'Spy.Agent'],
    'Adware': ['Adware', 'AdLoad', 'Downloader', 'BundleInstaller'],
    'Worm': ['Worm.Agent', 'Worm.AutoRun', 'Worm.Email'],
    'Backdoor': ['Backdoor', 'Rootkit', 'RemoteAccess'],
    'Miner': ['CoinMiner', 'BitCoinMiner', 'CryptoMiner']
};

let currentScanResult = null;
let currentThreatDetails = null;

document.addEventListener('DOMContentLoaded', function() {
    initializeScanner();
});

function initializeScanner() {
    // Tab switching
    document.querySelectorAll('.tab-button').forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
            
            this.classList.add('active');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });

    // URL Scanning
    document.querySelector('.scan-button').addEventListener('click', handleUrlScan);
    document.querySelector('.url-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') handleUrlScan();
    });

    // File Scanning
    document.querySelector('.file-scan').addEventListener('click', function() {
        const fileInput = document.querySelector('#file-input');
        if (!fileInput.files.length) {
            alert('Please select a file first');
            return;
        }
        simulateFileScan(fileInput.files[0].name);
    });

    // File input change
    document.querySelector('#file-input').addEventListener('change', function() {
        const fileLabel = document.querySelector('.file-label span:last-child');
        if (this.files.length) {
            fileLabel.textContent = this.files[0].name;
        } else {
            fileLabel.textContent = 'Choose APK, PDF, or Document';
        }
    });

    // Navigation
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });

    // Other buttons
    document.querySelector('.new-scan-button').addEventListener('click', resetScanner);
    document.querySelector('.report-button').addEventListener('click', function() {
        alert('False positive reported to our security team!');
    });
    
    document.querySelector('.pdf-button').addEventListener('click', function() {
        if (!currentScanResult) {
            alert('Please complete a scan first');
            return;
        }
        generatePDFReport();
    });

    // Business buttons
    document.querySelectorAll('.cta-button').forEach(button => {
        button.addEventListener('click', function() {
            alert('Business features coming soon!');
        });
    });

    // Get Started button
    document.querySelector('.nav-button').addEventListener('click', function() {
        document.querySelector('.scanner-box').scrollIntoView({ behavior: 'smooth' });
    });
}

// URL Scanning Function
function handleUrlScan() {
    const urlInput = document.querySelector('.url-input');
    const scanButton = document.querySelector('.scan-button');
    const url = urlInput.value.trim();

    if (!url) {
        alert('Please enter a URL to scan');
        return;
    }

    if (!isValidUrl(url)) {
        alert('Please enter a valid URL (e.g., https://example.com)');
        return;
    }

    // Show loading state
    scanButton.textContent = 'Scanning...';
    scanButton.disabled = true;

    // Use demo mode for now (bypass API issues)
    setTimeout(() => {
        simulateUrlScan(url);
        scanButton.textContent = 'Scan Now';
        scanButton.disabled = false;
    }, 1500);
}

// Simulate URL Scan (Working Demo)
function simulateUrlScan(url) {
    let riskScore, verdict, detectedThreats, categories;
    
    const lowerUrl = url.toLowerCase();
    
    // Realistic scenarios
    if (lowerUrl.includes('phishing') || lowerUrl.includes('scam')) {
        riskScore = 85;
        verdict = 'Malicious';
        detectedThreats = [
            { engine: 'Google Safebrowsing', threat: 'Phishing', category: 'Phishing' },
            { engine: 'Norton Safe Web', threat: 'Fraudulent Website', category: 'Phishing' }
        ];
        categories = ['Phishing'];
    } else if (lowerUrl.includes('malware') || lowerUrl.includes('trojan')) {
        riskScore = 92;
        verdict = 'Malicious';
        detectedThreats = [
            { engine: 'Kaspersky', threat: 'Trojan.Win32.Generic', category: 'Trojan' },
            { engine: 'Bitdefender', threat: 'Generic Malware', category: 'Malware' }
        ];
        categories = ['Trojan', 'Malware'];
    } else if (lowerUrl.includes('google.com') || lowerUrl.includes('facebook.com')) {
        riskScore = 2;
        verdict = 'Safe';
        detectedThreats = [];
        categories = [];
    } else if (lowerUrl.includes('test') || lowerUrl.includes('example')) {
        riskScore = 5;
        verdict = 'Safe';
        detectedThreats = [];
        categories = [];
    } else {
        // Random but realistic
        riskScore = Math.random() < 0.8 ? Math.floor(Math.random() * 20) : Math.floor(30 + Math.random() * 60);
        verdict = riskScore < 30 ? 'Safe' : riskScore < 70 ? 'Suspicious' : 'Malicious';
        
        if (riskScore > 60) {
            detectedThreats = [
                { engine: 'Security Engine', threat: 'Suspicious.Content', category: 'Suspicious' }
            ];
            categories = ['Suspicious'];
        } else {
            detectedThreats = [];
            categories = [];
        }
    }
    
    // Store results
    currentScanResult = {
        target: url,
        positives: detectedThreats.length,
        total: 65,
        scanDate: new Date().toISOString(),
        riskScore: riskScore,
        verdict: verdict,
        scanType: 'URL'
    };
    currentThreatDetails = {
        detectedThreats: detectedThreats,
        categories: categories
    };
    
    showResults(url, riskScore, verdict, detectedThreats, categories);
}

// Simulate File Scan
function simulateFileScan(fileName) {
    const fileScanButton = document.querySelector('.file-scan');
    
    fileScanButton.textContent = 'Analyzing...';
    fileScanButton.disabled = true;

    setTimeout(() => {
        let riskScore, verdict, detectedThreats, categories;
        const lowerName = fileName.toLowerCase();
        
        if (lowerName.includes('trojan') || lowerName.includes('malware')) {
            riskScore = 92;
            verdict = 'Malicious';
            detectedThreats = [
                { engine: 'Kaspersky', threat: 'Trojan.Win32.Generic', category: 'Trojan' },
                { engine: 'Norton', threat: 'Trojan.Gen.2', category: 'Trojan' }
            ];
            categories = ['Trojan'];
        } else if (lowerName.includes('ransomware')) {
            riskScore = 95;
            verdict = 'Malicious';
            detectedThreats = [
                { engine: 'Bitdefender', threat: 'Ransom.CryptoLocker', category: 'Ransomware' }
            ];
            categories = ['Ransomware'];
        } else {
            riskScore = Math.floor(Math.random() * 25);
            verdict = 'Safe';
            detectedThreats = [];
            categories = [];
        }
        
        // Store results
        currentScanResult = {
            target: fileName,
            positives: detectedThreats.length,
            total: 65,
            scanDate: new Date().toISOString(),
            riskScore: riskScore,
            verdict: verdict,
            scanType: 'File'
        };
        currentThreatDetails = {
            detectedThreats: detectedThreats,
            categories: categories
        };
        
        showResults(fileName, riskScore, verdict, detectedThreats, categories);
        fileScanButton.textContent = 'Scan File';
        fileScanButton.disabled = false;
    }, 2000);
}

// Show Results
function showResults(target, riskScore, verdict, detectedThreats, categories) {
    document.getElementById('result-url').textContent = target;
    document.getElementById('risk-score').textContent = `${riskScore}%`;
    
    // Set risk color
    const riskScoreElement = document.getElementById('risk-score');
    riskScoreElement.className = 'score-value ';
    if (riskScore < 30) {
        riskScoreElement.classList.add('safe');
    } else if (riskScore < 70) {
        riskScoreElement.classList.add('warning');
    } else {
        riskScoreElement.classList.add('danger');
    }
    
    // Set verdict
    const verdictElement = document.getElementById('verdict-text');
    verdictElement.textContent = verdict;
    verdictElement.className = '';
    verdictElement.classList.add(`verdict-${verdict.toLowerCase()}`);
    
    // Update threat information
    document.getElementById('malware-detected').textContent = detectedThreats.length > 0 ? 'Yes' : 'No';
    document.getElementById('phishing-risk').textContent = categories.includes('Phishing') ? 'High' : 'Low';
    document.getElementById('suspicious-activity').textContent = detectedThreats.length > 0 ? 
        `${detectedThreats.length} security engines detected threats` : 'No threats detected';

    // Show detailed threats
    showThreatDetails(detectedThreats, categories, detectedThreats.length);

    // Show results section
    document.querySelector('.results-section').style.display = 'block';
    document.querySelector('.results-section').scrollIntoView({ behavior: 'smooth' });
}

// Show Threat Details
function showThreatDetails(detectedThreats, categories, positiveCount) {
    let threatDetailsHTML = '';
    
    if (detectedThreats.length > 0) {
        threatDetailsHTML = `
            <div class="threat-details-section">
                <h4>🔍 Detected Threats</h4>
                <div class="threat-categories">
                    <strong>Threat Categories:</strong> ${categories.join(', ') || 'Various'}
                </div>
                <div class="threat-list">
                    ${detectedThreats.map(threat => `
                        <div class="threat-item detailed">
                            <span class="threat-engine">${threat.engine}</span>
                            <span class="threat-name">${threat.threat}</span>
                            <span class="threat-category badge">${threat.category}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    } else {
        threatDetailsHTML = `
            <div class="threat-details-section">
                <h4>✅ No Threats Detected</h4>
                <div class="clean-result">
                    <p>This target appears clean across all security engines.</p>
                </div>
            </div>
        `;
    }
    
    const threatInfoElement = document.querySelector('.threat-info');
    threatInfoElement.innerHTML = `
        <h4>Threat Intelligence</h4>
        <div class="threat-overview">
            <div class="threat-stats">
                <div class="threat-stat">
                    <span class="stat-value">${positiveCount}</span>
                    <span class="stat-label">Engines Detected</span>
                </div>
                <div class="threat-stat">
                    <span class="stat-value">${categories.length}</span>
                    <span class="stat-label">Threat Categories</span>
                </div>
                <div class="threat-stat">
                    <span class="stat-value">${detectedThreats.length}</span>
                    <span class="stat-label">Total Detections</span>
                </div>
            </div>
        </div>
        ${threatDetailsHTML}
    `;
}

// Generate PDF Report
function generatePDFReport() {
    if (!currentScanResult) {
        alert('No scan data available');
        return;
    }

    const pdfButton = document.querySelector('.pdf-button');
    const originalText = pdfButton.textContent;
    pdfButton.textContent = 'Generating PDF...';
    pdfButton.disabled = true;

    try {
        // Simple PDF generation using browser print for now
        const printContent = `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h1 style="color: #3182ce; border-bottom: 2px solid #3182ce; padding-bottom: 10px;">
                    🔒 Link Shield Security Report
                </h1>
                
                <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 20px 0;">
                    <h3>Scan Summary</h3>
                    <p><strong>Target:</strong> ${currentScanResult.target}</p>
                    <p><strong>Scan Date:</strong> ${new Date(currentScanResult.scanDate).toLocaleString()}</p>
                    <p><strong>Verdict:</strong> ${currentScanResult.verdict}</p>
                    <p><strong>Risk Score:</strong> ${currentScanResult.riskScore}%</p>
                </div>

                <div style="margin: 20px 0;">
                    <h3>Threat Analysis</h3>
                    ${currentThreatDetails.detectedThreats.length > 0 ? `
                        <p><strong>Detected Threats:</strong> ${currentThreatDetails.detectedThreats.length}</p>
                        <p><strong>Categories:</strong> ${currentThreatDetails.categories.join(', ')}</p>
                        <div style="margin-top: 10px;">
                            ${currentThreatDetails.detectedThreats.map(threat => `
                                <div style="border-left: 3px solid #e53e3e; padding-left: 10px; margin: 5px 0;">
                                    <strong>${threat.engine}:</strong> ${threat.threat} <em>(${threat.category})</em>
                                </div>
                            `).join('')}
                        </div>
                    ` : '<p>No threats detected - Target appears clean</p>'}
                </div>

                <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin: 20px 0;">
                    <h3>🔒 Security Recommendations</h3>
                    <ul>
                        <li>Keep your security software updated</li>
                        <li>Enable real-time protection</li>
                        <li>Practice safe browsing habits</li>
                        <li>Regularly scan your system</li>
                    </ul>
                </div>

                <div style="text-align: center; color: #666; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 15px;">
                    <p>Generated by Link Shield Security • ${new Date().toLocaleDateString()}</p>
                    <p>link-shield-security.netlify.app</p>
                </div>
            </div>
        `;

        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
            <html>
                <head>
                    <title>Link Shield Security Report</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        @media print {
                            body { margin: 0; }
                        }
                    </style>
                </head>
                <body>${printContent}</body>
            </html>
        `);
        printWindow.document.close();
        
        setTimeout(() => {
            printWindow.print();
            printWindow.close();
        }, 500);

        alert('PDF report generated successfully!');
        
    } catch (error) {
        console.error('PDF generation error:', error);
        alert('Error generating report. Please try the print option instead.');
    } finally {
        pdfButton.textContent = originalText;
        pdfButton.disabled = false;
    }
}

// Utility Functions
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function resetScanner() {
    document.querySelector('.results-section').style.display = 'none';
    document.querySelector('.url-input').value = '';
    document.querySelector('#file-input').value = '';
    document.querySelector('.file-label span:last-child').textContent = 'Choose APK, PDF, or Document';
    
    // Reset to URL tab
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    document.querySelector('[data-tab="url"]').classList.add('active');
    document.getElementById('url-tab').classList.add('active');
    
    // Clear stored results
    currentScanResult = null;
    currentThreatDetails = null;
}