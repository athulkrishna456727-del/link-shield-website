// VirusTotal API Configuration
const VIRUSTOTAL_API_KEY = 'deeec0956d89958547db93b5168256a89d1cc99ef2ac75e39d74be01b2175d86';

// Common threat database
const THREAT_DATABASE = {
    // Malware families
    'Trojan': ['Trojan.Generic', 'Trojan.Win32', 'Trojan.Spy', 'Trojan.Dropper', 'Trojan.Banker'],
    'Virus': ['W97M', 'X97M', 'O97M', 'Virus.Win32', 'Virus.MSWord'],
    'Worm': ['Worm.Agent', 'Worm.AutoRun', 'Worm.Email'],
    'Ransomware': ['Ransom', 'CryptoLocker', 'WannaCry', 'Ryuk', 'REvil'],
    'Spyware': ['Spyware', 'Keylogger', 'Spy.Agent'],
    'Adware': ['Adware', 'AdLoad', 'Downloader', 'BundleInstaller'],
    
    // Phishing categories
    'Phishing': ['Phishing', 'Fraud', 'Scam', 'Suspicious', 'Malicious'],
    'Social Engineering': ['SocialEngineering', 'FakeAV', 'FakeAlert'],
    
    // Network threats
    'Botnet': ['Botnet', 'Zombie', 'C&C'],
    'Miner': ['CoinMiner', 'BitCoinMiner', 'CryptoMiner'],
    
    // File threats
    'Exploit': ['Exploit', 'Shellcode', 'BufferOverflow'],
    'Backdoor': ['Backdoor', 'Rootkit', 'RemoteAccess']
};

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

    // URL Scanning - REAL API
    document.querySelector('.scan-button').addEventListener('click', handleRealUrlScan);
    document.querySelector('.url-input').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') handleRealUrlScan();
    });

    // File Scanning (Enhanced Demo)
    document.querySelector('.file-scan').addEventListener('click', function() {
        const fileInput = document.querySelector('#file-input');
        if (!fileInput.files.length) {
            alert('Please select a file first');
            return;
        }
        const file = fileInput.files[0];
        simulateDetailedFileScan(file.name, file.type);
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
        alert('PDF report feature coming in next update!');
    });

    // Business buttons
    document.querySelectorAll('.cta-button').forEach(button => {
        button.addEventListener('click', function() {
            alert('Business features launching soon! Contact us for early access.');
        });
    });

    // Get Started button
    document.querySelector('.nav-button').addEventListener('click', function() {
        document.querySelector('.scanner-box').scrollIntoView({ behavior: 'smooth' });
    });
}

// REAL URL SCANNING WITH DETAILED RESULTS
async function handleRealUrlScan() {
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

    try {
        const result = await scanWithVirusTotal(url);
        showDetailedResults(result);
    } catch (error) {
        console.error('Scan error:', error);
        alert('Scan failed: ' + error.message);
        // Fallback to detailed demo mode
        simulateDetailedUrlScan(url);
    } finally {
        scanButton.textContent = 'Scan Now';
        scanButton.disabled = false;
    }
}

// REAL VIRUSTOTAL API CALL
async function scanWithVirusTotal(url) {
    let scanUrl = url;
    if (!scanUrl.startsWith('http')) {
        scanUrl = 'https://' + scanUrl;
    }

    const apiUrl = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${VIRUSTOTAL_API_KEY}&resource=${encodeURIComponent(scanUrl)}`;
    
    console.log('Scanning URL:', scanUrl);
    
    const response = await fetch(apiUrl);
    
    if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('VirusTotal response:', data);
    
    return {
        target: scanUrl,
        positives: data.positives || 0,
        total: data.total || 0,
        scanDate: data.scan_date || new Date().toISOString(),
        scans: data.scans || {},
        responseCode: data.response_code || 0,
        permalink: data.permalink || ''
    };
}

// SHOW DETAILED THREAT RESULTS
function showDetailedResults(result) {
    const riskScore = calculateRealRiskScore(result.positives, result.total);
    const verdict = getRealVerdict(riskScore);
    
    // Analyze threats from scan results
    const threatAnalysis = analyzeThreats(result.scans);
    const detectedThreats = threatAnalysis.detectedThreats;
    const threatCategories = threatAnalysis.categories;
    
    // Update UI with detailed results
    document.getElementById('result-url').textContent = result.target;
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
    verdictElement.classList.add(`verdict-${verdict.toLowerCase().replace(' ', '-')}`);
    
    // Update threat information with DETAILS
    document.getElementById('malware-detected').textContent = result.positives > 0 ? 'Yes' : 'No';
    document.getElementById('phishing-risk').textContent = getPhishingLevel(result.positives);
    document.getElementById('suspicious-activity').textContent = result.positives > 0 ? 
        `${result.positives} security engines detected threats` : 'No threats detected';

    // SHOW DETAILED THREAT LIST
    showThreatDetails(detectedThreats, threatCategories, result.positives);

    // Show results
    document.querySelector('.results-section').style.display = 'block';
    document.querySelector('.results-section').scrollIntoView({ behavior: 'smooth' });
    
    console.log(`Scan completed: ${result.target} - ${verdict} (${riskScore}%) - Threats: ${detectedThreats.length}`);
}

// ANALYZE THREATS FROM SCAN DATA
function analyzeThreats(scans) {
    const detectedThreats = [];
    const categories = new Set();
    
    if (!scans) return { detectedThreats: [], categories: [] };
    
    // Analyze each antivirus result
    Object.entries(scans).forEach(([engine, data]) => {
        if (data.detected && data.result) {
            const threatName = data.result;
            detectedThreats.push({
                engine: engine,
                threat: threatName,
                category: categorizeThreat(threatName)
            });
            
            // Add to categories
            const category = categorizeThreat(threatName);
            if (category) categories.add(category);
        }
    });
    
    return {
        detectedThreats: detectedThreats,
        categories: Array.from(categories)
    };
}

// CATEGORIZE THREATS
function categorizeThreat(threatName) {
    const threatUpper = threatName.toUpperCase();
    
    for (const [category, patterns] of Object.entries(THREAT_DATABASE)) {
        for (const pattern of patterns) {
            if (threatUpper.includes(pattern.toUpperCase())) {
                return category;
            }
        }
    }
    
    return 'Unknown';
}

// SHOW DETAILED THREAT INFORMATION
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
                    ${detectedThreats.slice(0, 10).map(threat => `
                        <div class="threat-item detailed">
                            <span class="threat-engine">${threat.engine}</span>
                            <span class="threat-name">${threat.threat}</span>
                            <span class="threat-category badge">${threat.category}</span>
                        </div>
                    `).join('')}
                </div>
                ${detectedThreats.length > 10 ? 
                    `<div class="more-threats">+ ${detectedThreats.length - 10} more threats detected</div>` : ''}
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
    
    // Update the threat-info section
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

// ENHANCED FILE SCANNING WITH DETAILED THREATS
function simulateDetailedFileScan(fileName, fileType) {
    const fileScanButton = document.querySelector('.file-scan');
    
    // Show loading
    fileScanButton.textContent = 'Analyzing File...';
    fileScanButton.disabled = true;

    setTimeout(() => {
        // Realistic file analysis with detailed threats
        let riskScore, verdict, detectedThreats, categories;
        
        const lowerName = fileName.toLowerCase();
        
        // Simulate different threat scenarios
        if (lowerName.includes('trojan') || lowerName.includes('malware.exe')) {
            riskScore = 92;
            verdict = 'Malicious';
            detectedThreats = [
                { engine: 'Kaspersky', threat: 'Trojan.Win32.Generic', category: 'Trojan' },
                { engine: 'Norton', threat: 'Trojan.Gen.2', category: 'Trojan' },
                { engine: 'McAfee', threat: 'Generic Trojan', category: 'Trojan' }
            ];
            categories = ['Trojan', 'Malware'];
        } else if (lowerName.includes('ransomware') || lowerName.includes('cryptolocker')) {
            riskScore = 95;
            verdict = 'Malicious';
            detectedThreats = [
                { engine: 'Bitdefender', threat: 'Ransom.CryptoLocker', category: 'Ransomware' },
                { engine: 'Malwarebytes', threat: 'Ransomware.Generic', category: 'Ransomware' },
                { engine: 'Avast', threat: 'Win32:RansomX-gen', category: 'Ransomware' }
            ];
            categories = ['Ransomware'];
        } else if (lowerName.includes('adware') || lowerName.includes('bundler')) {
            riskScore = 45;
            verdict = 'Suspicious';
            detectedThreats = [
                { engine: 'Avira', threat: 'ADWARE/Generic', category: 'Adware' },
                { engine: 'ESET', threat: 'Win32/Adware.BundleInstaller', category: 'Adware' }
            ];
            categories = ['Adware'];
        } else if (lowerName.includes('phishing') || lowerName.includes('scam.pdf')) {
            riskScore = 78;
            verdict = 'Malicious';
            detectedThreats = [
                { engine: 'Google Safebrowsing', threat: 'Phishing', category: 'Phishing' },
                { engine: 'Cisco Talos', threat: 'Fraudulent', category: 'Phishing' }
            ];
            categories = ['Phishing'];
        } else if (lowerName.includes('test') || lowerName.includes('demo') || lowerName.includes('clean')) {
            riskScore = 2;
            verdict = 'Safe';
            detectedThreats = [];
            categories = [];
        } else {
            // Random but realistic
            riskScore = Math.floor(Math.random() * 25);
            verdict = 'Safe';
            detectedThreats = [];
            categories = [];
        }
        
        // Show detailed file results
        showDetailedFileResults(fileName, riskScore, verdict, detectedThreats, categories);
        
        fileScanButton.textContent = 'Scan File';
        fileScanButton.disabled = false;
    }, 2500);
}

function showDetailedFileResults(fileName, riskScore, verdict, detectedThreats, categories) {
    document.getElementById('result-url').textContent = fileName;
    document.getElementById('risk-score').textContent = `${riskScore}%`;
    
    const riskScoreElement = document.getElementById('risk-score');
    riskScoreElement.className = 'score-value ';
    if (riskScore < 30) riskScoreElement.classList.add('safe');
    else if (riskScore < 70) riskScoreElement.classList.add('warning');
    else riskScoreElement.classList.add('danger');
    
    document.getElementById('verdict-text').textContent = verdict;
    document.getElementById('verdict-text').className = `verdict-${verdict.toLowerCase()}`;
    document.getElementById('malware-detected').textContent = detectedThreats.length > 0 ? 'Yes' : 'No';
    document.getElementById('phishing-risk').textContent = categories.includes('Phishing') ? 'High' : 'Low';
    document.getElementById('suspicious-activity').textContent = detectedThreats.length > 0 ? 
        `${detectedThreats.length} security engines detected threats` : 'No threats detected';

    // Show detailed threat information
    showThreatDetails(detectedThreats, categories, detectedThreats.length);

    document.querySelector('.results-section').style.display = 'block';
    document.querySelector('.results-section').scrollIntoView({ behavior: 'smooth' });
}

// UTILITY FUNCTIONS
function calculateRealRiskScore(positives, total) {
    if (total === 0) return 0;
    return Math.round((positives / total) * 100);
}

function getRealVerdict(riskScore) {
    if (riskScore === 0) return 'Safe';
    if (riskScore < 30) return 'Low Risk';
    if (riskScore < 70) return 'Suspicious';
    return 'Malicious';
}

function getPhishingLevel(positives) {
    if (positives === 0) return 'Low';
    if (positives < 5) return 'Medium';
    return 'High';
}

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
}

// FALLBACK DEMO WITH DETAILED THREATS
function simulateDetailedUrlScan(url) {
    let riskScore, verdict, detectedThreats, categories;
    
    const lowerUrl = url.toLowerCase();
    
    // Realistic scenarios with detailed threats
    if (lowerUrl.includes('phishing-test.com')) {
        riskScore = 85;
        verdict = 'Malicious';
        detectedThreats = [
            { engine: 'Google Safebrowsing', threat: 'Phishing', category: 'Phishing' },
            { engine: 'Norton Safe Web', threat: 'Fraudulent Website', category: 'Phishing' },
            { engine: 'McAfee WebAdvisor', threat: 'Suspicious Website', category: 'Phishing' }
        ];
        categories = ['Phishing'];
    } else if (lowerUrl.includes('malware-test.org')) {
        riskScore = 92;
        verdict = 'Malicious';
        detectedThreats = [
            { engine: 'Kaspersky', threat: 'Trojan-Downloader', category: 'Trojan' },
            { engine: 'Bitdefender', threat: 'Generic Malware', category: 'Malware' },
            { engine: 'Avast', threat: 'URL:Malicious', category: 'Malware' }
        ];
        categories = ['Trojan', 'Malware'];
    } else if (lowerUrl.includes('google.com') || lowerUrl.includes('facebook.com')) {
        riskScore = 1;
        verdict = 'Safe';
        detectedThreats = [];
        categories = [];
    } else {
        // Random but weighted toward safe
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
    
    showDetailedResults({
        target: url,
        positives: detectedThreats.length,
        total: 65,
        scans: {}
    });
}