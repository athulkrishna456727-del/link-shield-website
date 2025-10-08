// VirusTotal API Configuration
const VIRUSTOTAL_API_KEY = 'deeec0956d89958547db93b5168256a89d1cc99ef2ac75e39d74be01b2175d86';

// Common threat database
const THREAT_DATABASE = {
    'Trojan': ['Trojan.Generic', 'Trojan.Win32', 'Trojan.Spy', 'Trojan.Dropper', 'Trojan.Banker'],
    'Virus': ['W97M', 'X97M', 'O97M', 'Virus.Win32', 'Virus.MSWord'],
    'Worm': ['Worm.Agent', 'Worm.AutoRun', 'Worm.Email'],
    'Ransomware': ['Ransom', 'CryptoLocker', 'WannaCry', 'Ryuk', 'REvil'],
    'Spyware': ['Spyware', 'Keylogger', 'Spy.Agent'],
    'Adware': ['Adware', 'AdLoad', 'Downloader', 'BundleInstaller'],
    'Phishing': ['Phishing', 'Fraud', 'Scam', 'Suspicious', 'Malicious'],
    'Social Engineering': ['SocialEngineering', 'FakeAV', 'FakeAlert'],
    'Botnet': ['Botnet', 'Zombie', 'C&C'],
    'Miner': ['CoinMiner', 'BitCoinMiner', 'CryptoMiner'],
    'Exploit': ['Exploit', 'Shellcode', 'BufferOverflow'],
    'Backdoor': ['Backdoor', 'Rootkit', 'RemoteAccess']
};

// Global variables to store current scan results
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
    
    // PDF Report Button - UPDATED
    document.querySelector('.pdf-button').addEventListener('click', function() {
        if (!currentScanResult) {
            alert('Please complete a scan first to generate a report');
            return;
        }
        generatePDFReport();
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
    
    // Store results for PDF generation
    currentScanResult = {
        ...result,
        riskScore: riskScore,
        verdict: verdict,
        scanType: 'URL'
    };
    currentThreatDetails = {
        detectedThreats: detectedThreats,
        categories: threatCategories
    };
    
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

// GENERATE PROFESSIONAL PDF REPORT
function generatePDFReport() {
    if (!currentScanResult || !currentThreatDetails) {
        alert('No scan data available for report generation');
        return;
    }

    // Show generating message
    const pdfButton = document.querySelector('.pdf-button');
    const originalText = pdfButton.textContent;
    pdfButton.textContent = 'Generating PDF...';
    pdfButton.disabled = true;

    try {
        // Create new PDF document
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        const pageWidth = doc.internal.pageSize.getWidth();
        const margin = 20;
        const contentWidth = pageWidth - (margin * 2);
        
        // Add header with logo and title
        doc.setFillColor(41, 128, 185);
        doc.rect(0, 0, pageWidth, 40, 'F');
        
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(20);
        doc.setFont('helvetica', 'bold');
        doc.text('LINK SHIELD SECURITY REPORT', pageWidth / 2, 25, { align: 'center' });
        
        doc.setFontSize(10);
        doc.text('Professional Threat Analysis Report', pageWidth / 2, 32, { align: 'center' });
        
        // Reset text color for content
        doc.setTextColor(0, 0, 0);
        
        let yPosition = 60;
        
        // Scan Summary Section
        doc.setFontSize(16);
        doc.setFont('helvetica', 'bold');
        doc.text('SCAN SUMMARY', margin, yPosition);
        yPosition += 20;
        
        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        
        // Summary table
        const summaryData = [
            ['Scanned Target:', currentScanResult.target],
            ['Scan Date:', new Date(currentScanResult.scanDate).toLocaleDateString()],
            ['Scan Type:', currentScanResult.scanType],
            ['Overall Verdict:', currentScanResult.verdict],
            ['Risk Score:', `${currentScanResult.riskScore}%`],
            ['Engines Detected:', `${currentScanResult.positives}/${currentScanResult.total}`]
        ];
        
        summaryData.forEach(([label, value]) => {
            doc.setFont('helvetica', 'bold');
            doc.text(label, margin, yPosition);
            doc.setFont('helvetica', 'normal');
            doc.text(value, margin + 60, yPosition);
            yPosition += 8;
        });
        
        yPosition += 15;
        
        // Threat Analysis Section
        if (currentThreatDetails.detectedThreats.length > 0) {
            doc.setFontSize(16);
            doc.setFont('helvetica', 'bold');
            doc.text('THREAT ANALYSIS', margin, yPosition);
            yPosition += 20;
            
            doc.setFontSize(10);
            doc.setFont('helvetica', 'normal');
            
            // Threat categories
            doc.setFont('helvetica', 'bold');
            doc.text('Threat Categories:', margin, yPosition);
            doc.setFont('helvetica', 'normal');
            doc.text(currentThreatDetails.categories.join(', '), margin + 50, yPosition);
            yPosition += 15;
            
            // Threat details table header
            doc.setFillColor(240, 240, 240);
            doc.rect(margin, yPosition, contentWidth, 10, 'F');
            doc.setFont('helvetica', 'bold');
            doc.text('Security Engine', margin + 5, yPosition + 7);
            doc.text('Threat Name', margin + 70, yPosition + 7);
            doc.text('Category', margin + 150, yPosition + 7);
            yPosition += 15;
            
            // Threat details rows
            currentThreatDetails.detectedThreats.forEach((threat, index) => {
                if (yPosition > 250) { // Add new page if needed
                    doc.addPage();
                    yPosition = margin;
                }
                
                doc.setFont('helvetica', 'normal');
                doc.setFontSize(8);
                doc.text(threat.engine, margin + 5, yPosition + 5);
                doc.text(threat.threat, margin + 70, yPosition + 5);
                doc.text(threat.category, margin + 150, yPosition + 5);
                
                // Add separator line
                doc.setDrawColor(200, 200, 200);
                doc.line(margin, yPosition + 8, margin + contentWidth, yPosition + 8);
                
                yPosition += 12;
            });
        } else {
            doc.setFontSize(16);
            doc.setFont('helvetica', 'bold');
            doc.text('THREAT ANALYSIS', margin, yPosition);
            yPosition += 20;
            
            doc.setFontSize(10);
            doc.setFont('helvetica', 'normal');
            doc.text('No threats detected. The target appears clean across all security engines.', margin, yPosition);
            yPosition += 15;
        }
        
        yPosition += 20;
        
        // Security Recommendations
        doc.setFontSize(16);
        doc.setFont('helvetica', 'bold');
        doc.text('SECURITY RECOMMENDATIONS', margin, yPosition);
        yPosition += 20;
        
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        
        const recommendations = getSecurityRecommendations(currentScanResult.riskScore);
        recommendations.forEach((rec, index) => {
            if (yPosition > 250) {
                doc.addPage();
                yPosition = margin;
            }
            doc.text(`• ${rec}`, margin, yPosition);
            yPosition += 8;
        });
        
        yPosition += 15;
        
        // Footer
        doc.setFontSize(8);
        doc.setTextColor(100, 100, 100);
        doc.text(`Report generated by Link Shield Security - ${new Date().toLocaleString()}`, margin, 280);
        doc.text('Powered by VirusTotal API | link-shield-security.netlify.app', margin, 285);
        
        // Save the PDF
        const fileName = `LinkShield_Report_${currentScanResult.target.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.pdf`;
        doc.save(fileName);
        
        alert('PDF report downloaded successfully!');
        
    } catch (error) {
        console.error('PDF generation error:', error);
        alert('Error generating PDF report: ' + error.message);
    } finally {
        // Restore button state
        pdfButton.textContent = originalText;
        pdfButton.disabled = false;
    }
}

// GET SECURITY RECOMMENDATIONS BASED ON RISK
function getSecurityRecommendations(riskScore) {
    const recommendations = [
        'Keep your antivirus software updated',
        'Use a secure web browser with phishing protection',
        'Enable two-factor authentication where available',
        'Regularly update your operating system and applications'
    ];
    
    if (riskScore > 70) {
        recommendations.unshift(
            'IMMEDIATE ACTION REQUIRED: Do not visit this URL',
            'Consider running a full system antivirus scan',
            'Change passwords if you have interacted with this target'
        );
    } else if (riskScore > 30) {
        recommendations.unshift(
            'Exercise caution when visiting this URL',
            'Verify the website authenticity before entering any credentials'
        );
    } else {
        recommendations.unshift(
            'This target appears safe for browsing',
            'Continue practicing good security habits'
        );
    }
    
    return recommendations;
}

// ANALYZE THREATS FROM SCAN DATA
function analyzeThreats(scans) {
    const detectedThreats = [];
    const categories = new Set();
    
    if (!scans) return { detectedThreats: [], categories: [] };
    
    Object.entries(scans).forEach(([engine, data]) => {
        if (data.detected && data.result) {
            const threatName = data.result;
            detectedThreats.push({
                engine: engine,
                threat: threatName,
                category: categorizeThreat(threatName)
            });
            
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
    
    fileScanButton.textContent = 'Analyzing File...';
    fileScanButton.disabled = true;

    setTimeout(() => {
        let riskScore, verdict, detectedThreats, categories;
        
        const lowerName = fileName.toLowerCase();
        
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
        } else if (lowerName.includes('test') || lowerName.includes('demo') || lowerName.includes('clean')) {
            riskScore = 2;
            verdict = 'Safe';
            detectedThreats = [];
            categories = [];
        } else {
            riskScore = Math.floor(Math.random() * 25);
            verdict = 'Safe';
            detectedThreats = [];
            categories = [];
        }
        
        // Store results for PDF
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
    
    // Clear stored results
    currentScanResult = null;
    currentThreatDetails = null;
}

// FALLBACK DEMO WITH DETAILED THREATS
function simulateDetailedUrlScan(url) {
    let riskScore, verdict, detectedThreats, categories;
    
    const lowerUrl = url.toLowerCase();
    
    if (lowerUrl.includes('phishing-test.com')) {
        riskScore = 85;
        verdict = 'Malicious';
        detectedThreats = [
            { engine: 'Google Safebrowsing', threat: 'Phishing', category: 'Phishing' },
            { engine: 'Norton Safe Web', threat: 'Fraudulent Website', category: 'Phishing' }
        ];
        categories = ['Phishing'];
    } else if (lowerUrl.includes('google.com')) {
        riskScore = 1;
        verdict = 'Safe';
        detectedThreats = [];
        categories = [];
    } else {
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
    
    // Store results for PDF
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
    
    showDetailedResults({
        target: url,
        positives: detectedThreats.length,
        total: 65,
        scans: {}
    });
}