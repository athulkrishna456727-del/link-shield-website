// Configuration
const CONFIG = {
    VIRUSTOTAL_API_KEY: 'deeec0956d89958547db93b5168256a89d1cc99ef2ac75e39d74be01b2175d86RE', // You'll get this from VirusTotal
    API_ENDPOINTS: {
        URL_SCAN: 'https://www.virustotal.com/vtapi/v2/url/report',
        FILE_SCAN: 'https://www.virustotal.com/vtapi/v2/file/report'
    }
};

// User session management
let currentUser = null;
let userScans = JSON.parse(localStorage.getItem('userScans')) || [];

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    checkLoginStatus();
    setupEventListeners();
    loadScanHistory();
}

function setupEventListeners() {
    // Scanner functionality
    const scanButton = document.querySelector('.scan-button');
    const urlInput = document.querySelector('.url-input');
    const fileScanButton = document.querySelector('.file-scan');
    const fileInput = document.querySelector('#file-input');
    
    // Tab switching
    document.querySelectorAll('.tab-button').forEach(button => {
        button.addEventListener('click', function() {
            switchTab(this.getAttribute('data-tab'));
        });
    });

    // URL Scanning
    scanButton.addEventListener('click', handleUrlScan);
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') handleUrlScan();
    });

    // File Scanning
    fileScanButton.addEventListener('click', handleFileScan);
    fileInput.addEventListener('change', handleFileSelect);

    // Authentication
    document.querySelector('.nav-button').addEventListener('click', showAuthModal);
    
    // Results actions
    document.querySelector('.new-scan-button').addEventListener('click', resetScanner);
    document.querySelector('.report-button').addEventListener('click', reportFalsePositive);
    document.querySelector('.pdf-button').addEventListener('click', downloadPDFReport);

    // Navigation
    setupSmoothScroll();
    setupBusinessButtons();
}

// Real VirusTotal API Integration
async function handleUrlScan() {
    const urlInput = document.querySelector('.url-input');
    const url = urlInput.value.trim();
    const scanButton = document.querySelector('.scan-button');

    if (!url) {
        showAlert('Please enter a URL to scan');
        return;
    }

    if (!isValidUrl(url)) {
        showAlert('Please enter a valid URL (e.g., https://example.com)');
        return;
    }

    // Show loading state
    scanButton.textContent = 'Scanning...';
    scanButton.disabled = true;

    try {
        const result = await scanUrlWithVirusTotal(url);
        showResults(result);
        saveToScanHistory(result);
    } catch (error) {
        showAlert('Scan failed: ' + error.message);
    } finally {
        scanButton.textContent = 'Scan Now';
        scanButton.disabled = false;
    }
}

async function scanUrlWithVirusTotal(url) {
    const apiKey = CONFIG.VIRUSTOTAL_API_KEY;
    
    const response = await fetch(`${CONFIG.API_ENDPOINTS.URL_SCAN}?apikey=${apiKey}&resource=${encodeURIComponent(url)}`);
    
    if (!response.ok) {
        throw new Error('API request failed');
    }

    const data = await response.json();
    
    return {
        target: url,
        type: 'url',
        positives: data.positives || 0,
        total: data.total || 0,
        scanDate: data.scan_date || new Date().toISOString(),
        scans: data.scans || {},
        permalink: data.permalink || ''
    };
}

async function handleFileScan() {
    const fileInput = document.querySelector('#file-input');
    const fileScanButton = document.querySelector('.file-scan');

    if (!fileInput.files.length) {
        showAlert('Please select a file to scan');
        return;
    }

    const file = fileInput.files[0];
    const allowedTypes = ['application/pdf', 'application/vnd.android.package-archive', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    
    if (!allowedTypes.includes(file.type) && !file.name.match(/\.(apk|pdf|doc|docx)$/i)) {
        showAlert('Please select APK, PDF, DOC, or DOCX files only');
        return;
    }

    // Show loading state
    fileScanButton.textContent = 'Uploading & Scanning...';
    fileScanButton.disabled = true;

    try {
        // Note: Actual file upload requires backend for security
        showAlert('File scanning requires backend setup. Currently demo mode.');
        simulateFileScan(file.name);
    } catch (error) {
        showAlert('Scan failed: ' + error.message);
    } finally {
        fileScanButton.textContent = 'Scan File';
        fileScanButton.disabled = false;
    }
}

// Authentication System
function showAuthModal() {
    const modalHTML = `
        <div class="auth-modal">
            <div class="auth-content">
                <h3>Welcome to Link Shield</h3>
                <div class="auth-tabs">
                    <button class="auth-tab active" data-tab="login">Login</button>
                    <button class="auth-tab" data-tab="signup">Sign Up</button>
                </div>
                <form class="auth-form" id="login-form">
                    <input type="email" placeholder="Email" required>
                    <input type="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                <form class="auth-form" id="signup-form" style="display: none;">
                    <input type="text" placeholder="Full Name" required>
                    <input type="email" placeholder="Email" required>
                    <input type="password" placeholder="Password" required>
                    <button type="submit">Create Account</button>
                </form>
                <button class="close-auth">×</button>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    setupAuthModal();
}

function setupAuthModal() {
    const modal = document.querySelector('.auth-modal');
    const tabs = document.querySelectorAll('.auth-tab');
    const forms = document.querySelectorAll('.auth-form');
    const closeBtn = document.querySelector('.close-auth');

    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            
            tabs.forEach(t => t.classList.remove('active'));
            forms.forEach(f => f.style.display = 'none');
            
            this.classList.add('active');
            document.getElementById(`${tabName}-form`).style.display = 'block';
        });
    });

    document.getElementById('login-form').addEventListener('submit', function(e) {
        e.preventDefault();
        handleLogin(this);
    });

    document.getElementById('signup-form').addEventListener('submit', function(e) {
        e.preventDefault();
        handleSignup(this);
    });

    closeBtn.addEventListener('click', () => {
        modal.remove();
    });

    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
    });
}

function handleLogin(form) {
    const formData = new FormData(form);
    const email = formData.get('email');
    const password = formData.get('password');

    // Simple demo login (replace with real auth later)
    if (email && password) {
        currentUser = {
            email: email,
            name: email.split('@')[0],
            joined: new Date().toISOString()
        };
        
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        updateUIForUser();
        document.querySelector('.auth-modal').remove();
        showAlert('Login successful!');
    }
}

function handleSignup(form) {
    const formData = new FormData(form);
    const name = formData.get('name');
    const email = formData.get('email');
    const password = formData.get('password');

    if (name && email && password) {
        currentUser = {
            name: name,
            email: email,
            joined: new Date().toISOString()
        };
        
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        updateUIForUser();
        document.querySelector('.auth-modal').remove();
        showAlert('Account created successfully!');
    }
}

function checkLoginStatus() {
    const savedUser = localStorage.getItem('currentUser');
    if (savedUser) {
        currentUser = JSON.parse(savedUser);
        updateUIForUser();
    }
}

function updateUIForUser() {
    const navButton = document.querySelector('.nav-button');
    if (currentUser) {
        navButton.textContent = `Welcome, ${currentUser.name}`;
        navButton.style.background = '#48bb78'; // Green color
    }
}

// Results Display
function showResults(result) {
    const riskScore = calculateRiskScore(result.positives, result.total);
    const verdict = getVerdict(riskScore);
    
    document.getElementById('result-url').textContent = result.target;
    document.getElementById('risk-score').textContent = `${riskScore}/100`;
    document.getElementById('risk-score').className = `score-value ${verdict.toLowerCase()}`;
    document.getElementById('verdict-text').textContent = verdict;
    document.getElementById('verdict-text').className = `verdict-${verdict.toLowerCase()}`;
    
    document.getElementById('malware-detected').textContent = result.positives > 0 ? 'Yes' : 'No';
    document.getElementById('phishing-risk').textContent = result.positives > 5 ? 'High' : result.positives > 0 ? 'Medium' : 'Low';
    document.getElementById('suspicious-activity').textContent = result.positives > 0 ? `${result.positives} engines detected threats` : 'None';

    document.querySelector('.results-section').style.display = 'block';
    document.querySelector('.results-section').scrollIntoView({ behavior: 'smooth' });
}

function calculateRiskScore(positives, total) {
    if (total === 0) return 0;
    return Math.round((positives / total) * 100);
}

function getVerdict(riskScore) {
    if (riskScore === 0) return 'Safe';
    if (riskScore < 30) return 'Low Risk';
    if (riskScore < 70) return 'Suspicious';
    return 'Malicious';
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

function showAlert(message) {
    alert(message); // Replace with better notification system later
}

function switchTab(tabName) {
    document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
    
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`${tabName}-tab`).classList.add('active');
}

function resetScanner() {
    document.querySelector('.results-section').style.display = 'none';
    document.querySelector('.url-input').value = '';
    document.querySelector('#file-input').value = '';
    document.querySelector('.file-label span:last-child').textContent = 'Choose APK, PDF, or Document';
    switchTab('url');
}

function saveToScanHistory(scanResult) {
    if (currentUser) {
        userScans.unshift({
            ...scanResult,
            id: Date.now(),
            timestamp: new Date().toISOString()
        });
        
        // Keep only last 50 scans
        userScans = userScans.slice(0, 50);
        localStorage.setItem('userScans', JSON.stringify(userScans));
    }
}

function loadScanHistory() {
    // Load and display user's scan history
    console.log('Loaded scans:', userScans.length);
}

function reportFalsePositive() {
    showAlert('False positive reported. Our team will review this.');
}

function downloadPDFReport() {
    showAlert('PDF report download will be available in the next update.');
}

function setupSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
}

function setupBusinessButtons() {
    document.querySelectorAll('.cta-button').forEach(button => {
        button.addEventListener('click', function() {
            showAlert('Business features coming soon!');
        });
    });
}