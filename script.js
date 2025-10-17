// ==========================================
// PhishGuard - JavaScript
// ==========================================

// ==========================================
// CONFIGURATION & CONSTANTS
// ==========================================
const SUSPICIOUS_TLDS = ['.tk', '.zip', '.ml', '.cf', '.ga', '.gq', '.review', '.work', '.party', '.top', '.win', '.download'];
const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'free', 'bank', 'secure', 'account', 'suspend', 'confirm', 'password', 'billing'];
const LOOKALIKE_DOMAINS = {
    'google': ['g00gle', 'goog1e', 'gooogle', 'go0gle'],
    'paypal': ['paypai', 'paypa1', 'paypall'],
    'facebook': ['faceb00k', 'facebok', 'facebo0k'],
    'amazon': ['amaz0n', 'amazom', 'arnazon'],
    'microsoft': ['micros0ft', 'microsft', 'mlcrosoft'],
    'apple': ['app1e', 'appl3', 'appie'],
    'netflix': ['netfl1x', 'netfllx', 'netf1ix']
};

// ==========================================
// STATE MANAGEMENT
// ==========================================
let currentUrl = '';
let scanHistory = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
let stats = JSON.parse(localStorage.getItem('phishguard_stats') || '{"total": 0, "phishing": 0, "today": 0, "lastDate": ""}');

// ==========================================
// INITIALIZATION
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    loadStats();
    loadHistory();
});

function initializeApp() {
    // Theme toggle
    document.getElementById('themeToggle').addEventListener('click', toggleTheme);
    
    // Analyze button
    document.getElementById('analyzeBtn').addEventListener('click', analyzeURL);
    
    // Enter key support
    document.getElementById('urlInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeURL();
    });

    // Report button
    document.getElementById('reportBtn').addEventListener('click', reportPhishing);

    // Clear history
    document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);

    // Check if it's a new day
    const today = new Date().toDateString();
    if (stats.lastDate !== today) {
        stats.today = 0;
        stats.lastDate = today;
        saveStats();
    }
}

// ==========================================
// THEME MANAGEMENT
// ==========================================
function toggleTheme() {
    const body = document.body;
    const themeIcon = document.getElementById('themeIcon');
    const currentTheme = body.getAttribute('data-theme');
    
    if (currentTheme === 'dark') {
        body.setAttribute('data-theme', 'light');
        themeIcon.textContent = '☀️';
        localStorage.setItem('phishguard_theme', 'light');
    } else {
        body.setAttribute('data-theme', 'dark');
        themeIcon.textContent = '🌙';
        localStorage.setItem('phishguard_theme', 'dark');
    }
}

// Load saved theme
const savedTheme = localStorage.getItem('phishguard_theme');
if (savedTheme === 'light') {
    document.body.setAttribute('data-theme', 'light');
    document.getElementById('themeIcon').textContent = '☀️';
}

// ==========================================
// STATS MANAGEMENT
// ==========================================
function loadStats() {
    document.getElementById('totalScans').textContent = stats.total;
    document.getElementById('phishingCaught').textContent = stats.phishing;
    document.getElementById('todaysCatches').textContent = stats.today;
}

function updateStats(isPhishing) {
    stats.total++;
    if (isPhishing) {
        stats.phishing++;
        stats.today++;
    }
    saveStats();
    loadStats();

    // Show celebration toast for catches
    if (isPhishing) {
        showToast('🎯 Great catch! You\'ve protected yourself from a potential phishing attempt!');
    }
}

function saveStats() {
    localStorage.setItem('phishguard_stats', JSON.stringify(stats));
}

// ==========================================
// URL ANALYSIS - MAIN FUNCTION
// ==========================================
async function analyzeURL() {
    const input = document.getElementById('urlInput').value.trim();
    
    if (!input) {
        showToast('⚠️ Please enter a URL to analyze');
        return;
    }

    // Validate and normalize URL
    currentUrl = normalizeURL(input);
    if (!currentUrl) {
        showToast('❌ Invalid URL format');
        return;
    }

    // Show loading state
    showLoading(true);
    document.getElementById('analyzeBtn').disabled = true;

    // Simulate realistic analysis time
    await sleep(1500);

    try {
        // Run all checks
        const checks = await runAllChecks(currentUrl);
        
        // Calculate threat score
        const threatScore = calculateThreatScore(checks);
        
        // Determine verdict
        const verdict = getVerdict(threatScore);
        
        // Display results
        displayResults(currentUrl, threatScore, verdict, checks);
        
        // Update stats
        updateStats(verdict.level === 'danger');
        
        // Add to history
        addToHistory(currentUrl, threatScore, verdict);
        
    } catch (error) {
        console.error('Analysis error:', error);
        showToast('❌ Error analyzing URL. Please try again.');
    } finally {
        showLoading(false);
        document.getElementById('analyzeBtn').disabled = false;
    }
}

// ==========================================
// URL VALIDATION & NORMALIZATION
// ==========================================
function normalizeURL(url) {
    try {
        // Add protocol if missing
        if (!url.match(/^https?:\/\//i)) {
            url = 'http://' + url;
        }
        
        const urlObj = new URL(url);
        return urlObj.href;
    } catch (e) {
        return null;
    }
}

// ==========================================
// PHISHING DETECTION CHECKS
// ==========================================
async function runAllChecks(url) {
    const urlObj = new URL(url);
    const checks = [];

    // Check 1: @ symbol in URL
    if (url.includes('@')) {
        checks.push({
            severity: 'high',
            icon: '🚫',
            title: 'Suspicious @ Symbol Detected',
            description: 'The URL contains an @ symbol, which can be used to hide the real destination.'
        });
    }

    // Check 2: IP address as domain
    if (isIPAddress(urlObj.hostname)) {
        checks.push({
            severity: 'high',
            icon: '🔢',
            title: 'IP Address Used as Domain',
            description: 'Legitimate websites rarely use IP addresses. This is a common phishing tactic.'
        });
    }

    // Check 3: Long URL
    if (url.length > 75) {
        checks.push({
            severity: 'medium',
            icon: '📏',
            title: 'Unusually Long URL',
            description: `URL is ${url.length} characters long. Phishing sites often use long URLs to hide suspicious elements.`
        });
    }

    // Check 4: Too many subdomains
    const subdomainCount = urlObj.hostname.split('.').length - 2;
    if (subdomainCount > 4) {
        checks.push({
            severity: 'medium',
            icon: '🔗',
            title: 'Excessive Subdomains',
            description: `Found ${subdomainCount} subdomains. Multiple subdomains can indicate phishing attempts.`
        });
    }

    // Check 5: Hyphens in domain
    if (urlObj.hostname.includes('-')) {
        checks.push({
            severity: 'medium',
            icon: '➖',
            title: 'Hyphens in Domain Name',
            description: 'Domain contains hyphens, which are often used to mimic legitimate domains.'
        });
    }

    // Check 6: Missing HTTPS
    if (urlObj.protocol === 'http:') {
        checks.push({
            severity: 'high',
            icon: '🔓',
            title: 'No HTTPS Encryption',
            description: 'The site doesn\'t use HTTPS. Never enter sensitive information on HTTP sites.'
        });
    }

    // Check 7: Suspicious TLDs
    const suspiciousTLD = SUSPICIOUS_TLDS.find(tld => urlObj.hostname.endsWith(tld));
    if (suspiciousTLD) {
        checks.push({
            severity: 'high',
            icon: '🌍',
            title: 'Suspicious Top-Level Domain',
            description: `The TLD "${suspiciousTLD}" is commonly used by phishing sites.`
        });
    }

    // Check 8: Suspicious keywords
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(keyword => 
        url.toLowerCase().includes(keyword)
    );
    if (foundKeywords.length > 0) {
        checks.push({
            severity: 'medium',
            icon: '🔑',
            title: 'Suspicious Keywords Detected',
            description: `Found keywords often used in phishing: ${foundKeywords.join(', ')}`
        });
    }

    // Check 9: Lookalike domains
    const lookalike = detectLookalike(urlObj.hostname);
    if (lookalike) {
        checks.push({
            severity: 'high',
            icon: '👁️',
            title: 'Lookalike Domain Detected',
            description: `This domain appears to mimic "${lookalike}". This is a common phishing technique.`
        });
    }

    // Check 10: Punycode domains
    if (urlObj.hostname.includes('xn--')) {
        checks.push({
            severity: 'high',
            icon: '🔤',
            title: 'Punycode Domain Detected',
            description: 'This URL uses punycode, which can hide non-Latin characters to create lookalike domains.'
        });
    }

    // Check 11: Redirect detection (simulated)
    // In a real implementation, this would make actual requests
    // For client-side only, we check for common redirect parameters
    const redirectParams = ['redirect', 'url', 'next', 'return', 'goto', 'link'];
    const hasRedirectParam = redirectParams.some(param => urlObj.searchParams.has(param));
    if (hasRedirectParam) {
        checks.push({
            severity: 'medium',
            icon: '↪️',
            title: 'Potential Redirect Detected',
            description: 'URL contains redirect parameters that could lead to a different destination.'
        });
    }

    // Check 12: Short domain name
    const domainParts = urlObj.hostname.split('.');
    const mainDomain = domainParts[domainParts.length - 2];
    if (mainDomain && mainDomain.length < 4) {
        checks.push({
            severity: 'low',
            icon: '📝',
            title: 'Very Short Domain Name',
            description: 'Extremely short domain names can be easier to typosquat or mimic.'
        });
    }

    // Additional check: Excessive dots
    if (url.split('.').length > 5) {
        checks.push({
            severity: 'low',
            icon: '•••',
            title: 'Excessive Dots in URL',
            description: 'URL contains many dots, which can be used to obfuscate the real domain.'
        });
    }

    return checks;
}

// ==========================================
// HELPER FUNCTIONS FOR CHECKS
// ==========================================
function isIPAddress(hostname) {
    // Check for IPv4
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(hostname)) return true;
    
    // Check for IPv6 (simplified)
    if (hostname.includes(':') && hostname.split(':').length > 2) return true;
    
    return false;
}

function detectLookalike(hostname) {
    const domain = hostname.toLowerCase().replace(/^www\./, '');
    
    for (const [legitimate, variants] of Object.entries(LOOKALIKE_DOMAINS)) {
        for (const variant of variants) {
            if (domain.includes(variant)) {
                return legitimate;
            }
        }
    }
    
    return null;
}

// ==========================================
// THREAT SCORING & VERDICT
// ==========================================
function calculateThreatScore(checks) {
    let score = 0;
    
    checks.forEach(check => {
        switch(check.severity) {
            case 'high': score += 3; break;
            case 'medium': score += 2; break;
            case 'low': score += 1; break;
        }
    });
    
    return Math.min(score, 10); // Cap at 10
}

function getVerdict(score) {
    if (score >= 7) {
        return {
            level: 'danger',
            icon: '🚨',
            text: 'High Risk - Likely Phishing',
            message: 'This URL shows multiple signs of phishing. Do not visit or enter any information.'
        };
    } else if (score >= 4) {
        return {
            level: 'suspicious',
            icon: '⚠️',
            text: 'Suspicious - Exercise Caution',
            message: 'This URL has some suspicious characteristics. Proceed with extreme caution.'
        };
    } else {
        return {
            level: 'safe',
            icon: '✅',
            text: 'Low Risk - Appears Safe',
            message: 'No major red flags detected, but always stay vigilant online.'
        };
    }
}

// ==========================================
// DISPLAY RESULTS
// ==========================================
function displayResults(url, score, verdict, checks) {
    const urlObj = new URL(url);
    
    // URL Preview
    document.getElementById('urlDomain').textContent = urlObj.hostname;
    const protocolEl = document.getElementById('urlProtocol');
    if (urlObj.protocol === 'https:') {
        protocolEl.textContent = '🔒 HTTPS';
        protocolEl.className = 'url-protocol secure';
    } else {
        protocolEl.textContent = '🔓 HTTP';
        protocolEl.className = 'url-protocol insecure';
    }

    // Try to load favicon
    const faviconEl = document.getElementById('favicon');
    faviconEl.textContent = '🌐';
    // Attempt to load real favicon
    const faviconImg = new Image();
    faviconImg.src = `https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=64`;
    faviconImg.onload = () => {
        faviconEl.innerHTML = `<img src="${faviconImg.src}" alt="favicon" style="width: 100%; height: 100%; border-radius: 6px;">`;
    };

    // Threat Score
    document.getElementById('scoreValue').textContent = score;
    const scoreFill = document.getElementById('scoreFill');
    scoreFill.style.width = (score * 10) + '%';
    scoreFill.textContent = `${score}/10`;
    scoreFill.className = 'score-fill ' + verdict.level;

    // Verdict
    const verdictEl = document.getElementById('verdict');
    verdictEl.className = 'verdict ' + verdict.level;
    document.getElementById('verdictIcon').textContent = verdict.icon;
    document.getElementById('verdictText').innerHTML = `
        <strong>${verdict.text}</strong><br>
        <span style="font-size: 0.7em; font-weight: normal;">${verdict.message}</span>
    `;

    // Show/hide report button
    const reportBtn = document.getElementById('reportBtn');
    if (verdict.level === 'danger' || verdict.level === 'suspicious') {
        reportBtn.style.display = 'inline-flex';
    } else {
        reportBtn.style.display = 'none';
    }

    // Warnings
    const warningsSection = document.getElementById('warningsSection');
    const warningList = document.getElementById('warningList');
    
    if (checks.length > 0) {
        warningsSection.style.display = 'block';
        warningList.innerHTML = checks.map((check, index) => `
            <div class="warning-item ${check.severity}" style="animation-delay: ${index * 0.1}s">
                <div class="warning-icon">${check.icon}</div>
                <div class="warning-content">
                    <div class="warning-title">${check.title}</div>
                    <div class="warning-description">${check.description}</div>
                </div>
            </div>
        `).join('');
    } else {
        warningsSection.style.display = 'none';
    }

    // Show results
    document.getElementById('results').classList.add('active');
}

// ==========================================
// HISTORY MANAGEMENT
// ==========================================
function addToHistory(url, score, verdict) {
    const historyItem = {
        url,
        score,
        verdict: verdict.level,
        timestamp: new Date().toISOString()
    };

    // Add to beginning of array
    scanHistory.unshift(historyItem);
    
    // Keep only last 5
    scanHistory = scanHistory.slice(0, 5);
    
    // Save to localStorage
    localStorage.setItem('phishguard_history', JSON.stringify(scanHistory));
    
    // Reload history display
    loadHistory();
}

function loadHistory() {
    const historyList = document.getElementById('historyList');
    const clearBtn = document.getElementById('clearHistoryBtn');
    
    if (scanHistory.length === 0) {
        historyList.innerHTML = '<div class="empty-history">No scans yet. Try analyzing a URL!</div>';
        clearBtn.style.display = 'none';
        return;
    }

    clearBtn.style.display = 'block';
    
    historyList.innerHTML = scanHistory.map(item => {
        const date = new Date(item.timestamp);
        const timeAgo = getTimeAgo(date);
        const urlObj = new URL(item.url);
        
        const icons = {
            safe: '✅',
            suspicious: '⚠️',
            danger: '🚨'
        };

        return `
            <div class="history-item" onclick="loadHistoryItem('${item.url}')">
                <div class="history-badge ${item.verdict}">
                    ${icons[item.verdict]}
                </div>
                <div class="history-details">
                    <div class="history-url" title="${item.url}">${urlObj.hostname}</div>
                    <div class="history-time">${timeAgo}</div>
                </div>
                <div class="history-score" style="color: var(--${item.verdict === 'safe' ? 'success' : item.verdict === 'suspicious' ? 'warning' : 'danger'})">${item.score}</div>
            </div>
        `;
    }).join('');
}

function loadHistoryItem(url) {
    document.getElementById('urlInput').value = url;
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function clearHistory() {
    if (confirm('Are you sure you want to clear your scan history?')) {
        scanHistory = [];
        localStorage.setItem('phishguard_history', JSON.stringify(scanHistory));
        loadHistory();
        showToast('🗑️ History cleared successfully');
    }
}

function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + ' minutes ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + ' hours ago';
    return Math.floor(seconds / 86400) + ' days ago';
}

// ==========================================
// REPORT PHISHING
// ==========================================
function reportPhishing() {
    const reportedUrls = JSON.parse(localStorage.getItem('phishguard_reported') || '[]');
    
    if (!reportedUrls.includes(currentUrl)) {
        reportedUrls.push({
            url: currentUrl,
            timestamp: new Date().toISOString()
        });
        localStorage.setItem('phishguard_reported', JSON.stringify(reportedUrls));
        showToast('✅ Thank you! This URL has been flagged for review.');
    } else {
        showToast('ℹ️ This URL has already been reported.');
    }
}

// ==========================================
// UI UTILITIES
// ==========================================
function showLoading(show) {
    document.getElementById('loading').classList.toggle('active', show);
    document.getElementById('results').classList.toggle('active', !show);
}

function showToast(message) {
    // Remove existing toast
    const existingToast = document.querySelector('.toast');
    if (existingToast) existingToast.remove();

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
        <div class="toast-content">
            <div class="toast-icon">${message.charAt(0)}</div>
            <div class="toast-message">${message.substring(2)}</div>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideInRight 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ==========================================
// EXAMPLE URLS FOR TESTING
// ==========================================
// Safe: https://www.google.com
// Suspicious: http://login-verify-account-paypal.com-secure.tk
// Phishing: http://192.168.1.1/verify-account@bank.com/login.php?redirect=http://evil.com

