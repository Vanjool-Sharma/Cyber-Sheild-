// Core configuration
const CONFIG = {
    API_KEY: '28339d8b908a7ffb4cb1d562b24a7ff742d21d194ab99ad29e8378a5e64977b7',
    VT_API_URL: 'https://www.virustotal.com/api/v3/urls/',
    BADGE_STATES: {
        INIT: { text: '⚡', color: '#6B7280', title: 'Initializing check...' },
        SCANNING: { text: '⌛', color: '#FCD34D', title: 'Scanning website...' },
        SAFE: { text: '✓', color: '#10B981', title: 'Website is safe' },
        UNSAFE: { text: '!', color: '#EF4444', title: 'Website is unsafe' },
        ERROR: { text: '×', color: '#6B7280', title: 'Error checking website' },
        QUEUED: { text: '⟳', color: '#60A5FA', title: 'Waiting to scan...' }
    },
    SCAN_TIMEOUT: 120000, // 2 minutes
    MAX_RETRIES: 3,
    RETRY_DELAY: 2000, // 2 seconds
    CACHE_DURATION: 3600000, // 1 hour cache
    DEBOUNCE_DELAY: 1000 // 1 second debounce
};

// Cache for scan results
const resultCache = new Map();

// Store for custom exceptions
let customExceptions = {};

// Queue for scanning with timestamps
let scanningQueue = new Map();

// Debounce timer
let debounceTimer = null;

// Initialize extension
async function initializeExtension() {
    try {
        // Load exceptions from storage
        const result = await chrome.storage.local.get(['exceptions', 'scanCache']);
        if (result.exceptions) {
            customExceptions = result.exceptions;
        }
        if (result.scanCache) {
            // Load cached results that haven't expired
            const now = Date.now();
            Object.entries(result.scanCache).forEach(([url, data]) => {
                if (now - data.timestamp < CONFIG.CACHE_DURATION) {
                    resultCache.set(url, data);
                }
            });
        }

        // Clear any existing badges
        const tabs = await chrome.tabs.query({});
        tabs.forEach(tab => {
            if (tab.url && tab.url.startsWith('http')) {
                updateBadge(tab.id, 'INIT');
            }
        });
    } catch (error) {
        console.error('Error initializing extension:', error);
    }
}

// Save cache to storage
async function saveCache() {
    try {
        const cacheObject = {};
        resultCache.forEach((value, key) => {
            cacheObject[key] = value;
        });
        await chrome.storage.local.set({ scanCache: cacheObject });
    } catch (error) {
        console.error('Error saving cache:', error);
    }
}

// Clean expired cache entries
function cleanCache() {
    const now = Date.now();
    for (const [url, data] of resultCache.entries()) {
        if (now - data.timestamp > CONFIG.CACHE_DURATION) {
            resultCache.delete(url);
        }
    }
    saveCache();
}

// Handle messages from popup and warning page
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    switch (request.action) {
        case 'checkException':
            sendResponse({ isExcepted: isUrlExcepted(request.url) });
            break;
        case 'addException':
            addException(request.url);
            sendResponse({ success: true });
            break;
        case 'removeException':
            removeException(request.url);
            sendResponse({ success: true });
            break;
        case 'forceCheck':
            // Clear cache for forced check
            if (request.url) {
                resultCache.delete(request.url);
            }
            checkWebsiteSecurity({ 
                url: request.url, 
                tabId: sender.tab?.id, 
                force: true 
            });
            sendResponse({ success: true });
            break;
        case 'getCachedResult':
            const cachedResult = resultCache.get(request.url);
            sendResponse({ 
                result: cachedResult && 
                        Date.now() - cachedResult.timestamp < CONFIG.CACHE_DURATION ? 
                        cachedResult.data : null 
            });
            break;
    }
    return true;
});

// Extract domain from URL
function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch (e) {
        console.error('Invalid URL:', e);
        return null;
    }
}

// Check if URL is in exceptions
function isUrlExcepted(url) {
    const domain = extractDomain(url);
    if (!domain) return false;

    return Object.keys(customExceptions).some(pattern => {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(domain);
    });
}

// Add URL to exceptions
function addException(url) {
    const domain = extractDomain(url);
    if (!domain) return;

    customExceptions[domain] = true;
    chrome.storage.local.set({ exceptions: customExceptions });
    
    // Update badge for all tabs with this domain
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
            if (tab.url && tab.url.includes(domain)) {
                updateBadge(tab.id, 'SAFE');
            }
        });
    });
}

// Remove URL from exceptions
function removeException(url) {
    const domain = extractDomain(url);
    if (!domain) return;

    delete customExceptions[domain];
    chrome.storage.local.set({ exceptions: customExceptions });
    
    // Recheck all tabs with this domain
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
            if (tab.url && tab.url.includes(domain)) {
                checkWebsiteSecurity({ 
                    url: tab.url, 
                    tabId: tab.id, 
                    force: true 
                });
            }
        });
    });
}

// Update badge with improved indication
function updateBadge(tabId, state) {
    if (!tabId) return;
    
    const badgeState = CONFIG.BADGE_STATES[state];
    if (badgeState) {
        chrome.action.setBadgeText({ text: badgeState.text, tabId });
        chrome.action.setBadgeBackgroundColor({ color: badgeState.color, tabId });
        chrome.action.setTitle({ title: badgeState.title, tabId });
    }
}

// Submit URL for scanning with rate limiting
async function submitUrlForScanning(url) {
    const formData = new FormData();
    formData.append('url', url);
    
    try {
        const response = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                'x-apikey': CONFIG.API_KEY
            },
            body: formData
        });

        if (!response.ok) {
            if (response.status === 429) { // Rate limit
                await new Promise(resolve => setTimeout(resolve, 60000)); // Wait 1 minute
                return submitUrlForScanning(url);
            }
            throw new Error('Failed to submit URL for scanning');
        }

        return response.json();
    } catch (error) {
        console.error('Error submitting URL:', error);
        throw error;
    }
}

// Scan URL using VirusTotal API with retries and caching
async function scanUrl(url) {
    // Check cache first
    const cachedResult = resultCache.get(url);
    if (cachedResult && Date.now() - cachedResult.timestamp < CONFIG.CACHE_DURATION) {
        return cachedResult.data;
    }

        const urlId = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    try {
        const response = await fetch(`${CONFIG.VT_API_URL}${urlId}`, {
            method: 'GET',
            headers: {
                'x-apikey': CONFIG.API_KEY
            }
        });

        if (!response.ok) {
            if (response.status === 404) {
                await submitUrlForScanning(url);
                throw new Error('URL queued for scanning');
            }
            if (response.status === 429) { // Rate limit
                await new Promise(resolve => setTimeout(resolve, 60000)); // Wait 1 minute
                return scanUrl(url);
            }
            throw new Error('API request failed');
        }

        const data = await response.json();
        const result = data.data.attributes.last_analysis_stats;

        // Cache the result
        resultCache.set(url, {
            timestamp: Date.now(),
            data: result
        });
        saveCache();

        return result;
    } catch (error) {
        throw error;
    }
}

// Debounced check function
function debouncedCheck(details) {
    if (debounceTimer) {
        clearTimeout(debounceTimer);
    }
    debounceTimer = setTimeout(() => {
        checkWebsiteSecurity(details);
    }, CONFIG.DEBOUNCE_DELAY);
}

// Check website security with improved handling
async function checkWebsiteSecurity(details) {
    const { url, tabId, force = false } = details;

    // Skip invalid URLs or browser UI pages
    if (!url || !tabId || !url.startsWith('http')) return;
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

    // Check if URL is already being scanned
    const queuedTime = scanningQueue.get(url);
    if (!force && queuedTime && (Date.now() - queuedTime) < CONFIG.SCAN_TIMEOUT) {
        updateBadge(tabId, 'QUEUED');
        return;
    }

    try {
        // Add URL to scanning queue
        scanningQueue.set(url, Date.now());
        updateBadge(tabId, 'SCANNING');

        // Check exceptions first
        if (isUrlExcepted(url)) {
            updateBadge(tabId, 'SAFE');
            return;
        }

        // Scan the URL
        const stats = await scanUrl(url);
        const total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
        const maliciousPercentage = ((stats.malicious + stats.suspicious) / total) * 100;

        if (maliciousPercentage > 0) {
        // Show notification for unsafe sites
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'images/icon128.png',
                title: 'Security Warning',
                message: `Blocked access to ${new URL(url).hostname} - ${stats.malicious} security threats detected`
            });

            updateBadge(tabId, 'UNSAFE');
            chrome.tabs.update(tabId, {
                url: chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&detections=${stats.malicious}&category=Malicious Website`)
            });
        } else {
            updateBadge(tabId, 'SAFE');
        }
    } catch (error) {
        console.error('Error checking website security:', error);
        updateBadge(tabId, 'ERROR');
        
        if (!error.message.includes('queued for scanning')) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'images/icon128.png',
                title: 'Security Check Error',
                message: `Unable to check security for ${new URL(url).hostname}. Please try again later.`
            });
        }
    } finally {
        // Remove URL from scanning queue after timeout
        setTimeout(() => {
            scanningQueue.delete(url);
        }, CONFIG.SCAN_TIMEOUT);
    }
}

// Listen for web navigation
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) { // Only check main frame
        debouncedCheck({ url: details.url, tabId: details.tabId });
    }
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        debouncedCheck({ url: changeInfo.url, tabId });
    }
});

// Clean cache periodically
setInterval(cleanCache, CONFIG.CACHE_DURATION);

// Initialize extension
initializeExtension();

