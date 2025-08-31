// Core configuration
const CONFIG = {
    API_KEY: '28339d8b908a7ffb4cb1d562b24a7ff742d21d194ab99ad29e8378a5e64977b7',
    VT_API_URL: 'https://www.virustotal.com/api/v3/urls/',
    THEMES: {
        LIGHT: 'light',
        DARK: 'dark'
    },
    AI_ASSISTANT_URL: 'https://v0-cybershield-eefpbf.vercel.app/'
};

// Initialize the extension
function initializeExtension() {
    setupThemeHandler();
    setupEventListeners();
    setupTabHandlers();
    setupFileUpload();
    setupAIAssistantButton();
    // Set initial state
    updateProgress(0, 'Ready to scan');
}

// Theme handling
function setupThemeHandler() {
    const themeSwitch = document.getElementById('theme-switch');
    const savedTheme = localStorage.getItem('theme');
    
    if (savedTheme) {
        document.body.setAttribute('data-theme', savedTheme);
        themeSwitch.checked = savedTheme === CONFIG.THEMES.DARK;
    }
    
    themeSwitch.addEventListener('change', function() {
        const newTheme = this.checked ? CONFIG.THEMES.DARK : CONFIG.THEMES.LIGHT;
        document.body.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    });
}

// Event listeners setup
function setupEventListeners() {
    chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
        const currentTab = tabs[0];
        if (currentTab && currentTab.url) {
            const urlInfo = document.getElementById('currentUrl');
            displayUrlInfo(currentTab.url, urlInfo);
            await checkUrl(currentTab.url);
            addExceptionButtons(currentTab.url);
        }
    });
}

// URL display handling
function displayUrlInfo(url, element) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        const fullUrl = url.length > 50 ? url.substring(0, 47) + '...' : url;
        
        element.innerHTML = `
            <div class="url-info">
                <div class="url-icon">&#127760;</div>
                <div class="url-details">
                    <div class="url-domain" title="${domain}">${domain}</div>
                    <div class="url-full" title="${url}">${fullUrl}</div>
                </div>
            </div>
        `;
    } catch (e) {
        element.innerHTML = `
            <div class="url-info">
                <div class="url-icon">&#9888;</div>
                <div class="url-details">
                    <div class="url-domain">Invalid URL</div>
                    <div class="url-full">Unable to parse the URL</div>
                </div>
            </div>
        `;
    }
}

// Update progress
function updateProgress(progress, message) {
    const progressBar = document.getElementById('loading-bar-progress');
    const loadingText = document.getElementById('loading-text');
    
    if (progressBar && loadingText) {
        progressBar.style.width = `${progress}%`;
        loadingText.textContent = message;
    }
}

// URL scanning
async function checkUrl(url) {
    const results = document.getElementById('results');
    results.innerHTML = '';
    updateProgress(50, 'Checking URL...');

    try {
        // Check if URL is in exceptions
        const isExcepted = await checkIfExcepted(url);
        
        if (isExcepted) {
            updateProgress(100, 'URL is in exceptions');
            showExceptedResults();
            return;
        }

        // Proceed with normal scan
        const response = await scanUrl(url);
        updateProgress(100, 'Scan complete');
        showResults(response);
    } catch (error) {
        updateProgress(0, 'Error: ' + error.message);
    }
}

// Scan URL using VirusTotal API
async function scanUrl(url) {
    const urlId = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const response = await fetch(`${CONFIG.VT_API_URL}${urlId}`, {
        method: 'GET',
        headers: {
            'x-apikey': CONFIG.API_KEY
        }
    });

    if (!response.ok) {
        throw new Error('Network response was not ok');
    }

    const data = await response.json();
    return data.data.attributes.last_analysis_stats;
}

// Show results
function showResults(stats) {
    const resultsDiv = document.getElementById('results');
    const total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
    const safePercentage = Math.round((stats.harmless / total) * 100);
    
    // More aggressive threat detection
    const hasThreats = stats.malicious > 0 || stats.suspicious > 0;
    // Consider undetected as potential risk if there are any suspicious/malicious findings
    const undetectedRiskPercentage = hasThreats ? Math.round((stats.undetected / total) * 25) : 0; // Count 25% of undetected as risk when threats found
    const riskPercentage = Math.round(((stats.malicious * 2 + stats.suspicious + undetectedRiskPercentage) / total) * 100); // Double weight for malicious
    
    // Aggressive threat level determination
    let threatLevel;
    let statusMessage;
    
    if (stats.malicious > 0) {
        threatLevel = 'danger';
        statusMessage = 'High Risk - Blocked';
    } else if (stats.suspicious > 0) {
        threatLevel = 'danger';
        statusMessage = 'Suspicious - Blocked';
    } else if (riskPercentage > 10) { // Lower threshold for unknown risks
        threatLevel = 'warning';
        statusMessage = 'Potentially Unsafe';
    } else {
        threatLevel = 'safe';
        statusMessage = 'Safe';
    }

    resultsDiv.innerHTML = `
        <div class="results-container">
            <div class="circular-progress ${threatLevel}-progress">
                <div class="progress-value">${riskPercentage}%</div>
            </div>
            <div class="progress-label">${statusMessage}</div>
        </div>

        <div class="results-details">
            ${stats.malicious > 0 ? `
            <div class="detail-item danger">
                <div class="detail-icon">
                    <img src="images/danger.png" alt="Malicious" class="status-icon">
                </div>
                <div class="detail-info">
                    <div class="detail-title">Critical Risk</div>
                    <div class="detail-count">${stats.malicious} security engines detected threats</div>
                </div>
            </div>` : ''}

            ${stats.suspicious > 0 ? `
            <div class="detail-item warning">
                <div class="detail-icon">
                    <img src="images/warning.png" alt="Suspicious" class="status-icon">
                </div>
                <div class="detail-info">
                    <div class="detail-title">Suspicious Activity</div>
                    <div class="detail-count">${stats.suspicious} security engines reported suspicious behavior</div>
                </div>
            </div>` : ''}

            <div class="detail-item ${stats.harmless > 0 ? 'safe' : 'neutral'}">
                <div class="detail-icon">
                    <img src="images/check.png" alt="Clean" class="status-icon">
                </div>
                <div class="detail-info">
                    <div class="detail-title">Verified Safe</div>
                    <div class="detail-count">${stats.harmless} security engines</div>
                </div>
            </div>

            <div class="detail-item neutral">
                <div class="detail-icon">
                    <img src="images/globe.png" alt="Undetected" class="status-icon">
                </div>
                <div class="detail-info">
                    <div class="detail-title">Risk Analysis</div>
                    <div class="detail-count">
                        Risk Score: ${riskPercentage}% | 
                        ${hasThreats ? 'Blocking Recommended' : 'No Known Threats'}
                    </div>
                </div>
            </div>
        </div>

        ${hasThreats ? `
        <div class="warning-banner">
            <div class="warning-icon">⚠️</div>
            <div class="warning-text">
                This website has been flagged as potentially dangerous. 
                Access is blocked for your safety.
            </div>
        </div>
        ` : ''}`;

    // Set progress for main progress bar
    const mainProgress = resultsDiv.querySelector('.circular-progress');
    mainProgress.style.setProperty('--progress', `${riskPercentage}%`);
}

// Check if URL is in exceptions
async function checkIfExcepted(url) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'checkException', url }, (response) => {
            resolve(response.isExcepted);
        });
    });
}

// Add current URL to exceptions
async function addToExceptions(url) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'addException', url }, (response) => {
            resolve(response.success);
        });
    });
}

// Remove current URL from exceptions
async function removeFromExceptions(url) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'removeException', url }, (response) => {
            resolve(response.success);
        });
    });
}

// Show passing results for excepted website
function showExceptedResults() {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `
        <div class="results-container">
            <div class="circular-progress safe-progress">
                <div class="progress-value">100%</div>
            </div>
            <div class="progress-label">Safe (Excepted)</div>
        </div>

        <div class="results-details">
            <div class="detail-item safe">
                <div class="detail-icon">
                    <img src="images/check.png" alt="Clean" class="status-icon">
                </div>
                <div class="detail-info">
                    <div class="detail-title">Clean (Excepted Website)</div>
                    <div class="detail-count">Custom exception</div>
                </div>
            </div>
        </div>`;

    // Set progress for main progress bar
    const mainProgress = resultsDiv.querySelector('.circular-progress');
    mainProgress.style.setProperty('--progress', '100%');
}

// Add exception handling buttons to results
function addExceptionButtons(url) {
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'action-buttons';

    const addButton = document.createElement('button');
    addButton.className = 'action-button add-exception';
    addButton.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M8 3.33334V12.6667" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            <path d="M12.6667 8L3.33333 8" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
        Add to Exceptions
    `;
    addButton.onclick = async () => {
        if (await addToExceptions(url)) {
            checkUrl(url);
        }
    };

    const removeButton = document.createElement('button');
    removeButton.className = 'action-button remove-exception';
    removeButton.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M12.6667 8L3.33333 8" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
        Remove from Exceptions
    `;
    removeButton.onclick = async () => {
        if (await removeFromExceptions(url)) {
            checkUrl(url);
        }
    };

    actionsDiv.appendChild(addButton);
    actionsDiv.appendChild(removeButton);

    const resultsContainer = document.querySelector('.results-container');
    if (resultsContainer) {
        resultsContainer.appendChild(actionsDiv);
    }
}

// Setup AI Assistant button
function setupAIAssistantButton() {
    const aiAssistantButton = document.getElementById('ai-assistant-button');
    const aiAssistantContainer = document.getElementById('ai-assistant-container');
    const aiAssistantIframe = document.getElementById('ai-assistant-iframe');
    const backToScanner = document.getElementById('back-to-scanner');
    const buttonText = document.getElementById('ai-assistant-button-text');
    const mainContent = document.querySelector('.main-content');
    let isAssistantOpen = false;

    // Set the iframe source immediately to start loading
    if (aiAssistantIframe) {
        aiAssistantIframe.src = CONFIG.AI_ASSISTANT_URL;
    }

    function toggleAIAssistant() {
        isAssistantOpen = !isAssistantOpen;
        
        if (isAssistantOpen) {
            // Hide the main scanning interface
            if (mainContent) {
                mainContent.style.display = 'none';
            }
            
            // Show the AI Assistant container
            aiAssistantContainer.style.display = 'block';
            buttonText.textContent = 'Close AI Assistant';
            
            // Set expanded size for AI Assistant
            document.body.style.width = '400px';
            document.body.style.height = '600px';
        } else {
            closeAIAssistant();
        }
    }

    function closeAIAssistant() {
        isAssistantOpen = false;
        
        // Show the main scanning interface
        if (mainContent) {
            mainContent.style.display = 'block';
        }
        
        // Hide the AI Assistant container
        aiAssistantContainer.style.display = 'none';
        buttonText.textContent = 'Open AI Assistant';
        
        // Reset to original compact size
        document.body.style.width = '260px';
        document.body.style.height = '280px';
    }

    // Handle iframe events
    if (aiAssistantIframe) {
        aiAssistantIframe.addEventListener('load', () => {
            console.log('AI Assistant iframe loaded');
        });

        aiAssistantIframe.addEventListener('error', (e) => {
            console.error('Error loading AI Assistant iframe:', e);
            aiAssistantContainer.innerHTML = `
                <div class="p-3 text-center text-sm">
                    Failed to load AI Assistant. Please try again.
                </div>
            `;
        });
    }

    aiAssistantButton.addEventListener('click', toggleAIAssistant);
    backToScanner.addEventListener('click', closeAIAssistant);
}

// Tab handling
function setupTabHandlers() {
    const urlTab = document.getElementById('urlTab');
    const fileTab = document.getElementById('fileTab');
    const urlContent = document.getElementById('urlContent');
    const fileContent = document.getElementById('fileContent');

    // Set website check as active by default
    urlContent.style.display = 'block';
    urlTab.classList.add('active');

    urlTab.addEventListener('click', function() {
        urlTab.classList.add('active');
        fileTab.classList.remove('active');
        urlContent.style.display = 'block';
        fileContent.style.display = 'none';
    });

    fileTab.addEventListener('click', function() {
        fileTab.classList.add('active');
        urlTab.classList.remove('active');
        fileContent.style.display = 'block';
        urlContent.style.display = 'none';
    });
}

// File upload handling
function setupFileUpload() {
    const fileUploadArea = document.querySelector('.file-upload-area');
    const fileInput = document.getElementById('fileInput');
    
    // Trigger file select when clicking on the area
    fileUploadArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    // Handle file selection
    fileInput.addEventListener('change', handleFileSelect);
    
    // Handle drag and drop
    fileUploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.stopPropagation();
        fileUploadArea.classList.add('drag-over');
    });
    
    fileUploadArea.addEventListener('dragleave', (e) => {
        e.preventDefault();
        e.stopPropagation();
        fileUploadArea.classList.remove('drag-over');
    });
    
    fileUploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        fileUploadArea.classList.remove('drag-over');
        
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length) {
            fileInput.files = files;
            handleFileSelect({ target: { files: files } });
        }
    });
}

// Handle file selection for scanning
async function handleFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const fileStatusText = document.getElementById('file-loading-text');
    const fileProgressBar = document.getElementById('file-loading-bar-progress');
    const fileResults = document.getElementById('fileResults');
    
    fileResults.innerHTML = '';
    fileStatusText.textContent = `Preparing to scan ${file.name}`;
    fileProgressBar.style.width = '20%';
    
    // Create recovery UI elements
    const recoveryDiv = document.createElement('div');
    recoveryDiv.id = 'file-recovery-ui';
    recoveryDiv.className = 'hidden';
    recoveryDiv.innerHTML = `
        <div class="p-3 bg-white border border-gray-200 rounded-lg shadow-sm mt-2">
            <div class="flex items-center gap-2 mb-2">
                <svg class="w-4 h-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
                <span class="text-sm font-medium text-gray-700">Upload taking longer than expected</span>
            </div>
            <div class="flex gap-2">
                <button id="retry-scan-btn" class="flex-1 px-3 py-1.5 text-xs bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors">
                    Retry
                </button>
                <button id="force-unstick-btn" class="flex-1 px-3 py-1.5 text-xs bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition-colors">
                    Reset
                </button>
                <button id="cancel-scan-btn" class="flex-1 px-3 py-1.5 text-xs bg-red-50 text-red-600 rounded hover:bg-red-100 transition-colors">
                    Cancel
                </button>
            </div>
        </div>
    `;
    fileResults.parentNode.insertBefore(recoveryDiv, fileResults.nextSibling);
    
    // Setup recovery button handlers
    document.getElementById('retry-scan-btn')?.addEventListener('click', () => {
        // Hide recovery UI
        recoveryDiv.className = 'hidden';
        // Retry the scan
        if (window.FileChecker && typeof window.FileChecker.forceUnstick === 'function') {
            window.FileChecker.forceUnstick();
            setTimeout(() => {
                handleFileSelect({ target: { files: [file] } });
            }, 1000);
        } else {
            reloadExtension(() => {
                handleFileSelect({ target: { files: [file] } });
            });
        }
    });
    
    document.getElementById('force-unstick-btn')?.addEventListener('click', () => {
        // Hide recovery UI
        recoveryDiv.className = 'hidden';
        // Force reset scanner
        reloadExtension();
    });

    document.getElementById('cancel-scan-btn')?.addEventListener('click', () => {
        // Hide recovery UI
        recoveryDiv.className = 'hidden';
        // Reset file input and status
        fileInput.value = '';
        fileStatusText.textContent = 'Select a file to scan';
        fileProgressBar.style.width = '0%';
        
        // Don't clear previous scan results
        // fileResults.innerHTML = '';
        
        // Clear any ongoing timeouts
        clearTimeout(uploadStuckTimeoutId);
        
        // Remove event listeners
        window.removeEventListener('uploadStarted', uploadStartedHandler);
        window.removeEventListener('uploadComplete', uploadCompleteHandler);
        window.removeEventListener('uploadStuck', uploadStuckHandler);
        window.removeEventListener('operationUnstuck', operationUnstuckHandler);
    });
    
    // Setup upload stuck detection timeout
    let uploadStuckTimeoutId = setTimeout(() => {
        console.warn('Upload seems to be stuck, showing recovery UI');
        recoveryDiv.className = 'block'; // Show recovery options
    }, 15000); // 15 seconds timeout
    
    try {
        // Wait for FileChecker to be available
        if (!window.FileChecker) {
            fileStatusText.textContent = 'Initializing file scanner...';
            
            try {
                await new Promise((resolve, reject) => {
                    // If FileChecker is already available, resolve immediately
                    if (window.FileChecker) {
                        resolve();
                        return;
                    }

                    // Set up event listener first
                    const readyHandler = () => {
                        clearTimeout(timeout);
                        resolve();
                    };
                    window.addEventListener('fileCheckerReady', readyHandler, { once: true });

                    // Then set the timeout
                    const timeout = setTimeout(() => {
                        window.removeEventListener('fileCheckerReady', readyHandler);
                        reject(new Error('File scanner initialization timed out. Please refresh and try again.'));
                    }, 5000);
                });
            } catch (error) {
                throw new Error('Failed to initialize file scanner. Please refresh the extension and try again.');
            }
        }

        if (!window.FileChecker) {
            throw new Error('File scanner not available. Please refresh the extension and try again.');
        }
        
        // Set up event listeners for upload events
        const uploadStartedHandler = () => {
            fileStatusText.textContent = `Uploading file to VirusTotal...`;
            fileProgressBar.style.width = '40%';
        };
        
        const uploadCompleteHandler = (event) => {
            const detail = event.detail || {};
            if (detail.success) {
                fileStatusText.textContent = `Processing scan results...`;
                fileProgressBar.style.width = '70%';
            } else {
                fileStatusText.textContent = `Upload failed: ${detail.error || 'Unknown error'}`;
                fileProgressBar.style.width = '30%';
                recoveryDiv.className = 'block'; // Show recovery options on explicit failure
            }
        };
        
        const uploadStuckHandler = () => {
            fileStatusText.textContent = `Upload may be stuck, attempting to recover...`;
            recoveryDiv.className = 'block'; // Show recovery options
        };
        
        const operationUnstuckHandler = () => {
            // This event is fired when the scanner automatically recovers
            fileStatusText.textContent = `Scanner reset successfully. Please try again.`;
            fileProgressBar.style.width = '0%';
            recoveryDiv.className = 'hidden'; // Hide recovery options
        };
        
        // Register listeners
        window.addEventListener('uploadStarted', uploadStartedHandler, { once: true });
        window.addEventListener('uploadComplete', uploadCompleteHandler, { once: true });
        window.addEventListener('uploadStuck', uploadStuckHandler, { once: true });
        window.addEventListener('operationUnstuck', operationUnstuckHandler, { once: true });
        
        // Start the scan
        fileStatusText.textContent = 'Analyzing file...';
        fileProgressBar.style.width = '30%';
        
        // Scan the file
        const result = await window.FileChecker.isFileSafe(file);
        
        // Clear timeout as scan completed successfully
        clearTimeout(uploadStuckTimeoutId);
        
        // Remove recovery UI as it's not needed
        recoveryDiv.remove();
        
        // Remove event listeners
        window.removeEventListener('uploadStarted', uploadStartedHandler);
        window.removeEventListener('uploadComplete', uploadCompleteHandler);
        window.removeEventListener('uploadStuck', uploadStuckHandler);
        window.removeEventListener('operationUnstuck', operationUnstuckHandler);
        
        // Show results
        fileStatusText.textContent = 'Scan completed';
        fileProgressBar.style.width = '100%';
        showFileResults(result, file);
    } catch (error) {
        console.error('File scan error:', error);
        fileStatusText.textContent = `Error: ${error.message}`;
        fileProgressBar.style.width = '0%';
        
        // Clear timeout
        clearTimeout(uploadStuckTimeoutId);
        
        // Show recovery UI if there was an error
        recoveryDiv.className = 'block';
    }
}

// Helper function to reload the extension
function reloadExtension(callback) {
    const fileStatusText = document.getElementById('file-loading-text');
    if (fileStatusText) {
        fileStatusText.textContent = 'Reloading scanner...';
    }
    
    // Try to use the FileChecker's reload method if available
    if (window.FileChecker && typeof window.FileChecker.reload === 'function') {
        window.FileChecker.reload()
            .then(() => {
                if (callback && typeof callback === 'function') {
                    callback();
                }
            })
            .catch(err => {
                console.error('Error reloading extension:', err);
                // Fallback to manual reload
                chrome.runtime.reload();
            });
    } else {
        // Fallback to refreshing the popup
        setTimeout(() => {
            if (callback && typeof callback === 'function') {
                callback();
            } else {
                window.location.reload();
            }
        }, 500);
    }
}

// Show file scan results
function showFileResults(result, file) {
    const fileResults = document.getElementById('fileResults');
    const { isSafe, maliciousPercentage, detectionCount, totalEngines, detailedResults } = result;
    const stats = detailedResults.stats || { malicious: 0, suspicious: 0, clean: 0, undetected: 0 };
    
    // Determine if file is unsafe based on malicious/suspicious counts
    const isUnsafe = stats.malicious > 0 || stats.suspicious > 0;
    
    // Calculate circle properties
    const radius = 30;
    const circumference = 2 * Math.PI * radius;
    // For unsafe files, show the threat percentage instead of safe percentage
    const displayPercentage = isUnsafe ? Math.round(maliciousPercentage) : Math.round(100 - maliciousPercentage);
    const offset = (displayPercentage / 100) * circumference;
    
    fileResults.innerHTML = `
        <div class="scan-header">
            <div class="scan-title">Scan completed</div>
            <div class="scan-filename">${file.name}</div>
        </div>

        <div class="scan-result">
            <div class="result-circle">
                <svg viewBox="0 0 64 64">
                    <circle class="bg" cx="32" cy="32" r="${radius}" />
                    <circle class="progress" cx="32" cy="32" r="${radius}" 
                        style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${circumference - offset}" />
                    <text class="percentage-text" x="32" y="32" text-anchor="middle" dominant-baseline="middle" font-size="12">
                        ${displayPercentage}%
                    </text>
                </svg>
            </div>
        </div>
        <div class="result-label">${isUnsafe ? 'Unsafe' : 'Safe'}</div>

        <div class="scan-details">
            <div class="detail-row">
                <div class="detail-icon">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M13.3332 4L5.99984 11.3333L2.6665 8" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
                <div class="detail-text">Clean</div>
                <div class="detail-count">${stats.clean || 0}</div>
            </div>
            <div class="detail-row">
                <div class="detail-icon">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M8 14C11.3137 14 14 11.3137 14 8C14 4.68629 11.3137 2 8 2C4.68629 2 2 4.68629 2 8C2 11.3137 4.68629 14 8 14Z" stroke="#EF4444" stroke-width="2"/>
                        <path d="M8 5V8M8 11H8.01" stroke="#EF4444" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                </div>
                <div class="detail-text">Malicious</div>
                <div class="detail-count">${stats.malicious || 0}</div>
            </div>
            <div class="detail-row">
                <div class="detail-icon">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M7.99984 5.33333V8M7.99984 10.6667H8.00651M14.6665 8C14.6665 11.6819 11.6817 14.6667 7.99984 14.6667C4.31794 14.6667 1.33317 11.6819 1.33317 8C1.33317 4.3181 4.31794 1.33333 7.99984 1.33333C11.6817 1.33333 14.6665 4.3181 14.6665 8Z" stroke="#F59E0B" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>
                <div class="detail-text">Suspicious</div>
                <div class="detail-count">${stats.suspicious || 0}</div>
            </div>
            <div class="detail-row">
                <div class="detail-icon">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                        <path d="M8 14C11.3137 14 14 11.3137 14 8C14 4.68629 11.3137 2 8 2C4.68629 2 2 4.68629 2 8C2 11.3137 4.68629 14 8 14Z" stroke="#6B7280" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                </div>
                <div class="detail-text">Undetected</div>
                <div class="detail-count">${stats.undetected || 0}</div>
            </div>
        </div>

        ${detailedResults.fileType ? `
        <div class="file-type">
            <div class="file-type-text">${detailedResults.fileType.toLowerCase()}</div>
        </div>
        ` : ''}

        <div class="vt-link">
            <a href="https://www.virustotal.com/gui/file/${detailedResults.sha256}" target="_blank">
                View full report on VirusTotal
            </a>
        </div>`;

    // Set the progress circle color based on safety level
    const progressCircle = fileResults.querySelector('.progress');
    if (progressCircle) {
        if (stats.malicious > 0) {
            progressCircle.style.stroke = '#EF4444'; // Red color for malicious findings
            fileResults.querySelector('.result-label').style.color = '#EF4444';
        } else if (stats.suspicious > 0) {
            progressCircle.style.stroke = '#F59E0B'; // Yellow color for suspicious
            fileResults.querySelector('.result-label').style.color = '#F59E0B';
        } else {
            progressCircle.style.stroke = '#10B981'; // Green color for safe
            fileResults.querySelector('.result-label').style.color = '#10B981';
        }
    }
}

// Helper function to format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Helper function to get progress color
function getProgressColor(level) {
    switch (level) {
        case 'safe': return '#10B981';
        case 'warning': return '#F59E0B';
        case 'danger': return '#EF4444';
        default: return '#6B7280';
    }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', initializeExtension);
