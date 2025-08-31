// Redesigned file scanning backend with multi-file format support
(function() {
    const CONFIG = {
        API_KEY: '28339d8b908a7ffb4cb1d562b24a7ff742d21d194ab99ad29e8378a5e64977b7',
        VT_API_URL: 'https://www.virustotal.com/api/v3',
        POLLING_INTERVAL: 10000, // 10 seconds
        MAX_POLLING_ATTEMPTS: 30,  // 5 minutes total
        PDF_CONTENT_SCAN: true,   // Enable PDF content scanning
        PDF_MAX_SIZE: 25 * 1024 * 1024,  // 25MB max for PDF content scanning
        CACHE_EXPIRY: 1800000, // 30 minutes cache expiry
        CACHE_MAX_SIZE: 50, // Maximum number of items in cache
        AUTO_RELOAD: true, // Auto-reload extension after each scan
        RELOAD_DELAY: 500,  // Increased delay before reload (ms)
        STUCK_TIMEOUT: 60000, // Increased to 60 seconds timeout to detect stuck operations
        UI_STUCK_TIMEOUT: 15000, // 15 second timeout for UI stuck detection
        UI_THEME: 'light', // light or dark theme
        SHOW_DETAILED_RESULTS: true, // Show detailed results by default,
        MAX_UPLOAD_RETRIES: 2, // Maximum number of upload retries
        
        // File type specific settings
        SUPPORTED_TYPES: {
            // Documents
            'pdf': { name: 'PDF Document', contentScan: true, riskLevel: 'medium' },
            'txt': { name: 'Text Document', contentScan: false, riskLevel: 'low' },
            'docx': { name: 'Word Document', contentScan: true, riskLevel: 'medium' },
            'doc': { name: 'Word Document', contentScan: true, riskLevel: 'medium' },
            
            // Images
            'jpg': { name: 'JPEG Image', contentScan: false, riskLevel: 'low' },
            'jpeg': { name: 'JPEG Image', contentScan: false, riskLevel: 'low' },
            'png': { name: 'PNG Image', contentScan: false, riskLevel: 'low' },
            
            // Videos
            'mp4': { name: 'MP4 Video', contentScan: false, riskLevel: 'low' },
            'mkv': { name: 'MKV Video', contentScan: false, riskLevel: 'low' },
            
            // Executables
            'apk': { name: 'Android Package', contentScan: true, riskLevel: 'high' },
            'exe': { name: 'Windows Executable', contentScan: true, riskLevel: 'high' }
        },
        
        // Content scan size limits by type (in bytes)
        TYPE_SIZE_LIMITS: {
            'pdf': 25 * 1024 * 1024,     // 25MB
            'docx': 15 * 1024 * 1024,    // 15MB
            'doc': 15 * 1024 * 1024,     // 15MB
            'apk': 100 * 1024 * 1024,    // 100MB
            'exe': 50 * 1024 * 1024      // 50MB
        }
    };

    let isApiKeyValid = false;
    let isProcessing = false;
    let stuckTimeoutId = null;
    
    // Improved cache implementation with expiry
    const cache = {
        items: new Map(),
        
        // Set a value in cache with expiry timestamp
        set: function(key, value) {
            // Enforce cache size limit
            if (this.items.size >= CONFIG.CACHE_MAX_SIZE) {
                // Remove oldest item
                const oldestKey = this.items.keys().next().value;
                this.items.delete(oldestKey);
                console.log('Cache limit reached, removed oldest item:', oldestKey);
            }
            
            this.items.set(key, {
                value: value,
                timestamp: Date.now()
            });
            console.log(`Cache: item stored with key ${key.substring(0, 8)}...`);
            
            // Optional: persist to sessionStorage for page refreshes
            try {
                const cacheEntry = JSON.stringify({
                    value: value,
                    timestamp: Date.now()
                });
                sessionStorage.setItem(`vtScan_${key}`, cacheEntry);
            } catch (e) {
                console.warn('Could not save to sessionStorage:', e);
            }
        },
        
        // Get a value if it exists and hasn't expired
        get: function(key) {
            // First try memory cache
            const item = this.items.get(key);
            
            if (item) {
                // Check if item has expired
                if (Date.now() - item.timestamp > CONFIG.CACHE_EXPIRY) {
                    console.log(`Cache: item with key ${key.substring(0, 8)}... expired`);
                    this.items.delete(key);
                    try {
                        sessionStorage.removeItem(`vtScan_${key}`);
                    } catch (e) { 
                        // Ignore sessionStorage errors
                    }
                    return null;
                }
                console.log(`Cache hit for key ${key.substring(0, 8)}...`);
                return item.value;
            }
            
            // Try sessionStorage if not in memory
            try {
                const storedItem = sessionStorage.getItem(`vtScan_${key}`);
                if (storedItem) {
                    const parsedItem = JSON.parse(storedItem);
                    if (Date.now() - parsedItem.timestamp <= CONFIG.CACHE_EXPIRY) {
                        // Add back to memory cache
                        this.items.set(key, {
                            value: parsedItem.value,
                            timestamp: parsedItem.timestamp
                        });
                        console.log(`Cache: restored item with key ${key.substring(0, 8)}... from sessionStorage`);
                        return parsedItem.value;
                    } else {
                        console.log(`Cache: removed expired item from sessionStorage with key ${key.substring(0, 8)}...`);
                        sessionStorage.removeItem(`vtScan_${key}`);
                    }
                }
            } catch (e) {
                console.warn('Error accessing sessionStorage:', e);
            }
            
            return null;
        },
        
        // Check if key exists and is valid
        has: function(key) {
            return this.get(key) !== null;
        },
        
        // Remove item from cache
        delete: function(key) {
            this.items.delete(key);
            try {
                sessionStorage.removeItem(`vtScan_${key}`);
            } catch (e) {
                // Ignore sessionStorage errors
            }
        },
        
        // Clear entire cache
        clear: function() {
            this.items.clear();
            try {
                // Remove only VT scan related items from sessionStorage
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    if (key && key.startsWith('vtScan_')) {
                        sessionStorage.removeItem(key);
                    }
                }
            } catch (e) {
                console.warn('Error clearing sessionStorage:', e);
            }
            console.log('Cache cleared');
        }
    };

    async function validateApiKeyOnce() {
        if (!isApiKeyValid) {
            console.log('Validating API key...');
            isApiKeyValid = await testApiKey();
            if (!isApiKeyValid) {
                console.error('API key validation failed');
                throw new Error('Invalid or expired API key. Please check your VirusTotal API key.');
            }
            console.log('API key validation successful');
        }
    }

    // Add reload mechanism with improved error handling
    function reloadExtension() {
        return new Promise((resolve) => {
            console.log('Preparing to reload extension...');
            
            // Clear memory state
            isApiKeyValid = false;
            cache.clear();
            
            // Clear any stuck detection timeout
            if (stuckTimeoutId) {
                clearTimeout(stuckTimeoutId);
                stuckTimeoutId = null;
            }
            
            // Reset any pending operations
            const pendingRequests = window.FileChecker._pendingRequests || [];
            console.log(`Aborting ${pendingRequests.length} pending requests...`);
            
            for (const controller of pendingRequests) {
                try {
                    controller.abort();
                } catch (e) {
                    console.warn('Error aborting request:', e);
                }
            }
            window.FileChecker._pendingRequests = [];
            
            // Set processing flag to false
            isProcessing = false;
            
            // Notify about reload
            window.dispatchEvent(new CustomEvent('fileCheckerReloading'));
            
            // Force garbage collection if supported
            if (window.gc) {
                try {
                    window.gc();
                } catch (e) {
                    // Ignore if gc is not available
                }
            }
            
            setTimeout(() => {
                console.log('Extension reload complete');
                window.dispatchEvent(new CustomEvent('fileCheckerReady', {
                    detail: { success: true, timestamp: Date.now() }
                }));
                resolve();
            }, CONFIG.RELOAD_DELAY);
        });
    }

    // Add stuck detection mechanism
    function setStuckDetection() {
        // Clear existing timeout if any
        if (stuckTimeoutId) {
            clearTimeout(stuckTimeoutId);
        }
        
        // Set a new timeout to detect if processing gets stuck
        stuckTimeoutId = setTimeout(() => {
            console.error('Stuck operation detected! Forcing reload...');
            // If we get here, something is stuck
            if (isProcessing) {
                isProcessing = false;
                // Abort all pending requests before reload
                const pendingRequests = window.FileChecker._pendingRequests || [];
                for (const controller of pendingRequests) {
                    try {
                        controller.abort();
                    } catch (e) {
                        console.warn('Error aborting request during stuck detection:', e);
                    }
                }
                window.FileChecker._pendingRequests = [];
                
                reloadExtension().catch(err => {
                    console.error('Error during force reload:', err);
                    // If reload fails, dispatch ready event anyway to unblock the UI
                    window.dispatchEvent(new CustomEvent('fileCheckerReady', {
                        detail: { success: false, error: 'Force reload failed', timestamp: Date.now() }
                    }));
                });
            }
        }, CONFIG.STUCK_TIMEOUT);
    }

    // Get file type based on extension or MIME type
    function getFileType(file) {
        let fileType = '';
        
        // First try to get from file name extension
        if (file.name) {
            const nameParts = file.name.split('.');
            if (nameParts.length > 1) {
                fileType = nameParts[nameParts.length - 1].toLowerCase();
            }
        }
        
        // If no extension or unrecognized, try MIME type
        if (!fileType || !CONFIG.SUPPORTED_TYPES[fileType]) {
            if (file.type) {
                const mimeType = file.type.toLowerCase();
                
                if (mimeType.includes('pdf')) {
                    fileType = 'pdf';
                } else if (mimeType.includes('text/plain')) {
                    fileType = 'txt';
                } else if (mimeType.includes('word') || mimeType.includes('docx')) {
                    fileType = 'docx';
                } else if (mimeType.includes('jpeg') || mimeType.includes('jpg')) {
                    fileType = 'jpg';
                } else if (mimeType.includes('png')) {
                    fileType = 'png';
                } else if (mimeType.includes('mp4')) {
                    fileType = 'mp4';
                } else if (mimeType.includes('x-matroska')) {
                    fileType = 'mkv';
                } else if (mimeType.includes('android') || mimeType.includes('apk')) {
                    fileType = 'apk';
                }
            }
        }
        
        return fileType;
    }

    // Update scanFile function to support multiple file types
    async function scanFile(file) {
        if (isProcessing) {
            console.warn('Another scan is already in progress. Please wait...');
            throw new Error('Another scan is in progress. Please wait for it to complete.');
        }
        
        isProcessing = true;
        setStuckDetection();
        
        try {
            console.log('Starting scan for file:', file.name);
            
            // Determine file type and use specialized scanning if available
            const fileType = getFileType(file);
            const fileTypeInfo = CONFIG.SUPPORTED_TYPES[fileType] || { name: 'Unknown', contentScan: false, riskLevel: 'medium' };
            
            console.log(`File identified as ${fileTypeInfo.name} (${fileType}), risk level: ${fileTypeInfo.riskLevel}`);
            
            // Special handling for different file types
            if (fileType === 'pdf') {
                console.log('PDF file detected, using specialized scanning');
                const results = await scanPdfFile(file);
                
                // Clean up after scan
                if (CONFIG.AUTO_RELOAD) {
                    await reloadExtension();
                } else {
                    isProcessing = false;
                    if (stuckTimeoutId) {
                        clearTimeout(stuckTimeoutId);
                        stuckTimeoutId = null;
                    }
                }
                
                return results;
            } else if (fileType === 'apk') {
                console.log('APK file detected, using specialized scanning');
                const results = await scanApkFile(file);
                
                // Clean up after scan
                if (CONFIG.AUTO_RELOAD) {
                    await reloadExtension();
                } else {
                    isProcessing = false;
                    if (stuckTimeoutId) {
                        clearTimeout(stuckTimeoutId);
                        stuckTimeoutId = null;
                    }
                }
                
                return results;
            } else if (fileType === 'docx' || fileType === 'doc') {
                console.log('Word document detected, using document scanning');
                const results = await scanDocumentFile(file, fileType);
                
                // Clean up after scan
                if (CONFIG.AUTO_RELOAD) {
                    await reloadExtension();
                } else {
                    isProcessing = false;
                    if (stuckTimeoutId) {
                        clearTimeout(stuckTimeoutId);
                        stuckTimeoutId = null;
                    }
                }
                
                return results;
            }
            
            // Regular file scanning process for other file types
            // 1. Get file hash
            const fileHash = await calculateFileHash(file);
            console.log('File hash:', fileHash);

            // 2. Check cache with improved handling
            if (cache.has(fileHash)) {
                console.log('Cache hit for file:', file.name);
                const results = cache.get(fileHash);
                
                // Add file type information
                results.fileType = fileType;
                results.fileTypeInfo = fileTypeInfo;
                
                // Auto-reload after cached scan if enabled
                if (CONFIG.AUTO_RELOAD) {
                    await reloadExtension();
                } else {
                    isProcessing = false;
                    if (stuckTimeoutId) {
                        clearTimeout(stuckTimeoutId);
                        stuckTimeoutId = null;
                    }
                }
                
                return results;
            }

            // 3. Check if file was previously analyzed
            try {
                const existingResult = await checkExistingFile(fileHash);
                if (existingResult) {
                    console.log('Found existing analysis');
                    
                    // Add file type information
                    existingResult.fileType = fileType;
                    existingResult.fileTypeInfo = fileTypeInfo;
                    
                    cache.set(fileHash, existingResult);
                    
                    // Auto-reload after analysis if enabled
                    if (CONFIG.AUTO_RELOAD) {
                        await reloadExtension();
                    } else {
                        isProcessing = false;
                        if (stuckTimeoutId) {
                            clearTimeout(stuckTimeoutId);
                            stuckTimeoutId = null;
                        }
                    }
                    
                    return existingResult;
                }
            } catch (error) {
                console.log('No existing analysis found');
            }

            // 4. Upload file
            const uploadUrl = await getUploadUrl();
            const analysisId = await uploadFile(file, uploadUrl);
            console.log('File uploaded, analysis ID:', analysisId);

            // 5. Get results
            const results = await pollAnalysisResults(analysisId);
            const processedResults = processResults(results);
            
            // Add file type information
            processedResults.fileType = fileType;
            processedResults.fileTypeInfo = fileTypeInfo;
            
            // Store in cache with proper expiry
            cache.set(fileHash, processedResults);
            
            // Auto-reload after scan if enabled
            if (CONFIG.AUTO_RELOAD) {
                await reloadExtension();
            } else {
                isProcessing = false;
                if (stuckTimeoutId) {
                    clearTimeout(stuckTimeoutId);
                    stuckTimeoutId = null;
                }
            }
            
            return processedResults;
        } catch (error) {
            console.error('Scan failed:', error);
            
            // Auto-reload on error too if enabled
            if (CONFIG.AUTO_RELOAD) {
                await reloadExtension();
            } else {
                isProcessing = false;
                if (stuckTimeoutId) {
                    clearTimeout(stuckTimeoutId);
                    stuckTimeoutId = null;
                }
            }
            
            throw error;
        }
    }

    async function calculateFileHash(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                const buffer = e.target.result;
                const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                resolve(hashHex);
                } catch (error) {
                    reject(error);
                }
            };
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }

    async function checkExistingFile(hash) {
        try {
            console.log('Checking existing file with hash:', hash);
            const response = await fetch(`${CONFIG.VT_API_URL}/files/${hash}`, {
                headers: {
                    'x-apikey': CONFIG.API_KEY,
                    'accept': 'application/json'
                }
            });

            if (response.status === 404) {
                console.log('No existing file found with hash:', hash);
                return null;
            }

            if (!response.ok) {
                const errorText = await response.text();
                console.error(`Error checking file: ${response.status} - ${errorText}`);
                throw new Error(`Failed to check file: ${response.status} - ${errorText}`);
            }

            const data = await response.json();
            console.log('Existing file found, processing results');
            return processResults(data);
        } catch (error) {
            console.error('Error in checkExistingFile:', error);
            throw error;
        }
    }

    // Improved upload file function with better tracking
    async function uploadFile(file, uploadUrl, retryCount = 0) {
        const formData = new FormData();
        formData.append('file', file);

        try {
            console.log('Uploading file to VirusTotal:', file.name);
            // Notify UI that upload is starting
            window.dispatchEvent(new CustomEvent('uploadStarted', {
                detail: { fileName: file.name }
            }));
            
            // Set a UI timeout to detect stuck uploads
            const uiTimeoutId = setTimeout(() => {
                console.warn('UI upload timeout - potential stuck state detected');
                window.dispatchEvent(new CustomEvent('uploadStuck', {
                    detail: { fileName: file.name, retryCount: retryCount }
                }));
            }, CONFIG.UI_STUCK_TIMEOUT);
            
            const response = await fetchWithLogging(uploadUrl, {
                method: 'POST',
                body: formData,
                headers: {
                    'x-apikey': CONFIG.API_KEY
                }
            });
            
            // Clear UI timeout as request completed
            clearTimeout(uiTimeoutId);
            
            // Notify UI that upload is complete
            window.dispatchEvent(new CustomEvent('uploadComplete', {
                detail: { fileName: file.name, success: true }
            }));
            
            const uploadData = await response.json();
            console.log('Upload response:', uploadData);
            
            if (!uploadData.data) {
                console.error('Invalid upload response:', uploadData);
                throw new Error('Invalid upload response from VirusTotal');
            }
            
            // Store the file ID for potential reanalysis
            if (uploadData.data.id) {
                window.FileChecker._lastFileId = uploadData.data.id;
            }

            if (uploadData.data.type === 'analysis') {
                console.log('Received analysis ID directly:', uploadData.data.id);
                return uploadData.data.id;
            }

            if (uploadData.data.type === 'file') {
                console.log('Received file ID, requesting analysis:', uploadData.data.id);
                return await requestAnalysis(uploadData.data.id);
            }
            
            throw new Error(`Unexpected response type: ${uploadData.data.type}`);
        } catch (error) {
            console.error('Error in file upload:', error);
            
            // Notify UI that upload failed
            window.dispatchEvent(new CustomEvent('uploadComplete', {
                detail: { fileName: file.name, success: false, error: error.message }
            }));
            
            // Retry logic for upload failures
            if (retryCount < CONFIG.MAX_UPLOAD_RETRIES) {
                console.log(`Retrying upload (attempt ${retryCount + 1}/${CONFIG.MAX_UPLOAD_RETRIES + 1})...`);
                // Get a fresh upload URL for retry
                try {
                    const newUploadUrl = await getUploadUrl();
                    return await uploadFile(file, newUploadUrl, retryCount + 1);
                } catch (retryError) {
                    console.error('Failed to get new upload URL for retry:', retryError);
                    throw error; // Throw original error if retry setup fails
                }
            }
            
            throw error;
        }
    }

    // Improved request analysis function
    async function requestAnalysis(fileId) {
        try {
            console.log('Requesting analysis for file ID:', fileId);
            const response = await fetchWithLogging(`${CONFIG.VT_API_URL}/files/${fileId}/analyse`, {
                method: 'POST',
                headers: {
                    'x-apikey': CONFIG.API_KEY,
                    'accept': 'application/json'
                }
            });
            
            const analysisData = await response.json();
            
            if (!analysisData.data) {
                console.error('Invalid analysis response:', analysisData);
                throw new Error('Invalid analysis response from VirusTotal');
            }
            
            console.log('Analysis requested successfully, ID:', analysisData.data.id);
            return analysisData.data.id;
        } catch (error) {
            console.error('Error requesting analysis:', error);
            throw error;
        }
    }

    // Enhanced fetch with logging, timeout and retry capability
    async function fetchWithLogging(url, options, retries = 2) {
        let currentTry = 0;
        
        while (currentTry <= retries) {
            try {
                console.log(`Fetching URL (attempt ${currentTry + 1}/${retries + 1}):`, url);
                
                // Add timeout to fetch
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
                
                const fetchOptions = {
                    ...options,
                    signal: controller.signal
                };
                
                const response = await fetch(url, fetchOptions);
                clearTimeout(timeoutId);
                
                if (!response.ok) {
                    const errorText = await response.text();
                    console.error('Fetch error:', {
                        status: response.status,
                        statusText: response.statusText,
                        errorText: errorText
                    });
                    
                    // If rate limited, wait longer before retry
                    if (response.status === 429 && currentTry < retries) {
                        const waitTime = 5000 * Math.pow(2, currentTry);
                        console.log(`Rate limited, waiting ${waitTime/1000} seconds before retry`);
                        await new Promise(resolve => setTimeout(resolve, waitTime));
                        currentTry++;
                        continue;
                    }
                    
                    throw new Error(`Fetch failed: ${response.status} - ${errorText}`);
                }
                
                return response;
            } catch (error) {
                if (error.name === 'AbortError') {
                    console.error('Fetch aborted due to timeout');
                    if (currentTry < retries) {
                        console.log('Retrying after timeout...');
                        currentTry++;
                        continue;
                    }
                }
                
                console.error('Network error:', error);
                
                // Try to retry transient network errors
                if (currentTry < retries && 
                    (error.message.includes('network') || 
                     error.message.includes('timeout') || 
                     error.message.includes('connection'))) {
                    console.log('Retrying after network error...');
                    const waitTime = 3000 * Math.pow(2, currentTry);
                    await new Promise(resolve => setTimeout(resolve, waitTime));
                    currentTry++;
                    continue;
                }
                
                throw error;
            }
        }
    }

    // Improved upload URL retrieval
    async function getUploadUrl() {
        try {
            console.log('Getting VirusTotal upload URL');
            const response = await fetchWithLogging(`${CONFIG.VT_API_URL}/files/upload_url`, {
                method: 'GET',
                headers: {
                    'x-apikey': CONFIG.API_KEY,
                    'accept': 'application/json',
                    'Cache-Control': 'no-cache'
                }
            });
            
            const urlData = await response.json();
            
            if (!urlData.data) {
                console.error('Invalid upload URL response:', urlData);
                throw new Error('Failed to get valid upload URL from VirusTotal');
            }
            
            console.log('Upload URL obtained successfully');
            return urlData.data;
        } catch (error) {
            console.error('Error getting upload URL:', error);
            throw error;
        }
    }

    // Improved API key validation
    async function testApiKey() {
        try {
            console.log('Validating VirusTotal API key...');
            const response = await fetchWithLogging(`${CONFIG.VT_API_URL}/users/current`, {
                method: 'GET',
                headers: {
                    'x-apikey': CONFIG.API_KEY,
                    'accept': 'application/json'
                }
            }, 1); // Single retry for API key validation
            
            const data = await response.json();
            
            if (!data.data || !data.data.id) {
                console.error('Invalid API key response format:', data);
                return false;
            }
            
            // Store API quota info if available
            if (data.data.attributes && data.data.attributes.quotas) {
                CONFIG.API_QUOTAS = data.data.attributes.quotas;
                console.log('API quotas:', CONFIG.API_QUOTAS);
            }
            
            console.log('API key is valid. User:', data.data.id);
            return true;
        } catch (error) {
            console.error('API key validation error:', error);
            return false;
        }
    }

    // Enhanced analysis results check
    async function checkAnalysisResults(analysisId) {
        try {
            console.log('Checking analysis results for ID:', analysisId);
            
            // Ensure we have a valid analysis ID
            if (!analysisId || typeof analysisId !== 'string' || !analysisId.trim()) {
                throw new Error('Invalid analysis ID');
            }

            const response = await fetchWithLogging(`${CONFIG.VT_API_URL}/analyses/${analysisId}`, {
                method: 'GET',
                headers: {
                    'x-apikey': CONFIG.API_KEY,
                    'accept': 'application/json',
                    'Cache-Control': 'no-cache'
                }
            });

            const data = await response.json();
            
            if (!data.data || !data.data.attributes) {
                console.error('Invalid response format:', data);
                throw new Error('Invalid response format from VirusTotal');
            }

            console.log('Analysis results received, status:', data.data.attributes.status);
            
            // Validate that we have meaningful data
            if (data.data.attributes.status === 'completed') {
                const stats = data.data.attributes.stats || {};
                const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
                
                if (totalEngines < 5) {
                    console.warn('Warning: Analysis completed but with very few engine results:', totalEngines);
                } else {
                    console.log(`Analysis has results from ${totalEngines} security engines`);
                }
            }
            
            return data.data;
        } catch (error) {
            console.error('Error in checkAnalysisResults:', error);
            throw error;
        }
    }

    async function pollAnalysisResults(analysisId, maxRetries = 30, interval = 5000) {
        let retries = 0;
        const controller = new AbortController();
        
        // Track this request so it can be aborted during reload
        if (!window.FileChecker._pendingRequests) {
            window.FileChecker._pendingRequests = [];
        }
        window.FileChecker._pendingRequests.push(controller);
        
        return new Promise((resolve, reject) => {
            const checkResults = async () => {
                try {
                    if (controller.signal.aborted) {
                        reject(new Error('Request aborted during extension reload'));
                        return;
                    }
                    
                    console.log(`Polling attempt ${retries + 1}/${maxRetries} for analysis ID: ${analysisId}`);
                    
                    // Double-check that we have a valid analysis ID
                    if (!analysisId || typeof analysisId !== 'string' || !analysisId.trim()) {
                        reject(new Error(`Invalid analysis ID: ${analysisId}`));
                        return;
                    }
                    
                    // Use robust fetch with timeout
                    const timeoutId = setTimeout(() => {
                        console.warn('API request timeout, aborting this attempt');
                        if (controller.signal.aborted) return;
                        // Create a separate controller for this specific fetch
                        const tempController = new AbortController();
                        tempController.abort();
                        // Continue polling on timeout rather than getting stuck
                        retries++;
                        if (retries < maxRetries) {
                            setTimeout(checkResults, interval);
                        } else {
                            reject(new Error('API requests timed out too many times'));
                        }
                    }, 20000); // 20 second timeout
                    
                    // Use a separate try/catch for the fetch operation to handle network errors properly
                    try {
                        const response = await fetch(`${CONFIG.VT_API_URL}/analyses/${analysisId}`, {
                            method: 'GET',
                            headers: {
                                'x-apikey': CONFIG.API_KEY,
                                'accept': 'application/json',
                                'Cache-Control': 'no-cache, no-store, must-revalidate'
                            },
                            signal: controller.signal
                        });
                        
                        clearTimeout(timeoutId);
                        
                        if (response.status === 404) {
                            console.error(`Analysis ID not found: ${analysisId}`);
                            // Try requesting a fresh analysis if possible
                            if (retries === 0 && window.FileChecker._lastFileId) {
                                console.log('Attempting to request a fresh analysis');
                                try {
                                    const newAnalysisId = await requestAnalysis(window.FileChecker._lastFileId);
                                    if (newAnalysisId !== analysisId) {
                                        console.log(`Got new analysis ID: ${newAnalysisId}, switching to it`);
                                        analysisId = newAnalysisId;
                                        // Continue with next polling attempt
                                        retries++;
                                        setTimeout(checkResults, interval);
                                        return;
                                    }
                                } catch (reanalysisError) {
                                    console.error('Failed to request fresh analysis:', reanalysisError);
                                }
                            }
                            
                            retries++;
                            if (retries >= maxRetries) {
                                reject(new Error('Analysis ID not found after maximum retries. The file may need to be re-uploaded.'));
                                return;
                            }
                            
                            console.log(`Retrying in ${interval/1000} seconds...`);
                            setTimeout(checkResults, interval);
                            return;
                        }
                        
                        if (!response.ok) {
                            const errorText = await response.text();
                            console.error(`Analysis check failed: ${response.status} - ${errorText}`);
                            
                            // Handle rate limiting specifically
                            if (response.status === 429) {
                                console.log('Rate limited by VirusTotal API, increasing wait time');
                                retries++;
                                if (retries >= maxRetries) {
                                    reject(new Error('Maximum retries reached during rate limiting'));
                                    return;
                                }
                                // Wait longer when rate limited
                                setTimeout(checkResults, interval * 2);
                                return;
                            }
                            
                            throw new Error(`Failed to get analysis results: ${response.status} - ${errorText}`);
                        }

                        const data = await response.json();
                        
                        if (!data.data || !data.data.attributes) {
                            console.error('Invalid response format:', data);
                            throw new Error('Invalid response format from VirusTotal');
                        }

                        console.log('Analysis status:', data.data.attributes.status);
                        
                        if (data.data.attributes.status === 'completed') {
                            console.log('Analysis completed successfully, validating results');
                            
                            // Validate the results to ensure we got meaningful data
                            const stats = data.data.attributes.stats || {};
                            const totalEngines = (stats.malicious || 0) + (stats.suspicious || 0) + 
                                                (stats.undetected || 0) + (stats.harmless || 0);
                            
                            if (totalEngines < 5) {
                                console.warn('Suspicious result: Very few engines reported. Retrying...');
                                retries++;
                                if (retries >= maxRetries) {
                                    console.warn('Giving up after max retries, returning potentially incomplete results');
                                    // Remove this request from pending list
                                    const index = window.FileChecker._pendingRequests.indexOf(controller);
                                    if (index > -1) {
                                        window.FileChecker._pendingRequests.splice(index, 1);
                                    }
                                    resolve(data);
                                    return;
                                }
                                setTimeout(checkResults, interval);
                                return;
                            }
                            
                            // Results look valid
                            console.log(`Results valid with ${totalEngines} security engines reporting`);
                            
                            // Remove this request from pending list
                            const index = window.FileChecker._pendingRequests.indexOf(controller);
                            if (index > -1) {
                                window.FileChecker._pendingRequests.splice(index, 1);
                            }
                            
                            resolve(data);
                            return;
                        } else if (data.data.attributes.status === 'failed') {
                            reject(new Error('VirusTotal analysis failed'));
                            return;
                        } else if (data.data.attributes.status === 'queued') {
                            console.log('Analysis is queued, continuing to wait');
                        }
                        
                        retries++;
                        
                        if (retries >= maxRetries) {
                            console.warn('Maximum polling attempts reached');
                            // As a fallback, check if we have any results at all
                            if (data.data.attributes.stats) {
                                console.log('Returning partial results after max retries');
                                resolve(data);
                                return;
                            }
                            reject(new Error('Analysis is taking longer than expected. Please try again later.'));
                            return;
                        }
                        
                        // Adjust interval based on status
                        let waitInterval = interval;
                        if (data.data.attributes.status === 'queued') {
                            // Wait longer if still queued
                            waitInterval = interval * 1.5;
                        }
                        
                        setTimeout(checkResults, waitInterval);
                    } catch (fetchError) {
                        clearTimeout(timeoutId);
                        
                        if (fetchError.name === 'AbortError') {
                            console.log('Fetch aborted due to timeout');
                            // This will be handled by the timeout handler above
                            return;
                        }
                        
                        console.error('Network error during polling:', fetchError);
                        retries++;
                        if (retries >= maxRetries) {
                            reject(fetchError);
                            return;
                        }
                        
                        // Wait and retry on network error
                        setTimeout(checkResults, interval);
                        return;
                    }
                    
                    // ... existing code ...
                } catch (error) {
                    if (error.name === 'AbortError') {
                        console.log('Polling aborted due to extension reload');
                        reject(new Error('Request aborted during extension reload'));
                    } else {
                        console.error('Error in polling:', error);
                        retries++;
                        if (retries >= maxRetries) {
                            reject(error);
                            return;
                        }
                        // Wait and retry on error
                        setTimeout(checkResults, interval);
                    }
                }
            };
            
            checkResults();
        });
    }

    // Update isFileSafe to handle different file types with varying risk thresholds
    async function isFileSafe(file) {
        if (isProcessing) {
            console.warn('Another process is already running. Please wait...');
            throw new Error('Another process is in progress. Please wait for it to complete.');
        }
        
        try {
            console.log('Starting file safety check for:', file.name);
            await validateApiKeyOnce();
            
            // First scan the file (scanFile handles isProcessing flag)
            const result = await scanFile(file);
            console.log('Scan completed, analyzing results');
            
            // Add original file information
            result.fileName = file.name;
            result.fileSize = file.size;
            
            // Check if we have the necessary data
            if (!result || !result.stats) {
                throw new Error('No valid analysis results available');
            }

            const stats = result.stats;
            const totalEngines = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
            const maliciousCount = stats.malicious + stats.suspicious;
            
            // Calculate percentage of malicious detections
            const maliciousPercentage = (maliciousCount / totalEngines) * 100;
            
            // Get file type information
            const fileType = result.fileType || getFileType(file);
            const fileTypeInfo = result.fileTypeInfo || CONFIG.SUPPORTED_TYPES[fileType] || 
                                { name: 'Unknown File', contentScan: false, riskLevel: 'medium' };
            
            // Determine risk level based on file type
            let riskLevel = 'medium';
            let hasRiskFeatures = false;
            
            // Special case for APK files
            if (fileType === 'apk') {
                riskLevel = 'high';
                
                // Check for excessive permissions
                if (result.androidInfo && result.androidInfo.permissions > 10) {
                    hasRiskFeatures = true;
                }
                
                // Check if packed
                if (result.packed) {
                    hasRiskFeatures = true;
                }
            }
            // Special case for PDF files
            else if (fileType === 'pdf') {
                riskLevel = 'medium';
                
                // Check for JavaScript content
                if (result.containsJavaScript) {
                    hasRiskFeatures = true;
                }
            }
            // Special case for Office documents
            else if (fileType === 'docx' || fileType === 'doc') {
                riskLevel = 'medium';
                
                // Check for macros
                if (result.hasMacros) {
                    hasRiskFeatures = true;
                    
                    // Suspicious macros are higher risk
                    if (result.suspiciousMacros) {
                        riskLevel = 'high';
                    }
                }
            }
            // Use default from config for other file types
            else {
                riskLevel = fileTypeInfo.riskLevel || 'medium';
            }
            
            // Set safety threshold based on risk level and risk features
            let safetyThreshold = 5; // Default 5% for medium risk
            
            if (riskLevel === 'low') {
                safetyThreshold = 8; // More tolerant for low-risk files
            } else if (riskLevel === 'high' || hasRiskFeatures) {
                safetyThreshold = 2; // Stricter for high-risk files
            }
            
            console.log('Results processed:', {
                totalEngines,
                maliciousCount,
                maliciousPercentage,
                fileType,
                riskLevel,
                hasRiskFeatures,
                safetyThreshold,
                stats
            });
            
            return {
                isSafe: maliciousPercentage < safetyThreshold,
                maliciousPercentage,
                detectionCount: maliciousCount,
                totalEngines,
                fileType,
                fileName: file.name,
                fileSize: file.size,
                riskLevel,
                hasRiskFeatures,
                detailedResults: result
            };
        } catch (error) {
            console.error('Error in isFileSafe:', error);
            throw error;
        }
    }

    async function uploadFiles(files) {
        try {
            console.log('Starting batch file upload...');
            await validateApiKeyOnce();

            const uploadPromises = files.map(async (file) => {
                console.log('Uploading file:', file.name);
                const fileHash = await calculateFileHash(file);
                if (cache.has(fileHash)) {
                    console.log('Cache hit for file:', file.name);
                    return cache.get(fileHash);
                }

                const maxSize = 100 * 1024 * 1024; // Ensure this is supported by the API
                if (file.size > maxSize) {
                    console.error('File size check failed for:', file.name);
                    throw new Error(`File size (${(file.size / 1024 / 1024).toFixed(2)} MB) exceeds the limit of 100MB`);
                }

                // Optimize handling for specific file types
                if (file.type === 'application/javascript' || file.name.endsWith('.json')) {
                    console.log('Processing JavaScript or JSON file:', file.name);
                    // Add any specific optimizations for these file types here
                }

                const uploadUrl = await getUploadUrl();
                const analysisId = await uploadFile(file, uploadUrl);

                cache.set(fileHash, analysisId);
                return analysisId;
            });

            const results = await Promise.all(uploadPromises);
            console.log('Batch upload completed');
            return results;
        } catch (error) {
            console.error('Error in batch upload:', error);
            throw error;
        }
    }

    // Update scanPdfFile to handle processing state
    async function scanPdfFile(file) {
        // Not setting isProcessing here as it's only called from scanFile
        try {
            console.log('Starting specialized PDF scan for:', file.name);
            
            // 1. Standard scan via hash
            const fileHash = await calculateFileHash(file);
            console.log('PDF hash:', fileHash);

            // Check cache with improved implementation
            if (cache.has(fileHash)) {
                console.log('Cache hit for PDF file:', file.name);
                const results = cache.get(fileHash);
                
                // Auto-reload after scan is handled by scanFile
                return results;
            }

            // Check for existing analysis
            try {
                const existingResult = await checkExistingFile(fileHash);
                if (existingResult) {
                    console.log('Found existing PDF analysis');
                    cache.set(fileHash, existingResult);
                    return existingResult;
                }
            } catch (error) {
                console.log('No existing PDF analysis found');
            }

            // 2. Additional content scanning for PDFs if enabled and within size limit
            if (CONFIG.PDF_CONTENT_SCAN && file.size <= CONFIG.PDF_MAX_SIZE) {
                console.log('Performing PDF content analysis...');
                try {
                    const pdfContent = await extractPdfContent(file);
                    if (pdfContent && pdfContent.hasJsContent) {
                        console.log('PDF contains JavaScript, marking as potentially unsafe');
                        // Upload file for deeper analysis if JavaScript is detected
                        const uploadUrl = await getUploadUrl();
                        const analysisId = await uploadFile(file, uploadUrl);
                        console.log('PDF uploaded for deep analysis, ID:', analysisId);
                        const results = await pollAnalysisResults(analysisId);
                        const processedResults = processResults(results);
                        
                        // Adjust results for JavaScript content
                        processedResults.containsJavaScript = true;
                        cache.set(fileHash, processedResults);
                        return processedResults;
                    }
                } catch (contentError) {
                    console.error('PDF content analysis error:', contentError);
                    // Continue with regular scanning if content analysis fails
                }
            }
            
            // 3. Regular upload and scan if content analysis is disabled or failed
            const uploadUrl = await getUploadUrl();
            const analysisId = await uploadFile(file, uploadUrl);
            console.log('PDF uploaded, analysis ID:', analysisId);
            
            // Wait longer for PDF analysis as it's more complex
            const results = await pollAnalysisResults(analysisId, 40, 8000); // More retries, longer interval
            const processedResults = processResults(results);
            cache.set(fileHash, processedResults);
            return processedResults;
        } catch (error) {
            console.error('PDF scan failed:', error);
            throw error;
        }
    }

    async function extractPdfContent(file) {
        return new Promise((resolve, reject) => {
            if (!window.pdfjsLib) {
                console.log('PDF.js not detected, loading dynamically...');
                
                // Try to load PDF.js dynamically if not available
                const script = document.createElement('script');
                script.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.min.js';
                script.onload = () => processPdf();
                script.onerror = () => {
                    console.error('Failed to load PDF.js, continuing without content analysis');
                    resolve({hasJsContent: false});
                };
                document.head.appendChild(script);
            } else {
                processPdf();
            }
            
            function processPdf() {
                const reader = new FileReader();
                reader.onload = async function(event) {
                    try {
                        const arrayBuffer = event.target.result;
                        const pdf = await window.pdfjsLib.getDocument({data: arrayBuffer}).promise;
                        
                        let hasJsContent = false;
                        let suspiciousStrings = 0;
                        
                        // Check document metadata
                        const metadata = await pdf.getMetadata().catch(() => ({}));
                        
                        // Process each page looking for JavaScript
                        for (let i = 1; i <= pdf.numPages; i++) {
                            const page = await pdf.getPage(i);
                            const content = await page.getTextContent();
                            const pageText = content.items.map(item => item.str).join(' ');
                            
                            // Look for JavaScript indicators
                            if (pageText.includes('JavaScript') || 
                                pageText.match(/eval\s*\(/) ||
                                pageText.match(/function\s*\(/) ||
                                pageText.includes('eval(') ||
                                pageText.includes('exec(')) {
                                suspiciousStrings++;
                            }
                        }
                        
                        // Check for JavaScript actions in annotations
                        for (let i = 1; i <= pdf.numPages; i++) {
                            const page = await pdf.getPage(i);
                            const annotations = await page.getAnnotations();
                            
                            for (const annotation of annotations) {
                                if (annotation.subtype === 'Link' && annotation.action) {
                                    if (annotation.action.type === 'JavaScript') {
                                        hasJsContent = true;
                                        break;
                                    }
                                }
                            }
                            
                            if (hasJsContent) break;
                        }
                        
                        // If we found multiple suspicious strings, consider it as having JS
                        if (suspiciousStrings >= 3) {
                            hasJsContent = true;
                        }
                        
                        resolve({
                            hasJsContent,
                            pageCount: pdf.numPages,
                            metadata: metadata.info
                        });
                    } catch (error) {
                        console.error('PDF parsing error:', error);
                        resolve({hasJsContent: false});
                    }
                };
                reader.onerror = reject;
                reader.readAsArrayBuffer(file);
            }
        });
    }

    // Add specialized scan for APK files
    async function scanApkFile(file) {
        try {
            console.log('Starting specialized APK scan for:', file.name);
            
            // Check size limit
            const sizeLimit = CONFIG.TYPE_SIZE_LIMITS['apk'] || 100 * 1024 * 1024;
            if (file.size > sizeLimit) {
                console.warn(`APK file size (${file.size}) exceeds limit (${sizeLimit})`);
            }
            
            // Get file hash
            const fileHash = await calculateFileHash(file);
            console.log('APK hash:', fileHash);

            // Check cache
            if (cache.has(fileHash)) {
                console.log('Cache hit for APK file:', file.name);
                const results = cache.get(fileHash);
                return results;
            }

            // Check for existing analysis
            try {
                const existingResult = await checkExistingFile(fileHash);
                if (existingResult) {
                    console.log('Found existing APK analysis');
                    
                    // Add APK specific info
                    existingResult.fileType = 'apk';
                    existingResult.fileTypeInfo = CONFIG.SUPPORTED_TYPES['apk'];
                    
                    cache.set(fileHash, existingResult);
                    return existingResult;
                }
            } catch (error) {
                console.log('No existing APK analysis found');
            }
            
            // Upload file with special APK parameters
            const uploadUrl = await getUploadUrl();
            const analysisId = await uploadFile(file, uploadUrl);
            console.log('APK uploaded, analysis ID:', analysisId);
            
            // APKs can take longer to analyze, use longer polling
            const results = await pollAnalysisResults(analysisId, 45, 12000); // More retries, longer interval
            const processedResults = processResults(results);
            
            // Add APK-specific information
            processedResults.fileType = 'apk';
            processedResults.fileTypeInfo = CONFIG.SUPPORTED_TYPES['apk'];
            
            // Extract additional APK info if available
            if (results.data && results.data.attributes) {
                const attributes = results.data.attributes;
                
                if (attributes.androguard) {
                    processedResults.androidInfo = {
                        appName: attributes.androguard.app_name,
                        packageName: attributes.androguard.package_name,
                        minSdkVersion: attributes.androguard.min_sdk_version,
                        permissions: attributes.androguard.permissions,
                        activities: attributes.androguard.activities?.length || 0,
                        services: attributes.androguard.services?.length || 0
                    };
                }
                
                if (attributes.packers) {
                    processedResults.packed = attributes.packers.length > 0;
                    processedResults.packers = attributes.packers;
                }
            }
            
            cache.set(fileHash, processedResults);
            return processedResults;
        } catch (error) {
            console.error('APK scan failed:', error);
            throw error;
        }
    }

    // Add specialized scan for document files (DOCX, DOC)
    async function scanDocumentFile(file, fileType) {
        try {
            console.log(`Starting specialized document scan (${fileType}) for:`, file.name);
            
            // Check size limit
            const sizeLimit = CONFIG.TYPE_SIZE_LIMITS[fileType] || 15 * 1024 * 1024;
            if (file.size > sizeLimit) {
                console.warn(`Document file size (${file.size}) exceeds limit (${sizeLimit})`);
            }
            
            // Get file hash
            const fileHash = await calculateFileHash(file);
            console.log('Document hash:', fileHash);

            // Check cache
            if (cache.has(fileHash)) {
                console.log('Cache hit for document file:', file.name);
                const results = cache.get(fileHash);
                return results;
            }

            // Check for existing analysis
            try {
                const existingResult = await checkExistingFile(fileHash);
                if (existingResult) {
                    console.log('Found existing document analysis');
                    
                    // Add document-specific info
                    existingResult.fileType = fileType;
                    existingResult.fileTypeInfo = CONFIG.SUPPORTED_TYPES[fileType];
                    
                    cache.set(fileHash, existingResult);
                    return existingResult;
                }
            } catch (error) {
                console.log('No existing document analysis found');
            }

            // Check for macros if document scan is enabled
            let hasMacros = false;
            if (CONFIG.SUPPORTED_TYPES[fileType]?.contentScan && file.size <= sizeLimit) {
                console.log('Performing document content analysis...');
                try {
                    // For future implementation: detailed document scanning logic
                    // For now, we'll just rely on VirusTotal's analysis
                } catch (error) {
                    console.error('Document content analysis error:', error);
                }
            }
            
            // Upload file
            const uploadUrl = await getUploadUrl();
            const analysisId = await uploadFile(file, uploadUrl);
            console.log('Document uploaded, analysis ID:', analysisId);
            
            // Documents can take longer to analyze
            const results = await pollAnalysisResults(analysisId, 35, 10000);
            const processedResults = processResults(results);
            
            // Add document-specific information
            processedResults.fileType = fileType;
            processedResults.fileTypeInfo = CONFIG.SUPPORTED_TYPES[fileType];
            
            // Extract additional document info if available
            if (results.data && results.data.attributes) {
                const attributes = results.data.attributes;
                
                if (attributes.office_macros) {
                    processedResults.hasMacros = attributes.office_macros.length > 0;
                    processedResults.macroCount = attributes.office_macros.length;
                }
                
                if (attributes.vba_macro_suspicious) {
                    processedResults.suspiciousMacros = attributes.vba_macro_suspicious.length > 0;
                }
            }
            
            cache.set(fileHash, processedResults);
            return processedResults;
        } catch (error) {
            console.error('Document scan failed:', error);
            throw error;
        }
    }

    // Add UI output generation function
    function generateResultUI(scanResult, containerId, options = {}) {
        const container = document.getElementById(containerId);
        if (!container) {
            console.error(`Container with ID "${containerId}" not found`);
            return;
        }
        
        // Default options
        const uiOptions = {
            theme: options.theme || CONFIG.UI_THEME,
            showDetailed: options.showDetailed !== undefined ? options.showDetailed : CONFIG.SHOW_DETAILED_RESULTS,
            animate: options.animate !== undefined ? options.animate : true,
            showVTLink: options.showVTLink !== undefined ? options.showVTLink : true
        };
        
        // Theme variables
        const isDark = uiOptions.theme === 'dark';
        const colors = {
            safe: isDark ? '#4caf50' : '#43a047',
            warning: isDark ? '#ff9800' : '#f57c00',
            danger: isDark ? '#f44336' : '#d32f2f',
            background: isDark ? '#292929' : '#ffffff',
            cardBg: isDark ? '#373737' : '#f5f5f5',
            text: isDark ? '#e0e0e0' : '#212121',
            border: isDark ? '#444444' : '#e0e0e0',
            shadowColor: isDark ? 'rgba(0,0,0,0.5)' : 'rgba(0,0,0,0.2)'
        };
        
        // Clear previous content
        container.innerHTML = '';
        container.style.fontFamily = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif';
        
        // Create main container
        const mainCard = document.createElement('div');
        mainCard.className = 'vt-result-card';
        mainCard.style.cssText = `
            background-color: ${colors.cardBg};
            border-radius: 8px;
            box-shadow: 0 4px 8px ${colors.shadowColor};
            padding: 20px;
            margin-bottom: 20px;
            color: ${colors.text};
            border: 1px solid ${colors.border};
            transition: all 0.3s ease;
        `;
        
        if (uiOptions.animate) {
            mainCard.style.animation = 'vtFadeIn 0.5s ease-in-out';
            const styleTag = document.createElement('style');
            styleTag.textContent = `
                @keyframes vtFadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                @keyframes vtPulse {
                    0% { transform: scale(1); }
                    50% { transform: scale(1.05); }
                    100% { transform: scale(1); }
                }
            `;
            document.head.appendChild(styleTag);
        }
        
        // Get status info
        const isSafe = scanResult.isSafe;
        const maliciousPercent = scanResult.maliciousPercentage || 0;
        const detectionCount = scanResult.detectionCount || 0;
        const totalEngines = scanResult.totalEngines || 0;
        const stats = scanResult.detailedResults?.stats || {};
        
        // Status indicator
        const statusHeader = document.createElement('div');
        statusHeader.className = 'vt-status-header';
        statusHeader.style.cssText = `
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        `;
        
        const statusIcon = document.createElement('div');
        statusIcon.className = 'vt-status-icon';
        
        let statusColor, statusText;
        if (isSafe) {
            statusColor = colors.safe;
            statusText = 'File is safe';
        } else if (maliciousPercent < 15) {
            statusColor = colors.warning;
            statusText = 'Suspicious file';
        } else {
            statusColor = colors.danger;
            statusText = 'Malicious file detected';
        }
        
        statusIcon.style.cssText = `
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background-color: ${statusColor};
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 15px;
            flex-shrink: 0;
        `;
        
        const iconSymbol = document.createElement('span');
        iconSymbol.style.cssText = `
            color: white;
            font-size: 24px;
            font-weight: bold;
        `;
        iconSymbol.innerHTML = isSafe ? '✓' : '!';
        statusIcon.appendChild(iconSymbol);
        
        const statusInfo = document.createElement('div');
        statusInfo.className = 'vt-status-info';
        
        const statusTitle = document.createElement('h2');
        statusTitle.style.cssText = `
            margin: 0 0 5px 0;
            font-size: 20px;
            font-weight: 600;
        `;
        statusTitle.textContent = statusText;
        
        const fileInfo = document.createElement('p');
        fileInfo.style.cssText = `
            margin: 0;
            font-size: 14px;
            color: ${isDark ? '#aaaaaa' : '#757575'};
        `;
        
        if (scanResult.detailedResults) {
            const fileType = scanResult.isPdf ? 'PDF Document' : (scanResult.detailedResults.fileType || 'File');
            fileInfo.textContent = `${fileType} • ${totalEngines} security vendors checked`;
        }
        
        statusInfo.appendChild(statusTitle);
        statusInfo.appendChild(fileInfo);
        
        statusHeader.appendChild(statusIcon);
        statusHeader.appendChild(statusInfo);
        
        // Results gauge
        const gaugeContainer = document.createElement('div');
        gaugeContainer.className = 'vt-gauge-container';
        gaugeContainer.style.cssText = `
            padding: 20px 0;
            text-align: center;
        `;
        
        const gaugeWrapper = document.createElement('div');
        gaugeWrapper.style.cssText = `
            position: relative;
            width: 150px;
            height: 150px;
            margin: 0 auto;
        `;
        
        const createSvgGauge = () => {
            const svgNS = "http://www.w3.org/2000/svg";
            const svg = document.createElementNS(svgNS, "svg");
            svg.setAttribute("width", "150");
            svg.setAttribute("height", "150");
            svg.setAttribute("viewBox", "0 0 100 100");
            
            // Background circle
            const backgroundCircle = document.createElementNS(svgNS, "circle");
            backgroundCircle.setAttribute("cx", "50");
            backgroundCircle.setAttribute("cy", "50");
            backgroundCircle.setAttribute("r", "45");
            backgroundCircle.setAttribute("fill", "none");
            backgroundCircle.setAttribute("stroke", isDark ? "#444444" : "#e0e0e0");
            backgroundCircle.setAttribute("stroke-width", "10");
            svg.appendChild(backgroundCircle);
            
            // Calculate the percentage for the progress circle
            const safePercent = 100 - maliciousPercent;
            const circumference = 2 * Math.PI * 45;
            const offset = circumference - (safePercent / 100 * circumference);
            
            // Progress circle
            const progressCircle = document.createElementNS(svgNS, "circle");
            progressCircle.setAttribute("cx", "50");
            progressCircle.setAttribute("cy", "50");
            progressCircle.setAttribute("r", "45");
            progressCircle.setAttribute("fill", "none");
            progressCircle.setAttribute("stroke", statusColor);
            progressCircle.setAttribute("stroke-width", "10");
            progressCircle.setAttribute("stroke-linecap", "round");
            progressCircle.setAttribute("transform", "rotate(-90 50 50)");
            progressCircle.setAttribute("stroke-dasharray", circumference);
            progressCircle.setAttribute("stroke-dashoffset", offset);
            
            if (uiOptions.animate) {
                progressCircle.setAttribute("style", "transition: stroke-dashoffset 1s ease-in-out");
            }
            
            svg.appendChild(progressCircle);
            
            return svg;
        };
        
        gaugeWrapper.appendChild(createSvgGauge());
        
        const percentText = document.createElement('div');
        percentText.style.cssText = `
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 24px;
            font-weight: bold;
            color: ${statusColor};
        `;
        percentText.textContent = `${Math.round(100 - maliciousPercent)}%`;
        
        const percentLabel = document.createElement('div');
        percentLabel.style.cssText = `
            position: absolute;
            top: 65%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 14px;
            color: ${isDark ? '#aaaaaa' : '#757575'};
        `;
        percentLabel.textContent = 'Safe score';
        
        gaugeWrapper.appendChild(percentText);
        gaugeWrapper.appendChild(percentLabel);
        gaugeContainer.appendChild(gaugeWrapper);
        
        // Detection stats
        const detectionStats = document.createElement('div');
        detectionStats.className = 'vt-detection-stats';
        detectionStats.style.cssText = `
            display: flex;
            justify-content: center;
            margin: 20px 0;
            gap: 15px;
            flex-wrap: wrap;
        `;
        
        const createStatBox = (label, value, color) => {
            const statBox = document.createElement('div');
            statBox.className = 'vt-stat-box';
            statBox.style.cssText = `
                background-color: ${isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.03)'};
                border-radius: 6px;
                padding: 12px 15px;
                text-align: center;
                min-width: 80px;
            `;
            
            const statValue = document.createElement('div');
            statValue.style.cssText = `
                font-size: 18px;
                font-weight: bold;
                color: ${color || colors.text};
                margin-bottom: 5px;
            `;
            statValue.textContent = value;
            
            const statLabel = document.createElement('div');
            statLabel.style.cssText = `
                font-size: 12px;
                color: ${isDark ? '#aaaaaa' : '#757575'};
            `;
            statLabel.textContent = label;
            
            statBox.appendChild(statValue);
            statBox.appendChild(statLabel);
            return statBox;
        };
        
        // Add stat boxes
        detectionStats.appendChild(createStatBox('Malicious', stats.malicious || 0, colors.danger));
        detectionStats.appendChild(createStatBox('Suspicious', stats.suspicious || 0, colors.warning));
        detectionStats.appendChild(createStatBox('Clean', stats.harmless || 0, colors.safe));
        detectionStats.appendChild(createStatBox('Undetected', stats.undetected || 0));
        
        // Add PDF-specific information if applicable
        if (scanResult.isPdf) {
            const pdfAlert = document.createElement('div');
            pdfAlert.className = 'vt-pdf-alert';
            pdfAlert.style.cssText = `
                background-color: ${scanResult.pdfRisk ? 'rgba(244,67,54,0.1)' : 'rgba(33,150,243,0.1)'};
                border-left: 4px solid ${scanResult.pdfRisk ? colors.danger : '#2196f3'};
                padding: 12px 15px;
                margin: 15px 0;
                border-radius: 4px;
            `;
            
            const pdfIcon = document.createElement('i');
            pdfIcon.style.cssText = `
                font-style: normal;
                margin-right: 10px;
                font-weight: bold;
            `;
            pdfIcon.textContent = 'PDF';
            
            const pdfText = document.createElement('span');
            if (scanResult.pdfRisk) {
                pdfText.textContent = 'This PDF contains JavaScript, which can potentially be malicious.';
            } else {
                pdfText.textContent = 'PDF document analyzed with enhanced security checks.';
            }
            
            pdfAlert.appendChild(pdfIcon);
            pdfAlert.appendChild(pdfText);
            
            mainCard.appendChild(statusHeader);
            mainCard.appendChild(pdfAlert);
            mainCard.appendChild(gaugeContainer);
            mainCard.appendChild(detectionStats);
        } else {
            mainCard.appendChild(statusHeader);
            mainCard.appendChild(gaugeContainer);
            mainCard.appendChild(detectionStats);
        }
        
        // Add VirusTotal link if enabled
        if (uiOptions.showVTLink && scanResult.detailedResults && scanResult.detailedResults.sha256) {
            const vtLink = document.createElement('div');
            vtLink.style.cssText = `
                text-align: center;
                margin-top: 15px;
                font-size: 13px;
            `;
            
            const link = document.createElement('a');
            link.href = `https://www.virustotal.com/gui/file/${scanResult.detailedResults.sha256}`;
            link.target = '_blank';
            link.style.cssText = `
                color: ${isDark ? '#64b5f6' : '#1976d2'};
                text-decoration: none;
            `;
            link.textContent = 'View complete analysis on VirusTotal';
            
            vtLink.appendChild(link);
            mainCard.appendChild(vtLink);
        }
        
        // Add detailed results toggle if applicable
        if (uiOptions.showDetailed && scanResult.detailedResults) {
            const detailsToggle = document.createElement('div');
            detailsToggle.className = 'vt-details-toggle';
            detailsToggle.style.cssText = `
                text-align: center;
                margin-top: 20px;
                cursor: pointer;
                padding: 8px;
                font-size: 14px;
                color: ${isDark ? '#64b5f6' : '#1976d2'};
            `;
            detailsToggle.textContent = 'Show technical details';
            
            const detailsContent = document.createElement('div');
            detailsContent.className = 'vt-details-content';
            detailsContent.style.cssText = `
                margin-top: 15px;
                display: none;
                font-size: 13px;
                background-color: ${isDark ? 'rgba(0,0,0,0.2)' : 'rgba(0,0,0,0.03)'};
                padding: 15px;
                border-radius: 4px;
                text-align: left;
                overflow-x: auto;
            `;
            
            const jsonPre = document.createElement('pre');
            jsonPre.style.cssText = `
                margin: 0;
                white-space: pre-wrap;
                word-break: break-word;
                font-family: monospace;
                color: ${isDark ? '#e0e0e0' : '#333333'};
            `;
            
            // Create a simplified version of the scan result for display
            const simplifiedResult = {
                scanId: scanResult.detailedResults.scanId,
                fileType: scanResult.detailedResults.fileType,
                stats: scanResult.detailedResults.stats,
                sha256: scanResult.detailedResults.sha256,
                status: scanResult.detailedResults.status
            };
            
            jsonPre.textContent = JSON.stringify(simplifiedResult, null, 2);
            detailsContent.appendChild(jsonPre);
            
            detailsToggle.addEventListener('click', () => {
                if (detailsContent.style.display === 'none') {
                    detailsContent.style.display = 'block';
                    detailsToggle.textContent = 'Hide technical details';
                } else {
                    detailsContent.style.display = 'none';
                    detailsToggle.textContent = 'Show technical details';
                }
            });
            
            mainCard.appendChild(detailsToggle);
            mainCard.appendChild(detailsContent);
        }
        
        container.appendChild(mainCard);
        return mainCard;
    }

    // Add compact UI output generation function
    function generateCompactResultUI(scanResult, containerId, options = {}) {
        const container = document.getElementById(containerId);
        if (!container) {
            console.error(`Container with ID "${containerId}" not found`);
            return;
        }
        
        // Default options
        const uiOptions = {
            theme: options.theme || CONFIG.UI_THEME,
            animate: options.animate !== undefined ? options.animate : true,
            showFileName: options.showFileName !== undefined ? options.showFileName : true,
            fileNameMaxLength: options.fileNameMaxLength || 30
        };
        
        // Theme variables
        const isDark = uiOptions.theme === 'dark';
        const colors = {
            safe: isDark ? '#4caf50' : '#43a047',
            warning: isDark ? '#ff9800' : '#f57c00',
            danger: isDark ? '#f44336' : '#d32f2f',
            background: isDark ? '#1e1e2f' : '#f8f9fa',
            text: isDark ? '#e0e0e0' : '#212121',
            subtext: isDark ? '#aaaaaa' : '#757575'
        };
        
        // Clear previous content
        container.innerHTML = '';
        
        // Create compact card
        const card = document.createElement('div');
        card.className = 'vt-compact-card';
        card.style.cssText = `
            background-color: ${colors.background};
            border-radius: 6px;
            overflow: hidden;
            font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 350px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.15);
            margin: 0 auto;
        `;
        
        if (uiOptions.animate) {
            card.style.animation = 'vtFadeIn 0.3s ease-in-out';
            const styleTag = document.createElement('style');
            styleTag.textContent = `
                @keyframes vtFadeIn {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            `;
            document.head.appendChild(styleTag);
        }
        
        // Header with status
        const header = document.createElement('div');
        header.style.cssText = `
            padding: 12px;
            text-align: center;
            font-weight: 600;
            border-bottom: 1px solid ${isDark ? '#383838' : '#e0e0e0'};
            background-color: ${isDark ? '#2a2a3c' : '#f0f0f0'};
            color: ${colors.text};
        `;
        header.textContent = 'Scan complete';
        
        // Status content
        const isSafe = scanResult.isSafe;
        const maliciousPercent = scanResult.maliciousPercentage || 0;
        const safetyScore = Math.round(100 - maliciousPercent);
        
        const contentSection = document.createElement('div');
        contentSection.style.cssText = `
            padding: 15px;
            text-align: center;
        `;
        
        // Status donut
        const donutContainer = document.createElement('div');
        donutContainer.style.cssText = `
            position: relative;
            width: 90px;
            height: 90px;
            margin: 0 auto 10px auto;
        `;
        
        let statusColor;
        if (isSafe) {
            statusColor = colors.safe;
        } else if (maliciousPercent < 15) {
            statusColor = colors.warning;
        } else {
            statusColor = colors.danger;
        }
        
        const createSvgDonut = () => {
            const svgNS = "http://www.w3.org/2000/svg";
            const svg = document.createElementNS(svgNS, "svg");
            svg.setAttribute("width", "90");
            svg.setAttribute("height", "90");
            svg.setAttribute("viewBox", "0 0 36 36");
            
            const circleTrack = document.createElementNS(svgNS, "path");
            circleTrack.setAttribute("d", "M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831");
            circleTrack.setAttribute("fill", "none");
            circleTrack.setAttribute("stroke", isDark ? "#444444" : "#e0e0e0");
            circleTrack.setAttribute("stroke-width", "3");
            svg.appendChild(circleTrack);
            
            // Calculate the percentage for the progress circle
            const percent = safetyScore;
            const dasharray = percent * 0.01 * 100;
            
            const circleFill = document.createElementNS(svgNS, "path");
            circleFill.setAttribute("d", "M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831");
            circleFill.setAttribute("fill", "none");
            circleFill.setAttribute("stroke", statusColor);
            circleFill.setAttribute("stroke-width", "3");
            circleFill.setAttribute("stroke-dasharray", `${dasharray}, 100`);
            circleFill.setAttribute("stroke-linecap", "round");
            
            if (uiOptions.animate) {
                circleFill.setAttribute("style", "transition: stroke-dasharray 0.8s ease-in-out");
            }
            
            svg.appendChild(circleFill);
            
            return svg;
        };
        
        donutContainer.appendChild(createSvgDonut());
        
        const percentText = document.createElement('div');
        percentText.style.cssText = `
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 20px;
            font-weight: bold;
            color: ${statusColor};
        `;
        percentText.textContent = `${safetyScore}%`;
        
        const safetyLabel = document.createElement('div');
        safetyLabel.style.cssText = `
            font-size: 14px;
            color: ${colors.text};
            margin-top: 5px;
            font-weight: 600;
        `;
        safetyLabel.textContent = 'Safe';
        
        donutContainer.appendChild(percentText);
        contentSection.appendChild(donutContainer);
        contentSection.appendChild(safetyLabel);
        
        // File name if requested
        if (uiOptions.showFileName && scanResult.fileName) {
            let fileName = scanResult.fileName;
            const fileSize = scanResult.fileSize ? ` (${formatFileSize(scanResult.fileSize)})` : '';
            
            // Truncate if too long
            if (fileName.length > uiOptions.fileNameMaxLength) {
                const ext = fileName.lastIndexOf('.');
                if (ext > 0) {
                    const extension = fileName.substring(ext);
                    fileName = fileName.substring(0, uiOptions.fileNameMaxLength - extension.length - 3) + '...' + extension;
                } else {
                    fileName = fileName.substring(0, uiOptions.fileNameMaxLength - 3) + '...';
                }
            }
            
            const fileNameEl = document.createElement('div');
            fileNameEl.style.cssText = `
                font-size: 12px;
                color: ${colors.subtext};
                margin-top: 8px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                max-width: 100%;
            `;
            fileNameEl.textContent = fileName + fileSize;
            contentSection.appendChild(fileNameEl);
        }
        
        // Results section
        const resultSection = document.createElement('div');
        resultSection.style.cssText = `
            border-top: 1px solid ${isDark ? '#383838' : '#e0e0e0'};
        `;
        
        // Result summary badge
        const resultBadge = document.createElement('div');
        resultBadge.style.cssText = `
            padding: 10px 15px;
            display: flex;
            align-items: center;
            background-color: ${isSafe ? 'rgba(76, 175, 80, 0.1)' : 'rgba(244, 67, 54, 0.1)'};
            border-left: 3px solid ${isSafe ? colors.safe : colors.danger};
        `;
        
        const resultIcon = document.createElement('div');
        resultIcon.style.cssText = `
            width: 24px;
            height: 24px;
            border-radius: 50%;
            background-color: ${isSafe ? colors.safe : colors.danger};
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 10px;
            font-weight: bold;
            font-size: 14px;
        `;
        resultIcon.innerHTML = isSafe ? '✓' : '!';
        
        const resultText = document.createElement('div');
        resultText.style.cssText = `
            flex: 1;
            font-size: 14px;
            font-weight: 500;
            color: ${colors.text};
        `;
        resultText.textContent = isSafe ? 'Clean File' : 'Potentially Harmful File';
        
        resultBadge.appendChild(resultIcon);
        resultBadge.appendChild(resultText);
        resultSection.appendChild(resultBadge);
        
        // Analysis info
        const analysisInfo = document.createElement('div');
        analysisInfo.style.cssText = `
            padding: 10px 15px;
            font-size: 13px;
            color: ${colors.subtext};
            display: flex;
            align-items: center;
            background-color: ${isDark ? '#262637' : '#f9f9f9'};
        `;
        
        const infoIcon = document.createElement('div');
        infoIcon.style.cssText = `
            margin-right: 10px;
            color: ${colors.subtext};
            font-size: 16px;
        `;
        infoIcon.innerHTML = '🔍';
        
        const stats = scanResult.detailedResults?.stats || {};
        const fileType = scanResult.isPdf ? 'application/pdf' : (scanResult.detailedResults?.fileType || 'unknown');
        const detectionRate = `${stats.malicious || 0}/${scanResult.totalEngines || 0}`;
        
        const infoText = document.createElement('div');
        infoText.style.cssText = `
            flex: 1;
        `;
        infoText.textContent = `File type: ${fileType} | Detection rate: ${detectionRate}`;
        
        analysisInfo.appendChild(infoIcon);
        analysisInfo.appendChild(infoText);
        resultSection.appendChild(analysisInfo);
        
        // Assemble card
        card.appendChild(header);
        card.appendChild(contentSection);
        card.appendChild(resultSection);
        container.appendChild(card);
        
        return card;
    }
    
    // Helper function to format file size
    function formatFileSize(bytes) {
        if (!bytes) return '';
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + sizes[i];
    }

    // Create and expose the FileChecker object
    const FileChecker = {
        scanFile,
        checkAnalysisResults,
        pollAnalysisResults,
        isFileSafe,
        testApiKey,
        uploadFiles, // Expose the batch upload function
        scanPdfFile, // Expose PDF-specific scan
        scanApkFile, // Expose APK-specific scan
        scanDocumentFile, // Expose document-specific scan
        getFileType, // Expose file type detection
        CONFIG,
        clearCache: cache.clear.bind(cache), // Add method to clear cache
        reload: reloadExtension, // Add explicit reload method
        isProcessing: () => isProcessing, // Expose processing state
        forceUnstick: () => {  // Add method to force unstick
            if (isProcessing) {
                console.log('Force unsticking processing state');
                isProcessing = false;
                if (stuckTimeoutId) {
                    clearTimeout(stuckTimeoutId);
                    stuckTimeoutId = null;
                }
                
                // Abort all pending requests
                const pendingRequests = window.FileChecker._pendingRequests || [];
                for (const controller of pendingRequests) {
                    try {
                        controller.abort();
                    } catch (e) {
                        console.warn('Error aborting request during force unstick:', e);
                    }
                }
                window.FileChecker._pendingRequests = [];
                
                // Notify UI that operation was unstuck
                window.dispatchEvent(new CustomEvent('operationUnstuck', {
                    detail: { timestamp: Date.now() }
                }));
                
                reloadExtension();
            }
        },
        displayResults: generateResultUI, // Expose UI generator function
        displayCompactResults: generateCompactResultUI, // Expose compact UI generator
        _pendingRequests: [] // Track pending requests for clean reloads
    };

    // Expose FileChecker to window object
    window.FileChecker = FileChecker;

    // Add global error handler for unhandled promises
    window.addEventListener('unhandledrejection', (event) => {
        console.error('Unhandled promise rejection:', event.reason);
        if (isProcessing) {
            console.log('Unhandled promise detected during processing, forcing reload');
            FileChecker.forceUnstick();
        }
    });

    // Add handler for stuck upload detection on UI side
    window.addEventListener('uploadStuck', (event) => {
        console.warn('Upload appears to be stuck:', event.detail);
        if (isProcessing) {
            console.log('Forcing unstick due to UI timeout');
            FileChecker.forceUnstick();
        }
    });

    // Track activity to prevent false stuck detection
    window.addEventListener('uploadStarted', () => {
        updateActivityTimestamp();
    });

    window.addEventListener('uploadComplete', () => {
        updateActivityTimestamp();
    });

    // Add automatic recovery check that runs periodically
    setInterval(() => {
        if (isStuck()) {
            console.warn('Automatic stuck detection triggered - recovering');
            FileChecker.forceUnstick();
        }
    }, 15000); // Check every 15 seconds

    // Add event listener for browser/tab closedown to clean up resources
    window.addEventListener('beforeunload', () => {
        if (isProcessing) {
            console.log('Page unloading while processing, cleaning up');
            FileChecker.forceUnstick();
        }
    });

    // Initialize when the script loads
    console.log('FileChecker module loaded and initialized with PDF support and anti-stuck protection');
    window.dispatchEvent(new CustomEvent('fileCheckerReady', {
        detail: { success: true, initialLoad: true }
    }));

    // Initialize timestamp tracking
    window.FileChecker._lastActivityTimestamp = Date.now();

    // Enhanced final result processing
    function processResults(data) {
        try {
            console.log('Processing scan results');
            const attributes = data.data.attributes;
            const stats = attributes.stats || attributes.last_analysis_stats;

            if (!stats) {
                console.error('No stats in result data:', data);
                throw new Error('No analysis statistics available');
            }

            // Calculate total engines and percentages
            const totalEngines = (stats.malicious || 0) + (stats.suspicious || 0) + 
                               (stats.undetected || 0) + (stats.harmless || 0);
            
            const maliciousPercentage = totalEngines > 0 ? 
                Math.round(((stats.malicious || 0) + (stats.suspicious || 0)) / totalEngines * 100) : 0;
            
            // Get file type
            const fileType = attributes.type_description || attributes.type_tag || 'Unknown';
            
            // Determine if file is safe based on stricter criteria
            let isSafe = false;
            
            // For APK files, use stricter criteria
            if (fileType.toLowerCase().includes('apk') || fileType.toLowerCase().includes('android')) {
                // APKs are considered unsafe if there are ANY malicious or suspicious findings
                isSafe = stats.malicious === 0 && stats.suspicious === 0;
            } else {
                // For other files, allow a small threshold
                const maliciousCount = (stats.malicious || 0);
                const suspiciousCount = (stats.suspicious || 0);
                
                // Consider safe only if:
                // 1. No malicious findings
                // 2. At most 1 suspicious finding
                // 3. Malicious percentage is less than 2%
                isSafe = maliciousCount === 0 && 
                        suspiciousCount <= 1 && 
                        maliciousPercentage < 2;
            }
            
            const result = {
                status: 'completed',
                stats: stats,
                isSafe: isSafe,
                maliciousPercentage: maliciousPercentage,
                detectionCount: (stats.malicious || 0) + (stats.suspicious || 0),
                totalEngines: totalEngines,
                scanId: data.data.id,
                sha256: attributes.sha256 || data.data.id,
                detailedResults: {
                    fileType: fileType,
                    stats: stats,
                    scanId: data.data.id,
                    sha256: attributes.sha256 || data.data.id,
                    status: 'completed'
                }
            };

            // Add detailed scan info if available
            if (attributes.last_analysis_results) {
                result.detailedResults.engineResults = {};
                Object.entries(attributes.last_analysis_results).forEach(([vendor, info]) => {
                    result.detailedResults.engineResults[vendor] = {
                        result: info.result || 'unknown',
                        category: info.category || 'undetected',
                        method: info.method || 'unknown',
                        engine_name: info.engine_name || vendor
                    };
                });
            }

            console.log('Processed results:', result);
            return result;
        } catch (error) {
            console.error('Error processing results:', error);
            throw error;
        }
    }

    // Check if the scanner is in a stuck state
    function isStuck() {
        return isProcessing && Date.now() - window.FileChecker._lastActivityTimestamp > CONFIG.STUCK_TIMEOUT;
    }

    // Update activity timestamp to prevent false stuck detection
    function updateActivityTimestamp() {
        window.FileChecker._lastActivityTimestamp = Date.now();
    }
})(); 