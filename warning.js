document.addEventListener('DOMContentLoaded', function() {
    // Get URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const blockedUrl = urlParams.get('url');
    const detections = urlParams.get('detections');
    const category = urlParams.get('category');

    // Update UI with blocked URL details
    document.getElementById('blocked-url').textContent = blockedUrl || 'Unknown URL';
    document.getElementById('detection-count').textContent = detections ? `${detections} security engines` : 'Multiple security engines';
    document.getElementById('category').textContent = category || 'Malicious Website';

    // Handle theme
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.body.setAttribute('data-theme', savedTheme);
    }

    // Handle go back button
    document.getElementById('go-back').addEventListener('click', function() {
        window.history.back();
    });

    // Handle add to exceptions button
    document.getElementById('add-exception').addEventListener('click', function() {
        chrome.runtime.sendMessage({ 
            action: 'addException', 
            url: blockedUrl 
        }, function(response) {
            if (response.success) {
                // Redirect to the previously blocked URL
                window.location.href = blockedUrl;
            }
        });
    });
}); 