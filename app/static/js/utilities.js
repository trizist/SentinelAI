/**
 * utilities.js
 * 
 * Utility functions for the SentinelAI dashboard
 */

/**
 * Show a notification toast to the user
 * @param {string} message - Message to display
 * @param {string} type - Bootstrap alert type (success, info, warning, danger)
 * @param {number} duration - Duration in milliseconds (optional)
 */
function showNotification(message, type = 'info', duration = 5000) {
    console.log(`Notification (${type}): ${message}`);
    
    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.setAttribute('id', toastId);
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    // Find or create toast container
    let toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Add toast to container
    toastContainer.appendChild(toast);
    
    // Initialize and show the toast using Bootstrap
    const bsToast = new bootstrap.Toast(toast, { autohide: true, delay: duration });
    bsToast.show();
    
    // Remove from DOM after hiding
    toast.addEventListener('hidden.bs.toast', function () {
        toast.remove();
    });
}

/**
 * Format a number with K/M/B suffixes for readability
 * @param {number} num - Number to format
 * @param {number} digits - Number of decimal places
 * @returns {string} - Formatted number
 */
function formatNumber(num, digits = 1) {
    if (!num || isNaN(num)) return '0';
    
    const si = [
        { value: 1, symbol: "" },
        { value: 1E3, symbol: "K" },
        { value: 1E6, symbol: "M" },
        { value: 1E9, symbol: "B" }
    ];
    
    const rx = /\.0+$|(\.[0-9]*[1-9])0+$/;
    let i;
    for (i = si.length - 1; i > 0; i--) {
        if (num >= si[i].value) {
            break;
        }
    }
    return (num / si[i].value).toFixed(digits).replace(rx, "$1") + si[i].symbol;
}

/**
 * Format a date/time string 
 * @param {string|Date} dateInput - Date to format
 * @param {boolean} includeTime - Whether to include time
 * @returns {string} - Formatted date
 */
function formatDateTime(dateInput, includeTime = false) {
    if (!dateInput) return 'N/A';
    
    try {
        const date = (typeof dateInput === 'string') ? new Date(dateInput) : dateInput;
        
        if (isNaN(date.getTime())) {
            return dateInput; // Return original if not a valid date
        }
        
        if (includeTime) {
            return date.toLocaleString();
        } else {
            return date.toLocaleDateString();
        }
    } catch (error) {
        console.error('Error formatting date:', error);
        return dateInput; // Return original on error
    }
}

/**
 * Format bytes to human-readable format
 * @param {number} bytes - Number of bytes
 * @param {number} decimals - Number of decimal places
 * @returns {string} - Formatted size string
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Generate a random string ID
 * @param {number} length - Length of the ID
 * @returns {string} - Random ID
 */
function generateId(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

/**
 * Create a debounced function
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} - Debounced function
 */
function debounce(func, wait = 300) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Truncate a string to a certain length and add ellipsis
 * @param {string} str - String to truncate
 * @param {number} maxLength - Maximum length
 * @returns {string} - Truncated string
 */
function truncateString(str, maxLength = 30) {
    if (!str) return '';
    if (str.length <= maxLength) return str;
    return str.substring(0, maxLength) + '...';
}

/**
 * Get a color for a severity level
 * @param {string} severity - Severity level (HIGH, MEDIUM, LOW, etc.)
 * @returns {string} - Bootstrap color class
 */
function getSeverityColor(severity) {
    if (!severity) return 'secondary';
    
    const sev = severity.toUpperCase();
    if (sev === 'HIGH' || sev === 'CRITICAL') return 'danger';
    if (sev === 'MEDIUM' || sev === 'MODERATE') return 'warning';
    if (sev === 'LOW' || sev === 'MINOR') return 'info';
    return 'secondary';
}

/**
 * Get a random item from an array
 * @param {Array} array - Array to pick from
 * @returns {*} - Random item
 */
function getRandomItem(array) {
    if (!array || array.length === 0) return null;
    return array[Math.floor(Math.random() * array.length)];
}

/**
 * Check if an element exists in the DOM
 * @param {string} selector - CSS selector
 * @returns {boolean} - Whether element exists
 */
function elementExists(selector) {
    return document.querySelector(selector) !== null;
}

/**
 * Safely access a deeply nested property in an object
 * @param {Object} obj - Object to access
 * @param {string} path - Dot-notation path to property
 * @param {*} defaultValue - Default value if property doesn't exist
 * @returns {*} - Property value or default
 */
function getNestedProperty(obj, path, defaultValue = null) {
    if (!obj || !path) return defaultValue;
    
    const parts = path.split('.');
    let current = obj;
    
    for (const part of parts) {
        if (current === null || current === undefined || !Object.prototype.hasOwnProperty.call(current, part)) {
            return defaultValue;
        }
        current = current[part];
    }
    
    return current !== undefined ? current : defaultValue;
}

/**
 * Format a datetime
 * @param {string|Date} datetime - Date to format
 * @param {boolean} includeDate - Whether to include the date (default: false)
 * @returns {string} - Formatted date
 */
function formatDateTimeOriginal(datetime, includeDate = false) {
    if (!datetime) return 'Unknown';
    
    let date;
    
    try {
        // Handle string datetime
        if (typeof datetime === 'string') {
            if (datetime.includes('T')) {
                // ISO format
                date = new Date(datetime);
            } else {
                // Custom format like "03/03-21:25:54.942969"
                // Extract the time part
                const parts = datetime.split('-');
                if (parts.length > 1) {
                    date = new Date();
                    const timeParts = parts[1].split(':');
                    date.setHours(parseInt(timeParts[0]));
                    date.setMinutes(parseInt(timeParts[1]));
                    date.setSeconds(parseInt(timeParts[2].split('.')[0]));
                } else {
                    date = new Date(datetime);
                }
            }
        } else if (datetime instanceof Date) {
            date = datetime;
        } else {
            return 'Unknown';
        }
        
        // Format based on preference
        if (includeDate) {
            return date.toLocaleString();
        } else {
            return date.toLocaleTimeString();
        }
    } catch (e) {
        console.error("Error formatting date:", e);
        return String(datetime);
    }
}

/**
 * Debounce function to limit how often a function can be called
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in ms
 * @returns {Function} - Debounced function
 */
function debounceOriginal(func, wait = 300) {
    let timeout;
    
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Format bytes to human readable format
 * @param {number} bytes - Bytes to format
 * @param {number} decimals - Decimal places (default: 2)
 * @returns {string} - Formatted string
 */
function formatBytesOriginal(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Create a throttled function that only invokes the provided function once per wait period
 * @param {Function} func - Function to throttle
 * @param {number} wait - Wait time in ms
 * @returns {Function} - Throttled function
 */
function throttleOriginal(func, wait = 300) {
    let inThrottle = false;
    
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, wait);
        }
    };
}

/**
 * Get color based on severity level
 * @param {string} severity - Severity level ('HIGH', 'MEDIUM', 'LOW')
 * @returns {string} - Bootstrap color class
 */
function getSeverityColorOriginal(severity) {
    switch (severity?.toUpperCase()) {
        case 'HIGH':
            return 'danger';
        case 'MEDIUM':
            return 'warning';
        case 'LOW':
            return 'info';
        default:
            return 'secondary';
    }
}

/**
 * Convert camel case to title case
 * @param {string} text - Text to convert
 * @returns {string} - Title case text
 */
function camelToTitleCaseOriginal(text) {
    if (!text) return '';
    
    const result = text.replace(/([A-Z])/g, ' $1');
    return result.charAt(0).toUpperCase() + result.slice(1);
}

/**
 * Format a number with commas for thousands separators
 * @param {number} number - The number to format
 * @returns {string} - Formatted number string
 */
function formatNumberOriginal(number) {
    if (number === undefined || number === null) {
        return '0';
    }
    return number.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Format a date to a readable string
 * @param {string|Date} date - The date to format
 * @returns {string} - Formatted date string
 */
function formatDateOriginal(date) {
    if (!date) return 'Unknown';
    
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    
    if (isNaN(dateObj.getTime())) {
        return 'Invalid Date';
    }
    
    return dateObj.toLocaleDateString() + ' ' + dateObj.toLocaleTimeString();
}

/**
 * Get a random color with specified opacity
 * @param {number} opacity - Opacity value between 0 and 1
 * @returns {string} - RGBA color string
 */
function getRandomColorOriginal(opacity = 0.7) {
    const r = Math.floor(Math.random() * 256);
    const g = Math.floor(Math.random() * 256);
    const b = Math.floor(Math.random() * 256);
    
    return `rgba(${r}, ${g}, ${b}, ${opacity})`;
}

/**
 * Filter threats by time range
 * @param {string} range - The time range to filter (today, week, month)
 */
function filterThreatsByTimeRangeOriginal(range) {
    // Make sure we have threats to filter
    if (!window.threats || window.threats.length === 0) {
        showNotification('No threats to filter', 'warning');
        return;
    }
    
    const now = new Date();
    let filteredThreats;
    
    if (range === 'today') {
        // Filter threats from today
        filteredThreats = window.threats.filter(threat => {
            if (!threat.timestamp) return false;
            const threatDate = new Date(threat.timestamp);
            return threatDate.toDateString() === now.toDateString();
        });
        showNotification(`Showing threats from today (${filteredThreats.length})`, 'info');
    } else if (range === 'week') {
        // Filter threats from the past week
        const oneWeekAgo = new Date();
        oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
        
        filteredThreats = window.threats.filter(threat => {
            if (!threat.timestamp) return false;
            const threatDate = new Date(threat.timestamp);
            return threatDate >= oneWeekAgo;
        });
        showNotification(`Showing threats from the past week (${filteredThreats.length})`, 'info');
    } else if (range === 'month') {
        // Filter threats from the past month
        const oneMonthAgo = new Date();
        oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
        
        filteredThreats = window.threats.filter(threat => {
            if (!threat.timestamp) return false;
            const threatDate = new Date(threat.timestamp);
            return threatDate >= oneMonthAgo;
        });
        showNotification(`Showing threats from the past month (${filteredThreats.length})`, 'info');
    } else {
        // Invalid range
        showNotification('Invalid time range', 'danger');
        return;
    }
    
    // Update the dashboard with filtered threats
    if (typeof populateDashboard === 'function') {
        populateDashboard(filteredThreats);
    } else {
        console.error('populateDashboard function not available');
    }
}

/**
 * Add an event to the timeline
 * @param {Object} threat - The threat object to add to the timeline
 */
function addTimelineEventOriginal(threat) {
    if (!threat) return;
    
    const timeline = document.getElementById('timeline');
    if (!timeline) return;
    
    const eventTime = threat.timestamp ? new Date(threat.timestamp) : new Date();
    const timeString = eventTime.toLocaleTimeString();
    
    // Create event item HTML
    const eventClass = threat.severity === 'HIGH' ? 'danger' :
                      threat.severity === 'MEDIUM' ? 'warning' : 'info';
                
    const behavior = threat.behavior ? 
                      threat.behavior.replace(/_/g, ' ') : 
                      'Unknown activity';
                
    // Create timeline item
    const timelineItem = document.createElement('div');
    timelineItem.className = `timeline-item`;
    timelineItem.innerHTML = `
        <div class="timeline-badge bg-${eventClass}">
            <i class="bi bi-shield-exclamation"></i>
        </div>
        <div class="timeline-content">
            <span class="time">${timeString}</span>
            <h6 class="mb-1">${behavior}</h6>
            <p class="mb-0 small">From ${threat.source_ip || 'Unknown'} to ${threat.destination_ip || 'Internal network'}</p>
        </div>
    `;
    
    // Add to timeline (prepend to show newest first)
    if (timeline) {
        timeline.prepend(timelineItem);
    }
}

/**
 * Update dashboard statistics based on threat data
 * @param {Array} threatData - Array of threat objects
 */
function updateStatsOriginal(threatData) {
    // Safety check
    if (!threatData) {
        threatData = [];
    }
    
    // Update total threat count
    const totalThreats = document.getElementById('total-threats');
    if (totalThreats) {
        totalThreats.textContent = formatNumberOriginal(threatData.length);
    }
    
    // Count threats by severity
    let highSeverity = 0;
    let mediumSeverity = 0;
    let lowSeverity = 0;
    
    threatData.forEach(threat => {
        if (threat.severity === 'HIGH') {
            highSeverity++;
        } else if (threat.severity === 'MEDIUM') {
            mediumSeverity++;
        } else {
            lowSeverity++;
        }
    });
    
    // Update severity counts
    const highThreats = document.getElementById('high-threats');
    if (highThreats) {
        highThreats.textContent = formatNumberOriginal(highSeverity);
    }
    
    const mediumThreats = document.getElementById('medium-threats');
    if (mediumThreats) {
        mediumThreats.textContent = formatNumberOriginal(mediumSeverity);
    }
    
    const lowThreats = document.getElementById('low-threats');
    if (lowThreats) {
        lowThreats.textContent = formatNumberOriginal(lowSeverity);
    }
    
    // Update blocked count (in a real app, this would be from real data)
    const blockedCount = document.getElementById('blocked-count');
    if (blockedCount) {
        const blocked = Math.floor(threatData.length * 0.8); // Example: 80% of threats are blocked
        blockedCount.textContent = formatNumberOriginal(blocked);
    }
    
    // Update threat list
    updateThreatListOriginal(threatData);
}

/**
 * Update the threat list in the UI
 * @param {Array} threatData - Array of threat objects
 */
function updateThreatListOriginal(threatData) {
    const threatList = document.getElementById('threat-list');
    if (!threatList) return;
    
    // Clear existing list
    threatList.innerHTML = '';
    
    // Check if we have any threats
    if (!threatData || threatData.length === 0) {
        threatList.innerHTML = '<div class="alert alert-info">No threats detected</div>';
        return;
    }
    
    // Add each threat to the list
    threatData.forEach(threat => {
        // Determine severity class
        const severityClass = threat.severity === 'HIGH' ? 'danger' :
                             threat.severity === 'MEDIUM' ? 'warning' : 'info';
                  
        // Format behavior text
        const behavior = threat.behavior ? 
                        threat.behavior.replace(/_/g, ' ') : 
                        'Unknown activity';
                  
        // Create threat card
        const threatCard = document.createElement('div');
        threatCard.className = `card mb-3 threat-card border-${severityClass}`;
        threatCard.id = `threat-${threat.id}`;
        
        // Create card content
        threatCard.innerHTML = `
            <div class="card-header bg-${severityClass} bg-opacity-25 d-flex justify-content-between align-items-center">
                <h6 class="mb-0">${behavior}</h6>
                <span class="badge bg-${severityClass}">${threat.severity || 'UNKNOWN'}</span>
            </div>
            <div class="card-body py-2">
                <div class="row">
                    <div class="col-md-6">
                        <p class="mb-1"><strong>Source:</strong> ${threat.source_ip || 'Unknown'}</p>
                        <p class="mb-1"><strong>Destination:</strong> ${threat.destination_ip || 'Internal network'}</p>
                    </div>
                    <div class="col-md-6">
                        <p class="mb-1"><strong>Protocol:</strong> ${threat.protocol || 'Unknown'}</p>
                        <p class="mb-1"><strong>Time:</strong> ${threat.timestamp ? new Date(threat.timestamp).toLocaleTimeString() : 'Unknown'}</p>
                    </div>
                </div>
            </div>
            <div class="card-footer bg-transparent d-flex justify-content-between py-1">
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-secondary view-threat-details" data-threat-id="${threat.id}">
                        <i class="bi bi-info-circle"></i> Details
                    </button>
                    <button class="btn btn-outline-success resolve-threat" data-threat-id="${threat.id}">
                        <i class="bi bi-check-circle"></i> Resolve
                    </button>
                </div>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-warning block-threat" data-threat-id="${threat.id}">
                        <i class="bi bi-shield"></i> Block
                    </button>
                    <button class="btn btn-outline-danger escalate-threat" data-threat-id="${threat.id}">
                        <i class="bi bi-exclamation-triangle"></i> Escalate
                    </button>
                </div>
            </div>
        `;
        
        // Add to threat list
        if (threatList) {
            threatList.appendChild(threatCard);
        }
    });
}

/**
 * Generate test data for the dashboard when real data is not available
 */
function populateWithTestDataOriginal() {
    console.log('Populating with test data since real data is not available');
    
    // Generate random threats
    const testThreats = [];
    const behaviors = [
        'PORT_SCAN', 'BRUTE_FORCE', 'SQL_INJECTION', 'XSS_ATTEMPT', 
        'COMMAND_INJECTION', 'FILE_INCLUSION', 'DOS_ATTEMPT', 'DATA_EXFILTRATION'
    ];
    
    const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'SMB', 'FTP'];
    const severities = ['HIGH', 'MEDIUM', 'LOW'];
    
    // Generate 20 random threats
    for (let i = 0; i < 20; i++) {
        const now = new Date();
        const randomTimeOffset = Math.floor(Math.random() * 24 * 60 * 60 * 1000);
        const timestamp = new Date(now.getTime() - randomTimeOffset);
        
        testThreats.push({
            id: 'TEST-' + (100000 + i),
            source_ip: `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
            destination_ip: '192.168.1.' + Math.floor(Math.random() * 254 + 1),
            protocol: protocols[Math.floor(Math.random() * protocols.length)],
            behavior: behaviors[Math.floor(Math.random() * behaviors.length)],
            severity: severities[Math.floor(Math.random() * severities.length)],
            timestamp: timestamp.toISOString(),
            additional_data: {
                snort_signature_name: 'Snort Rule ' + (100000 + i),
                port: Math.floor(Math.random() * 65535)
            }
        });
    }
    
    // Store in global variable
    window.threats = testThreats;
    
    // Update dashboard
    populateDashboardOriginal(testThreats);
    
    // Show notification
    showNotification('Using test data (API not available)', 'warning');
}

// Export utility functions to global scope
window.Utilities = {
    showNotification,
    formatNumber,
    formatDateTime,
    formatBytes,
    generateId,
    debounce,
    truncateString,
    getSeverityColor,
    getRandomItem,
    elementExists,
    getNestedProperty,
    formatDateTimeOriginal,
    debounceOriginal,
    formatBytesOriginal,
    throttleOriginal,
    getSeverityColorOriginal,
    camelToTitleCaseOriginal,
    formatNumberOriginal,
    formatDateOriginal,
    getRandomColorOriginal,
    filterThreatsByTimeRangeOriginal,
    addTimelineEventOriginal,
    updateStatsOriginal,
    updateThreatListOriginal,
    populateWithTestDataOriginal
};
