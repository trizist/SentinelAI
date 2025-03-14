/**
 * threatManager.js
 * Handles all threat-related functionality for the SentinelAI dashboard
 */

// Global threats array to store all loaded threats
let threats = [];

/**
 * Add a new threat to the dashboard
 * @param {Object} threat - The threat object to add
 */
function addThreat(threat) {
    // Create a new card element
    const card = document.createElement('div');
    card.className = 'card mb-3 threat-card';
    card.id = `threat-${threat.id}`;
    
    let formattedTime;
    if (threat.timestamp) {
        // Check if timestamp is already a Date object
        if (threat.timestamp instanceof Date) {
            formattedTime = threat.timestamp.toLocaleTimeString();
        } else if (typeof threat.timestamp === 'string') {
            // Handle different timestamp formats
            try {
                if (threat.timestamp.includes('T')) {
                    // ISO format
                    formattedTime = new Date(threat.timestamp).toLocaleTimeString();
                } else {
                    // Custom format like "03/03-21:25:54.942969"
                    // Extract the time part
                    const timePart = threat.timestamp.split('-')[1] || threat.timestamp;
                    formattedTime = timePart.split('.')[0]; // Remove microseconds
                }
            } catch (e) {
                formattedTime = threat.timestamp; // Use as-is if parsing fails
            }
        } else {
            formattedTime = "Unknown";
        }
    } else {
        formattedTime = "Unknown";
    }
    
    // Get behavior label
    let behaviorLabel = threat.behavior || "Unknown";
    behaviorLabel = behaviorLabel.replace(/_/g, ' ');
    
    // Get snort signature if available
    let signatureName = "";
    if (threat.additional_data && threat.additional_data.snort_signature_name) {
        signatureName = `<span class="threat-detail">Signature: ${threat.additional_data.snort_signature_name}</span><br>`;
    }
    
    card.innerHTML = `
        <div class="card-header ${threat.severity?.toLowerCase() || 'normal'}">
            ${behaviorLabel} 
            <span class="severity-badge badge bg-${threat.severity === 'HIGH' ? 'danger' : threat.severity === 'MEDIUM' ? 'warning' : 'info'}">${threat.severity || 'NORMAL'}</span>
        </div>
        <div class="card-body">
            <h6 class="card-title">Source: ${threat.source_ip}</h6>
            <p class="card-text">
                <span class="threat-detail">Target: ${threat.destination_ip || 'Unknown'}</span><br>
                <span class="threat-detail">Protocol: ${threat.protocol || 'Unknown'}</span><br>
                <span class="threat-detail">Time: ${formattedTime}</span><br>
                ${signatureName}
                <span class="threat-detail">Confidence: ${threat.confidence ? Math.round(threat.confidence * 100) + '%' : 'N/A'}</span>
            </p>
            <div class="card-actions">
                <button class="btn btn-sm btn-outline-primary resolve-threat" data-threat-id="${threat.id}">Resolve</button>
                <button class="btn btn-sm btn-outline-danger ms-2 block-threat" data-threat-id="${threat.id}">Block</button>
                <button class="btn btn-sm btn-outline-warning ms-2 escalate-threat" data-threat-id="${threat.id}">Escalate</button>
                <button class="btn btn-sm btn-outline-info ms-2 view-threat-details" data-threat-id="${threat.id}">View Details</button>
            </div>
        </div>
    `;
    
    // Get the threat list container
    const threatList = document.getElementById('threat-list');
    
    // Add to the top of the list
    if (threatList.firstChild) {
        threatList.insertBefore(card, threatList.firstChild);
    } else {
        threatList.appendChild(card);
    }
    
    // Limit displayed threats to 5
    if (threatList.children.length > 5) {
        threatList.removeChild(threatList.lastChild);
    }
}

/**
 * Filter threats by time range
 * @param {string} range - The time range to filter by ('today', 'week', 'month')
 */
function filterThreatsByTimeRange(range) {
    const now = new Date();
    let filteredThreats = [];
    
    if (range === 'today') {
        // Filter threats from today only
        filteredThreats = threats.filter(threat => {
            const threatDate = new Date(threat.timestamp);
            return threatDate.toDateString() === now.toDateString();
        });
    } else if (range === 'week') {
        // Filter threats from the last 7 days
        const weekAgo = new Date(now);
        weekAgo.setDate(now.getDate() - 7);
        
        filteredThreats = threats.filter(threat => {
            const threatDate = new Date(threat.timestamp);
            return threatDate >= weekAgo;
        });
    } else if (range === 'month') {
        // Filter threats from the last 30 days
        const monthAgo = new Date(now);
        monthAgo.setDate(now.getDate() - 30);
        
        filteredThreats = threats.filter(threat => {
            const threatDate = new Date(threat.timestamp);
            return threatDate >= monthAgo;
        });
    } else {
        // Default: show all threats
        filteredThreats = [...threats];
    }
    
    // Update entire dashboard with filtered threats
    populateDashboard(filteredThreats);
    
    // Update button styles
    updateTimeRangeButtonStyles(range);
}

/**
 * Update time range button styles
 * @param {string} activeRange - The active range button to highlight
 */
function updateTimeRangeButtonStyles(activeRange) {
    // Get all time range buttons
    const todayBtn = document.getElementById('time-range-today');
    const weekBtn = document.getElementById('time-range-week');
    const monthBtn = document.getElementById('time-range-month');
    
    // Remove active class from all buttons
    [todayBtn, weekBtn, monthBtn].forEach(btn => {
        btn.classList.remove('btn-secondary');
        btn.classList.remove('active');
        btn.classList.add('btn-outline-secondary');
    });
    
    // Add active class to the selected button
    let activeButton;
    if (activeRange === 'today') activeButton = todayBtn;
    else if (activeRange === 'week') activeButton = weekBtn;
    else if (activeRange === 'month') activeButton = monthBtn;
    
    if (activeButton) {
        activeButton.classList.remove('btn-outline-secondary');
        activeButton.classList.add('btn-secondary');
        activeButton.classList.add('active');
    }
}

/**
 * Populate the dashboard with threat data
 * @param {Array} threatData - Array of threat objects
 */
function populateDashboard(threatData) {
    // Clear current threats
    const threatsList = document.getElementById('threats-list');
    if (threatsList) {
        threatsList.innerHTML = '';
    }
    
    // Update dashboard components with the threat data
    if (threatData.length > 0) {
        // Add each threat to the list
        threatData.forEach(threat => {
            addThreat(threat);
        });
        
        // Update time range button styles
        updateTimeRangeButtonStyles('all');
    } else {
        // No threats to display
        if (threatsList) {
            threatsList.innerHTML = '<div class="text-center p-4"><p class="text-muted">No threats detected</p></div>';
        }
    }
}

/**
 * Fetch the latest threats from the API
 */
function fetchLatestThreats() {
    // Correct endpoint path for the threats API
    fetch('/api/threats/recent')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok: ' + response.status);
            }
            return response.json();
        })
        .then(data => {
            // Clear existing threats
            threats = [];
            
            // Add each threat from the API
            if (Array.isArray(data)) {
                data.forEach(threat => {
                    // Ensure threat has an ID (generate one if missing)
                    if (!threat.id) {
                        threat.id = 'threat-' + Math.random().toString(36).substring(2, 9);
                    }
                    
                    // Ensure severity is capitalized for consistent display
                    if (threat.severity) {
                        threat.severity = threat.severity.toUpperCase();
                    } else {
                        threat.severity = 'NORMAL';
                    }
                    
                    threats.push(threat);
                });
                
                // Update the entire dashboard with real data
                populateDashboard(threats);
                
                // Show notification
                if (data.length > 0) {
                    Utilities.showNotification(`Loaded ${data.length} threats from API`, 'info');
                } else {
                    Utilities.showNotification('No threats found in the database', 'info');
                }
            } else {
                console.error("Invalid threat data format:", data);
                Utilities.showNotification('Received invalid threat data format from API', 'danger');
            }
        })
        .catch(error => {
            console.error("Error fetching threats:", error);
            Utilities.showNotification('Failed to load threats from API: ' + error.message, 'danger');
        });
}
