/**
 * dashboardManager.js
 * Handles dashboard visualization and updates for the SentinelAI dashboard
 */

// Chart objects for global reference
let threatActivityChart;
let threatOriginsChart;
let cpuChart;
let memoryChart;
let networkChart;
let anomalyChart;

// Track charts for consistent updates
const charts = {
    activityChart: null,
    originsChart: null
};

/**
 * Initialize all charts and visualizations
 */
function initCharts() {
    console.log('Initializing all dashboard charts');
    
    try {
        // Initialize the threat activity chart
        initThreatActivityChart();
        
        // Initialize the threat origins chart
        initThreatOriginsChart();
        
        // Initialize any other charts
        initSystemResourceCharts();
        
        console.log('All charts initialized successfully');
        return true;
    } catch (error) {
        console.error('Error initializing charts:', error);
        return false;
    }
}

/**
 * Initialize the threat activity chart
 * @returns {boolean} - Whether the chart was successfully initialized
 */
function initThreatActivityChart() {
    console.log('Initializing threat activity chart...');
    
    try {
        // Check if Chart is defined
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded - cannot initialize threat activity chart');
            return false;
        }
        
        // Get the chart canvas
        const chartCanvas = document.getElementById('threatChart');
        if (!chartCanvas) {
            console.error('Threat activity chart canvas not found (ID: threatChart)');
            return false;
        }
        
        // Destroy existing chart if it exists
        if (charts.activityChart) {
            charts.activityChart.destroy();
        }
        
        // Initial data - will be updated with real data
        const initialData = {
            labels: ['00:00', '01:00', '02:00', '03:00', '04:00', '05:00'],
            datasets: [{
                label: 'Threats',
                data: [0, 0, 0, 0, 0, 0],
                borderColor: 'rgba(255, 99, 132, 1)',
                backgroundColor: 'rgba(255, 99, 132, 0.2)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        };
        
        // Create the chart
        charts.activityChart = new Chart(chartCanvas, {
            type: 'line',
            data: initialData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                }
            }
        });
        
        console.log('Threat activity chart initialized');
        return true;
    } catch (error) {
        console.error('Error initializing threat activity chart:', error);
        return false;
    }
}

/**
 * Initialize the threat origins chart
 * @returns {boolean} - Whether the chart was successfully initialized
 */
function initThreatOriginsChart() {
    console.log('Initializing threat origins chart');
    
    try {
        // Check if Chart is defined
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded - cannot initialize threat origins chart');
            return false;
        }
        
        // Get the chart canvas element
        const chartCanvas = document.getElementById('originsChart');
        if (!chartCanvas) {
            console.error('Origins chart canvas not found');
            return false;
        }
        
        // Check if chart already exists and destroy it
        if (charts.originsChart) {
            charts.originsChart.destroy();
        }
        
        // Create the chart with default data
        charts.originsChart = new Chart(chartCanvas, {
            type: 'pie',
            data: {
                labels: ['Unknown'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['#6c757d'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                legend: {
                    position: 'right',
                    labels: {
                        padding: 20,
                        boxWidth: 12
                    }
                },
                tooltips: {
                    callbacks: {
                        label: function(tooltipItem, data) {
                            const dataset = data.datasets[tooltipItem.datasetIndex];
                            const total = dataset.data.reduce((acc, current) => acc + current, 0);
                            const currentValue = dataset.data[tooltipItem.index];
                            const percentage = Math.round((currentValue / total) * 100);
                            return `${data.labels[tooltipItem.index]}: ${percentage}%`;
                        }
                    }
                }
            }
        });
        
        console.log('Origins chart initialized successfully');
        return true;
    } catch (error) {
        console.error('Error initializing threat origins chart:', error);
        return false;
    }
}

/**
 * Populate dashboard with data
 * @param {Array} threatData - Array of threat objects
 */
function populateDashboard(threatData) {
    console.log('Populating dashboard with', threatData.length, 'threats');
    
    try {
        // Update all dashboard components with the new data
        updateThreatActivityChart(threatData);
        updateThreatOriginsChart(threatData);
        updateStats(threatData);
        updateAIMetrics(threatData);
        updateMap(threatData);
        
        console.log('Dashboard updated successfully');
    } catch (error) {
        console.error('Error populating dashboard:', error);
    }
}

/**
 * Update the threat activity chart with new data
 * @param {Array} threatData - Array of threat objects
 */
function updateThreatActivityChart(threatData) {
    try {
        if (!charts.activityChart) {
            console.error('Threat activity chart not initialized');
            // Try to initialize the chart if it doesn't exist
            initThreatActivityChart();
            // Return early to avoid errors, we'll update on next data refresh
            return;
        }
        
        // Count threats by hour
        const hourCounts = Array(24).fill(0);
        
        threatData.forEach(threat => {
            const hour = new Date(threat.timestamp).getHours();
            hourCounts[hour]++;
        });
        
        // Update chart data for Chart.js 2.x
        charts.activityChart.data.datasets[0].data = hourCounts;
        charts.activityChart.update();
        
        console.log('Threat activity chart updated');
    } catch (error) {
        console.error('Error updating threat activity chart:', error);
    }
}

/**
 * Update the threat origins chart
 * @param {Array} threatData - Array of threat objects
 */
function updateThreatOriginsChart(threatData) {
    console.log('Updating threat origins chart');
    
    try {
        // Check if chart exists or initialize it
        if (!charts.originsChart && !initThreatOriginsChart()) {
            console.error('Cannot update threat origins chart - initialization failed');
            return;
        }
        
        // Aggregate threat sources
        const sourceCount = {};
        
        // Count threats by source
        threatData.forEach(threat => {
            const source = threat.source || 'Unknown';
            sourceCount[source] = (sourceCount[source] || 0) + 1;
        });
        
        // Convert to arrays for the chart
        const sources = Object.keys(sourceCount);
        const counts = Object.values(sourceCount);
        
        // Generate colors based on the number of sources
        const colors = [];
        sources.forEach((_, index) => {
            // Create a color based on index
            const hue = (index * 137) % 360; // Golden ratio to spread colors
            colors.push(`hsl(${hue}, 70%, 60%)`);
        });
        
        // Update chart data
        charts.originsChart.data.labels = sources;
        charts.originsChart.data.datasets[0].data = counts;
        charts.originsChart.data.datasets[0].backgroundColor = colors;
        
        // Update the chart
        charts.originsChart.update();
        
        console.log('Origins chart updated with', sources.length, 'sources');
    } catch (error) {
        console.error('Error updating threat origins chart:', error);
    }
}

/**
 * Initialize system resource charts (CPU, Memory, Network)
 */
function initSystemResourceCharts() {
    // Implementation for system resource charts
    console.log('System resource charts initialized');
}

/**
 * Update system resource charts with new data
 */
function updateSystemResourceCharts() {
    // Implementation for updating system resource charts
    console.log('System resource charts updated');
}

/**
 * Update dashboard stats based on threat data
 * @param {Array} threatData - Array of threat objects
 */
function updateStats(threatData) {
    try {
        // Count threats by severity
        let highCount = 0;
        let mediumCount = 0;
        let lowCount = 0;
        let total = threatData.length;
        
        // Calculate response time
        let totalResponseTime = 0;
        let responseTimeCount = 0;
        
        threatData.forEach(threat => {
            if (threat.severity === 'high') highCount++;
            else if (threat.severity === 'medium') mediumCount++;
            else lowCount++;
            
            // If threat has response time data
            if (threat.responseTime) {
                totalResponseTime += threat.responseTime;
                responseTimeCount++;
            }
        });
        
        // Update the UI with the stats
        updateElementText('high-count', highCount);
        updateElementText('medium-count', mediumCount);
        // Using total-count instead of low-count since that's what exists in the HTML
        updateElementText('total-count', total);
        
        // Calculate and update average response time
        const avgResponseTime = responseTimeCount > 0 ? Math.round(totalResponseTime / responseTimeCount) : 0;
        // Using response-time instead of avg-response since that's what exists in the HTML
        updateElementText('response-time', avgResponseTime + 's');
        
        // Update alert count
        const alertCount = threatData.filter(threat => 
            threat.severity === 'high' || (threat.isAnomaly && threat.aiConfidence > 0.8)
        ).length;
        updateElementText('alert-count', alertCount);
        
        console.log('Dashboard stats updated');
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

/**
 * Update AI metrics based on threat data
 * @param {Array} threatData - Array of threat objects
 */
function updateAIMetrics(threatData) {
    console.log('Updating AI metrics');
    
    try {
        // Count AI-analyzed threats
        const analyzedCount = threatData.filter(threat => threat.ai_analyzed).length;
        
        // Count anomalies detected
        const anomalyCount = threatData.filter(threat => 
            threat.ai_analyzed && (threat.ai_anomaly_score > 0.7 || threat.isAnomaly)
        ).length;
        
        // Count threats with pattern matches
        const patternMatchCount = threatData.filter(threat => 
            threat.ai_analyzed && threat.ai_pattern_match
        ).length;
        
        // Update UI elements with the counts using the correct element IDs
        const analyzedElement = document.getElementById('ai-analyzed-count');
        const anomalyElement = document.getElementById('ai-anomalies');
        const patternElement = document.getElementById('ai-patterns');
        
        if (analyzedElement) {
            analyzedElement.textContent = analyzedCount;
        } else {
            console.warn('AI analyzed count element not found (ID: ai-analyzed-count)');
        }
        
        if (anomalyElement) {
            anomalyElement.textContent = anomalyCount;
        } else {
            console.warn('AI anomalies element not found (ID: ai-anomalies)');
        }
        
        if (patternElement) {
            patternElement.textContent = patternMatchCount;
        } else {
            console.warn('AI patterns element not found (ID: ai-patterns)');
        }
        
        console.log('AI metrics updated');
    } catch (error) {
        console.error('Error updating AI metrics:', error);
    }
}

/**
 * Update the map with threat locations
 * @param {Array} threatData - Array of threat objects
 */
function updateMap(threatData) {
    console.log('Updating map with threat locations');
    
    // Check if window.updateMapMarkers exists (it might be defined in main.js)
    if (typeof window.updateMapMarkers !== 'function') {
        console.error('updateMapMarkers function not found');
        return;
    }
    
    try {
        // Get threats with valid coordinates
        const validThreats = threatData.filter(threat => 
            threat.latitude && threat.longitude &&
            !isNaN(threat.latitude) && !isNaN(threat.longitude)
        );
        
        if (validThreats.length === 0) {
            console.warn('No threats with valid coordinates found');
        }
        
        // Call the map update function from main.js
        window.updateMapMarkers(validThreats);
    } catch (error) {
        console.error('Error updating map:', error);
    }
}

/**
 * Helper function to safely update element text content
 * @param {string} elementId - ID of the element to update
 * @param {*} value - New text value
 */
function updateElementText(elementId, value) {
    try {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
        } else {
            console.warn(`Element with ID "${elementId}" not found for updating text to "${value}"`);
        }
    } catch (error) {
        console.error(`Error updating element text for "${elementId}"`, error);
    }
}

/**
 * Add a new event to the timeline
 * @param {Object} threat - Threat object to add to timeline
 */
function addTimelineEvent(threat) {
    const timeline = document.getElementById('timeline');
    if (!timeline) {
        console.error('Timeline element not found');
        return;
    }
    
    const timelineItem = document.createElement('div');
    timelineItem.className = 'timeline-item';
    
    const severityClass = threat.severity === 'high' ? 'danger' : 
                          threat.severity === 'medium' ? 'warning' : 'info';
    
    const formattedTime = formatDateTime(threat.timestamp);
    
    timelineItem.innerHTML = `
        <div class="timeline-marker bg-${severityClass}"></div>
        <div class="timeline-content">
            <h6 class="mb-1">${threat.type || 'Unknown Threat'}</h6>
            <p class="mb-0 small text-muted">${formattedTime}</p>
            <p class="mb-0 small">${threat.source} → ${threat.target}</p>
        </div>
    `;
    
    timeline.appendChild(timelineItem);
}

/**
 * Format a date/time string
 * @param {string} dateString - ISO date string
 * @returns {string} - Formatted date/time
 */
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Export functions for other modules
window.DashboardManager = {
    initCharts,
    populateDashboard,
    updateStats,
    updateAIMetrics
};
