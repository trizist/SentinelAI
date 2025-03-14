/**
 * Refresh AI data
 */
function refreshAIData() {
    console.log('Refreshing AI data from API');
    
    // Add loading indicators
    document.querySelectorAll('[id^="ai-"]').forEach(el => {
        el.classList.add('text-muted');
        el.dataset.originalText = el.textContent;
        el.textContent = 'Loading...';
    });
    
    // Fetch AI stats from the API
    fetch('/api/v1/ai/stats')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Received AI stats:', data);
            
            // Update Azure AI metrics
            const detectionRateElement = document.getElementById('azure-detection-rate');
            if (detectionRateElement) {
                detectionRateElement.textContent = `${data.azure_detection_rate}%`;
            }
            
            const accuracyElement = document.getElementById('azure-accuracy');
            if (accuracyElement) {
                accuracyElement.textContent = `${data.azure_accuracy}%`;
            }
            
            const responseTimeElement = document.getElementById('azure-response-time');
            if (responseTimeElement) {
                responseTimeElement.textContent = `${data.azure_response_time}ms`;
            }
            
            // Update AI stats on the dashboard
            const aiAnalyzedElement = document.getElementById('ai-analyzed-count');
            if (aiAnalyzedElement) {
                aiAnalyzedElement.textContent = data.ai_analyzed || 0;
                aiAnalyzedElement.classList.remove('text-muted');
            }
            
            const anomaliesElement = document.getElementById('ai-anomalies');
            if (anomaliesElement) {
                anomaliesElement.textContent = data.anomalies || 0;
                anomaliesElement.classList.remove('text-muted');
            }
            
            const similarThreatsElement = document.getElementById('ai-similar-threats');
            if (similarThreatsElement) {
                similarThreatsElement.textContent = data.similar_threats || 0;
                similarThreatsElement.classList.remove('text-muted');
            }
            
            const metricsAlertsElement = document.getElementById('ai-metrics-alerts');
            if (metricsAlertsElement) {
                metricsAlertsElement.textContent = data.metrics_alerts || 0;
                metricsAlertsElement.classList.remove('text-muted');
            }
            
            const aiConfidenceElement = document.getElementById('ai-confidence');
            if (aiConfidenceElement) {
                aiConfidenceElement.textContent = `${data.ai_confidence || 0}%`;
                aiConfidenceElement.classList.remove('text-muted');
            }
            
            // Update service health if available
            const serviceHealthElement = document.getElementById('service-health');
            if (serviceHealthElement && data.service_health !== undefined) {
                serviceHealthElement.textContent = `${data.service_health}%`;
                
                // Update health indicator color
                if (data.service_health > 80) {
                    serviceHealthElement.className = 'badge bg-success';
                } else if (data.service_health > 50) {
                    serviceHealthElement.className = 'badge bg-warning';
                } else {
                    serviceHealthElement.className = 'badge bg-danger';
                }
            }
            
            // Check for fallback warning
            if (data.using_fallback) {
                showNotification('Using fallback data: ' + (data.error || 'Azure services unavailable'), 'warning');
            } else {
                showNotification('AI data refreshed successfully', 'success');
            }
        })
        .catch(error => {
            console.error('Error fetching AI stats:', error);
            
            // Restore original values
            document.querySelectorAll('[id^="ai-"]').forEach(el => {
                if (el.dataset.originalText) {
                    el.textContent = el.dataset.originalText;
                }
                el.classList.remove('text-muted');
            });
            
            showNotification('Failed to refresh AI data: ' + error.message, 'danger');
        });
}

/**
 * Initialize AI service settings and load them
 */
function initializeAISettings() {
    // Load settings when page loads
    loadAISettings();
    
    // Set up event listeners for settings modal
    document.getElementById('saveSettingsButton').addEventListener('click', saveAISettings);
    
    // Listen for modal open to refresh settings
    const settingsModal = document.getElementById('settingsModal');
    if (settingsModal) {
        settingsModal.addEventListener('show.bs.modal', loadAISettings);
    }
    
    // Handle Azure services toggle
    const azureServicesToggle = document.getElementById('azure-services-toggle');
    if (azureServicesToggle) {
        azureServicesToggle.addEventListener('change', function() {
            const serviceStatuses = document.querySelectorAll('.azure-service-status');
            serviceStatuses.forEach(status => {
                status.textContent = this.checked ? 'Enabled' : 'Disabled';
                status.className = this.checked ? 'badge bg-success azure-service-status' : 'badge bg-secondary azure-service-status';
            });
            
            // Update UI to preview changes
            updateAIServiceIndicators({
                azure_services_enabled: this.checked,
                use_gpt4o: document.getElementById('local-gpt4-toggle').checked,
                hide_disabled_services: document.getElementById('hide-disabled-services').checked
            });
        });
    }
    
    // Handle display options for hiding services
    const hideDisabledServices = document.getElementById('hide-disabled-services');
    if (hideDisabledServices) {
        hideDisabledServices.addEventListener('change', function() {
            updateAIServiceIndicators({
                azure_services_enabled: document.getElementById('azure-services-toggle').checked,
                use_gpt4o: document.getElementById('local-gpt4-toggle').checked,
                hide_disabled_services: this.checked
            });
        });
    }
}

/**
 * Load AI service settings from the API
 */
function loadAISettings() {
    console.log('Loading AI settings from API');
    
    fetch('/api/v1/ai/settings')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(settings => {
            console.log('Received AI settings:', settings);
            
            // Update toggle based on settings
            const azureServicesToggle = document.getElementById('azure-services-toggle');
            if (azureServicesToggle) {
                azureServicesToggle.checked = settings.azure_services_enabled || false;
            }
            
            // Update all service statuses
            const serviceStatuses = document.querySelectorAll('.azure-service-status');
            const statusText = settings.azure_services_enabled ? 'Enabled' : 'Disabled';
            const statusClass = settings.azure_services_enabled ? 'badge bg-success azure-service-status' : 'badge bg-secondary azure-service-status';
            
            serviceStatuses.forEach(status => {
                status.textContent = statusText;
                status.className = statusClass;
            });
            
            // Update GPT-4o settings
            const localGPT4Toggle = document.getElementById('local-gpt4-toggle');
            if (localGPT4Toggle) {
                localGPT4Toggle.checked = settings.use_gpt4o !== false; // Default to true if not specified
            }
            
            // Set API key if available
            const apiKeyField = document.getElementById('gpt4o-api-key');
            if (apiKeyField && settings.gpt4o_api_key) {
                apiKeyField.value = settings.gpt4o_api_key;
            }
            
            // Set endpoint if available
            const endpointField = document.getElementById('gpt4o-endpoint');
            if (endpointField && settings.gpt4o_endpoint) {
                endpointField.value = settings.gpt4o_endpoint;
            }
            
            // Update hide disabled services toggle
            const hideDisabledServices = document.getElementById('hide-disabled-services');
            if (hideDisabledServices) {
                hideDisabledServices.checked = settings.hide_disabled_services !== false; // Default to true
            }
            
            // Update service indicators based on current settings
            updateAIServiceIndicators(settings);
        })
        .catch(error => {
            console.error('Error loading AI settings:', error);
            showNotification('Failed to load AI settings: ' + error.message, 'danger');
        });
}

/**
 * Save AI service settings to the API
 */
function saveAISettings() {
    console.log('Saving AI settings to API');
    
    // Get settings from form elements
    const azureServicesEnabled = document.getElementById('azure-services-toggle').checked;
    const useGPT4o = document.getElementById('local-gpt4-toggle').checked;
    const gpt4oApiKey = document.getElementById('gpt4o-api-key').value;
    const gpt4oEndpoint = document.getElementById('gpt4o-endpoint').value;
    const hideDisabledServices = document.getElementById('hide-disabled-services').checked;
    
    // Prepare settings object
    const settings = {
        azure_services_enabled: azureServicesEnabled,
        use_gpt4o: useGPT4o,
        gpt4o_api_key: gpt4oApiKey,
        gpt4o_endpoint: gpt4oEndpoint,
        hide_disabled_services: hideDisabledServices
    };
    
    // Send settings to the API
    fetch('/api/v1/ai/settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(settings)
    })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Settings saved successfully:', data);
            showNotification('AI settings updated successfully', 'success');
            
            // Update service indicators
            updateAIServiceIndicators(settings);
            
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
            if (modal) {
                modal.hide();
            }
            
            // Refresh AI data to reflect new settings
            refreshAIData();
        })
        .catch(error => {
            console.error('Error saving AI settings:', error);
            showNotification('Failed to save AI settings: ' + error.message, 'danger');
        });
}

/**
 * Update Azure service indicators based on settings
 */
function updateAIServiceIndicators(settings) {
    // If settings not provided, use current form values
    if (!settings) {
        settings = {
            azure_services_enabled: document.getElementById('azure-services-toggle').checked,
            use_gpt4o: document.getElementById('local-gpt4-toggle').checked,
            hide_disabled_services: document.getElementById('hide-disabled-services').checked
        };
    }
    
    // Update Azure service badges
    const azureBadges = document.querySelectorAll('.azure-service-badge');
    azureBadges.forEach(badge => {
        if (settings.azure_services_enabled) {
            badge.classList.remove('bg-secondary');
            badge.classList.add('bg-primary');
        } else {
            badge.classList.remove('bg-primary');
            badge.classList.add('bg-secondary');
        }
    });
    
    // Get all Azure service sections - using multiple selectors to ensure all sections are targeted
    const azureServiceSections = [
        document.getElementById('openai-section'),
        document.getElementById('search-section'),
        document.getElementById('metrics-section'),
        document.getElementById('synapse-section'),
        document.getElementById('content-safety-section'),
        document.getElementById('azure-detection-section'),
        document.querySelectorAll('[id$="-module-section"]') // Handle any other sections with -module-section suffix
    ];
    
    // Flatten the array since querySelectorAll returns a NodeList
    const allSections = azureServiceSections.reduce((acc, curr) => {
        if (curr instanceof NodeList) {
            return acc.concat(Array.from(curr));
        } else if (curr) {
            acc.push(curr);
        }
        return acc;
    }, []);
    
    // Update visibility and styling of Azure service sections
    allSections.forEach(section => {
        if (section) {
            if (settings.azure_services_enabled) {
                section.classList.remove('disabled-service');
                section.style.display = '';
            } else {
                section.classList.add('disabled-service');
                if (settings.hide_disabled_services) {
                    section.style.display = 'none';
                } else {
                    section.style.display = '';
                }
            }
        }
    });
    
    // Also update the Azure AI headers/titles
    const azureHeaders = document.querySelectorAll('h4:has(.azure-service-badge), h5:has(.azure-service-badge)');
    azureHeaders.forEach(header => {
        if (settings.azure_services_enabled || !settings.hide_disabled_services) {
            header.style.display = '';
        } else {
            header.style.display = 'none';
        }
    });
    
    // Update Intelligence Metrics section
    const intelligenceMetricsSection = document.querySelector('.row:has([id="ai-analyzed-count"])');
    if (intelligenceMetricsSection) {
        if (settings.azure_services_enabled || !settings.hide_disabled_services) {
            intelligenceMetricsSection.style.display = '';
        } else {
            intelligenceMetricsSection.style.display = 'none';
        }
    }
}

// Add to window.onload to initialize settings
window.addEventListener('DOMContentLoaded', function() {
    initializeAISettings();
    
    // Set up event listener for AI data refresh button
    const refreshButton = document.getElementById('refresh-ai-stats');
    if (refreshButton) {
        refreshButton.addEventListener('click', refreshAIData);
    }
});
