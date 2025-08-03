// NexusScan Options Page Script - Enhanced with urlscan.io Fixes
class NexusScanOptions {
  constructor() {
    this.isTestingVT = false;
    this.isTestingUrlscan = false;
    this.isDiagnosticsRunning = false;
    this.initialize();
  }

  async initialize() {
    console.log('🔍 NexusScan Options page initializing - Scan Smarter. Stay Safer');
    this.loadSettings();
    this.setupEventListeners();
    this.updateDiagnostics();
    this.checkPermissions();
  }

  setupEventListeners() {
    // Password visibility toggles
    document.getElementById('toggleVtKey')?.addEventListener('click', () => {
      this.togglePasswordVisibility('vtApiKey', 'toggleVtKey');
    });

    document.getElementById('toggleUrlscanKey')?.addEventListener('click', () => {
      this.togglePasswordVisibility('urlscanApiKey', 'toggleUrlscanKey');
    });

    // API Test buttons
    document.getElementById('testVtApi')?.addEventListener('click', () => {
      this.testVirusTotalConnection();
    });

    document.getElementById('testUrlscanApi')?.addEventListener('click', () => {
      this.testUrlscanConnection();
    });

    // Action buttons
    document.getElementById('saveSettings')?.addEventListener('click', () => {
      this.saveSettings();
    });

    document.getElementById('resetSettings')?.addEventListener('click', () => {
      this.resetToDefaults();
    });

    // Enhanced action buttons
    document.getElementById('runDiagnostics')?.addEventListener('click', () => {
      this.runFullDiagnostics();
    });

    document.getElementById('clearCache')?.addEventListener('click', () => {
      this.clearCache();
    });

    // Input change listeners
    document.getElementById('vtApiKey')?.addEventListener('input', () => {
      this.clearStatus('vtStatus');
      this.updateDiagnostics();
    });

    document.getElementById('urlscanApiKey')?.addEventListener('input', () => {
      this.clearStatus('urlscanStatus');
      this.updateDiagnostics();
    });

    document.getElementById('cacheEnabled')?.addEventListener('change', () => {
      this.updateDiagnostics();
    });

    document.getElementById('realTimeProtection')?.addEventListener('change', () => {
      this.updateDiagnostics();
    });

    document.getElementById('debugMode')?.addEventListener('change', () => {
      this.toggleDebugMode();
    });
  }

  async loadSettings() {
    try {
      console.log('NexusScan: Loading settings from storage');
      
      const settings = await chrome.storage.sync.get([
        'vtApiKey',
        'urlscanApiKey', 
        'urlscanVisibility',
        'desktopNotifications',
        'cacheEnabled',
        'realTimeProtection',
        'scanSensitivity',
        'debugMode'
      ]);

      // Load API keys
      if (settings.vtApiKey) {
        document.getElementById('vtApiKey').value = settings.vtApiKey;
      }
      if (settings.urlscanApiKey) {
        document.getElementById('urlscanApiKey').value = settings.urlscanApiKey;
      }

      // Load other settings
      if (settings.urlscanVisibility) {
        document.getElementById('urlscanVisibility').value = settings.urlscanVisibility;
      }

      if (settings.scanSensitivity) {
        document.getElementById('scanSensitivity').value = settings.scanSensitivity;
      }

      // Load checkbox settings
      document.getElementById('desktopNotifications').checked = settings.desktopNotifications !== false;
      document.getElementById('cacheEnabled').checked = settings.cacheEnabled !== false;
      document.getElementById('realTimeProtection').checked = settings.realTimeProtection !== false;
      document.getElementById('debugMode').checked = settings.debugMode === true;

      this.updateDiagnostics();
      console.log('NexusScan: Settings loaded successfully');

    } catch (error) {
      console.error('NexusScan: Failed to load settings:', error);
      this.showToast('Failed to load settings', 'error');
    }
  }

  async saveSettings() {
    try {
      console.log('NexusScan: Saving settings to storage');
      
      const settings = {
        vtApiKey: document.getElementById('vtApiKey').value.trim(),
        urlscanApiKey: document.getElementById('urlscanApiKey').value.trim(),
        urlscanVisibility: document.getElementById('urlscanVisibility').value,
        desktopNotifications: document.getElementById('desktopNotifications').checked,
        cacheEnabled: document.getElementById('cacheEnabled').checked,
        realTimeProtection: document.getElementById('realTimeProtection').checked,
        scanSensitivity: document.getElementById('scanSensitivity').value,
        debugMode: document.getElementById('debugMode').checked
      };

      // Show saving state
      const saveBtn = document.getElementById('saveSettings');
      this.setButtonLoading(saveBtn, true);

      await chrome.storage.sync.set(settings);
      
      // Notify background script of settings change
      try {
        await chrome.runtime.sendMessage({ 
          action: 'settingsUpdated', 
          settings: settings 
        });
      } catch (error) {
        console.log('NexusScan: Background script not responding (this is normal)');
      }

      this.showToast('🎉 NexusScan settings saved successfully!', 'success');
      this.updateDiagnostics();
      console.log('NexusScan: Settings saved successfully');

    } catch (error) {
      console.error('NexusScan: Failed to save settings:', error);
      this.showToast('Failed to save settings: ' + error.message, 'error');
    } finally {
      const saveBtn = document.getElementById('saveSettings');
      this.setButtonLoading(saveBtn, false);
    }
  }

  async resetToDefaults() {
    if (!confirm('Are you sure you want to reset all NexusScan settings to defaults? This will clear your API keys and you will need to re-enter them.')) {
      return;
    }

    try {
      console.log('NexusScan: Resetting settings to defaults');
      
      const resetBtn = document.getElementById('resetSettings');
      this.setButtonLoading(resetBtn, true);

      // Clear storage
      await chrome.storage.sync.clear();
      await chrome.storage.local.clear();

      // Reset form to defaults
      document.getElementById('vtApiKey').value = '';
      document.getElementById('urlscanApiKey').value = '';
      document.getElementById('urlscanVisibility').value = 'private';
      document.getElementById('desktopNotifications').checked = true;
      document.getElementById('cacheEnabled').checked = true;
      document.getElementById('realTimeProtection').checked = true;
      document.getElementById('scanSensitivity').value = 'balanced';
      document.getElementById('debugMode').checked = false;

      // Clear status indicators
      this.clearStatus('vtStatus');
      this.clearStatus('urlscanStatus');

      this.showToast('🔄 NexusScan settings reset to defaults', 'info');
      this.updateDiagnostics();
      console.log('NexusScan: Settings reset completed');

    } catch (error) {
      console.error('NexusScan: Failed to reset settings:', error);
      this.showToast('Failed to reset settings: ' + error.message, 'error');
    } finally {
      const resetBtn = document.getElementById('resetSettings');
      this.setButtonLoading(resetBtn, false);
    }
  }

  togglePasswordVisibility(inputId, buttonId) {
    const input = document.getElementById(inputId);
    const button = document.getElementById(buttonId);
    
    if (input.type === 'password') {
      input.type = 'text';
      button.textContent = '🙈';
      button.title = 'Hide API key';
    } else {
      input.type = 'password';
      button.textContent = '👁️';
      button.title = 'Show API key';
    }
  }

  async testVirusTotalConnection() {
    if (this.isTestingVT) return;

    const apiKey = document.getElementById('vtApiKey').value.trim();
    const testBtn = document.getElementById('testVtApi');
    const statusDiv = document.getElementById('vtStatus');

    if (!apiKey) {
      this.setStatus(statusDiv, '❌ Please enter a VirusTotal API key first', 'error');
      return;
    }

    if (apiKey.length < 64) {
      this.setStatus(statusDiv, '❌ VirusTotal API key appears to be invalid (too short)', 'error');
      return;
    }

    console.log('NexusScan: Testing VirusTotal API connection');
    this.isTestingVT = true;
    this.setButtonLoading(testBtn, true);
    this.setStatus(statusDiv, '🔄 Testing VirusTotal connection with NexusScan...', 'testing');
    this.updateApiStatus('testing');

    try {
      // Test with a simple URL report request
      const testUrl = 'https://www.google.com';
      const urlId = btoa(testUrl).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      
      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        method: 'GET',
        headers: {
          'x-apikey': apiKey,
          'User-Agent': 'NexusScan/1.0'
        }
      });

      if (response.ok) {
        this.setStatus(statusDiv, '✅ VirusTotal connection successful! NexusScan is ready.', 'success');
        this.showToast('🎉 VirusTotal API key is valid and working!', 'success');
        console.log('NexusScan: VirusTotal API test successful');
      } else if (response.status === 401 || response.status === 403) {
        this.setStatus(statusDiv, '❌ Invalid VirusTotal API key', 'error');
        this.showToast('VirusTotal API key is invalid', 'error');
      } else if (response.status === 429) {
        this.setStatus(statusDiv, '⚠️ VirusTotal rate limit reached (API key is valid)', 'success');
        this.showToast('VirusTotal API key is valid (rate limited)', 'info');
      } else if (response.status === 404) {
        // URL not found is actually a good sign - API key works
        this.setStatus(statusDiv, '✅ VirusTotal connection successful! NexusScan is ready.', 'success');
        this.showToast('🎉 VirusTotal API key is valid and working!', 'success');
      } else {
        this.setStatus(statusDiv, `❌ VirusTotal error: ${response.status} ${response.statusText}`, 'error');
        this.showToast(`VirusTotal API error: ${response.status}`, 'error');
      }
    } catch (error) {
      console.error('NexusScan: VirusTotal test error:', error);
      this.setStatus(statusDiv, `❌ Network error: ${error.message}`, 'error');
      this.showToast('Network error testing VirusTotal API', 'error');
    } finally {
      this.isTestingVT = false;
      this.setButtonLoading(testBtn, false);
      this.updateDiagnostics();
    }
  }

  async testUrlscanConnection() {
    if (this.isTestingUrlscan) return;

    const apiKey = document.getElementById('urlscanApiKey').value.trim();
    const testBtn = document.getElementById('testUrlscanApi');
    const statusDiv = document.getElementById('urlscanStatus');

    if (!apiKey) {
      this.setStatus(statusDiv, '❌ Please enter a urlscan.io API key first', 'error');
      return;
    }

    if (apiKey.length < 32) {
      this.setStatus(statusDiv, '❌ urlscan.io API key appears to be invalid (too short)', 'error');
      return;
    }

    console.log('NexusScan: Testing urlscan.io API connection');
    this.isTestingUrlscan = true;
    this.setButtonLoading(testBtn, true);
    this.setStatus(statusDiv, '🔄 Testing urlscan.io connection with NexusScan...', 'testing');
    this.updateApiStatus('testing');

    try {
      // FIXED: Test with correct headers and format
      const response = await fetch('https://urlscan.io/api/v1/scan/', {
        method: 'POST',
        headers: {
          'API-Key': apiKey,  // Fixed: Capital 'K' in API-Key
          'Content-Type': 'application/json',
          'User-Agent': 'NexusScan/1.0'
        },
        body: JSON.stringify({
          url: 'https://www.google.com',
          visibility: 'private',  // Fixed: Always use private for testing
          tags: ['nexusscan-test']
        })
      });

      if (response.ok) {
        const data = await response.json();
        if (data.uuid) {
          this.setStatus(statusDiv, '✅ urlscan.io connection successful! NexusScan is ready.', 'success');
          this.showToast('🎉 urlscan.io API key is valid and working!', 'success');
          console.log('NexusScan: urlscan.io API test successful, UUID:', data.uuid);
        } else {
          this.setStatus(statusDiv, '❌ Unexpected response from urlscan.io', 'error');
        }
      } else if (response.status === 401) {
        this.setStatus(statusDiv, '❌ Invalid urlscan.io API key', 'error');
        this.showToast('urlscan.io API key is invalid', 'error');
      } else if (response.status === 429) {
        this.setStatus(statusDiv, '⚠️ urlscan.io rate limit reached (API key is valid)', 'success');
        this.showToast('urlscan.io API key is valid (rate limited)', 'info');
      } else if (response.status === 400) {
        // Bad request - check the error details
        const errorData = await response.json().catch(() => ({ message: 'Bad request' }));
        if (errorData.message && errorData.message.includes('DNS Error')) {
          this.setStatus(statusDiv, '❌ DNS Error: Cannot resolve test domain', 'error');
        } else if (errorData.message && errorData.message.includes('Missing URL')) {
          this.setStatus(statusDiv, '❌ Missing URL in request', 'error');
        } else {
          this.setStatus(statusDiv, '✅ urlscan.io API key is valid! NexusScan is ready.', 'success');
          this.showToast('🎉 urlscan.io API key is valid!', 'success');
        }
      } else {
        const errorText = await response.text().catch(() => 'Unknown error');
        this.setStatus(statusDiv, `❌ urlscan.io error (${response.status}): ${errorText}`, 'error');
        this.showToast(`urlscan.io API error: ${response.status}`, 'error');
      }
    } catch (error) {
      console.error('NexusScan: urlscan.io test error:', error);
      this.setStatus(statusDiv, `❌ Network error: ${error.message}`, 'error');
      this.showToast('Network error testing urlscan.io API', 'error');
    } finally {
      this.isTestingUrlscan = false;
      this.setButtonLoading(testBtn, false);
      this.updateDiagnostics();
    }
  }

  async runFullDiagnostics() {
    if (this.isDiagnosticsRunning) return;

    console.log('NexusScan: Running full system diagnostics');
    this.isDiagnosticsRunning = true;
    
    const diagnosticsBtn = document.getElementById('runDiagnostics');
    this.setButtonLoading(diagnosticsBtn, true);
    
    this.showToast('🔍 Running NexusScan diagnostics...', 'info');

    try {
      // Test extension functionality
      const results = [];
      
      // Test storage access
      try {
        await chrome.storage.local.set({ 'nexusscan_test': Date.now() });
        await chrome.storage.local.remove('nexusscan_test');
        results.push('✅ Storage access: Working');
      } catch (error) {
        results.push('❌ Storage access: Failed');
      }

      // Test background script communication
      try {
        const response = await chrome.runtime.sendMessage({ action: 'getStats' });
        if (response && response.success) {
          results.push('✅ Background script: Active');
          results.push(`✅ Cache size: ${response.data.cacheSize} entries`);
        } else {
          results.push('⚠️ Background script: Not responding');
        }
      } catch (error) {
        results.push('❌ Background script: Error');
      }

      // Test API keys if present
      const vtKey = document.getElementById('vtApiKey').value.trim();
      const urlscanKey = document.getElementById('urlscanApiKey').value.trim();
      
      if (vtKey) {
        results.push('✅ VirusTotal API: Configured');
      } else {
        results.push('⚠️ VirusTotal API: Not configured');
      }
      
      if (urlscanKey) {
        results.push('✅ urlscan.io API: Configured');
      } else {
        results.push('⚠️ urlscan.io API: Not configured');
      }

      // Test permissions
      const permissions = await chrome.permissions.getAll();
      if (permissions.permissions.includes('activeTab')) {
        results.push('✅ Tab permissions: Granted');
      } else {
        results.push('❌ Tab permissions: Missing');
      }

      if (permissions.permissions.includes('storage')) {
        results.push('✅ Storage permissions: Granted');
      } else {
        results.push('❌ Storage permissions: Missing');
      }

      // Test API connectivity if keys are present
      if (vtKey && vtKey.length >= 64) {
        try {
          const vtResponse = await fetch(`https://www.virustotal.com/api/v3/urls/${btoa('https://www.google.com').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`, {
            headers: { 'x-apikey': vtKey, 'User-Agent': 'NexusScan/1.0' }
          });
          if (vtResponse.ok || vtResponse.status === 404) {
            results.push('✅ VirusTotal API: Connection successful');
          } else if (vtResponse.status === 401 || vtResponse.status === 403) {
            results.push('❌ VirusTotal API: Invalid key');
          } else if (vtResponse.status === 429) {
            results.push('⚠️ VirusTotal API: Rate limited (key valid)');
          } else {
            results.push(`⚠️ VirusTotal API: Error ${vtResponse.status}`);
          }
        } catch (error) {
          results.push('❌ VirusTotal API: Network error');
        }
      }

      if (urlscanKey && urlscanKey.length >= 32) {
        try {
          const urlscanResponse = await fetch('https://urlscan.io/api/v1/scan/', {
            method: 'POST',
            headers: {
              'API-Key': urlscanKey,
              'Content-Type': 'application/json',
              'User-Agent': 'NexusScan/1.0'
            },
            body: JSON.stringify({
              url: 'https://www.google.com',
              visibility: 'private'
            })
          });
          
          if (urlscanResponse.ok) {
            results.push('✅ urlscan.io API: Connection successful');
          } else if (urlscanResponse.status === 401) {
            results.push('❌ urlscan.io API: Invalid key');
          } else if (urlscanResponse.status === 429) {
            results.push('⚠️ urlscan.io API: Rate limited (key valid)');
          } else if (urlscanResponse.status === 400) {
            results.push('✅ urlscan.io API: Key valid (request format issue)');
          } else {
            results.push(`⚠️ urlscan.io API: Error ${urlscanResponse.status}`);
          }
        } catch (error) {
          results.push('❌ urlscan.io API: Network error');
        }
      }

      // Display results
      const resultsHtml = results.map(result => `<div style="margin-bottom: 8px;">${result}</div>`).join('');
      
      this.showToast('✅ NexusScan diagnostics completed!', 'success');
      
      // Create modal with results
      this.showDiagnosticsResults(resultsHtml);

    } catch (error) {
      console.error('NexusScan: Diagnostics failed:', error);
      this.showToast('Diagnostics failed: ' + error.message, 'error');
    } finally {
      this.isDiagnosticsRunning = false;
      this.setButtonLoading(diagnosticsBtn, false);
    }
  }

  async clearCache() {
    try {
      console.log('NexusScan: Clearing cache');
      
      const clearBtn = document.getElementById('clearCache');
      this.setButtonLoading(clearBtn, true);

      // Clear all NexusScan related storage
      const response = await chrome.runtime.sendMessage({ action: 'clearCache' });
      
      if (response && response.success) {
        this.showToast('🗑️ NexusScan cache cleared successfully!', 'success');
      } else {
        throw new Error('Failed to clear cache');
      }

    } catch (error) {
      console.error('NexusScan: Failed to clear cache:', error);
      this.showToast('Failed to clear cache: ' + error.message, 'error');
    } finally {
      const clearBtn = document.getElementById('clearCache');
      this.setButtonLoading(clearBtn, false);
    }
  }

  toggleDebugMode() {
    const debugMode = document.getElementById('debugMode').checked;
    console.log('NexusScan: Debug mode', debugMode ? 'enabled' : 'disabled');
    
    if (debugMode) {
      this.showToast('🐛 Debug mode enabled - Detailed logging active', 'info');
    } else {
      this.showToast('Debug mode disabled', 'info');
    }
  }

  async checkPermissions() {
    try {
      const permissions = await chrome.permissions.getAll();
      console.log('NexusScan: Current permissions:', permissions);
      
      if (!permissions.permissions.includes('bookmarks')) {
        this.showToast('⚠️ Bookmark scanning requires additional permissions', 'warning');
      }
    } catch (error) {
      console.error('NexusScan: Failed to check permissions:', error);
    }
  }

  showDiagnosticsResults(resultsHtml) {
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10001;
    `;
    
    modal.innerHTML = `
      <div style="
        background: #252525;
        border-radius: 12px;
        padding: 30px;
        max-width: 500px;
        width: 90%;
        border: 2px solid #00d4ff;
        box-shadow: 0 16px 48px rgba(0, 0, 0, 0.4);
      ">
        <h3 style="color: #00d4ff; margin-bottom: 20px; text-align: center;">
          🔍 NexusScan System Diagnostics
        </h3>
        <div style="color: #fff; line-height: 1.6; max-height: 300px; overflow-y: auto;">
          ${resultsHtml}
        </div>
        <div style="text-align: center; margin-top: 20px;">
          <button class="btn" onclick="this.closest('div').parentElement.remove()">
            Close
          </button>
        </div>
      </div>
    `;
    
    document.body.appendChild(modal);
    
    // Close on click outside
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
  }

  setButtonLoading(button, isLoading) {
    if (!button) return;

    if (isLoading) {
      button.classList.add('btn-loading');
      button.disabled = true;
    } else {
      button.classList.remove('btn-loading');
      button.disabled = false;
    }
  }

  setStatus(statusDiv, message, type) {
    if (!statusDiv) return;

    statusDiv.innerHTML = `<span class="${type}-message">${message}</span>`;
    statusDiv.style.display = 'block';
  }

  clearStatus(statusId) {
    const statusDiv = document.getElementById(statusId);
    if (statusDiv) {
      statusDiv.innerHTML = '';
      statusDiv.style.display = 'none';
    }
  }

  updateDiagnostics() {
    // Update API connectivity status
    const vtKey = document.getElementById('vtApiKey')?.value.trim();
    const urlscanKey = document.getElementById('urlscanApiKey')?.value.trim();
    
    const apiStatus = document.getElementById('apiStatus');
    const apiStatusText = document.getElementById('apiStatusText');
    
    if (apiStatus && apiStatusText) {
      if (vtKey && urlscanKey) {
        apiStatus.className = 'status-indicator status-connected';
        apiStatusText.textContent = 'Both APIs Configured';
      } else if (vtKey || urlscanKey) {
        apiStatus.className = 'status-indicator status-connected';
        apiStatusText.textContent = 'Partially Configured';
      } else {
        apiStatus.className = 'status-indicator status-disconnected';
        apiStatusText.textContent = 'No API Keys';
      }
    }

    // Update cache status
    const cacheEnabled = document.getElementById('cacheEnabled')?.checked;
    const cacheStatusIndicator = document.getElementById('cacheStatusIndicator');
    const cacheStatusText = document.getElementById('cacheStatusText');
    
    if (cacheStatusIndicator && cacheStatusText) {
      if (cacheEnabled) {
        cacheStatusIndicator.className = 'status-indicator status-connected';
        cacheStatusText.textContent = 'Enabled';
      } else {
        cacheStatusIndicator.className = 'status-indicator status-disconnected';
        cacheStatusText.textContent = 'Disabled';
      }
    }

    console.log('NexusScan: Diagnostics updated');
  }

  updateApiStatus(status) {
    const apiStatus = document.getElementById('apiStatus');
    const apiStatusText = document.getElementById('apiStatusText');
    
    if (apiStatus && apiStatusText) {
      if (status === 'testing') {
        apiStatus.className = 'status-indicator status-testing';
        apiStatusText.textContent = 'Testing APIs...';
      } else {
        this.updateDiagnostics();
      }
    }
  }

  showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (!toast) return;

    toast.textContent = message;
    toast.className = `toast show ${type}`;
    
    console.log(`NexusScan: Toast - ${message}`);
    
    // Auto-hide after 4 seconds
    setTimeout(() => {
      toast.classList.remove('show');
    }, 4000);
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  console.log('🔍 NexusScan Options page loaded - Scan Smarter. Stay Safer');
  new NexusScanOptions();
});
