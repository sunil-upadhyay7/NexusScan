// NexusScan Popup Script - Advanced URL Security Scanner | Scan Smarter. Stay Safer
class NexusScanPopup {
  constructor() {
    this.currentURL = '';
    this.scanResults = null;
    this.isDarkTheme = true;
    this.isScanning = false;
    this.showingHistory = false;
    this.showingCommunity = false;
    this.showingBookmarks = false;
    this.currentHistoryPage = 1;
    this.historyPerPage = 10;
    this.filteredHistory = [];
    this.allHistory = [];
    this.currentRating = 0;
    this.bookmarks = [];
    this.filteredBookmarks = [];
    this.bookmarkScanResults = new Map();
    this.isBookmarkScanning = false;
    this.bookmarkScanProgress = { current: 0, total: 0 };
    this.initialize();
  }

  async initialize() {
    console.log('🔍 NexusScan popup initializing - Scan Smarter. Stay Safer');
    await this.loadSettings();
    this.setupEventListeners();
    await this.loadCurrentURL();
    this.updateTheme();
    await this.loadCachedResults();
    console.log('NexusScan: Popup initialized successfully');
  }

  async loadSettings() {
    try {
      const settings = await chrome.storage.sync.get(['theme']);
      this.isDarkTheme = settings.theme !== 'light';
      console.log('NexusScan: Theme loaded:', this.isDarkTheme ? 'dark' : 'light');
    } catch (error) {
      console.error('NexusScan: Failed to load settings:', error);
    }
  }

  setupEventListeners() {
    console.log('NexusScan: Setting up event listeners');

    document.getElementById('scanButton').addEventListener('click', () => {
      this.performScan();
    });

    document.getElementById('rescanButton').addEventListener('click', () => {
      this.performScan(true);
    });

    document.getElementById('themeToggle').addEventListener('click', () => {
      this.toggleTheme();
    });

    document.getElementById('blockButton').addEventListener('click', () => {
      this.blockCurrentURL();
    });

    document.getElementById('settingsLink').addEventListener('click', () => {
      chrome.runtime.openOptionsPage();
    });

    // History event listeners
    document.getElementById('historyToggle').addEventListener('click', () => {
      this.toggleHistoryView();
    });

    // REMOVED: Refresh History button event listener

    document.getElementById('exportHistory')?.addEventListener('click', () => {
      this.exportHistory();
    });

    document.getElementById('clearHistory')?.addEventListener('click', () => {
      this.clearHistory();
    });

    document.getElementById('historyFilter')?.addEventListener('change', (e) => {
      this.filterHistory(e.target.value);
    });

    document.getElementById('historySearch')?.addEventListener('input', (e) => {
      this.searchHistory(e.target.value);
    });

    document.getElementById('prevPage')?.addEventListener('click', () => {
      this.changePage(-1);
    });

    document.getElementById('nextPage')?.addEventListener('click', () => {
      this.changePage(1);
    });

    // Community Feedback event listeners
    document.getElementById('communityToggle').addEventListener('click', () => {
      this.toggleCommunityView();
    });

    document.getElementById('addFeedbackBtn')?.addEventListener('click', () => {
      this.showFeedbackForm();
    });

    document.getElementById('submitFeedbackBtn')?.addEventListener('click', () => {
      this.submitFeedback();
    });

    document.getElementById('refreshCommunity')?.addEventListener('click', () => {
      this.loadCommunityStats();
    });

    // NexusScan Bookmark Scanner event listeners
    document.getElementById('bookmarkToggle').addEventListener('click', () => {
      this.toggleBookmarkView();
    });

    document.getElementById('scanAllBookmarks')?.addEventListener('click', () => {
      this.scanAllBookmarks();
    });

    document.getElementById('exportBookmarkResults')?.addEventListener('click', () => {
      this.exportBookmarkResults();
    });

    document.getElementById('clearBookmarkResults')?.addEventListener('click', () => {
      this.clearBookmarkResults();
    });

    document.getElementById('bookmarkFilter')?.addEventListener('change', (e) => {
      this.filterBookmarks(e.target.value);
    });

    document.getElementById('bookmarkSearch')?.addEventListener('input', (e) => {
      this.searchBookmarks(e.target.value);
    });

    // Enhanced Star Rating System for NexusScan
    document.querySelectorAll('#ratingInput .rating-star').forEach(star => {
      star.addEventListener('click', (e) => {
        e.preventDefault();
        const rating = parseInt(star.dataset.rating);
        this.setRating(rating);
        
        if ('vibrate' in navigator) {
          navigator.vibrate(50);
        }
      });

      star.addEventListener('mouseover', () => {
        const rating = parseInt(star.dataset.rating);
        this.previewRating(rating);
        this.showHorizontalDescription(rating);
      });

      star.addEventListener('mouseleave', () => {
        this.previewRating(this.currentRating);
        this.hideHorizontalDescription();
        setTimeout(() => {
          if (this.currentRating > 0) {
            this.updateRatingText();
          }
        }, 100);
      });
      
      star.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          const rating = parseInt(star.dataset.rating);
          this.setRating(rating);
        }
      });
    });

    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('copy-btn')) {
        this.copyToClipboard(e.target.dataset.copy, e.target.dataset.label || 'Text');
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.ctrlKey && !this.isScanning) {
        this.performScan();
      }
      if (e.key === 'Escape') {
        this.closeScreenshotModal();
      }
    });

    console.log('NexusScan: All event listeners configured');
  }

  async loadCurrentURL() {
    try {
      console.log('NexusScan: Loading current tab URL');
      const response = await chrome.runtime.sendMessage({ action: 'getCurrentTab' });
      if (response.success && response.data) {
        this.currentURL = response.data.url;
        document.getElementById('currentURL').textContent = this.currentURL;
        
        const feedbackURLInput = document.getElementById('feedbackURL');
        if (feedbackURLInput) {
          feedbackURLInput.value = this.currentURL;
        }
        console.log('NexusScan: Current URL loaded:', this.currentURL);
      } else {
        document.getElementById('currentURL').textContent = 'Unable to load current URL';
        console.warn('NexusScan: Failed to get current tab');
      }
    } catch (error) {
      console.error('NexusScan: Failed to load current URL:', error);
      document.getElementById('currentURL').textContent = 'Error loading URL';
    }
  }

  async loadCachedResults() {
    if (!this.currentURL) return;
    
    try {
      console.log('NexusScan: Checking for cached results');
      const cacheKey = `nexusscan_results_${this.currentURL}`;
      const cached = await chrome.storage.local.get(cacheKey);
      
      if (cached[cacheKey]) {
        const cachedData = cached[cacheKey];
        const maxAge = 30 * 60 * 1000; // 30 minutes
        if (Date.now() - cachedData.timestamp < maxAge) {
          this.scanResults = cachedData;
          this.displayResults();
          console.log('NexusScan: Loaded cached results for:', this.currentURL);
          // REMOVED: Unwanted toast notification for cached results
        }
      }
    } catch (error) {
      console.error('NexusScan: Failed to load cached results:', error);
    }
  }

  async saveScanResults(results) {
    if (!this.currentURL || !results) return;
    
    try {
      const cacheKey = `nexusscan_results_${this.currentURL}`;
      await chrome.storage.local.set({
        [cacheKey]: {
          ...results,
          timestamp: Date.now()
        }
      });
      console.log('NexusScan: Scan results cached');
    } catch (error) {
      console.error('NexusScan: Failed to save scan results:', error);
    }
  }

  // **FIXED: Save scan to history**
  async saveScanToHistory(url, scanResults) {
    try {
      const result = await chrome.storage.local.get(['nexusscan_history']);
      const history = result.nexusscan_history || [];
      
      // Add new scan to history
      const scanEntry = {
        url: url,
        score: scanResults.score || 0,
        timestamp: Date.now(),
        threats: scanResults.threats || [],
        sources: {
          virustotal: scanResults.sources?.virustotal?.malicious || 0,
          urlscan: scanResults.sources?.urlscan?.verdict || 'unknown'
        }
      };
      
      // Remove duplicate entries for the same URL (keep latest)
      const filteredHistory = history.filter(entry => entry.url !== url);
      filteredHistory.push(scanEntry);
      
      // Keep only last 100 scans to prevent storage bloat
      const trimmedHistory = filteredHistory.slice(-100);
      
      await chrome.storage.local.set({ nexusscan_history: trimmedHistory });
      console.log('NexusScan: Scan saved to history');
    } catch (error) {
      console.error('NexusScan: Failed to save scan to history:', error);
    }
  }

  async performScan(forceRescan = false) {
    if (!this.currentURL || this.isScanning) {
      if (!this.currentURL) {
        this.showToast('❌ No URL to scan', 'error');
      }
      return;
    }

    console.log('NexusScan: Starting security scan', forceRescan ? '(forced rescan)' : '');
    this.isScanning = true;
    this.showLoading();
    this.hideError();
    
    if (forceRescan) {
      this.hideResults();
    }

    try {
      const response = await chrome.runtime.sendMessage({
        action: 'scanURL',
        url: this.currentURL,
        forceRescan: forceRescan
      });

      if (response.success) {
        this.scanResults = response.data;
        await this.saveScanResults(this.scanResults);
        
        // **FIXED: Save scan to history**
        await this.saveScanToHistory(this.currentURL, this.scanResults);
        
        this.displayResults();
        // REMOVED: Unwanted success toast notification
        console.log('NexusScan: Scan completed with score:', this.scanResults.score);
      } else {
        throw new Error(response.error || 'NexusScan failed');
      }
    } catch (error) {
      console.error('NexusScan: Scan error:', error);
      this.showError(error.message);
    } finally {
      this.isScanning = false;
      this.hideLoading();
    }
  }

  showLoading() {
    document.getElementById('loadingSection').style.display = 'block';
    document.getElementById('scanButton').disabled = true;
    document.getElementById('rescanButton').disabled = true;
    
    const nexusLoadingMessages = [
      '🔍 NexusScan initiating security analysis...',
      '📡 Analyzing URL with advanced algorithms...',
      '🔍 Checking threat intelligence databases...',
      '⏳ Processing multi-source security data...',
      '📊 Calculating comprehensive risk score...',
      '👥 Loading NexusScan community insights...',
      '🛡️ Finalizing advanced security report...'
    ];
    
    const loadingTextElement = document.getElementById('loadingText');
    let messageIndex = 0;
    
    this.loadingInterval = setInterval(() => {
      if (messageIndex < nexusLoadingMessages.length) {
        loadingTextElement.textContent = nexusLoadingMessages[messageIndex];
        messageIndex++;
      } else {
        loadingTextElement.textContent = 'NexusScan completing analysis...';
      }
    }, 2000);

    console.log('NexusScan: Loading animation started');
  }

  hideLoading() {
    document.getElementById('loadingSection').style.display = 'none';
    document.getElementById('scanButton').disabled = false;
    document.getElementById('rescanButton').disabled = false;
    
    if (this.loadingInterval) {
      clearInterval(this.loadingInterval);
    }
    console.log('NexusScan: Loading animation stopped');
  }

  showError(message) {
    console.error('NexusScan: Displaying error:', message);
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('errorSection').style.display = 'block';
  }

  hideError() {
    document.getElementById('errorSection').style.display = 'none';
  }

  hideResults() {
    document.getElementById('resultsSection').style.display = 'none';
  }

  displayResults() {
    if (!this.scanResults) return;

    console.log('NexusScan: Displaying scan results');
    document.getElementById('resultsSection').style.display = 'block';
    this.updateRiskScore(this.scanResults.score);
    this.displayVirusTotalResults(this.scanResults.sources.virustotal);
    this.displayUrlscanResults(this.scanResults.sources.urlscan);
    this.displayThreats(this.scanResults.threats);
    this.displayCommunityFeedback(this.scanResults.communityFeedback);
    
    const blockButton = document.getElementById('blockButton');
    if (this.scanResults.score >= 70) {
      blockButton.style.display = 'block';
    } else {
      blockButton.style.display = 'none';
    }
  }

  updateRiskScore(score) {
    const riskScoreElement = document.getElementById('riskScore');
    const riskCircle = document.getElementById('riskCircle');
    const riskLevel = document.getElementById('riskLevel');
    
    this.animateNumber(riskScoreElement, 0, score, 1000);
    
    const circumference = 2 * Math.PI * 40;
    const offset = circumference - (score / 100) * circumference;
    riskCircle.style.strokeDashoffset = offset;
    
    if (score <= 30) {
      riskCircle.style.stroke = this.isDarkTheme ? '#4ade80' : '#16a34a';
      riskLevel.textContent = '✅ Safe - NexusScan Verified';
      riskLevel.className = 'risk-level safe';
    } else if (score <= 69) {
      riskCircle.style.stroke = this.isDarkTheme ? '#fbbf24' : '#ea580c';
      riskLevel.textContent = '⚠️ Suspicious - NexusScan Alert';
      riskLevel.className = 'risk-level suspicious';
    } else {
      riskCircle.style.stroke = this.isDarkTheme ? '#f87171' : '#dc2626';
      riskLevel.textContent = '🔴 Dangerous - NexusScan Warning';
      riskLevel.className = 'risk-level dangerous';
    }

    console.log('NexusScan: Risk score updated:', score);
  }

  displayVirusTotalResults(vtData) {
    const vtContent = document.getElementById('vtContent');
    const vtFullReport = document.getElementById('vtFullReport');
    
    if (vtData && vtData.error) {
      vtContent.innerHTML = `<div style="color: #ef4444; font-size: 12px;">❌ ${this.escapeHtml(vtData.error)}</div>`;
      vtFullReport.style.display = 'none';
      return;
    }
    
    if (!vtData || !vtData.vendors) {
      vtContent.innerHTML = `<div style="text-align: center; color: #888; font-size: 12px;">NexusScan: VirusTotal data pending...</div>`;
      vtFullReport.style.display = 'none';
      return;
    }

    vtFullReport.href = vtData.scan_url;
    vtFullReport.style.display = 'inline';

    // Dynamic colors based on theme
    const tableHeaderBg = this.isDarkTheme ? '#333' : '#f1f5f9';
    const tableBorderColor = this.isDarkTheme ? '#404040' : '#e2e8f0';
    const tableTextColor = this.isDarkTheme ? '#fff' : '#1e293b';
    const rowEvenBg = this.isDarkTheme ? 'rgba(255, 255, 255, 0.02)' : 'rgba(0, 0, 0, 0.02)';

    let content = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
        <span style="background: ${vtData.malicious === 0 ? '#10b981' : vtData.malicious <= 2 ? '#f59e0b' : '#ef4444'}; color: white; padding: 6px 12px; border-radius: 12px; font-size: 12px; font-weight: 600;">
          ${vtData.malicious}/${vtData.total} flagged
        </span>
        <span style="font-size: 10px; color: #888;">
          NexusScan • ${vtData.scan_date ? new Date(vtData.scan_date * 1000).toLocaleDateString() : 'Recent'}
        </span>
      </div>
      <div style="max-height: 120px; overflow-y: auto; border: 1px solid ${tableBorderColor}; border-radius: 12px;">
        <table style="width: 100%; font-size: 11px; border-collapse: collapse;">
          <thead style="background: ${tableHeaderBg}; position: sticky; top: 0;">
            <tr>
              <th style="text-align: left; padding: 8px; color: ${tableTextColor}; border-bottom: 1px solid ${tableBorderColor};">Vendor</th>
              <th style="text-align: left; padding: 8px; color: ${tableTextColor}; border-bottom: 1px solid ${tableBorderColor};">Result</th>
            </tr>
          </thead>
          <tbody>
    `;

    vtData.vendors.forEach((vendor, index) => {
      const resultColor = vendor.category === 'malicious' ? '#ef4444' :
                         vendor.category === 'suspicious' ? '#f59e0b' : '#10b981';
      
      const rowBg = index % 2 === 1 ? rowEvenBg : 'transparent';
      
      content += `
        <tr style="border-bottom: 1px solid ${tableBorderColor}; background: ${rowBg};">
          <td style="padding: 6px 8px; color: ${tableTextColor};">${this.escapeHtml(vendor.name)}</td>
          <td style="padding: 6px 8px; color: ${resultColor}; font-weight: 500;">
            ${this.escapeHtml(vendor.result)}
          </td>
        </tr>
      `;
    });

    content += `</tbody></table></div>`;
    vtContent.innerHTML = content;
  }

  displayUrlscanResults(urlscanData) {
    const urlscanContent = document.getElementById('urlscanContent');
    const urlscanFullReport = document.getElementById('urlscanFullReport');
    
    if (urlscanData && urlscanData.error) {
      urlscanContent.innerHTML = `<div style="color: #ef4444; font-size: 12px;">❌ ${this.escapeHtml(urlscanData.error)}</div>`;
      urlscanFullReport.style.display = 'none';
      return;
    }
    
    if (!urlscanData || !urlscanData.uuid) {
      urlscanContent.innerHTML = `<div style="text-align: center; color: #888; font-size: 12px;">NexusScan: urlscan.io data pending...</div>`;
      urlscanFullReport.style.display = 'none';
      return;
    }

    urlscanFullReport.href = urlscanData.scan_url;
    urlscanFullReport.style.display = 'inline';

    // Dynamic colors based on theme
    const sectionBg = this.isDarkTheme ? '#2a2a2a' : '#f8fafc';
    const sectionBorder = this.isDarkTheme ? '#404040' : '#e2e8f0';
    const fallbackBg = this.isDarkTheme ? '#333' : '#f1f5f9';
    const tableBorderColor = this.isDarkTheme ? '#404040' : '#e2e8f0';
    const tableHeaderBg = this.isDarkTheme ? '#333' : '#f1f5f9';
    const tableTextColor = this.isDarkTheme ? '#fff' : '#1e293b';
    const labelColor = this.isDarkTheme ? '#ccc' : '#64748b';

    const verdictColors = {
      'clean': '#10b981',
      'suspicious': '#f59e0b', 
      'malicious': '#ef4444'
    };
    const verdictColor = verdictColors[urlscanData.verdict] || '#888';

    let content = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <span style="background: ${verdictColor}; color: white; padding: 6px 14px; border-radius: 12px; font-size: 12px; font-weight: 600;">
          ${urlscanData.verdict.toUpperCase()}
        </span>
        <button class="copy-btn" style="font-size: 10px; background: ${this.isDarkTheme ? '#333' : '#f1f5f9'}; color: ${this.isDarkTheme ? '#fff' : '#1e293b'}; border: 1px solid ${sectionBorder}; padding: 4px 8px; border-radius: 8px; cursor: pointer;" 
                data-copy="${urlscanData.uuid}" data-label="NexusScan UUID">
          📋 Copy UUID
        </button>
      </div>
    `;

    // DOMAIN INFORMATION DISPLAY
    if (urlscanData.page_info) {
      content += `
        <div style="background: ${sectionBg}; padding: 12px; border-radius: 8px; margin-bottom: 15px; border: 1px solid ${sectionBorder};">
          <h4 style="color: #3b82f6; font-size: 12px; margin-bottom: 8px; text-transform: uppercase; font-weight: 700;">🌐 NexusScan Domain Analysis</h4>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 11px;">
            ${urlscanData.page_info.domain ? `
              <div><strong style="color: ${labelColor};">Domain:</strong><br><span style="color: #3b82f6; font-weight: 600;">${this.escapeHtml(urlscanData.page_info.domain)}</span></div>
            ` : ''}
            ${urlscanData.page_info.ip ? `
              <div><strong style="color: ${labelColor};">Primary IP:</strong><br><span style="color: #3b82f6; font-weight: 600;">${this.escapeHtml(urlscanData.page_info.ip)}</span></div>
            ` : ''}
            ${urlscanData.page_info.country ? `
              <div><strong style="color: ${labelColor};">Country:</strong><br><span style="color: #3b82f6; font-weight: 600;">${this.escapeHtml(urlscanData.page_info.country)}</span></div>
            ` : ''}
            ${urlscanData.page_info.server ? `
              <div><strong style="color: ${labelColor};">Server:</strong><br><span style="color: #3b82f6; font-weight: 600;">${this.escapeHtml(urlscanData.page_info.server)}</span></div>
            ` : ''}
          </div>
        </div>
      `;
    }

    // **SIMPLIFIED: IP ADDRESSES TABLE - Only IP Address and Requests Columns**
    if (urlscanData.ip_addresses && urlscanData.ip_addresses.length > 0) {
      content += `
        <div style="background: ${sectionBg}; padding: 12px; border-radius: 8px; margin-bottom: 15px; border: 1px solid ${sectionBorder};">
          <h4 style="color: #3b82f6; font-size: 12px; margin-bottom: 12px; text-transform: uppercase; font-weight: 700;">🌐 NexusScan IP Address Analysis (${urlscanData.ip_addresses.length} IPs Found)</h4>
          <div style="max-height: 250px; overflow-y: auto; border: 1px solid ${tableBorderColor}; border-radius: 8px;">
            <table style="width: 100%; font-size: 11px; border-collapse: collapse;">
              <thead style="background: ${tableHeaderBg}; position: sticky; top: 0;">
                <tr>
                  <th style="text-align: left; padding: 10px 12px; color: ${tableTextColor}; border-bottom: 1px solid ${tableBorderColor}; font-size: 10px; width: 70%;">IP Address</th>
                  <th style="text-align: center; padding: 10px 12px; color: ${tableTextColor}; border-bottom: 1px solid ${tableBorderColor}; font-size: 10px; width: 30%;">Requests</th>
                </tr>
              </thead>
              <tbody>
      `;

      urlscanData.ip_addresses.forEach((ipInfo, index) => {
        const isPrimary = index === 0;
        const rowBg = isPrimary ? 'rgba(59, 130, 246, 0.1)' : (index % 2 === 1 ? (this.isDarkTheme ? 'rgba(255, 255, 255, 0.02)' : 'rgba(0, 0, 0, 0.02)') : 'transparent');
        
        content += `
          <tr style="border-bottom: 1px solid ${tableBorderColor}; background: ${rowBg};">
            <td style="padding: 12px; color: #3b82f6; font-weight: ${isPrimary ? '600' : '500'}; font-family: 'Courier New', monospace;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 13px;">${this.escapeHtml(ipInfo.ip)}</span>
                ${isPrimary ? '<span style="background: #3b82f6; color: #fff; font-size: 8px; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-family: Arial, sans-serif;">PRIMARY</span>' : ''}
              </div>
            </td>
            <td style="padding: 12px; text-align: center;">
              <span style="color: #3b82f6; font-weight: 600; background: rgba(59, 130, 246, 0.1); padding: 4px 8px; border-radius: 4px; font-size: 12px;">
                ${ipInfo.requests || ipInfo.count || 1}
              </span>
            </td>
          </tr>
        `;
      });

      content += `
              </tbody>
            </table>
          </div>
          <div style="margin-top: 10px; display: flex; justify-content: space-between; align-items: center; font-size: 9px; color: #888;">
            <span>NexusScan detected ${urlscanData.ip_addresses.length} unique IP address${urlscanData.ip_addresses.length !== 1 ? 'es' : ''}</span>
            <button class="copy-btn" style="font-size: 8px; background: ${this.isDarkTheme ? '#404040' : '#e2e8f0'}; color: ${this.isDarkTheme ? '#fff' : '#1e293b'}; border: none; padding: 3px 6px; border-radius: 4px; cursor: pointer;" 
                    data-copy="${urlscanData.ip_addresses.map(ip => ip.ip).join('\\n')}" data-label="All IP Addresses">
              📋 Copy All IPs
            </button>
          </div>
        </div>
      `;
    } else if (urlscanData.page_info && urlscanData.page_info.ip) {
      // Fallback to single IP if no IP list available
      content += `
        <div style="background: ${sectionBg}; padding: 12px; border-radius: 8px; margin-bottom: 15px; border: 1px solid ${sectionBorder};">
          <h4 style="color: #3b82f6; font-size: 12px; margin-bottom: 8px; text-transform: uppercase; font-weight: 700;">🌐 NexusScan IP Address Analysis</h4>
          <div style="text-align: center; padding: 16px; background: ${fallbackBg}; border-radius: 8px;">
            <div style="font-size: 16px; font-weight: bold; color: #3b82f6; font-family: 'Courier New', monospace; margin-bottom: 4px;">
              ${this.escapeHtml(urlscanData.page_info.ip)}
            </div>
            <div style="color: #888; font-size: 10px; margin-bottom: 10px;">Primary IP Address</div>
            <button class="copy-btn" style="font-size: 9px; background: ${this.isDarkTheme ? '#404040' : '#e2e8f0'}; color: ${this.isDarkTheme ? '#fff' : '#1e293b'}; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer;" 
                    data-copy="${urlscanData.page_info.ip}" data-label="IP Address">
              📋 Copy IP
            </button>
          </div>
        </div>
      `;
    }

    // DETECTED TECHNOLOGIES
    if (urlscanData.technologies && urlscanData.technologies.length > 0) {
      content += `
        <div style="background: ${sectionBg}; padding: 12px; border-radius: 8px; margin-bottom: 15px; border: 1px solid ${sectionBorder};">
          <h4 style="color: #3b82f6; font-size: 12px; margin-bottom: 8px; text-transform: uppercase; font-weight: 700;">🔧 Detected Technologies</h4>
          <div style="display: flex; flex-wrap: wrap; gap: 4px;">
            ${urlscanData.technologies.slice(0, 12).map(tech => `
              <span style="background: ${this.isDarkTheme ? '#404040' : '#e2e8f0'}; color: ${this.isDarkTheme ? '#fff' : '#1e293b'}; padding: 2px 6px; border-radius: 4px; font-size: 10px; border: 1px solid ${this.isDarkTheme ? '#555' : '#cbd5e1'};">
                ${this.escapeHtml(tech.app || tech.name || tech)}
              </span>
            `).join('')}
            ${urlscanData.technologies.length > 12 ? `<span style="color: #888; font-size: 10px; padding: 2px 4px;">+${urlscanData.technologies.length - 12} more</span>` : ''}
          </div>
        </div>
      `;
    }

    // SCREENSHOT SECTION
    if (urlscanData.screenshot) {
      const screenshotId = `nexus-screenshot-${Date.now()}`;
      content += `
        <div style="text-align: center; margin-bottom: 18px;">
          <img id="${screenshotId}" src="${urlscanData.screenshot}" 
               alt="NexusScan Website Screenshot" 
               style="width: 100%; max-width: 300px; height: auto; border-radius: 12px; cursor: pointer; border: 1px solid ${sectionBorder}; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
          <div style="font-size: 11px; color: #888; margin-top: 8px;">🔍 NexusScan Screenshot - Click to expand</div>
        </div>
      `;
      
      setTimeout(() => {
        const screenshotImg = document.getElementById(screenshotId);
        if (screenshotImg) {
          screenshotImg.addEventListener('click', () => {
            this.openScreenshotModal(urlscanData.screenshot);
          });
        }
      }, 100);
    }

    urlscanContent.innerHTML = content;
  }

  displayThreats(threats) {
    const threatsList = document.getElementById('threatsList');
    
    if (!threats || threats.length === 0) {
      threatsList.innerHTML = `<div class="threat-item low">✅ NexusScan: No specific threats detected</div>`;
      return;
    }

    const threatsHtml = threats.map(threat => {
      let threatClass = 'threat-item low';
      if (threat.toLowerCase().includes('malicious') || threat.toLowerCase().includes('dangerous')) {
        threatClass = 'threat-item high';
      } else if (threat.toLowerCase().includes('suspicious')) {
        threatClass = 'threat-item medium';
      }

      return `<div class="${threatClass}">🔍 NexusScan: ${this.escapeHtml(threat)}</div>`;
    }).join('');

    threatsList.innerHTML = threatsHtml;
  }

  displayCommunityFeedback(communityFeedback) {
    const communityDisplay = document.getElementById('communityFeedbackDisplay');
    
    if (!communityFeedback || communityFeedback.totalRatings === 0) {
      communityDisplay.style.display = 'none';
      return;
    }

    communityDisplay.style.display = 'block';

    const starsContainer = document.getElementById('communityStars');
    starsContainer.innerHTML = '';
    
    for (let i = 1; i <= 5; i++) {
      const star = document.createElement('span');
      star.className = i <= Math.round(communityFeedback.averageRating) ? 'star' : 'star empty';
      star.textContent = '⭐';
      starsContainer.appendChild(star);
    }

    document.getElementById('communityRatingText').textContent = 
      `${communityFeedback.averageRating}/5 (${communityFeedback.totalRatings} NexusScan ratings)`;

    const statsContainer = document.getElementById('communityStats');
    statsContainer.innerHTML = '';
    
    Object.entries(communityFeedback.categories).forEach(([category, count]) => {
      if (count > 0) {
        const statDiv = document.createElement('div');
        statDiv.className = 'community-stat';
        
        const categoryEmojis = {
          safe: '✅',
          suspicious: '⚠️',
          malicious: '🚨',
          false_positive: '🔄'
        };
        
        const categoryNames = {
          safe: 'Safe',
          suspicious: 'Suspicious',
          malicious: 'Malicious',
          false_positive: 'False Positive'
        };
        
        statDiv.innerHTML = `
          <div class="stat-number">${count}</div>
          <div class="stat-name">${categoryEmojis[category]} ${categoryNames[category]}</div>
        `;
        
        statsContainer.appendChild(statDiv);
      }
    });

    const commentsContainer = document.getElementById('communityComments');
    commentsContainer.innerHTML = '';
    
    if (communityFeedback.comments && communityFeedback.comments.length > 0) {
      communityFeedback.comments.forEach(comment => {
        if (comment.comment && comment.comment.trim()) {
          const commentDiv = document.createElement('div');
          commentDiv.className = 'comment-item';
          
          const categoryEmojis = {
            safe: '✅',
            suspicious: '⚠️',
            malicious: '🚨',
            false_positive: '🔄'
          };
          
          commentDiv.innerHTML = `
            <div class="comment-meta">
              <span>${categoryEmojis[comment.category]} ${comment.rating}/5 NexusScan</span>
              <span>${this.getTimeAgo(comment.timestamp)}</span>
            </div>
            <div>${this.escapeHtml(comment.comment)}</div>
          `;
          
          commentsContainer.appendChild(commentDiv);
        }
      });
    } else {
      commentsContainer.innerHTML = '<div style="text-align: center; color: #888; font-style: italic;">No NexusScan community comments yet</div>';
    }
  }

  // **FIXED: Single Back Button System**
  toggleHistoryView() {
    this.showingHistory = !this.showingHistory;
    this.showingCommunity = false;
    this.showingBookmarks = false;
    
    const body = document.body;
    const historySection = document.getElementById('historySection');
    const communitySection = document.getElementById('communitySection');
    const bookmarkSection = document.getElementById('bookmarkSection');
    
    // Update ALL footer buttons to show current state
    this.updateFooterButtons();

    if (this.showingHistory) {
      body.classList.add('history-mode');
      body.classList.remove('community-mode', 'bookmark-mode');
      if (historySection) historySection.style.display = 'block';
      if (communitySection) communitySection.style.display = 'none';
      if (bookmarkSection) bookmarkSection.style.display = 'none';
      
      // Load REAL history data
      this.loadRealHistoryData();
      console.log('NexusScan: History view opened');
    } else {
      body.classList.remove('history-mode');
      if (historySection) historySection.style.display = 'none';
      console.log('NexusScan: History view closed');
    }
  }

  toggleCommunityView() {
    this.showingCommunity = !this.showingCommunity;
    this.showingHistory = false;
    this.showingBookmarks = false;
    
    const body = document.body;
    const communitySection = document.getElementById('communitySection');
    const historySection = document.getElementById('historySection');
    const bookmarkSection = document.getElementById('bookmarkSection');
    
    // Update ALL footer buttons to show current state
    this.updateFooterButtons();

    if (this.showingCommunity) {
      body.classList.add('community-mode');
      body.classList.remove('history-mode', 'bookmark-mode');
      if (communitySection) communitySection.style.display = 'block';
      if (historySection) historySection.style.display = 'none';
      if (bookmarkSection) bookmarkSection.style.display = 'none';
      
      // Load REAL community data
      this.loadRealCommunityData();
      console.log('NexusScan: Community view opened');
    } else {
      body.classList.remove('community-mode');
      if (communitySection) communitySection.style.display = 'none';
      console.log('NexusScan: Community view closed');
    }
  }

  toggleBookmarkView() {
    this.showingBookmarks = !this.showingBookmarks;
    this.showingHistory = false;
    this.showingCommunity = false;
    
    const body = document.body;
    const bookmarkSection = document.getElementById('bookmarkSection');
    const historySection = document.getElementById('historySection');
    const communitySection = document.getElementById('communitySection');
    
    // Update ALL footer buttons to show current state
    this.updateFooterButtons();

    if (this.showingBookmarks) {
      body.classList.add('bookmark-mode');
      body.classList.remove('history-mode', 'community-mode');
      if (bookmarkSection) bookmarkSection.style.display = 'block';
      if (historySection) historySection.style.display = 'none';
      if (communitySection) communitySection.style.display = 'none';
      
      // Load REAL bookmark data
      this.loadRealBookmarkData();
      console.log('NexusScan: Bookmark scanner opened');
    } else {
      body.classList.remove('bookmark-mode');
      if (bookmarkSection) bookmarkSection.style.display = 'none';
      console.log('NexusScan: Bookmark scanner closed');
    }
  }

  // **NEW: Unified Footer Button Update Method**
  updateFooterButtons() {
    const historyToggle = document.getElementById('historyToggle');
    const communityToggle = document.getElementById('communityToggle');
    const bookmarkToggle = document.getElementById('bookmarkToggle');
    
    // Check if any section is active
    const isAnyActive = this.showingHistory || this.showingCommunity || this.showingBookmarks;
    
    if (isAnyActive) {
      // Show single "Back" button on the active section, normal text on others
      if (this.showingHistory) {
        if (historyToggle) historyToggle.textContent = '🔙 Back';
        if (communityToggle) communityToggle.textContent = '👥 Community';
        if (bookmarkToggle) bookmarkToggle.textContent = '🔖 Bookmarks';
      } else if (this.showingCommunity) {
        if (historyToggle) historyToggle.textContent = '📊 History';
        if (communityToggle) communityToggle.textContent = '🔙 Back';
        if (bookmarkToggle) bookmarkToggle.textContent = '🔖 Bookmarks';
      } else if (this.showingBookmarks) {
        if (historyToggle) historyToggle.textContent = '📊 History';
        if (communityToggle) communityToggle.textContent = '👥 Community';
        if (bookmarkToggle) bookmarkToggle.textContent = '🔙 Back';
      }
    } else {
      // No sections active - show normal text on all buttons
      if (historyToggle) historyToggle.textContent = '📊 History';
      if (communityToggle) communityToggle.textContent = '👥 Community';
      if (bookmarkToggle) bookmarkToggle.textContent = '🔖 Bookmarks';
    }
  }

  // **NEW: REAL Data Loading Methods**
  async loadRealHistoryData() {
    try {
      // Load actual scan history from Chrome storage
      const result = await chrome.storage.local.get(['nexusscan_history']);
      const history = result.nexusscan_history || [];
      
      // Calculate real stats
      const today = new Date().toDateString();
      const todayScans = history.filter(scan => new Date(scan.timestamp).toDateString() === today).length;
      const totalScans = history.length;
      const averageScore = totalScans > 0 ? Math.round(history.reduce((sum, scan) => sum + (scan.score || 0), 0) / totalScans) : 0;
      const dangerousScans = history.filter(scan => (scan.score || 0) >= 70).length;
      
      // Update stats with REAL data
      document.getElementById('totalScans').textContent = totalScans;
      document.getElementById('todayScans').textContent = todayScans;
      document.getElementById('averageScore').textContent = averageScore;
      document.getElementById('dangerousScans').textContent = dangerousScans;
      
      // Display real history list
      const historyList = document.getElementById('historyList');
      if (history.length === 0) {
        historyList.innerHTML = `
          <div class="history-empty">
            <div class="history-empty-icon">📊</div>
            <div>No NexusScan history found</div>
            <div style="margin-top: 8px; font-size: 12px;">Start scanning URLs to build your history</div>
          </div>
        `;
      } else {
        const recentHistory = history.slice(-10).reverse(); // Show 10 most recent
        historyList.innerHTML = recentHistory.map(scan => {
          const scoreClass = (scan.score || 0) >= 70 ? 'dangerous' : (scan.score || 0) >= 40 ? 'suspicious' : 'safe';
          const scoreText = (scan.score || 0) >= 70 ? 'Dangerous' : (scan.score || 0) >= 40 ? 'Suspicious' : 'Safe';
          const timeAgo = this.getTimeAgo(scan.timestamp);
          
          return `
            <div class="history-item">
              <div class="history-url">${this.escapeHtml(scan.url)}</div>
              <div class="history-score ${scoreClass}">NexusScan ${scan.score || 0} - ${scoreText}</div>
              <div style="font-size: 12px; color: #888; margin-top: 4px;">Scanned ${timeAgo}</div>
            </div>
          `;
        }).join('');
      }
    } catch (error) {
      console.error('Failed to load real history:', error);
      document.getElementById('totalScans').textContent = '0';
      document.getElementById('todayScans').textContent = '0';
      document.getElementById('averageScore').textContent = '0';
      document.getElementById('dangerousScans').textContent = '0';
      document.getElementById('historyList').innerHTML = '<div class="history-empty"><div class="history-empty-icon">❌</div><div>Error loading history</div></div>';
    }
  }

  async loadRealCommunityData() {
    try {
      // Load actual community feedback from Chrome storage
      const result = await chrome.storage.local.get(['nexusscan_community_feedback']);
      const feedback = result.nexusscan_community_feedback || [];
      
      // Calculate real community stats
      const today = new Date().toDateString();
      const todayFeedback = feedback.filter(f => new Date(f.timestamp).toDateString() === today).length;
      const totalFeedback = feedback.length;
      const avgRating = totalFeedback > 0 ? (feedback.reduce((sum, f) => sum + (f.rating || 0), 0) / totalFeedback).toFixed(1) : '0.0';
      const maliciousReports = feedback.filter(f => f.category === 'malicious').length;
      
      // Update stats with REAL data
      document.getElementById('totalFeedback').textContent = totalFeedback;
      document.getElementById('todayFeedback').textContent = todayFeedback;
      document.getElementById('avgCommunityRating').textContent = avgRating;
      document.getElementById('maliciousReports').textContent = maliciousReports;
      
      // Show feedback form
      const feedbackForm = document.getElementById('feedbackForm');
      if (feedbackForm) {
        feedbackForm.style.display = 'block';
      }

      // Display real community list
      const communityList = document.getElementById('communityList');
      if (feedback.length === 0) {
        communityList.innerHTML = `
          <div class="history-empty">
            <div class="history-empty-icon">👥</div>
            <div>No community feedback yet</div>
            <div style="margin-top: 8px; font-size: 12px;">Be the first to share your experience!</div>
          </div>
        `;
      } else {
        const recentFeedback = feedback.slice(-5).reverse(); // Show 5 most recent
        communityList.innerHTML = recentFeedback.map(f => {
          const scoreClass = f.category === 'malicious' ? 'dangerous' : f.category === 'suspicious' ? 'suspicious' : 'safe';
          const stars = '⭐'.repeat(f.rating || 1);
          const timeAgo = this.getTimeAgo(f.timestamp);
          
          return `
            <div class="history-item">
              <div class="history-url">${this.escapeHtml(f.url)}</div>
              <div class="history-score ${scoreClass}">${stars} ${f.category}</div>
              <div style="font-size: 12px; color: #888; margin-top: 4px;">"${this.escapeHtml(f.comment || 'No comment')}" - ${timeAgo}</div>
            </div>
          `;
        }).join('');
      }
    } catch (error) {
      console.error('Failed to load real community data:', error);
      document.getElementById('totalFeedback').textContent = '0';
      document.getElementById('todayFeedback').textContent = '0';
      document.getElementById('avgCommunityRating').textContent = '0.0';
      document.getElementById('maliciousReports').textContent = '0';
    }
  }

  async loadRealBookmarkData() {
    try {
      // Get actual Chrome bookmarks
      const bookmarks = await chrome.bookmarks.getTree();
      const flatBookmarks = this.flattenBookmarks(bookmarks);
      
      // Load scan results for bookmarks
      const result = await chrome.storage.local.get(['nexusscan_bookmark_results']);
      const scanResults = result.nexusscan_bookmark_results || {};
      
      // Calculate real stats
      const totalBookmarks = flatBookmarks.length;
      const scannedBookmarksCount = Object.keys(scanResults).length;
      const safeBookmarksCount = Object.values(scanResults).filter(r => (r.score || 0) < 40).length;
      const dangerousBookmarksCount = Object.values(scanResults).filter(r => (r.score || 0) >= 70).length;
      
      // Update stats with REAL data
      document.getElementById('totalBookmarks').textContent = totalBookmarks;
      document.getElementById('scannedBookmarks').textContent = scannedBookmarksCount;
      document.getElementById('safeBookmarks').textContent = safeBookmarksCount;
      document.getElementById('dangerousBookmarks').textContent = dangerousBookmarksCount;
      
      // Display real bookmark list
      const bookmarkList = document.getElementById('bookmarkList');
      if (flatBookmarks.length === 0) {
        bookmarkList.innerHTML = `
          <div class="history-empty">
            <div class="history-empty-icon">🔖</div>
            <div>No bookmarks found</div>
            <div style="margin-top: 8px; font-size: 12px;">Add bookmarks to scan them with NexusScan</div>
          </div>
        `;
      } else {
        const displayBookmarks = flatBookmarks.slice(0, 20); // Show first 20
        bookmarkList.innerHTML = displayBookmarks.map(bookmark => {
          const scanResult = scanResults[bookmark.url];
          const score = scanResult?.score || 0;
          const statusClass = score >= 70 ? 'dangerous' : score >= 40 ? 'suspicious' : scanResult ? 'safe' : 'pending';
          const statusText = score >= 70 ? `Dangerous (Score: ${score})` : 
                           score >= 40 ? `Suspicious (Score: ${score})` : 
                           scanResult ? `Safe (Score: ${score})` : 'Pending Scan';
          
          return `
            <div class="bookmark-item">
              <div class="bookmark-title">${this.escapeHtml(bookmark.title)}</div>
              <div class="bookmark-url">${this.escapeHtml(bookmark.url)}</div>
              <div class="bookmark-status ${statusClass}">${statusText}</div>
            </div>
          `;
        }).join('');
      }
    } catch (error) {
      console.error('Failed to load real bookmark data:', error);
      document.getElementById('totalBookmarks').textContent = '0';
      document.getElementById('scannedBookmarks').textContent = '0';
      document.getElementById('safeBookmarks').textContent = '0';
      document.getElementById('dangerousBookmarks').textContent = '0';
      document.getElementById('bookmarkList').innerHTML = '<div class="history-empty"><div class="history-empty-icon">❌</div><div>Error loading bookmarks</div></div>';
    }
  }

  // Helper method to flatten bookmark tree
  flattenBookmarks(bookmarkTree) {
    let bookmarks = [];
    
    function traverse(nodes) {
      for (let node of nodes) {
        if (node.url) {
          bookmarks.push({
            title: node.title,
            url: node.url
          });
        }
        if (node.children) {
          traverse(node.children);
        }
      }
    }
    
    traverse(bookmarkTree);
    return bookmarks;
  }

  // **FUNCTIONAL METHODS FOR FEATURES**
  // REMOVED: loadHistory method (refresh button functionality removed)

  async exportHistory() {
    try {
      const result = await chrome.storage.local.get(['nexusscan_history']);
      const history = result.nexusscan_history || [];
      
      const historyData = {
        totalScans: history.length,
        exportDate: new Date().toISOString(),
        scans: history
      };
      
      this.downloadFile(JSON.stringify(historyData, null, 2), 'nexusscan-history.json', 'application/json');
      this.showToast('📤 History exported successfully', 'success');
    } catch (error) {
      this.showToast('❌ Failed to export history', 'error');
    }
  }

  async clearHistory() {
    if (confirm('Clear all NexusScan history?')) {
      try {
        await chrome.storage.local.remove(['nexusscan_history']);
        await this.loadRealHistoryData();
        this.showToast('🗑️ History cleared', 'info');
      } catch (error) {
        this.showToast('❌ Failed to clear history', 'error');
      }
    }
  }

  filterHistory(filterType) {
    // REMOVED: Unwanted toast notification
    // Implementation would filter the history list based on filterType
  }

  searchHistory(searchTerm) {
    console.log('Searching history:', searchTerm);
    // Implementation would filter history based on search term
  }

  changePage(direction) {
    this.currentHistoryPage += direction;
    if (this.currentHistoryPage < 1) this.currentHistoryPage = 1;
    // REMOVED: Unwanted toast notification
  }

  showFeedbackForm() {
    const feedbackForm = document.getElementById('feedbackForm');
    if (feedbackForm) {
      feedbackForm.style.display = feedbackForm.style.display === 'none' ? 'block' : 'none';
    }
  }

  async submitFeedback() {
    const url = document.getElementById('feedbackURL')?.value;
    const rating = this.currentRating;
    const category = document.getElementById('feedbackCategory')?.value;
    const comment = document.getElementById('feedbackComment')?.value;

    if (!url || !rating) {
      this.showToast('❌ Please fill in required fields', 'error');
      return;
    }

    try {
      // Save real feedback to storage
      const result = await chrome.storage.local.get(['nexusscan_community_feedback']);
      const feedback = result.nexusscan_community_feedback || [];
      
      feedback.push({
        url: url,
        rating: rating,
        category: category,
        comment: comment,
        timestamp: Date.now()
      });
      
      await chrome.storage.local.set({ nexusscan_community_feedback: feedback });
      
      this.showToast('🚀 Feedback submitted to NexusScan community!', 'success');
      
      // Clear form
      document.getElementById('feedbackComment').value = '';
      this.currentRating = 0;
      this.updateStarDisplay();
      
      // Refresh community data
      await this.loadRealCommunityData();
    } catch (error) {
      this.showToast('❌ Failed to submit feedback', 'error');
    }
  }

  async loadCommunityStats() {
    this.loadRealCommunityData();
    // REMOVED: Unwanted toast notification
  }

  async scanAllBookmarks() {
    try {
      const bookmarks = await chrome.bookmarks.getTree();
      const flatBookmarks = this.flattenBookmarks(bookmarks);
      
      if (flatBookmarks.length === 0) {
        this.showToast('❌ No bookmarks to scan', 'error');
        return;
      }
      
      this.showToast(`🔍 Scanning ${flatBookmarks.length} bookmarks...`, 'info');
      
      // Show progress container
      const progressContainer = document.getElementById('scanProgressContainer');
      if (progressContainer) {
        progressContainer.style.display = 'block';
      }
      
      let scannedCount = 0;
      const results = {};
      
      for (const bookmark of flatBookmarks) {
        try {
          // Update progress
          scannedCount++;
          const progress = (scannedCount / flatBookmarks.length) * 100;
          document.getElementById('scanProgressBarFill').style.width = `${progress}%`;
          document.getElementById('scanProgressStats').textContent = `${scannedCount} / ${flatBookmarks.length}`;
          document.getElementById('scanCurrentUrl').textContent = bookmark.url;
          
          // Scan bookmark (simplified - in real implementation, this would call your scan API)
          const response = await chrome.runtime.sendMessage({
            action: 'scanURL',
            url: bookmark.url,
            quickScan: true // Add a quick scan mode for bulk scanning
          });
          
          if (response.success) {
            results[bookmark.url] = response.data;
          }
          
          // Small delay to prevent rate limiting
          await new Promise(resolve => setTimeout(resolve, 100));
        } catch (error) {
          console.error('Error scanning bookmark:', bookmark.url, error);
        }
      }
      
      // Save results
      await chrome.storage.local.set({ nexusscan_bookmark_results: results });
      
      // Hide progress and refresh display
      if (progressContainer) {
        progressContainer.style.display = 'none';
      }
      
      await this.loadRealBookmarkData();
      this.showToast(`✅ Scanned ${scannedCount} bookmarks!`, 'success');
    } catch (error) {
      console.error('Failed to scan bookmarks:', error);
      this.showToast('❌ Failed to scan bookmarks', 'error');
    }
  }

  async exportBookmarkResults() {
    try {
      const result = await chrome.storage.local.get(['nexusscan_bookmark_results']);
      const results = result.nexusscan_bookmark_results || {};
      
      const bookmarkData = {
        exportDate: new Date().toISOString(),
        totalResults: Object.keys(results).length,
        results: results
      };
      
      this.downloadFile(JSON.stringify(bookmarkData, null, 2), 'nexusscan-bookmarks.json', 'application/json');
      this.showToast('📤 Bookmark results exported', 'success');
    } catch (error) {
      this.showToast('❌ Failed to export results', 'error');
    }
  }

  async clearBookmarkResults() {
    if (confirm('Clear all bookmark scan results?')) {
      try {
        await chrome.storage.local.remove(['nexusscan_bookmark_results']);
        await this.loadRealBookmarkData();
        this.showToast('🗑️ Bookmark results cleared', 'info');
      } catch (error) {
        this.showToast('❌ Failed to clear results', 'error');
      }
    }
  }

  filterBookmarks(filterType) {
    // REMOVED: Unwanted toast notification
    // Implementation would filter bookmarks based on filterType
  }

  searchBookmarks(searchTerm) {
    console.log('Searching bookmarks:', searchTerm);
    // Implementation would filter bookmarks based on search term
  }

  // **STAR RATING METHODS**
  setRating(rating) {
    this.currentRating = rating;
    this.updateStarDisplay();
    this.updateRatingText();
    // REMOVED: Unwanted toast notification for rating
  }

  previewRating(rating) {
    const stars = document.querySelectorAll('#ratingInput .rating-star');
    stars.forEach((star, index) => {
      star.classList.remove('active');
      if (index < rating) {
        star.classList.add('active');
      }
    });
  }

  updateStarDisplay() {
    this.previewRating(this.currentRating);
  }

  updateRatingText() {
    const ratingText = document.getElementById('ratingSelectedText');
    if (!ratingText) return;
    
    if (this.currentRating === 0) {
      ratingText.style.display = 'none';
      return;
    }

    const descriptions = {
      1: "⭐ Very Safe - NexusScan verified",
      2: "⭐⭐ Safe - NexusScan approved", 
      3: "⭐⭐⭐ Neutral - NexusScan caution",
      4: "⭐⭐⭐⭐ Suspicious - NexusScan alert",
      5: "⭐⭐⭐⭐⭐ Dangerous - NexusScan warning"
    };
    
    ratingText.textContent = descriptions[this.currentRating];
    ratingText.style.display = 'block';
    ratingText.style.color = this.isDarkTheme ? '#fff' : '#1e293b';
  }

  showHorizontalDescription(rating) {
    const ratingText = document.getElementById('ratingSelectedText');
    if (!ratingText) return;
    
    const descriptions = {
      1: "⭐ Very Safe - NexusScan verified, completely trustworthy",
      2: "⭐⭐ Safe - NexusScan approved, generally secure", 
      3: "⭐⭐⭐ Neutral - NexusScan suggests caution",
      4: "⭐⭐⭐⭐ Suspicious - NexusScan detected potential risks",
      5: "⭐⭐⭐⭐⭐ Dangerous - NexusScan critical threat alert"
    };
    
    ratingText.textContent = descriptions[rating];
    ratingText.style.display = 'block';
    ratingText.style.opacity = '0.8';
    ratingText.style.fontStyle = 'italic';
  }

  hideHorizontalDescription() {
    if (this.currentRating > 0) {
      this.updateRatingText();
    } else {
      const ratingText = document.getElementById('ratingSelectedText');
      if (ratingText) {
        ratingText.style.display = 'none';
      }
    }
  }

  // **THEME AND UTILITY METHODS**
  toggleTheme() {
    this.isDarkTheme = !this.isDarkTheme;
    this.updateTheme();
    this.saveTheme();
    console.log('NexusScan: Theme toggled to', this.isDarkTheme ? 'dark' : 'light');
  }

  updateTheme() {
    const body = document.body;
    const themeToggle = document.getElementById('themeToggle');
    
    if (this.isDarkTheme) {
      body.className = 'dark-theme';
      themeToggle.textContent = '🌙';
    } else {
      body.className = 'light-theme';
      themeToggle.textContent = '☀️';
    }
  }

  async saveTheme() {
    try {
      await chrome.storage.sync.set({ 
        theme: this.isDarkTheme ? 'dark' : 'light' 
      });
    } catch (error) {
      console.error('NexusScan: Failed to save theme:', error);
    }
  }

  // **FIXED: Compact Toast Notifications**
  showToast(message, type = 'info') {
    // Remove any existing toasts first
    const existingToasts = document.querySelectorAll('.nexus-toast');
    existingToasts.forEach(toast => toast.remove());
    
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = `nexus-toast nexus-toast-${type}`;
    toast.innerHTML = `
      <div class="nexus-toast-content">
        <span class="nexus-toast-message">${message}</span>
        <button class="nexus-toast-close" onclick="this.closest('.nexus-toast').remove()">×</button>
      </div>
    `;
    
    // Enhanced styling for compact, corner positioning
    toast.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 16px;
      border-radius: 8px;
      color: white;
      font-weight: 600;
      font-size: 14px;
      z-index: 10000;
      opacity: 0;
      transform: translateX(100%);
      transition: all 0.3s ease;
      max-width: 300px;
      min-width: 250px;
      word-wrap: break-word;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      pointer-events: auto;
    `;
    
    // Set background color based on type
    switch (type) {
      case 'success':
        toast.style.backgroundColor = '#10b981';
        break;
      case 'error':
        toast.style.backgroundColor = '#ef4444';
        break;
      case 'info':
      default:
        toast.style.backgroundColor = '#3b82f6';
        break;
    }
    
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => {
      toast.style.opacity = '1';
      toast.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto-dismiss
    const dismissTime = type === 'success' ? 4000 : 3000;
    setTimeout(() => {
      if (toast.parentNode) {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => {
          if (toast.parentNode) {
            toast.parentNode.removeChild(toast);
          }
        }, 300);
      }
    }, dismissTime);
  }

  async copyToClipboard(text, label = 'Text') {
    try {
      await navigator.clipboard.writeText(text);
      this.showToast(`📋 ${label} copied!`, 'success');
    } catch (error) {
      console.error('NexusScan: Copy failed:', error);
      this.showToast('❌ Copy failed', 'error');
    }
  }

  // **UTILITY METHODS**
  getTimeAgo(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
    
    return new Date(timestamp).toLocaleDateString();
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  animateNumber(element, start, end, duration) {
    const startTime = performance.now();
    const updateNumber = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const current = Math.floor(start + (end - start) * progress);
      element.textContent = current;
      
      if (progress < 1) {
        requestAnimationFrame(updateNumber);
      }
    };
    requestAnimationFrame(updateNumber);
  }

  downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }

  openScreenshotModal(screenshotUrl) {
    this.ensureModalExists();
    
    const modal = document.getElementById('screenshotModal');
    const modalScreenshot = document.getElementById('modalScreenshot');
    const openScreenshot = document.getElementById('openScreenshot');
    
    if (modal && modalScreenshot && openScreenshot) {
      modalScreenshot.src = screenshotUrl;
      openScreenshot.onclick = () => window.open(screenshotUrl, '_blank');
      modal.style.display = 'flex';
    }
  }

  ensureModalExists() {
    let modal = document.getElementById('screenshotModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'screenshotModal';
      modal.className = 'screenshot-modal';
      modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        display: none;
        align-items: center;
        justify-content: center;
        z-index: 10000;
      `;
      modal.innerHTML = `
        <div style="max-width: 90%; max-height: 90%; position: relative; background: #333; border-radius: 16px; padding: 24px;">
          <button id="closeModal" style="position: absolute; top: 15px; right: 15px; background: #ef4444; color: white; border: none; border-radius: 10px; padding: 8px 12px; cursor: pointer;">✕</button>
          <img id="modalScreenshot" style="width: 100%; height: auto; border-radius: 12px; margin-bottom: 15px;" alt="NexusScan Screenshot">
          <div style="text-align: center;">
            <button id="openScreenshot" style="background: #3b82f6; color: white; border: none; border-radius: 12px; padding: 12px 20px; cursor: pointer;">🌐 Open in New Tab</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
      
      document.getElementById('closeModal').addEventListener('click', () => {
        this.closeScreenshotModal();
      });
      
      modal.addEventListener('click', (e) => {
        if (e.target.id === 'screenshotModal') {
          this.closeScreenshotModal();
        }
      });
    }
  }

  closeScreenshotModal() {
    const modal = document.getElementById('screenshotModal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  async blockCurrentURL() {
    if (!this.currentURL) return;
    
    try {
      console.log('NexusScan: Blocking URL:', this.currentURL);
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const response = await chrome.runtime.sendMessage({
        action: 'blockURL',
        url: this.currentURL,
        tabId: tabs[0]?.id
      });
      
      if (response.success) {
        this.showToast('🚫 URL blocked by NexusScan', 'success');
        window.close();
      } else {
        throw new Error(response.error);
      }
    } catch (error) {
      console.error('NexusScan: Block URL error:', error);
      this.showToast('❌ Failed to block URL: ' + error.message, 'error');
    }
  }
}

// Initialize NexusScan popup when DOM is loaded
let nexusScanPopup;
document.addEventListener('DOMContentLoaded', () => {
  nexusScanPopup = new NexusScanPopup();
});
