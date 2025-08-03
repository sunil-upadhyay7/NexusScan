// background.js - NexusScan Background Script - Enhanced with IP Address Analysis
class ThreatIntelligence {
  constructor() {
    this.VT_API_KEY = null;
    this.URLSCAN_API_KEY = null;
    this.cache = new Map();
    this.maxCacheSize = 100;
    this.initializeMonitoring();
    this.loadApiKeys();
    this.initializeStorage();
  }

  async initializeStorage() {
    try {
      const storageAreas = [
        'nexusscan_scan_history',
        'nexusscan_community_feedback', 
        'nexusscan_bookmark_scan_results',
        'nexusscan_url_reports'
      ];

      for (const area of storageAreas) {
        const existing = await chrome.storage.local.get(area);
        if (!existing[area]) {
          await chrome.storage.local.set({ [area]: [] });
          console.log(`NexusScan: Initialized storage area: ${area}`);
        }
      }
    } catch (error) {
      console.error('NexusScan: Failed to initialize storage:', error);
    }
  }

  async loadApiKeys() {
    try {
      const settings = await chrome.storage.sync.get(['vtApiKey', 'urlscanApiKey', 'urlscanVisibility']);
      this.VT_API_KEY = settings.vtApiKey;
      this.URLSCAN_API_KEY = settings.urlscanApiKey;
      this.URLSCAN_VISIBILITY = settings.urlscanVisibility || 'private';
      
      console.log('NexusScan: API keys loaded:', {
        hasVT: !!this.VT_API_KEY,
        hasUrlscan: !!this.URLSCAN_API_KEY,
        visibility: this.URLSCAN_VISIBILITY
      });
    } catch (error) {
      console.error('NexusScan: Failed to load API keys:', error);
    }
  }

  initializeMonitoring() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse);
      return true;
    });

    chrome.storage.onChanged.addListener((changes) => {
      if (changes.vtApiKey || changes.urlscanApiKey || changes.urlscanVisibility) {
        this.loadApiKeys();
      }
    });

    setInterval(() => {
      this.cleanCache();
    }, 30 * 60 * 1000);
  }

  cleanCache() {
    if (this.cache.size > this.maxCacheSize) {
      const entries = Array.from(this.cache.entries());
      entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
      
      const toRemove = Math.floor(this.cache.size * 0.2);
      for (let i = 0; i < toRemove; i++) {
        this.cache.delete(entries[i][0]);
      }
      console.log(`NexusScan: Cache cleaned: removed ${toRemove} entries`);
    }
  }

  async handleMessage(request, sender, sendResponse) {
    try {
      switch (request.action) {
        case 'scanURL':
          const result = await this.comprehensiveScan(request.url, request.forceRescan);
          sendResponse({ success: true, data: result });
          break;
        
        case 'getCurrentTab':
          const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
          sendResponse({ success: true, data: tabs[0] });
          break;
        
        case 'blockURL':
          await this.blockURL(request.url, request.tabId);
          sendResponse({ success: true });
          break;
        
        case 'clearCache':
          this.cache.clear();
          sendResponse({ success: true, message: 'NexusScan cache cleared' });
          break;
        
        case 'getHistory':
          const history = await this.getHistory(request.limit);
          sendResponse({ success: true, data: history });
          break;
        
        case 'getHistoryStats':
          const stats = await this.getHistoryStats();
          sendResponse({ success: true, data: stats });
          break;
        
        case 'clearHistory':
          const cleared = await this.clearHistory();
          sendResponse({ success: true, cleared });
          break;
        
        case 'exportHistory':
          const exportData = await this.exportHistory(request.format);
          sendResponse({ success: true, data: exportData });
          break;

        case 'submitFeedback':
          const feedbackResult = await this.submitFeedback(request.feedback);
          sendResponse({ success: true, data: feedbackResult });
          break;
        
        case 'getFeedback':
          const urlFeedback = await this.getFeedback(request.url);
          sendResponse({ success: true, data: urlFeedback });
          break;
        
        case 'getFeedbackStats':
          const feedbackStats = await this.getFeedbackStats();
          sendResponse({ success: true, data: feedbackStats });
          break;
        
        case 'reportURL':
          const reportResult = await this.reportURL(request.report);
          sendResponse({ success: true, data: reportResult });
          break;
        
        case 'getUserFeedback':
          const userFeedback = await this.getUserFeedback();
          sendResponse({ success: true, data: userFeedback });
          break;
        
        case 'deleteFeedback':
          const deleteResult = await this.deleteFeedback(request.feedbackId);
          sendResponse({ success: true, data: deleteResult });
          break;

        case 'getBookmarks':
          const bookmarks = await this.getBookmarks();
          sendResponse({ success: true, data: bookmarks });
          break;
        
        case 'getBookmarkScanResults':
          const bookmarkResults = await this.getBookmarkScanResults();
          sendResponse({ success: true, data: bookmarkResults });
          break;
        
        case 'saveBookmarkScanResults':
          const saveResult = await this.saveBookmarkScanResults(request.results);
          sendResponse({ success: true, data: saveResult });
          break;
        
        case 'scanBookmarksBulk':
          const bulkScanResult = await this.scanBookmarksBulk(request.bookmarks, request.callback);
          sendResponse({ success: true, data: bulkScanResult });
          break;
        
        case 'clearBookmarkScanResults':
          const clearResult = await this.clearBookmarkScanResults();
          sendResponse({ success: true, data: clearResult });
          break;
        
        case 'exportBookmarkResults':
          const exportBookmarkData = await this.exportBookmarkResults();
          sendResponse({ success: true, data: exportBookmarkData });
          break;
          
        case 'getStats':
          sendResponse({ 
            success: true, 
            data: {
              cacheSize: this.cache.size,
              hasVTKey: !!this.VT_API_KEY,
              hasUrlscanKey: !!this.URLSCAN_API_KEY
            }
          });
          break;
        
        default:
          sendResponse({ success: false, error: 'Unknown action' });
      }
    } catch (error) {
      console.error('NexusScan background script error:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  // ENHANCED: urlscan.io Integration with IP Address Extraction
  async submitUrlscan(url) {
    if (!this.URLSCAN_API_KEY) {
      console.log('NexusScan: No urlscan.io API key available');
      return { error: 'No urlscan.io API key configured' };
    }

    try {
      console.log('NexusScan: Submitting URL to urlscan.io:', url);
      
      const response = await fetch('https://urlscan.io/api/v1/scan/', {
        method: 'POST',
        headers: {
          'API-Key': this.URLSCAN_API_KEY,
          'Content-Type': 'application/json',
          'User-Agent': 'NexusScan/1.0'
        },
        body: JSON.stringify({
          url: url,
          visibility: this.URLSCAN_VISIBILITY || 'private',
          tags: ['nexusscan', 'security-scan']
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
        
        switch (response.status) {
          case 400:
            if (errorData.message && errorData.message.includes('DNS Error')) {
              throw new Error(`NexusScan: Domain resolution failed - ${errorData.description || 'Invalid domain'}`);
            } else if (errorData.message && errorData.message.includes('Missing URL')) {
              throw new Error('NexusScan: Invalid URL format provided');
            } else {
              throw new Error(`NexusScan: Invalid request - ${errorData.message || 'Bad request'}`);
            }
          case 401:
            throw new Error('NexusScan: Invalid urlscan.io API key');
          case 429:
            throw new Error('NexusScan: Rate limit exceeded. Please wait before scanning again.');
          case 404:
            throw new Error('NexusScan: urlscan.io endpoint not found');
          default:
            throw new Error(`NexusScan: urlscan.io error (${response.status}): ${errorData.message || response.statusText}`);
        }
      }

      const scanData = await response.json();
      console.log('NexusScan: urlscan.io scan submitted:', scanData.uuid);
      
      // Wait and poll for results
      const results = await this.pollUrlscanResults(scanData.uuid);
      return results;

    } catch (error) {
      console.error('NexusScan: urlscan.io submission error:', error);
      return { error: error.message };
    }
  }

  // ENHANCED: Polling with IP Address Collection
  async pollUrlscanResults(uuid) {
    const maxRetries = 15;
    const retryDelay = 10000;
    
    console.log('NexusScan: Polling urlscan.io results for UUID:', uuid);
    
    for (let i = 0; i < maxRetries; i++) {
      try {
        const response = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, {
          headers: {
            'API-Key': this.URLSCAN_API_KEY,
            'User-Agent': 'NexusScan/1.0'
          }
        });

        if (response.ok) {
          const resultData = await response.json();
          console.log('NexusScan: urlscan.io results retrieved successfully');
          
          return {
            uuid: uuid,
            verdict: resultData.verdicts?.overall?.score || 0 > 50 ? 'malicious' : 
                    resultData.verdicts?.overall?.score || 0 > 25 ? 'suspicious' : 'clean',
            scan_url: `https://urlscan.io/result/${uuid}/`,
            screenshot: resultData.task?.screenshotURL || null,
            page_info: {
              domain: resultData.page?.domain || null,
              ip: resultData.page?.ip || null,
              country: resultData.page?.country || null,
              server: resultData.page?.server || null
            },
            // ENHANCED: IP ADDRESS COLLECTION
            ip_addresses: this.extractIPAddresses(resultData),
            stats: {
              malicious: resultData.stats?.malicious || 0,
              suspicious: resultData.stats?.suspicious || 0,
              requests: resultData.stats?.requests || 0
            },
            technologies: resultData.meta?.processors?.wappa?.data || [],
            scan_time: resultData.task?.time || Date.now()
          };
          
        } else if (response.status === 404) {
          if (i < maxRetries - 1) {
            console.log(`NexusScan: Scan still processing, retry ${i + 1}/${maxRetries}`);
            await new Promise(resolve => setTimeout(resolve, retryDelay));
            continue;
          } else {
            throw new Error('NexusScan: Timeout waiting for urlscan.io results');
          }
        } else if (response.status === 410) {
          throw new Error('NexusScan: Scan result was deleted or expired');
        } else if (response.status === 429) {
          console.log('NexusScan: Rate limited while polling, waiting longer...');
          await new Promise(resolve => setTimeout(resolve, retryDelay * 2));
          continue;
        } else {
          const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
          throw new Error(`NexusScan: Error retrieving results (${response.status}): ${errorData.message}`);
        }
        
      } catch (error) {
        if (i === maxRetries - 1) {
          console.error('NexusScan: Final polling attempt failed:', error);
          throw error;
        }
        console.log(`NexusScan: Polling retry ${i + 1}, error:`, error.message);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }
    
    throw new Error('NexusScan: Timeout waiting for urlscan.io scan results');
  }

  // ENHANCED: Extract ALL IP Addresses from urlscan.io Results
  extractIPAddresses(resultData) {
    const ipAddresses = [];
    const ipMap = new Map();
    
    try {
      console.log('NexusScan: Extracting IP addresses from urlscan.io data');
      
      // Method 1: Extract from requests array (most comprehensive)
      if (resultData.requests && Array.isArray(resultData.requests)) {
        resultData.requests.forEach(request => {
          if (request.request && request.request.ip) {
            const ip = request.request.ip;
            const country = request.request.country || 'Unknown';
            const asn = request.request.asn || null;
            
            if (!ipMap.has(ip)) {
              ipMap.set(ip, {
                ip: ip,
                country: country,
                asn: asn,
                requests: 1
              });
            } else {
              ipMap.get(ip).requests++;
            }
          }
        });
      }
      
      // Method 2: Extract from lists.ips array (additional IPs)
      if (resultData.lists && resultData.lists.ips && Array.isArray(resultData.lists.ips)) {
        resultData.lists.ips.forEach(ip => {
          if (ip && typeof ip === 'string') {
            if (!ipMap.has(ip)) {
              ipMap.set(ip, {
                ip: ip,
                country: 'Unknown',
                asn: null,
                requests: 1
              });
            }
          }
        });
      }
      
      // Method 3: Extract from data.requests if available
      if (resultData.data && resultData.data.requests && Array.isArray(resultData.data.requests)) {
        resultData.data.requests.forEach(request => {
          if (request.response && request.response.response && request.response.response.remoteIPAddress) {
            const ip = request.response.response.remoteIPAddress;
            const country = request.geoip && request.geoip.country ? request.geoip.country : 'Unknown';
            
            if (!ipMap.has(ip)) {
              ipMap.set(ip, {
                ip: ip,
                country: country,
                asn: null,
                requests: 1
              });
            } else {
              ipMap.get(ip).requests++;
            }
          }
        });
      }
      
      // Method 4: Extract from verdicts.urlscan.brands if available
      if (resultData.verdicts && resultData.verdicts.urlscan && resultData.verdicts.urlscan.brands) {
        // Sometimes IPs are in brands data
      }
      
      // Method 5: Look for IPs in stats data
      if (resultData.stats && resultData.stats.ipStats && Array.isArray(resultData.stats.ipStats)) {
        resultData.stats.ipStats.forEach(ipStat => {
          if (ipStat.ip) {
            const ip = ipStat.ip;
            if (!ipMap.has(ip)) {
              ipMap.set(ip, {
                ip: ip,
                country: ipStat.country || 'Unknown',
                asn: ipStat.asn || null,
                requests: ipStat.requests || 1
              });
            }
          }
        });
      }
      
      // Convert map to array and sort by request count
      const sortedIPs = Array.from(ipMap.values()).sort((a, b) => b.requests - a.requests);
      
      // Ensure primary IP from page info is first if available
      if (resultData.page && resultData.page.ip) {
        const primaryIP = resultData.page.ip;
        const primaryIndex = sortedIPs.findIndex(ip => ip.ip === primaryIP);
        
        if (primaryIndex > 0) {
          // Move primary IP to first position
          const primary = sortedIPs.splice(primaryIndex, 1)[0];
          sortedIPs.unshift(primary);
        } else if (primaryIndex === -1) {
          // Add primary IP if not found in other methods
          sortedIPs.unshift({
            ip: primaryIP,
            country: resultData.page.country || 'Unknown',
            asn: resultData.page.asn || null,
            requests: 1
          });
        }
      }
      
      console.log(`NexusScan: Successfully extracted ${sortedIPs.length} unique IP addresses`);
      
      // Log first few IPs for debugging
      if (sortedIPs.length > 0) {
        console.log('NexusScan: Top IPs found:', sortedIPs.slice(0, 5).map(ip => `${ip.ip} (${ip.country})`));
      }
      
      return sortedIPs; // Return all IPs found
      
    } catch (error) {
      console.error('NexusScan: Failed to extract IP addresses:', error);
      
      // Fallback: try to get at least the primary IP
      if (resultData.page && resultData.page.ip) {
        return [{
          ip: resultData.page.ip,
          country: resultData.page.country || 'Unknown',
          asn: null,
          requests: 1
        }];
      }
      
      return [];
    }
  }

  async getVirusTotalReport(url) {
    if (!this.VT_API_KEY) {
      console.log('NexusScan: No VirusTotal API key available');
      return { error: 'No VirusTotal API key configured' };
    }

    try {
      const urlId = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      
      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: {
          'x-apikey': this.VT_API_KEY,
          'User-Agent': 'NexusScan/1.0'
        }
      });

      if (!response.ok) {
        if (response.status === 404) {
          return await this.submitUrlToVirusTotal(url);
        } else if (response.status === 401 || response.status === 403) {
          throw new Error('NexusScan: Invalid VirusTotal API key');
        } else if (response.status === 429) {
          throw new Error('NexusScan: VirusTotal rate limit exceeded');
        } else {
          throw new Error(`NexusScan: VirusTotal error (${response.status}): ${response.statusText}`);
        }
      }

      const data = await response.json();
      const stats = data.data?.attributes?.last_analysis_stats || {};
      const results = data.data?.attributes?.last_analysis_results || {};
      
      const vendors = Object.entries(results).map(([vendor, result]) => ({
        name: vendor,
        result: result.result || 'Clean',
        category: result.category || 'harmless'
      }));

      return {
        total: stats.harmless + stats.malicious + stats.suspicious + stats.undetected,
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        clean: stats.harmless + stats.undetected,
        scan_url: `https://www.virustotal.com/gui/url/${urlId}`,
        scan_date: data.data?.attributes?.last_analysis_date,
        vendors: vendors.slice(0, 10)
      };

    } catch (error) {
      console.error('NexusScan: VirusTotal error:', error);
      return { error: error.message };
    }
  }

  async submitUrlToVirusTotal(url) {
    try {
      const response = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': this.VT_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'NexusScan/1.0'
        },
        body: `url=${encodeURIComponent(url)}`
      });

      if (!response.ok) {
        throw new Error(`NexusScan: Failed to submit URL to VirusTotal (${response.status})`);
      }

      await new Promise(resolve => setTimeout(resolve, 5000));
      return await this.getVirusTotalReport(url);

    } catch (error) {
      console.error('NexusScan: VirusTotal submission error:', error);
      return { error: error.message };
    }
  }

  async comprehensiveScan(url, forceRescan = false) {
    const startTime = Date.now();
    
    if (!forceRescan && this.cache.has(url)) {
      const cached = this.cache.get(url);
      const maxAge = 30 * 60 * 1000;
      if (Date.now() - cached.timestamp < maxAge) {
        console.log('NexusScan: Returning cached result for:', url);
        const communityFeedback = await this.getFeedback(url);
        cached.communityFeedback = communityFeedback;
        return cached;
      }
    }

    const scanResults = {
      url: url,
      timestamp: Date.now(),
      score: 0,
      threats: [],
      sources: {},
      status: 'scanning'
    };

    try {
      const validatedUrl = this.validateURL(url);
      scanResults.url = validatedUrl;

      console.log('NexusScan: Starting comprehensive scan for:', validatedUrl);

      const [vtResults, urlscanResults] = await Promise.allSettled([
        this.getVirusTotalReport(validatedUrl),
        this.submitUrlscan(validatedUrl)
      ]);

      if (vtResults.status === 'fulfilled') {
        scanResults.sources.virustotal = vtResults.value;
      } else {
        console.error('NexusScan: VirusTotal scan failed:', vtResults.reason);
        scanResults.sources.virustotal = { error: vtResults.reason?.message || 'VirusTotal scan failed' };
      }

      if (urlscanResults.status === 'fulfilled') {
        scanResults.sources.urlscan = urlscanResults.value;
      } else {
        console.error('NexusScan: urlscan.io scan failed:', urlscanResults.reason);
        scanResults.sources.urlscan = { error: urlscanResults.reason?.message || 'urlscan.io scan failed' };
      }

      scanResults.score = this.calculateCombinedScore(scanResults.sources);
      scanResults.threats = this.generateThreats(scanResults.sources, validatedUrl);

      try {
        const urlObj = new URL(validatedUrl);
        if (urlObj.protocol !== 'https:') {
          scanResults.threats.push('Not using secure HTTPS connection');
          scanResults.score += 10;
        }
      } catch (error) {
        scanResults.threats.push('Invalid URL format');
        scanResults.score += 30;
      }

      const communityFeedback = await this.getFeedback(validatedUrl);
      scanResults.communityFeedback = communityFeedback;
      
      if (communityFeedback.totalRatings > 0) {
        const communityScore = this.calculateCommunityScore(communityFeedback);
        scanResults.score = Math.round((scanResults.score + communityScore) / 2);
      }

      scanResults.score = Math.min(scanResults.score, 100);
      scanResults.status = 'complete';
      scanResults.scanDuration = Date.now() - startTime;
      
      await this.saveToHistory(scanResults);
      this.cache.set(url, scanResults);
      
      console.log('NexusScan: Comprehensive scan completed with score:', scanResults.score);
      return scanResults;

    } catch (error) {
      console.error('NexusScan: Comprehensive scan error:', error);
      scanResults.status = 'error';
      scanResults.error = error.message;
      throw error;
    }
  }

  calculateCombinedScore(sources) {
    let score = 0;
    
    if (sources.virustotal && !sources.virustotal.error) {
      const vtData = sources.virustotal;
      if (vtData.total > 0) {
        const maliciousRatio = vtData.malicious / vtData.total;
        const suspiciousRatio = (vtData.suspicious || 0) / vtData.total;
        score += Math.min((maliciousRatio * 30) + (suspiciousRatio * 15), 40);
      }
    }
    
    if (sources.urlscan && !sources.urlscan.error) {
      const urlscanData = sources.urlscan;
      switch (urlscanData.verdict) {
        case 'malicious':
          score += 50;
          break;
        case 'suspicious':
          score += 30;
          break;
        case 'clean':
          score += 0;
          break;
        default:
          score += 10;
      }
    }
    
    return Math.min(score, 100);
  }

  generateThreats(sources, url) {
    const threats = [];
    
    if (sources.virustotal && !sources.virustotal.error) {
      const vtData = sources.virustotal;
      if (vtData.malicious > 0) {
        threats.push(`${vtData.malicious} security vendors flagged this URL as malicious`);
      }
      if (vtData.suspicious > 0) {
        threats.push(`${vtData.suspicious} security vendors flagged this URL as suspicious`);
      }
    }

    if (sources.urlscan && !sources.urlscan.error) {
      const urlscanData = sources.urlscan;
      if (urlscanData.verdict === 'malicious') {
        threats.push('urlscan.io detected malicious behavior');
      } else if (urlscanData.verdict === 'suspicious') {
        threats.push('urlscan.io detected suspicious activity');
      }
      
      if (urlscanData.stats && urlscanData.stats.malicious > 0) {
        threats.push(`${urlscanData.stats.malicious} malicious resources detected`);
      }
    }
    
    return threats;
  }

  // Bookmark Management Methods (keeping existing functionality)
  async getBookmarks() {
    try {
      if (!chrome.bookmarks) {
        throw new Error('Bookmarks API not available');
      }

      console.log('NexusScan: Getting bookmark tree...');
      const bookmarkTree = await chrome.bookmarks.getTree();
      console.log('NexusScan: Bookmark tree retrieved:', bookmarkTree);
      
      const flatBookmarks = this.flattenBookmarks(bookmarkTree);
      console.log('NexusScan: Flattened bookmarks:', flatBookmarks.length, 'bookmarks found');
      
      return flatBookmarks;
    } catch (error) {
      console.error('NexusScan: Failed to get bookmarks:', error);
      throw new Error(`Failed to access bookmarks: ${error.message}`);
    }
  }

  flattenBookmarks(bookmarkTree) {
    const result = [];
    
    const traverse = (nodes) => {
      if (!Array.isArray(nodes)) return;
      
      for (const node of nodes) {
        if (node.url) {
          result.push({
            id: node.id,
            title: node.title || 'Untitled',
            url: node.url,
            dateAdded: node.dateAdded,
            parentId: node.parentId
          });
        }
        
        if (node.children && Array.isArray(node.children)) {
          traverse(node.children);
        }
      }
    };
    
    traverse(bookmarkTree);
    
    const filteredResult = result.filter(bookmark => {
      try {
        const url = new URL(bookmark.url);
        return ['http:', 'https:'].includes(url.protocol);
      } catch (error) {
        console.warn('NexusScan: Invalid bookmark URL:', bookmark.url);
        return false;
      }
    });
    
    console.log(`NexusScan: Filtered ${result.length - filteredResult.length} non-HTTP(S) bookmarks`);
    return filteredResult;
  }

  async getBookmarkScanResults() {
    try {
      const storageKey = 'nexusscan_bookmark_scan_results';
      const result = await chrome.storage.local.get(storageKey);
      const scanResults = result[storageKey] || [];
      
      console.log('NexusScan: Retrieved bookmark scan results:', scanResults.length, 'entries');
      return scanResults;
    } catch (error) {
      console.error('NexusScan: Failed to get bookmark scan results:', error);
      return [];
    }
  }

  async saveBookmarkScanResults(results) {
    try {
      const storageKey = 'nexusscan_bookmark_scan_results';
      const resultsArray = Array.isArray(results) ? results : Array.from(results);
      
      await chrome.storage.local.set({
        [storageKey]: resultsArray
      });
      
      console.log('NexusScan: Saved bookmark scan results:', resultsArray.length, 'entries');
      return true;
    } catch (error) {
      console.error('NexusScan: Failed to save bookmark scan results:', error);
      throw error;
    }
  }

  async scanBookmarksBulk(bookmarks, progressCallback) {
    try {
      const results = new Map();
      let completed = 0;
      const total = bookmarks.length;
      
      console.log(`NexusScan: Starting bulk scan of ${total} bookmarks`);
      
      for (const bookmark of bookmarks) {
        try {
          if (progressCallback) {
            progressCallback({
              current: completed + 1,
              total: total,
              currentUrl: bookmark.url,
              status: 'scanning'
            });
          }
          
          const scanResult = await this.comprehensiveScan(bookmark.url, false);
          
          results.set(bookmark.url, {
            status: 'completed',
            score: scanResult.score,
            threats: scanResult.threats,
            lastScanned: Date.now(),
            sources: {
              virustotal: {
                malicious: scanResult.sources.virustotal?.malicious || 0,
                total: scanResult.sources.virustotal?.total || 0
              },
              urlscan: {
                verdict: scanResult.sources.urlscan?.verdict || 'unknown'
              }
            }
          });
          
          console.log(`NexusScan: Scanned bookmark: ${bookmark.url} - Score: ${scanResult.score}`);
          
        } catch (error) {
          console.error(`NexusScan: Failed to scan bookmark ${bookmark.url}:`, error);
          results.set(bookmark.url, {
            status: 'error',
            error: error.message,
            lastScanned: Date.now()
          });
        }
        
        completed++;
        
        if (completed < total) {
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      }
      
      await this.saveBookmarkScanResults(Array.from(results.entries()));
      
      console.log(`NexusScan: Bulk scan completed: ${completed}/${total} bookmarks processed`);
      
      return {
        completed: completed,
        total: total,
        results: Array.from(results.entries())
      };
      
    } catch (error) {
      console.error('NexusScan: Bulk bookmark scan failed:', error);
      throw error;
    }
  }

  async clearBookmarkScanResults() {
    try {
      const storageKey = 'nexusscan_bookmark_scan_results';
      await chrome.storage.local.remove(storageKey);
      
      console.log('NexusScan: Bookmark scan results cleared');
      return true;
    } catch (error) {
      console.error('NexusScan: Failed to clear bookmark scan results:', error);
      throw error;
    }
  }

  async exportBookmarkResults() {
    try {
      const bookmarks = await this.getBookmarks();
      const scanResults = await this.getBookmarkScanResults();
      const resultsMap = new Map(scanResults);
      
      const exportData = {
        metadata: {
          exportDate: new Date().toISOString(),
          totalBookmarks: bookmarks.length,
          scannedBookmarks: scanResults.length,
          version: 'NexusScan v1.0.0'
        },
        bookmarks: bookmarks.map(bookmark => {
          const scanResult = resultsMap.get(bookmark.url);
          return {
            title: bookmark.title,
            url: bookmark.url,
            dateAdded: bookmark.dateAdded ? new Date(bookmark.dateAdded).toISOString() : null,
            scanResult: scanResult ? {
              status: scanResult.status,
              score: scanResult.score,
              threats: scanResult.threats,
              lastScanned: scanResult.lastScanned ? new Date(scanResult.lastScanned).toISOString() : null
            } : null
          };
        })
      };
      
      return exportData;
    } catch (error) {
      console.error('NexusScan: Failed to export bookmark results:', error);
      throw error;
    }
  }

  // Community Feedback Methods (keeping existing functionality)
  async submitFeedback(feedback) {
    try {
      const feedbackKey = 'nexusscan_community_feedback';
      const existing = await chrome.storage.local.get(feedbackKey);
      let allFeedback = existing[feedbackKey] || [];
      
      const newFeedback = {
        id: this.generateFeedbackId(),
        url: feedback.url,
        rating: feedback.rating,
        comment: feedback.comment || '',
        category: feedback.category,
        timestamp: Date.now(),
        userAgent: navigator.userAgent,
        version: 'NexusScan v1.0.0'
      };
      
      allFeedback.unshift(newFeedback);
      
      if (allFeedback.length > 1000) {
        allFeedback = allFeedback.slice(0, 1000);
      }
      
      await chrome.storage.local.set({ [feedbackKey]: allFeedback });
      console.log('NexusScan: Community feedback submitted:', newFeedback.id);
      
      return newFeedback;
    } catch (error) {
      console.error('NexusScan: Failed to submit feedback:', error);
      throw error;
    }
  }

  async getFeedback(url) {
    try {
      const feedbackKey = 'nexusscan_community_feedback';
      const result = await chrome.storage.local.get(feedbackKey);
      const allFeedback = result[feedbackKey] || [];
      
      const urlFeedback = allFeedback.filter(feedback => feedback.url === url);
      
      if (urlFeedback.length === 0) {
        return {
          totalRatings: 0,
          averageRating: 0,
          comments: [],
          categories: { safe: 0, suspicious: 0, malicious: 0, false_positive: 0 }
        };
      }
      
      const totalRatings = urlFeedback.length;
      const averageRating = urlFeedback.reduce((sum, f) => sum + f.rating, 0) / totalRatings;
      
      const categories = {
        safe: urlFeedback.filter(f => f.category === 'safe').length,
        suspicious: urlFeedback.filter(f => f.category === 'suspicious').length,
        malicious: urlFeedback.filter(f => f.category === 'malicious').length,
        false_positive: urlFeedback.filter(f => f.category === 'false_positive').length
      };
      
      const comments = urlFeedback
        .filter(f => f.comment && f.comment.trim())
        .map(f => ({
          comment: f.comment,
          rating: f.rating,
          category: f.category,
          timestamp: f.timestamp,
          id: f.id
        }))
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 10);
      
      return {
        totalRatings,
        averageRating: Math.round(averageRating * 10) / 10,
        comments,
        categories
      };
    } catch (error) {
      console.error('NexusScan: Failed to get feedback:', error);
      return {
        totalRatings: 0,
        averageRating: 0,
        comments: [],
        categories: { safe: 0, suspicious: 0, malicious: 0, false_positive: 0 }
      };
    }
  }

  async getFeedbackStats() {
    try {
      const feedbackKey = 'nexusscan_community_feedback';
      const result = await chrome.storage.local.get(feedbackKey);
      const allFeedback = result[feedbackKey] || [];
      
      const now = Date.now();
      const oneDayAgo = now - (24 * 60 * 60 * 1000);
      
      return {
        total: allFeedback.length,
        today: allFeedback.filter(f => f.timestamp > oneDayAgo).length,
        categories: {
          safe: allFeedback.filter(f => f.category === 'safe').length,
          suspicious: allFeedback.filter(f => f.category === 'suspicious').length,
          malicious: allFeedback.filter(f => f.category === 'malicious').length,
          false_positive: allFeedback.filter(f => f.category === 'false_positive').length
        },
        averageRating: allFeedback.length > 0 ? 
          Math.round((allFeedback.reduce((sum, f) => sum + f.rating, 0) / allFeedback.length) * 10) / 10 : 0
      };
    } catch (error) {
      console.error('NexusScan: Failed to get feedback stats:', error);
      return {
        total: 0, today: 0,
        categories: { safe: 0, suspicious: 0, malicious: 0, false_positive: 0 },
        averageRating: 0
      };
    }
  }

  async reportURL(report) {
    try {
      const reportKey = 'nexusscan_url_reports';
      const existing = await chrome.storage.local.get(reportKey);
      let allReports = existing[reportKey] || [];
      
      const newReport = {
        id: this.generateReportId(),
        url: report.url,
        type: report.type,
        description: report.description || '',
        evidence: report.evidence || '',
        timestamp: Date.now(),
        status: 'pending',
        userAgent: navigator.userAgent
      };
      
      allReports.unshift(newReport);
      
      if (allReports.length > 500) {
        allReports = allReports.slice(0, 500);
      }
      
      await chrome.storage.local.set({ [reportKey]: allReports });
      console.log('NexusScan: URL report submitted:', newReport.id);
      
      return newReport;
    } catch (error) {
      console.error('NexusScan: Failed to submit report:', error);
      throw error;
    }
  }

  async getUserFeedback() {
    try {
      const feedbackKey = 'nexusscan_community_feedback';
      const result = await chrome.storage.local.get(feedbackKey);
      const allFeedback = result[feedbackKey] || [];
      
      return allFeedback.slice(0, 20).map(feedback => ({
        id: feedback.id,
        url: feedback.url,
        rating: feedback.rating,
        comment: feedback.comment,
        category: feedback.category,
        timestamp: feedback.timestamp
      }));
    } catch (error) {
      console.error('NexusScan: Failed to get user feedback:', error);
      return [];
    }
  }

  async deleteFeedback(feedbackId) {
    try {
      const feedbackKey = 'nexusscan_community_feedback';
      const existing = await chrome.storage.local.get(feedbackKey);
      let allFeedback = existing[feedbackKey] || [];
      
      const initialLength = allFeedback.length;
      allFeedback = allFeedback.filter(feedback => feedback.id !== feedbackId);
      
      if (allFeedback.length < initialLength) {
        await chrome.storage.local.set({ [feedbackKey]: allFeedback });
        console.log('NexusScan: Feedback deleted:', feedbackId);
        return true;
      }
      
      return false;
    } catch (error) {
      console.error('NexusScan: Failed to delete feedback:', error);
      throw error;
    }
  }

  // History Management Methods (keeping existing functionality)
  async saveToHistory(scanResults) {
    try {
      const historyKey = 'nexusscan_scan_history';
      const existing = await chrome.storage.local.get(historyKey);
      let history = existing[historyKey] || [];
      
      const historyEntry = {
        id: this.generateHistoryId(),
        url: scanResults.url,
        timestamp: scanResults.timestamp,
        score: scanResults.score,
        status: scanResults.status,
        threats: scanResults.threats,
        sources: {
          virustotal: {
            total: scanResults.sources.virustotal?.total || 0,
            malicious: scanResults.sources.virustotal?.malicious || 0,
            suspicious: scanResults.sources.virustotal?.suspicious || 0,
            hasError: !!scanResults.sources.virustotal?.error
          },
          urlscan: {
            verdict: scanResults.sources.urlscan?.verdict || 'unknown',
            uuid: scanResults.sources.urlscan?.uuid,
            hasError: !!scanResults.sources.urlscan?.error
          }
        },
        scanDuration: scanResults.scanDuration || 0
      };
      
      history.unshift(historyEntry);
      
      if (history.length > 100) {
        history = history.slice(0, 100);
      }
      
      await chrome.storage.local.set({ [historyKey]: history });
      return historyEntry.id;
    } catch (error) {
      console.error('NexusScan: Failed to save scan to history:', error);
    }
  }

  async getHistory(limit = 50) {
    try {
      const historyKey = 'nexusscan_scan_history';
      const result = await chrome.storage.local.get(historyKey);
      const history = result[historyKey] || [];
      return limit ? history.slice(0, limit) : history;
    } catch (error) {
      console.error('NexusScan: Failed to get history:', error);
      return [];
    }
  }

  async clearHistory() {
    try {
      const historyKey = 'nexusscan_scan_history';
      await chrome.storage.local.remove(historyKey);
      return true;
    } catch (error) {
      console.error('NexusScan: Failed to clear history:', error);
      return false;
    }
  }

  async getHistoryStats() {
    try {
      const history = await this.getHistory();
      const now = Date.now();
      const oneDayAgo = now - (24 * 60 * 60 * 1000);
      
      return {
        total: history.length,
        today: history.filter(scan => scan.timestamp > oneDayAgo).length,
        dangerousScans: history.filter(scan => scan.score >= 70).length,
        averageScore: history.length > 0 ? 
          Math.round(history.reduce((sum, scan) => sum + scan.score, 0) / history.length) : 0
      };
    } catch (error) {
      console.error('NexusScan: Failed to get history stats:', error);
      return { total: 0, today: 0, dangerousScans: 0, averageScore: 0 };
    }
  }

  async exportHistory(format = 'json') {
    try {
      const history = await this.getHistory();
      const stats = await this.getHistoryStats();
      
      const exportData = {
        metadata: {
          exportDate: new Date().toISOString(),
          totalScans: history.length,
          version: 'NexusScan v1.0.0'
        },
        statistics: stats,
        scans: history.map(scan => ({
          ...scan,
          timestamp: new Date(scan.timestamp).toISOString(),
          formattedDate: new Date(scan.timestamp).toLocaleString()
        }))
      };
      
      return exportData;
    } catch (error) {
      console.error('NexusScan: Failed to export history:', error);
      throw error;
    }
  }

  // Utility Methods
  calculateCommunityScore(communityFeedback) {
    if (communityFeedback.totalRatings === 0) return 0;
    const riskScore = ((communityFeedback.averageRating - 1) / 4) * 100;
    const confidence = Math.min(communityFeedback.totalRatings / 10, 1);
    return Math.round(riskScore * confidence);
  }

  validateURL(url) {
    try {
      const urlObj = new URL(url);
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        throw new Error('Invalid protocol. Only HTTP and HTTPS are supported.');
      }
      return urlObj.toString();
    } catch (error) {
      throw new Error(`Invalid URL format: ${error.message}`);
    }
  }

  async blockURL(url, tabId) {
    if (tabId) {
      chrome.tabs.update(tabId, { url: 'about:blank' });
    }
  }

  generateFeedbackId() {
    return 'nexusscan_feedback_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  generateReportId() {
    return 'nexusscan_report_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  generateHistoryId() {
    return 'nexusscan_scan_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
}

const threatIntel = new ThreatIntelligence();

chrome.runtime.onInstalled.addListener(() => {
  console.log('🔍 NexusScan extension installed - Scan Smarter. Stay Safer');
});
