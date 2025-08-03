// content.js - NexusScan Content Script - Advanced Page Security Analysis
console.log('🔍 NexusScan content script loaded - Scan Smarter. Stay Safer');

class NexusScanContentScript {
  constructor() {
    this.initialize();
  }

  initialize() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      console.log('NexusScan: Received message in content script:', request.action);
      
      switch (request.action) {
        case 'scanCurrentPage':
          this.scanCurrentPage();
          sendResponse({ success: true, message: 'NexusScan page analysis initiated' });
          break;
        
        case 'getPageSecurityInfo':
          const securityInfo = this.analyzePageSecurity();
          sendResponse({ success: true, data: securityInfo });
          break;
        
        case 'highlightSuspiciousElements':
          this.highlightSuspiciousElements();
          sendResponse({ success: true, message: 'Suspicious elements highlighted' });
          break;
        
        default:
          sendResponse({ success: false, error: 'Unknown action' });
      }
    });

    // Perform initial page security analysis
    this.performInitialAnalysis();
  }

  performInitialAnalysis() {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        this.analyzePageSecurity();
      });
    } else {
      this.analyzePageSecurity();
    }
  }

  analyzePageSecurity() {
    console.log('NexusScan: Analyzing page security for:', window.location.href);
    
    const securityInfo = {
      url: window.location.href,
      title: document.title,
      hasHttps: window.location.protocol === 'https:',
      hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
      hasLoginForms: document.querySelectorAll('form').length > 0,
      hasCookieNotices: this.detectCookieNotices(),
      hasExternalLinks: this.countExternalLinks(),
      hasInlineScripts: document.querySelectorAll('script:not([src])').length,
      hasUnsafeElements: this.detectUnsafeElements(),
      securityHeaders: this.analyzeSecurityHeaders(),
      timestamp: Date.now()
    };

    // Send security info to background script
    chrome.runtime.sendMessage({
      action: 'pageSecurityInfo',
      data: securityInfo
    }).catch(error => {
      console.error('NexusScan: Failed to send security info:', error);
    });

    console.log('NexusScan: Page security analysis completed:', securityInfo);
    return securityInfo;
  }

  scanCurrentPage() {
    console.log('NexusScan: Performing comprehensive page security scan...');
    
    const scanResults = {
      timestamp: Date.now(),
      url: window.location.href,
      findings: []
    };

    // Check for security vulnerabilities
    const vulnerabilities = this.detectVulnerabilities();
    scanResults.findings.push(...vulnerabilities);

    // Check for suspicious content
    const suspiciousContent = this.detectSuspiciousContent();
    scanResults.findings.push(...suspiciousContent);

    // Check for privacy concerns
    const privacyConcerns = this.detectPrivacyConcerns();
    scanResults.findings.push(...privacyConcerns);

    // Send scan results to background
    chrome.runtime.sendMessage({
      action: 'pageSecurityScanResults',
      data: scanResults
    }).catch(error => {
      console.error('NexusScan: Failed to send scan results:', error);
    });

    console.log('NexusScan: Page scan completed with', scanResults.findings.length, 'findings');
    return scanResults;
  }

  detectVulnerabilities() {
    const vulnerabilities = [];

    // Check for mixed content
    if (window.location.protocol === 'https:') {
      const httpResources = document.querySelectorAll(
        'img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"]'
      );
      if (httpResources.length > 0) {
        vulnerabilities.push({
          type: 'mixed_content',
          severity: 'medium',
          message: `Found ${httpResources.length} insecure HTTP resources on HTTPS page`,
          count: httpResources.length
        });
      }
    }

    // Check for insecure forms
    const insecureForms = document.querySelectorAll('form:not([action^="https:"]):not([action^="/"])');
    if (insecureForms.length > 0) {
      vulnerabilities.push({
        type: 'insecure_forms',
        severity: 'high',
        message: `Found ${insecureForms.length} forms with insecure action URLs`,
        count: insecureForms.length
      });
    }

    // Check for password fields without HTTPS
    if (window.location.protocol === 'http:') {
      const passwordFields = document.querySelectorAll('input[type="password"]');
      if (passwordFields.length > 0) {
        vulnerabilities.push({
          type: 'insecure_password',
          severity: 'critical',
          message: 'Password fields detected on insecure HTTP connection',
          count: passwordFields.length
        });
      }
    }

    return vulnerabilities;
  }

  detectSuspiciousContent() {
    const suspicious = [];

    // Check for suspicious keywords in text content
    const suspiciousKeywords = [
      'urgent', 'act now', 'limited time', 'click here immediately',
      'verify account', 'suspended account', 'confirm identity',
      'free money', 'you have won', 'congratulations winner'
    ];

    const pageText = document.body.textContent.toLowerCase();
    const foundKeywords = suspiciousKeywords.filter(keyword => 
      pageText.includes(keyword.toLowerCase())
    );

    if (foundKeywords.length > 0) {
      suspicious.push({
        type: 'suspicious_text',
        severity: 'medium',
        message: `Found suspicious keywords: ${foundKeywords.join(', ')}`,
        keywords: foundKeywords
      });
    }

    // Check for suspicious links
    const externalLinks = document.querySelectorAll('a[href^="http"]:not([href*="' + window.location.hostname + '"])');
    const suspiciousLinks = Array.from(externalLinks).filter(link => {
      const href = link.href.toLowerCase();
      return href.includes('bit.ly') || href.includes('tinyurl') || 
             href.includes('shortened') || href.match(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/);
    });

    if (suspiciousLinks.length > 0) {
      suspicious.push({
        type: 'suspicious_links',
        severity: 'medium',
        message: `Found ${suspiciousLinks.length} suspicious external links`,
        count: suspiciousLinks.length
      });
    }

    return suspicious;
  }

  detectPrivacyConcerns() {
    const concerns = [];

    // Check for tracking scripts
    const trackingScripts = document.querySelectorAll(
      'script[src*="google-analytics"], script[src*="googletagmanager"], ' +
      'script[src*="facebook"], script[src*="doubleclick"], script[src*="adsystem"]'
    );

    if (trackingScripts.length > 0) {
      concerns.push({
        type: 'tracking_scripts',
        severity: 'low',
        message: `Found ${trackingScripts.length} tracking scripts`,
        count: trackingScripts.length
      });
    }

    // Check for third-party iframes
    const thirdPartyIframes = document.querySelectorAll('iframe[src]:not([src*="' + window.location.hostname + '"])');
    if (thirdPartyIframes.length > 0) {
      concerns.push({
        type: 'third_party_iframes',
        severity: 'medium',
        message: `Found ${thirdPartyIframes.length} third-party iframes`,
        count: thirdPartyIframes.length
      });
    }

    return concerns;
  }

  detectCookieNotices() {
    const cookieSelectors = [
      '[class*="cookie"]', '[id*="cookie"]', '[class*="gdpr"]', '[id*="gdpr"]',
      '[class*="consent"]', '[id*="consent"]', '[class*="privacy"]'
    ];
    
    return cookieSelectors.some(selector => 
      document.querySelector(selector) !== null
    );
  }

  countExternalLinks() {
    const externalLinks = document.querySelectorAll(
      'a[href^="http"]:not([href*="' + window.location.hostname + '"])'
    );
    return externalLinks.length;
  }

  detectUnsafeElements() {
    const unsafeElements = [];

    // Check for potential XSS vectors
    const scriptElements = document.querySelectorAll('script:not([src])');
    if (scriptElements.length > 0) {
      unsafeElements.push(`${scriptElements.length} inline scripts`);
    }

    // Check for eval usage (basic check)
    if (document.documentElement.innerHTML.includes('eval(')) {
      unsafeElements.push('Potential eval() usage detected');
    }

    // Check for document.write usage
    if (document.documentElement.innerHTML.includes('document.write')) {
      unsafeElements.push('document.write() usage detected');
    }

    return unsafeElements;
  }

  analyzeSecurityHeaders() {
    // Note: Content scripts can't access response headers directly
    // This is a placeholder for potential future enhancement
    return {
      note: 'Security header analysis requires background script integration',
      analyzed: false
    };
  }

  highlightSuspiciousElements() {
    console.log('NexusScan: Highlighting suspicious elements on page...');
    
    // Remove existing highlights
    document.querySelectorAll('.nexusscan-highlight').forEach(el => {
      el.classList.remove('nexusscan-highlight');
    });

    // Add CSS for highlighting if not exists
    if (!document.querySelector('#nexusscan-highlight-styles')) {
      const style = document.createElement('style');
      style.id = 'nexusscan-highlight-styles';
      style.textContent = `
        .nexusscan-highlight {
          outline: 2px solid #ff6b6b !important;
          outline-offset: 2px !important;
          background-color: rgba(255, 107, 107, 0.1) !important;
          position: relative !important;
        }
        .nexusscan-highlight::before {
          content: "⚠️ NexusScan: Potentially Suspicious";
          position: absolute;
          top: -25px;
          left: 0;
          background: #ff6b6b;
          color: white;
          padding: 2px 6px;
          font-size: 11px;
          border-radius: 3px;
          z-index: 10000;
          font-family: Arial, sans-serif;
        }
      `;
      document.head.appendChild(style);
    }

    // Highlight suspicious links
    const suspiciousLinks = document.querySelectorAll('a[href*="bit.ly"], a[href*="tinyurl"]');
    suspiciousLinks.forEach(link => {
      link.classList.add('nexusscan-highlight');
    });

    // Highlight insecure forms
    if (window.location.protocol === 'http:') {
      const passwordFields = document.querySelectorAll('input[type="password"]');
      passwordFields.forEach(field => {
        field.closest('form')?.classList.add('nexusscan-highlight');
      });
    }

    console.log('NexusScan: Highlighted', suspiciousLinks.length + 
                (window.location.protocol === 'http:' ? document.querySelectorAll('input[type="password"]').length : 0), 
                'suspicious elements');
  }

  // Utility method to inject NexusScan security badge
  injectSecurityBadge(securityScore) {
    // Remove existing badge
    const existingBadge = document.querySelector('#nexusscan-security-badge');
    if (existingBadge) {
      existingBadge.remove();
    }

    const badge = document.createElement('div');
    badge.id = 'nexusscan-security-badge';
    badge.innerHTML = `
      <div style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        color: white;
        padding: 12px 16px;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        z-index: 10000;
        font-family: Arial, sans-serif;
        font-size: 14px;
        border: 2px solid #00d4ff;
        max-width: 250px;
      ">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
          <span style="font-size: 18px;">🔍</span>
          <strong style="color: #00d4ff;">NexusScan</strong>
        </div>
        <div style="font-size: 11px; color: #a0a0a0; margin-bottom: 8px;">
          Scan Smarter. Stay Safer
        </div>
        <div style="font-size: 12px;">
          Security Score: <strong style="color: ${securityScore >= 70 ? '#ff6b6b' : securityScore >= 40 ? '#ffa726' : '#4caf50'}">${securityScore}/100</strong>
        </div>
      </div>
    `;

    document.body.appendChild(badge);

    // Auto-hide after 5 seconds
    setTimeout(() => {
      if (badge.parentNode) {
        badge.style.transition = 'opacity 0.5s';
        badge.style.opacity = '0';
        setTimeout(() => badge.remove(), 500);
      }
    }, 5000);
  }
}

// Initialize NexusScan content script
new NexusScanContentScript();

// Export for potential use by other scripts
window.NexusScanContentScript = NexusScanContentScript;
