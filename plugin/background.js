browser.storage.local.get(['apiKey', 'sensitivity', 'whitelist', 'autoBlock', 'showSafeNotifications']).then((settings) => {
  let currentSettings = {
    apiKey: CONFIG.GOOGLE_SAFE_BROWSING_API_KEY || settings.apiKey || '',
    sensitivity: settings.sensitivity || 'medium',
    whitelist: settings.whitelist ? JSON.parse(settings.whitelist) : [],
    autoBlock: settings.autoBlock || false,
    showSafeNotifications: settings.showSafeNotifications || false
  };

  console.log('Initial settings:', currentSettings);

  // Listen for storage changes
  browser.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local') {
      console.log('Settings changed:', changes);
      
      if (changes.sensitivity) {
        currentSettings.sensitivity = changes.sensitivity.newValue;
        console.log('Sensitivity updated to:', currentSettings.sensitivity);
      }
      if (changes.whitelist) {
        currentSettings.whitelist = JSON.parse(changes.whitelist.newValue);
        console.log('Whitelist updated');
      }
      if (changes.autoBlock) {
        currentSettings.autoBlock = changes.autoBlock.newValue;
        console.log('Auto block updated to:', currentSettings.autoBlock);
      }
      if (changes.showSafeNotifications) {
        currentSettings.showSafeNotifications = changes.showSafeNotifications.newValue;
        console.log('Show safe notifications updated to:', currentSettings.showSafeNotifications);
      }
      
      // Log all current settings after any change
      console.log('Current settings after update:', currentSettings);
    }
  });

  if (!currentSettings.apiKey) {
    console.error('No Google Safe Browsing API key provided in config.js or storage');
  }

  // Check suspicious patterns
  function checkSuspiciousPatterns(url) {
    const patterns = {
      numbers_in_domain: false,
      excessive_subdomains: false,
      special_chars: false
    };

    // Extract domain from URL
    const domainMatch = url.match(/^(?:https?:\/\/)?(?:[^\/]+\.)*([^\/]+\.[^\/]+)/i);
    const domain = domainMatch ? domainMatch[1] : '';

    // Check for numbers in domain
    if (/\d/.test(domain)) {
      patterns.numbers_in_domain = true;
    }

    // Check for excessive subdomains
    const subdomains = domain.split('.');
    if (subdomains.length > 3) {
      patterns.excessive_subdomains = true;
    }

    // Check for special characters in domain
    if (/[^a-zA-Z0-9.-]/.test(domain)) {
      patterns.special_chars = true;
    }

    return patterns;
  }

  // Extract domain from URL
  function getDomain(url) {
    const domainMatch = url.match(/^(?:https?:\/\/)?(?:[^\/]+\.)*([^\/]+\.[^\/]+)/i);
    return domainMatch ? domainMatch[1] : url;
  }

  // Check Google Safe Browsing with caching
  async function checkGoogleSafeBrowsing(url) {
    if (!currentSettings.apiKey) {
      return { blacklisted: false, failed: true };
    }

    // Check cache
    const cache = await browser.storage.local.get('sbCache');
    const sbCache = cache.sbCache ? JSON.parse(cache.sbCache) : {};
    const now = Date.now();
    if (sbCache[url] && now - sbCache[url].timestamp < 24 * 60 * 60 * 1000) {
      return { blacklisted: sbCache[url].blacklisted, failed: false };
    }

    const endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
    const body = {
      client: { clientId: 'PhishDetector', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    };

    try {
      const response = await fetch(`${endpoint}?key=${currentSettings.apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'PhishDetector/1.0' },
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        return { blacklisted: false, failed: true };
      }

      const result = await response.json();
      const blacklisted = result.matches && result.matches.length > 0;
      sbCache[url] = { blacklisted, timestamp: now };
      await browser.storage.local.set({ sbCache: JSON.stringify(sbCache) });
      return { blacklisted, failed: false };

    } catch (e) {
      return { blacklisted: false, failed: true };
    }
  }

  // Determine if URL is suspicious based on sensitivity
  function isSuspicious(patterns, sbBlacklisted) {
    console.log('Checking suspicious with sensitivity:', currentSettings.sensitivity);
    if (currentSettings.sensitivity === 'high') {
      return sbBlacklisted || Object.values(patterns).some(v => v);
    } else if (currentSettings.sensitivity === 'medium') {
      return sbBlacklisted || Object.values(patterns).filter(v => v).length >= 2;
    } else {
      return sbBlacklisted;
    }
  }

  // Check if URL is in whitelist
  function isWhitelisted(url) {
    return currentSettings.whitelist.some(w => url.includes(w));
  }

  // Get reasons for suspicion
  function getSuspicionReasons(patterns, sbBlacklisted, sbFailed = false) {
    const reasons = [];
    if (patterns.numbers_in_domain) reasons.push("Numbers in domain");
    if (patterns.excessive_subdomains) reasons.push("Excessive subdomains");
    if (patterns.special_chars) reasons.push("Special characters");
    if (sbBlacklisted) reasons.push("Blacklisted by Google Safe Browsing");
    if (sbFailed && reasons.length === 0) reasons.push("Safe Browsing check failed");
    return reasons.length > 0 ? reasons.join(", ") : "Blocked by settings";
  }

  // Get warning page URL
  function getWarningPageUrl(url, reason) {
    const warningUrl = browser.runtime.getURL('warning.html');
    const params = new URLSearchParams({
      url: encodeURIComponent(url),
      reason: encodeURIComponent(reason)
    });
    const finalUrl = `${warningUrl}?${params.toString()}`;
    console.log('Generated warning URL:', finalUrl);
    return finalUrl;
  }

  // Show notification
  function showNotification(url, isSuspicious, patterns, sbBlacklisted, sbFailed = false) {
    const domain = getDomain(url);
    if (isSuspicious || sbFailed) {
      const reasons = getSuspicionReasons(patterns, sbBlacklisted, sbFailed);
      browser.notifications.create({
        type: 'basic',
        title: 'Phishing Alert',
        message: `Suspicious URL detected: ${domain}\nReasons: ${reasons}`
      });
    } else if (currentSettings.showSafeNotifications) {
      browser.notifications.create({
        type: 'basic',
        title: 'Safe URL',
        message: `Safe URL confirmed: ${domain}`
      });
    }
  }

  // Handle messages from content.js
  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkSafeBrowsing') {
      checkGoogleSafeBrowsing(message.url).then(({ blacklisted, failed }) => {
        sendResponse({ blacklisted, failed });
      }).catch(error => {
        sendResponse({ blacklisted: false, failed: true });
      });
      return true;
    }
  });

  // Monitor navigation only for current page
  browser.webNavigation.onBeforeNavigate.addListener(async (details) => {
    const url = details.url;
    console.log('Navigation detected:', url, 'Frame ID:', details.frameId, 'Parent Frame ID:', details.parentFrameId);
    
    // Skip if it's our warning page or moz-extension URLs
    if (url.startsWith(browser.runtime.getURL('warning.html')) || url.startsWith('moz-extension://')) {
      console.log('Skipping extension URL or warning page');
      return;
    }

    // Only process main frame navigation (frameId === 0) or top-level navigation (parentFrameId === -1)
    if (details.frameId === 0 || details.parentFrameId === -1) {
      console.log('Processing main frame navigation');
      await checkAndBlockUrl(url, details.tabId);
    } else {
      console.log('Skipping non-main frame navigation');
    }
  });

  // Check current page when it's already loaded
  browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
      console.log('Page loaded:', tab.url);
      
      // Skip if it's our warning page or moz-extension URLs
      if (tab.url.startsWith(browser.runtime.getURL('warning.html')) || tab.url.startsWith('moz-extension://')) {
        console.log('Skipping extension URL or warning page');
        return;
      }
      
      await checkAndBlockUrl(tab.url, tabId);
    }
  });

  // Function to check and block URL
  async function checkAndBlockUrl(url, tabId) {
    console.log('Checking URL:', url);
    console.log('Current settings:', currentSettings);
    
    if (isWhitelisted(url)) {
      console.log('URL is whitelisted');
      if (currentSettings.showSafeNotifications) {
        browser.notifications.create({
          type: 'basic',
          title: 'Safe URL',
          message: `Safe URL confirmed (whitelisted): ${getDomain(url)}`
        });
      }
      return;
    }

    const patterns = checkSuspiciousPatterns(url);
    console.log('Suspicious patterns:', patterns);
    
    const { blacklisted: sbBlacklisted, failed: sbFailed } = await checkGoogleSafeBrowsing(url);
    console.log('Safe Browsing check:', { blacklisted: sbBlacklisted, failed: sbFailed });
    
    const suspicious = isSuspicious(patterns, sbBlacklisted);
    console.log('Is suspicious:', suspicious);

    showNotification(url, suspicious, patterns, sbBlacklisted, sbFailed);

    console.log('Checking block conditions:', {
      suspicious,
      sbFailed,
      autoBlock: currentSettings.autoBlock,
      shouldBlock: (suspicious || sbFailed) && currentSettings.autoBlock
    });

    if ((suspicious || sbFailed) && currentSettings.autoBlock) {
      const reason = getSuspicionReasons(patterns, sbBlacklisted, sbFailed);
      console.log('Attempting to block URL:', url);
      console.log('Reason:', reason);
      console.log('Tab ID:', tabId);
      
      try {
        const warningUrl = getWarningPageUrl(url, reason);
        console.log('Redirecting to:', warningUrl);
        
        // Try to update the tab
        await browser.tabs.update(tabId, { url: warningUrl });
        console.log('Tab updated successfully');
        
        browser.notifications.create({
          type: 'basic',
          title: 'Link Blocked',
          message: `Access to ${getDomain(url)} was blocked due to: ${reason}`
        });
      } catch (error) {
        console.error('Error redirecting to warning page:', error);
        // Fallback: try to create a new tab with the warning page
        try {
          await browser.tabs.create({ url: getWarningPageUrl(url, reason) });
          console.log('Created new tab with warning page');
        } catch (fallbackError) {
          console.error('Fallback also failed:', fallbackError);
        }
      }
    } else {
      console.log('Not blocking because:', {
        suspicious,
        sbFailed,
        autoBlock: currentSettings.autoBlock
      });
    }
  }
});