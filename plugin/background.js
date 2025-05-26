browser.storage.local.get(['apiKey', 'sensitivity', 'whitelist', 'autoBlock', 'showSafeNotifications', 'blockAllLinks']).then((settings) => {
  const apiKey = CONFIG.GOOGLE_SAFE_BROWSING_API_KEY || settings.apiKey || '';
  const sensitivity = settings.sensitivity || 'medium';
  const whitelist = settings.whitelist ? JSON.parse(settings.whitelist) : [];
  const autoBlock = settings.autoBlock || false;
  const showSafeNotifications = settings.showSafeNotifications || false;
  const blockAllLinks = settings.blockAllLinks || false;

  console.log('Extension initialized with settings:', { apiKey: !!apiKey, sensitivity, whitelist, autoBlock, showSafeNotifications, blockAllLinks });

  if (!apiKey) {
    console.error('No Google Safe Browsing API key provided in config.js or storage');
  }

  // Check suspicious patterns
  function checkSuspiciousPatterns(url) {
    const patterns = {
      numbers_in_domain: false,
      excessive_subdomains: false,
      special_chars: false
    };

    const domainMatch = url.match(/^(?:https?:\/\/)?(?:[^\/]+\.)*([^\/]+\.[^\/]+)/i);
    const domain = domainMatch ? domainMatch[1] : '';

    if (/\d/.test(domain)) {
      patterns.numbers_in_domain = true;
    }

    const subdomains = url.match(/^(?:https?:\/\/)?((?:[^\/]+\.)+)/i);
    if (subdomains && subdomains[1].split('.').length > 3) {
      patterns.excessive_subdomains = true;
    }

    if (/[^a-zA-Z0-9.:\/-]/.test(url)) {
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
    if (!apiKey) {
      console.warn('Google Safe Browsing API key not set');
      return { blacklisted: false, failed: true };
    }

    // Skip Safe Browsing API endpoint
    if (url.includes('safebrowsing.googleapis.com')) {
      console.log(`Skipping Safe Browsing check for API endpoint: ${url}`);
      return { blacklisted: false, failed: false };
    }

    // Check cache
    const cache = await browser.storage.local.get('sbCache');
    const sbCache = cache.sbCache ? JSON.parse(cache.sbCache) : {};
    const now = Date.now();
    if (sbCache[url] && now - sbCache[url].timestamp < 24 * 60 * 60 * 1000) {
      console.log(`Cache hit for ${url}: blacklisted=${sbCache[url].blacklisted}`);
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
      console.log(`Fetching Google Safe Browsing for ${url}`);
      const response = await fetch(`${endpoint}?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'PhishDetector/1.0' },
        body: JSON.stringify(body)
      });

      console.log(`Safe Browsing response status for ${url}: ${response.status} ${response.statusText}`);

      if (!response.ok) {
        const text = await response.text();
        console.error(`Safe Browsing API error for ${url}: ${response.status} ${response.statusText}, body: ${text}`);
        return { blacklisted: false, failed: true };
      }

      const result = await response.json();
      console.log(`Safe Browsing response for ${url}:`, result);
      const blacklisted = result.matches && result.matches.length > 0;
      if (!blacklisted) {
        console.log(`No threats found for ${url}`);
      }
      sbCache[url] = { blacklisted, timestamp: now };
      await browser.storage.local.set({ sbCache: JSON.stringify(sbCache) });
      return { blacklisted, failed: false };

    } catch (error) {
      console.error(`Error checking Safe Browsing for ${url}: ${error}`);
      return { blacklisted: false, failed: true };
    }
  }

  // Determine if URL is suspicious based on sensitivity
  function isSuspicious(patterns, sbBlacklisted) {
    if (sensitivity === 'high') {
      return sbBlacklisted || Object.values(patterns).some(v => v);
    } else if (sensitivity === 'medium') {
      return sbBlacklisted || Object.values(patterns).filter(v => v).length >= 2;
    } else {
      return sbBlacklisted;
    }
  }

  // Check if URL is in whitelist
  function isWhitelisted(url) {
    return whitelist.some(w => url.includes(w));
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

  // Show notification
  function showNotification(url, isSuspicious, patterns, sbBlacklisted, sbFailed = false) {
    const domain = getDomain(url);
    if (isSuspicious || sbFailed) {
      const reasons = getSuspicionReasons(patterns, sbBlacklisted, sbFailed);
      console.log(`Showing phishing alert for ${url}: ${reasons}`);
      browser.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png',
        title: 'Phishing Alert',
        message: `Suspicious link detected: ${domain}\nReasons: ${reasons}`
      });
    } else if (showSafeNotifications) {
      console.log(`Showing safe notification for ${url}`);
      browser.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png',
        title: 'Safe URL',
        message: `Safe link confirmed: ${domain}`
      });
    }
  }

  // Get warning page URL
  function getWarningPageUrl(url, reason) {
    const warningUrl = browser.runtime.getURL('warning.html');
    const params = new URLSearchParams({ url, reason });
    return `${warningUrl}?${params.toString()}`;
  }

  // Handle messages from content.js
  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'checkSafeBrowsing') {
      console.log(`Content script requested Safe Browsing check for ${message.url}`);
      checkGoogleSafeBrowsing(message.url).then(({ blacklisted, failed }) => {
        sendResponse({ blacklisted, failed });
      }).catch(error => {
        console.error(`Error in Safe Browsing check for ${message.url}:`, error);
        sendResponse({ blacklisted: false, failed: true });
      });
      return true; // Keep the message channel open for async response
    }
  });

  // Monitor navigation
  browser.webNavigation.onBeforeNavigate.addListener(async (details) => {
    const url = details.url;
    console.log(`Navigating to ${url}`);
    if (isWhitelisted(url)) {
      console.log(`URL is whitelisted: ${url}`);
      if (showSafeNotifications) {
        browser.notifications.create({
          type: 'basic',
          iconUrl: 'icon48.png',
          title: 'Safe URL',
          message: `Safe link confirmed (whitelisted): ${getDomain(url)}`
        });
      }
      return;
    }

    if (url.includes('safebrowsing.googleapis.com')) {
      console.log(`Skipping navigation check for Safe Browsing API: ${url}`);
      return;
    }

    if (blockAllLinks) {
      console.log(`Blocking navigation due to blockAllLinks: ${url}`);
      browser.tabs.update(details.tabId, { url: getWarningPageUrl(url, 'Blocked by settings') });
      browser.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png',
        title: 'Link Blocked',
        message: `Access to ${getDomain(url)} was blocked by settings.`
      });
      return;
    }

    const patterns = checkSuspiciousPatterns(url);
    const { blacklisted: sbBlacklisted, failed: sbFailed } = await checkGoogleSafeBrowsing(url);
    const suspicious = isSuspicious(patterns, sbBlacklisted);

    console.log(`Navigation check for ${url}: suspicious=${suspicious}, sbBlacklisted=${sbBlacklisted}, sbFailed=${sbFailed}, autoBlock=${autoBlock}`);

    showNotification(url, suspicious, patterns, sbBlacklisted, sbFailed);

    if ((suspicious || sbFailed) && autoBlock) {
      const reason = getSuspicionReasons(patterns, sbBlacklisted, sbFailed);
      console.log(`Blocking navigation to ${url} due to: ${reason}`);
      browser.tabs.update(details.tabId, { url: getWarningPageUrl(url, reason) });
      browser.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png',
        title: 'Link Blocked',
        message: `Access to ${getDomain(url)} was blocked due to: ${reason}`
      });
    }
  });

  // Intercept requests
  browser.webRequest.onBeforeRequest.addListener(
    (details) => {
      const url = details.url;
      console.log(`Request for ${url}`);
      if (isWhitelisted(url)) {
        console.log(`URL whitelisted, allowing request: ${url}`);
        return { cancel: false };
      }
      if (url.includes('safebrowsing.googleapis.com')) {
        console.log(`Skipping request check for Safe Browsing API: ${url}`);
        return { cancel: false };
      }
      if (blockAllLinks) {
        console.log(`Blocking request due to blockAllLinks: ${url}`);
        browser.notifications.create({
          type: 'basic',
          iconUrl: 'icon48.png',
          title: 'Link Blocked',
          message: `Access to ${getDomain(url)} was blocked by settings.`
        });
        return { redirectUrl: getWarningPageUrl(url, 'Blocked by settings') };
      }
      // Synchronous pattern check
      const patterns = checkSuspiciousPatterns(url);
      // Use cached Safe Browsing result if available
      return browser.storage.local.get('sbCache').then(cache => {
        const sbCache = cache.sbCache ? JSON.parse(cache.sbCache) : {};
        const now = Date.now();
        let sbBlacklisted = false;
        let sbFailed = false;
        if (sbCache[url] && now - sbCache[url].timestamp < 24 * 60 * 60 * 1000) {
          console.log(`Cache hit in webRequest for ${url}: blacklisted=${sbCache[url].blacklisted}`);
          sbBlacklisted = sbCache[url].blacklisted;
        } else {
          // Fallback to async check (may not block in time)
          console.warn(`No cache hit for ${url} in webRequest, performing async check`);
          return checkGoogleSafeBrowsing(url).then(({ blacklisted, failed }) => {
            sbBlacklisted = blacklisted;
            sbFailed = failed;
            const suspicious = isSuspicious(patterns, sbBlacklisted);
            console.log(`Async request check for ${url}: suspicious=${suspicious}, sbBlacklisted=${sbBlacklisted}, sbFailed=${sbFailed}, autoBlock=${autoBlock}`);
            if ((suspicious || sbFailed) && autoBlock) {
              const reason = getSuspicionReasons(patterns, sbBlacklisted, sbFailed);
              console.log(`Blocking request for ${url} due to: ${reason}`);
              browser.notifications.create({
                type: 'basic',
                iconUrl: 'icon48.png',
                title: 'Link Blocked',
                message: `Access to ${getDomain(url)} was blocked due to: ${reason}`
              });
              return { redirectUrl: getWarningPageUrl(url, reason) };
            }
            return { cancel: false };
          });
        }
        const suspicious = isSuspicious(patterns, sbBlacklisted);
        console.log(`Sync request check for ${url}: suspicious=${suspicious}, sbBlacklisted=${sbBlacklisted}, sbFailed=${sbFailed}, autoBlock=${autoBlock}`);
        if ((suspicious || sbFailed) && autoBlock) {
          const reason = getSuspicionReasons(patterns, sbBlacklisted, sbFailed);
          console.log(`Blocking request for ${url} due to: ${reason}`);
          browser.notifications.create({
            type: 'basic',
            iconUrl: 'icon48.png',
            title: 'Link Blocked',
            message: `Access to ${getDomain(url)} was blocked due to: ${reason}`
          });
          return { redirectUrl: getWarningPageUrl(url, reason) };
        }
        return { cancel: false };
      });
    },
    { urls: ['https://*/*', 'http://*/*'] },
    ['blocking']
  );
});