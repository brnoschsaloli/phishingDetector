browser.storage.local.get(['sensitivity', 'whitelist', 'showSafeNotifications']).then((settings) => {
  const sensitivity = settings.sensitivity || 'medium';
  const whitelist = settings.whitelist ? JSON.parse(settings.whitelist) : [];
  const showSafeNotifications = settings.showSafeNotifications || false;

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

  // Get reasons for suspicion
  function getSuspicionReasons(patterns, sbBlacklisted, sbFailed = false) {
    const reasons = [];
    if (patterns.numbers_in_domain) reasons.push("Numbers in domain");
    if (patterns.excessive_subdomains) reasons.push("Excessive subdomains");
    if (patterns.special_chars) reasons.push("Special characters");
    if (sbBlacklisted) reasons.push("Blacklisted by Google Safe Browsing");
    if (sbFailed && reasons.length === 0) reasons.push("Safe Browsing check failed");
    return reasons.length > 0 ? reasons.join(", ") : "Unknown";
  }

  // Create notification element
  function showNotification(url, isSuspicious, patterns, sbBlacklisted, sbFailed = false) {
    const domain = getDomain(url);
    const notification = document.createElement('div');
    if (isSuspicious || sbFailed) {
      const reasons = getSuspicionReasons(patterns, sbBlacklisted, sbFailed);
      notification.className = 'phishing-alert';
      notification.textContent = `Warning: Suspicious link detected - ${domain} (Reasons: ${reasons})`;
    } else if (showSafeNotifications) {
      notification.className = 'safe-alert';
      notification.textContent = `Safe link confirmed - ${domain}`;
    } else {
      return; // No notification if safe notifications are disabled and URL is safe
    }
    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 5000);
  }

  // Monitor links on hover with debouncing
  let lastCheckedUrl = null;
  let lastCheckTime = 0;
  const debounceDelay = 1500; // 1500ms debounce to avoid rate limits

  function checkLink(url, callback) {
    if (!url || url === lastCheckedUrl && Date.now() - lastCheckTime < debounceDelay) {
      return;
    }
    lastCheckedUrl = url;
    lastCheckTime = Date.now();

    if (whitelist.some(w => url.includes(w))) {
      if (showSafeNotifications) {
        callback(false, {}, false, false);
      }
      return;
    }

    const patterns = checkSuspiciousPatterns(url);
    browser.runtime.sendMessage({
      action: 'checkSafeBrowsing',
      url: url
    }).then(response => {
      const sbBlacklisted = response ? response.blacklisted : false;
      const sbFailed = response ? response.failed : true;
      const suspicious = isSuspicious(patterns, sbBlacklisted);
      callback(suspicious, patterns, sbBlacklisted, sbFailed);
    }).catch(error => {
      console.error(`Error communicating with background script for ${url}: ${error}`);
      const suspicious = isSuspicious(patterns, false);
      callback(suspicious, patterns, false, true);
    });
  }

  document.querySelectorAll('a').forEach(link => {
    link.addEventListener('mouseover', (e) => {
      const url = link.href;
      checkLink(url, (suspicious, patterns, sbBlacklisted, sbFailed) => {
        showNotification(url, suspicious, patterns, sbBlacklisted, sbFailed);
      });
    });
  });

  // Monitor dynamically added links
  const observer = new MutationObserver((mutations) => {
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.tagName === 'A') {
          node.addEventListener('mouseover', (e) => {
            const url = node.href;
            checkLink(url, (suspicious, patterns, sbBlacklisted, sbFailed) => {
              showNotification(url, suspicious, patterns, sbBlacklisted, sbFailed);
            });
          });
        } else if (node.querySelectorAll) {
          node.querySelectorAll('a').forEach(link => {
            link.addEventListener('mouseover', (e) => {
              const url = link.href;
              checkLink(url, (suspicious, patterns, sbBlacklisted, sbFailed) => {
                showNotification(url, suspicious, patterns, sbBlacklisted, sbFailed);
              });
            });
          });
        }
      });
    });
  });

  observer.observe(document.body, { childList: true, subtree: true });
});