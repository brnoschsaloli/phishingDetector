browser.storage.local.get(['sensitivity', 'whitelist', 'showSafeNotifications']).then((settings) => {
  const sensitivity = settings.sensitivity || 'medium';
  const whitelist = settings.whitelist ? JSON.parse(settings.whitelist) : [];
  const showSafeNotifications = settings.showSafeNotifications || false;

  // Check if current page is an email client
  function isEmailClient() {
    const hostname = window.location.hostname;
    return hostname.includes('mail.google.com') || hostname.includes('outlook.live.com') || hostname.includes('outlook.office.com');
  }

  // Check if element is a link in an email
  function isEmailLink(element) {
    if (!isEmailClient()) return false;
    
    // For Gmail
    if (window.location.hostname.includes('mail.google.com')) {
      return element.closest('.gmail_quote') !== null || element.closest('.adn.ads') !== null;
    }
    
    // For Outlook
    if (window.location.hostname.includes('outlook.live.com') || window.location.hostname.includes('outlook.office.com')) {
      return element.closest('.ms-email-body') !== null;
    }
    
    return false;
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

  // Add hover effect to suspicious links
  function addHoverEffect(element) {
    element.style.borderBottom = '2px solid red';
    element.style.cursor = 'not-allowed';
  }

  // Remove hover effect from links
  function removeHoverEffect(element) {
    element.style.borderBottom = '';
    element.style.cursor = '';
  }

  // Create notification element
  function showNotification(url, isSuspicious, patterns, sbBlacklisted, sbFailed = false) {
    const domain = getDomain(url);
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 15px;
      border-radius: 5px;
      z-index: 10000;
      max-width: 400px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2);
      font-family: Arial, sans-serif;
      font-size: 14px;
      line-height: 1.4;
    `;

    if (isSuspicious || sbFailed) {
      notification.style.backgroundColor = '#f8d7da';
      notification.style.color = '#721c24';
      notification.style.border = '1px solid #f5c6cb';
      const reasons = getSuspicionReasons(patterns, sbBlacklisted, sbFailed);
      notification.textContent = `Warning: Suspicious link detected - ${domain}\nReasons: ${reasons}`;
    } else if (showSafeNotifications) {
      notification.style.backgroundColor = '#d4edda';
      notification.style.color = '#155724';
      notification.style.border = '1px solid #c3e6cb';
      notification.textContent = `Safe link confirmed - ${domain}`;
    } else {
      return;
    }

    document.body.appendChild(notification);
    setTimeout(() => notification.remove(), 5000);
  }

  // Check URL and update link appearance
  async function checkUrl(url, element) {
    if (!url || !url.startsWith('http')) return;

    if (whitelist.some(w => url.includes(w))) {
      if (showSafeNotifications) {
        showNotification(url, false, {}, false, false);
      }
      return;
    }

    const patterns = checkSuspiciousPatterns(url);
    try {
      const response = await browser.runtime.sendMessage({
        action: 'checkSafeBrowsing',
        url: url
      });

      const sbBlacklisted = response ? response.blacklisted : false;
      const sbFailed = response ? response.failed : true;
      const suspicious = isSuspicious(patterns, sbBlacklisted);

      if (suspicious || sbFailed) {
        addHoverEffect(element);
      } else {
        removeHoverEffect(element);
      }

      showNotification(url, suspicious, patterns, sbBlacklisted, sbFailed);
    } catch (error) {
      console.error('Error checking URL:', error);
      const suspicious = isSuspicious(patterns, false);
      showNotification(url, suspicious, patterns, false, true);
    }
  }

  // Handle mouseover events
  function handleMouseOver(event) {
    const element = event.target;
    if (element.tagName === 'A' && isEmailLink(element)) {
      const url = element.href;
      checkUrl(url, element);
    }
  }

  // Handle mouseout events
  function handleMouseOut(event) {
    const element = event.target;
    if (element.tagName === 'A') {
      removeHoverEffect(element);
    }
  }

  // Add event listeners
  document.addEventListener('mouseover', handleMouseOver);
  document.addEventListener('mouseout', handleMouseOut);

  // Check all links in the page when it loads
  function checkAllLinks() {
    if (!isEmailClient()) return;

    const links = document.getElementsByTagName('a');
    for (const link of links) {
      if (isEmailLink(link)) {
        checkUrl(link.href, link);
      }
    }
  }

  // Run initial check
  checkAllLinks();

  // Watch for new links being added to the page
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const links = node.getElementsByTagName('a');
          for (const link of links) {
            if (isEmailLink(link)) {
              checkUrl(link.href, link);
            }
          }
        }
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
});