document.addEventListener('DOMContentLoaded', () => {
  const apiKeyInput = document.getElementById('apiKey');
  const sensitivitySelect = document.getElementById('sensitivity');
  const showSafeNotificationsCheckbox = document.getElementById('showSafeNotifications');
  const autoBlockCheckbox = document.getElementById('autoBlock');
  const whitelistInput = document.getElementById('whitelist');
  const saveButton = document.getElementById('save');
  const clearCacheButton = document.getElementById('clearCache');

  // Load settings
  browser.storage.local.get(['apiKey', 'sensitivity', 'showSafeNotifications', 'autoBlock', 'whitelist']).then((settings) => {
    apiKeyInput.value = settings.apiKey || '';
    sensitivitySelect.value = settings.sensitivity || 'medium';
    showSafeNotificationsCheckbox.checked = settings.showSafeNotifications || false;
    autoBlockCheckbox.checked = settings.autoBlock || false;
    whitelistInput.value = settings.whitelist ? JSON.parse(settings.whitelist).join('\n') : '';
    if (!settings.apiKey) {
      apiKeyInput.placeholder = 'Using Google Safe Browsing API key from config.js (override here if needed)';
    }
  });

  // Save settings
  saveButton.addEventListener('click', () => {
    const whitelist = whitelistInput.value.trim().split('\n').map(url => url.trim()).filter(url => url);
    browser.storage.local.set({
      apiKey: apiKeyInput.value.trim(),
      sensitivity: sensitivitySelect.value,
      showSafeNotifications: showSafeNotificationsCheckbox.checked,
      autoBlock: autoBlockCheckbox.checked,
      whitelist: JSON.stringify(whitelist)
    }).then(() => {
      alert('Settings saved!');
    }).catch(error => {
      console.error('Error saving settings:', error);
      alert('Failed to save settings.');
    });
  });

  // Clear Safe Browsing cache
  clearCacheButton.addEventListener('click', () => {
    browser.storage.local.remove('sbCache').then(() => {
      alert('Safe Browsing cache cleared!');
    }).catch(error => {
      console.error('Error clearing cache:', error);
      alert('Failed to clear cache.');
    });
  });
});