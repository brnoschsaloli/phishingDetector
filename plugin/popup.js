document.addEventListener('DOMContentLoaded', () => {
    const autoBlockCheckbox = document.getElementById('autoBlock');
    const whitelistUl = document.getElementById('whitelist');
    const newSiteInput = document.getElementById('newSite');
    const addSiteButton = document.getElementById('addSite');
  
    // Load settings
    browser.storage.local.get(['autoBlock', 'whitelist']).then((settings) => {
      autoBlockCheckbox.checked = settings.autoBlock || false;
      const whitelist = settings.whitelist ? JSON.parse(settings.whitelist) : [];
  
      whitelist.forEach(site => {
        const li = document.createElement('li');
        li.textContent = site;
        const removeBtn = document.createElement('button');
        removeBtn.textContent = 'Remove';
        removeBtn.onclick = () => {
          const newWhitelist = whitelist.filter(s => s !== site);
          browser.storage.local.set({ whitelist: JSON.stringify(newWhitelist) });
          li.remove();
        };
        li.appendChild(removeBtn);
        whitelistUl.appendChild(li);
      });
    });
  
    // Save auto-block setting
    autoBlockCheckbox.addEventListener('change', () => {
      browser.storage.local.set({ autoBlock: autoBlockCheckbox.checked });
    });
  
    // Add site to whitelist
    addSiteButton.addEventListener('click', () => {
      const site = newSiteInput.value.trim();
      if (site) {
        browser.storage.local.get(['whitelist']).then((settings) => {
          const whitelist = settings.whitelist ? JSON.parse(settings.whitelist) : [];
          if (!whitelist.includes(site)) {
            whitelist.push(site);
            browser.storage.local.set({ whitelist: JSON.stringify(whitelist) });
            const li = document.createElement('li');
            li.textContent = site;
            const removeBtn = document.createElement('button');
            removeBtn.textContent = 'Remove';
            removeBtn.onclick = () => {
              const newWhitelist = whitelist.filter(s => s !== site);
              browser.storage.local.set({ whitelist: JSON.stringify(newWhitelist) });
              li.remove();
            };
            li.appendChild(removeBtn);
            whitelistUl.appendChild(li);
            newSiteInput.value = '';
          }
        });
      }
    });
  });