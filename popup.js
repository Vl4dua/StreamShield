
'use strict';

const $ = id => document.getElementById(id);

const ui = {
  html:            document.documentElement,
  themeBtn:        $('themeBtn'),
  modeBadge:       $('modeBadge'),
  streamerToggle:  $('streamerToggle'),
  emailToggle:     $('emailToggle'),
  ipToggle:        $('ipToggle'),
  phoneToggle:     $('phoneToggle'),
  addressToggle:   $('addressToggle'),
  geoToggle:       $('geoToggle'),
  uaToggle:        $('uaToggle'),
  autofillToggle:  $('autofillToggle'),
  popupToggle:     $('popupToggle'),
  cardsSection:    $('cardsSection'),
  toolsSection:    $('toolsSection'),
  selectBtn:       $('selectElementBtn'),
  selectLabel:     $('selectBtnLabel'),
  selectHint:      $('selectHint'),
  screenshotBtn:   $('screenshotBtn'),
  panicBtn:        $('panicBtn'),
  panicLabel:      $('panicLabel'),
  currentDomain:   $('currentDomain'),
  whitelistBtn:    $('whitelistBtn'),
  whitelistList:   $('whitelistList'),
  cardEmail:       $('cardEmail'),
  cardIp:          $('cardIp'),
  cardPhone:       $('cardPhone'),
  cardAddress:     $('cardAddress'),
  cardGeo:         $('cardGeo'),
  cardUA:          $('cardUA'),
  cardAutofill:    $('cardAutofill'),
  cardPopup:       $('cardPopup'),
};

let settings = {};
let panicActive = false;
let selectModeActive = false;
let screenshotActive = false;
let currentDomain = '';

document.addEventListener('DOMContentLoaded', async () => {
  await loadAll();
  bindEvents();
});

async function loadAll() {
  try {
    const res = await msg({ type: 'GET_SETTINGS' });
    if (res?.success) settings = res.settings;
  } catch (_) {}
  applyTheme(settings.theme || 'dark');
  applySettings(settings);
  await loadCurrentDomain();
  renderWhitelist(settings.whitelist || []);
}

function applyTheme(theme) {
  ui.html.setAttribute('data-theme', theme);
  const icon = $('themeIconSvg');
  if (theme === 'dark') {
    icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
  } else {
    icon.innerHTML = '<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>';
  }
}

async function toggleTheme() {
  const next = (settings.theme || 'dark') === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  await save({ theme: next });
}

function applySettings(s) {
  ui.streamerToggle.checked  = !!s.streamerMode;
  ui.emailToggle.checked     = s.emailProtection     !== false;
  ui.ipToggle.checked        = s.ipProtection        !== false;
  ui.phoneToggle.checked     = s.phoneProtection     !== false;
  ui.addressToggle.checked   = s.addressProtection   !== false;
  ui.geoToggle.checked       = s.geoProtection       !== false;
  ui.uaToggle.checked        = s.userAgentProtection !== false;
  ui.autofillToggle.checked  = s.autofillProtection  !== false;
  ui.popupToggle.checked     = s.popupProtection     !== false;
  updateStreamerUI(!!s.streamerMode);
  updateCards(s);
}

function updateStreamerUI(on) {
  ui.modeBadge.textContent = on ? 'ON' : 'OFF';
  ui.modeBadge.classList.toggle('on', on);
  ui.cardsSection.classList.toggle('disabled', !on);
  ui.toolsSection.classList.toggle('disabled', !on);
}

function updateCards(s) {
  const on = !!s.streamerMode;
  ui.cardEmail.classList.toggle('active',    on && s.emailProtection     !== false);
  ui.cardIp.classList.toggle('active',       on && s.ipProtection        !== false);
  ui.cardPhone.classList.toggle('active',    on && s.phoneProtection     !== false);
  ui.cardAddress.classList.toggle('active',  on && s.addressProtection   !== false);
  ui.cardGeo.classList.toggle('active',      on && s.geoProtection       !== false);
  ui.cardUA.classList.toggle('active',       on && s.userAgentProtection !== false);
  ui.cardAutofill.classList.toggle('active', on && s.autofillProtection  !== false);
  ui.cardPopup.classList.toggle('active',    on && s.popupProtection     !== false);
}

function bindEvents() {
  ui.themeBtn.addEventListener('click', toggleTheme);

  ui.streamerToggle.addEventListener('change', async () => {
    const on = ui.streamerToggle.checked;
    await save({ streamerMode: on });
    updateStreamerUI(on);
    updateCards(settings);
    await notifyTab({ type: 'SETTINGS_UPDATED', settings });
  });

  [
    { el: ui.emailToggle,    key: 'emailProtection' },
    { el: ui.ipToggle,       key: 'ipProtection' },
    { el: ui.phoneToggle,    key: 'phoneProtection' },
    { el: ui.addressToggle,  key: 'addressProtection' },
    { el: ui.geoToggle,      key: 'geoProtection' },
    { el: ui.uaToggle,       key: 'userAgentProtection' },
    { el: ui.autofillToggle, key: 'autofillProtection' },
    { el: ui.popupToggle,    key: 'popupProtection' },
  ].forEach(({ el, key }) => {
    el.addEventListener('change', async () => {
      await save({ [key]: el.checked });
      updateCards(settings);
      if (settings.streamerMode) await notifyTab({ type: 'SETTINGS_UPDATED', settings });
    });
  });

  ui.panicBtn.addEventListener('click', async () => {
    panicActive = !panicActive;
    ui.panicBtn.classList.toggle('active', panicActive);
    ui.panicLabel.textContent = panicActive ? 'Restore View' : 'Blur Everything';
    await notifyTab({ type: 'PANIC_BLUR', active: panicActive });
  });

  ui.selectBtn.addEventListener('click', async () => {
    selectModeActive = !selectModeActive;
    ui.selectBtn.classList.toggle('active', selectModeActive);
    ui.selectLabel.textContent = selectModeActive ? 'Cancel' : 'Click to Hide';
    ui.selectHint.classList.toggle('visible', selectModeActive);
    await notifyTab({ type: 'SELECT_MODE', active: selectModeActive });
    if (selectModeActive) window.close();
  });

  ui.screenshotBtn.addEventListener('click', async () => {
    screenshotActive = !screenshotActive;
    ui.screenshotBtn.classList.toggle('active', screenshotActive);
    await notifyTab({ type: 'SCREENSHOT_MODE', active: screenshotActive });
  });

  ui.whitelistBtn.addEventListener('click', async () => {
    if (!currentDomain) return;
    const list = settings.whitelist || [];
    const idx = list.indexOf(currentDomain);
    if (idx >= 0) list.splice(idx, 1);
    else list.push(currentDomain);
    await save({ whitelist: list });
    renderWhitelist(list);
    updateWhitelistBtn(list.includes(currentDomain));
    await notifyTab({ type: 'WHITELIST_UPDATED', whitelist: list });
  });
}

async function loadCurrentDomain() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('edge://')) {
      currentDomain = new URL(tab.url).hostname;
      ui.currentDomain.textContent = currentDomain;
      updateWhitelistBtn((settings.whitelist || []).includes(currentDomain));
    }
  } catch (_) {}
}

function updateWhitelistBtn(isWhitelisted) {
  ui.whitelistBtn.textContent = isWhitelisted ? 'Enable here' : 'Disable here';
  ui.whitelistBtn.classList.toggle('whitelisted', isWhitelisted);
}

function renderWhitelist(list) {
  ui.whitelistList.innerHTML = '';
  if (!list || !list.length) return;
  list.forEach(domain => {
    const item = document.createElement('div');
    item.className = 'whitelist-item';
    const span = document.createElement('span');
    span.textContent = domain;
    const btn = document.createElement('button');
    btn.className = 'whitelist-remove';
    btn.textContent = 'x';
    btn.title = `Remove ${domain}`;
    btn.addEventListener('click', async () => {
      const newList = (settings.whitelist || []).filter(x => x !== domain);
      await save({ whitelist: newList });
      renderWhitelist(newList);
      if (domain === currentDomain) updateWhitelistBtn(false);
      await notifyTab({ type: 'WHITELIST_UPDATED', whitelist: newList });
    });
    item.appendChild(span);
    item.appendChild(btn);
    ui.whitelistList.appendChild(item);
  });
}

async function save(partial) {
  Object.assign(settings, partial);
  try {
    await msg({ type: 'UPDATE_SETTINGS', settings: partial });
  } catch (_) {}
}

function msg(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, res => {
      if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
      else resolve(res);
    });
  });
}

async function notifyTab(message) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('edge://') && !tab.url.startsWith('about:')) {
      await chrome.tabs.sendMessage(tab.id, message);
    }
  } catch (_) {}
}
