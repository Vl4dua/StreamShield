
'use strict';

const DEFAULTS = {
  streamerMode:       false,
  emailProtection:    true,
  ipProtection:       true,
  autofillProtection: true,
  popupProtection:    true,
  theme:              'dark',
  whitelist:          [],
};


chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  if (reason === 'install') {
    await chrome.storage.local.set(DEFAULTS);
  } else if (reason === 'update') {
    const existing = await chrome.storage.local.get(null);
    await chrome.storage.local.set({ ...DEFAULTS, ...existing });
  }
  updateBadge(false);
});


chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  switch (msg.type) {
    case 'GET_SETTINGS':
      getSettings().then(s => reply({ success: true, settings: s }));
      return true;

    case 'UPDATE_SETTINGS':
      updateSettings(msg.settings).then(s => reply({ success: true, settings: s }));
      return true;

    default:
      reply({ success: false, error: 'unknown' });
  }
});


async function getSettings() {
  const stored = await chrome.storage.local.get(null);
  return { ...DEFAULTS, ...stored };
}

async function updateSettings(partial) {
  const current = await chrome.storage.local.get(null);
  const next = { ...DEFAULTS, ...current, ...partial };
  await chrome.storage.local.set(next);
  updateBadge(next.streamerMode);
  return next;
}


function updateBadge(on) {
  if (on) {
    chrome.action.setBadgeText({ text: 'ON' });
    chrome.action.setBadgeBackgroundColor({ color: '#00ffc8' });
    chrome.action.setBadgeTextColor?.({ color: '#0f1115' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}


chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== 'complete') return;
  if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) return;

  const s = await getSettings();
  if (!s.streamerMode) return;

  chrome.tabs.sendMessage(tabId, { type: 'SETTINGS_UPDATED', settings: s }).catch(() => {});
});
