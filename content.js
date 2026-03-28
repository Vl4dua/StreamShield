
'use strict';


const RE_IPV4_RAW = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
const RE_EMAIL    = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
const RE_IPV6     = /(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}/g;
const RE_PHONE    = /(?:\+\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}(?:[\s\-.]?\d{1,4})?/g;
const RE_ADDRESS  = /\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Terrace|Ter|Circle|Cir|Via|Viale|Corso|Piazza)\b/g;
const RE_USERAGENT = /Mozilla\/[\d.]+\s*\([^)]+\)[^"'\n]*/g;


const WHITELIST_PATTERNS = {
  versions: /\b(v|version)\s*\d+\.\d+(\.\d+)?(\.\d+)?\b/gi,
  
  dates: /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g,
  
  times: /\b\d{1,2}:\d{2}(:\d{2})?\s*(am|pm)?\b/gi,
  
  prices: /\$\s*\d+(\.\d{2})?\b|\b\d+(\.\d{2})?\s*(usd|eur|gbp|\u20ac|\u00a3)\b/gi,
  
  measurements: /\b\d+(\.\d+)?\s*(px|em|rem|%|cm|mm|in|pt|vh|vw|deg)\b/gi,
  
  files: /\b\w+\.(jpg|jpeg|png|gif|svg|webp|pdf|doc|docx|xls|xlsx|zip|rar|js|css|html|json|xml)\b/gi,
  
  coords: /\b\d{1,3}\.\d{6,}\b/g,
  
  ids: /\b[a-f0-9]{32,}\b/gi,
};

const GEO_LABELS = new Set([
  'country','region','state','province','city','town','municipality',
  'zip','postal','postcode','postal code','zip code',
  'timezone','time zone',
  'isp','internet service provider','provider','carrier',
  'organization','organisation','org',
  'as number','as name','asn','autonomous system',
  'latitude','longitude','lat','lon','lng','coordinates',
  'hostname','host','reverse dns','rdns',
  'continent','district','county',
]);

const USERAGENT_LABELS = new Set([
  'user agent','useragent','browser',
]);

const SKIP_TAGS = new Set([
  'SCRIPT','STYLE','NOSCRIPT','IFRAME','OBJECT','EMBED',
  'HEAD','META','LINK','TITLE','SVG','CANVAS','VIDEO','AUDIO',
]);

const SKIP_INPUT_TYPES = new Set([
  'checkbox','radio','button','submit','reset','hidden','file','range','color','image',
]);

const SCAN_ATTRS = [
  'title','alt','placeholder','aria-label','aria-description',
  'data-tooltip','data-content','data-original-title','data-tip',
];
const URL_ATTRS = ['href','src','action','data-url','data-href'];
const POPUP_SELECTORS = [
  'dialog',
  '[role="dialog"]',
  '[role="alertdialog"]',
  '[aria-modal="true"]',
  '[data-modal]',
  '[data-popup]',
  '[class*="modal"]',
  '[class*="popup"]',
  '[class*="drawer"]',
  '[class*="tooltip"]',
  '[class*="popover"]',
];
const GEO_VALUE_SELECTORS = [
  '[class*="geo"]',
  '[class*="location"]',
  '[class*="country"]',
  '[class*="region"]',
  '[class*="state"]',
  '[class*="province"]',
  '[class*="city"]',
  '[class*="timezone"]',
  '[class*="postal"]',
  '[class*="zipcode"]',
  '[class*="zip-code"]',
  '[class*="coords"]',
  '[class*="coordinate"]',
  '[class*="latitude"]',
  '[class*="longitude"]',
  '[class*="hostname"]',
  '[class*="reverse-dns"]',
  '[class*="rdns"]',
  '[class*="isp"]',
  '[class*="carrier"]',
  '[class*="asn"]',
  '[id*="geo"]',
  '[id*="location"]',
  '[id*="country"]',
  '[id*="region"]',
  '[id*="state"]',
  '[id*="province"]',
  '[id*="city"]',
  '[id*="timezone"]',
  '[id*="postal"]',
  '[id*="zipcode"]',
  '[id*="coords"]',
  '[id*="coordinate"]',
  '[id*="latitude"]',
  '[id*="longitude"]',
  '[id*="hostname"]',
  '[id*="rdns"]',
  '[id*="isp"]',
  '[id*="carrier"]',
  '[id*="asn"]',
  '[data-testid*="location"]',
  '[data-testid*="country"]',
  '[data-testid*="city"]',
  '[data-testid*="region"]',
  '[data-testid*="timezone"]',
  '[data-testid*="isp"]',
  '[data-testid*="asn"]',
];
const GEO_INLINE_RE = /\b(location|country|region|state|province|city|timezone|time zone|postal code|zip code|postcode|coordinates?|latitude|longitude|lat|lon|lng|hostname|reverse dns|rdns|isp|carrier|asn)\b\s*[:\-]/i;
const GEO_INLINE_VALUE_RE = /\b(location|country|region|state|province|city|timezone|time zone|postal code|zip code|postcode|coordinates?|latitude|longitude|lat|lon|lng|hostname|reverse dns|rdns|isp|carrier|asn)\b\s*:\s*([^\n\r|]{2,120})/gi;

const A_SPAN   = 'data-ss-span';
const A_ORIG   = 'data-ss-orig';
const A_TYPE   = 'data-ss-type';
const A_MASKED = 'data-ss-masked';
const A_HIDDEN = 'data-ss-hidden';
const A_APFX   = 'data-ss-a-';
const A_GEO    = 'data-ss-geo';
const A_GEO_KIND = 'data-ss-geo-kind';

const TYPE_STYLE = {
  ip:       { bg: 'rgba(251,191,36,0.15)',  border: 'rgba(251,191,36,0.5)',  color: '#d97706' },
  email:    { bg: 'rgba(99,102,241,0.15)',  border: 'rgba(99,102,241,0.5)',  color: '#6366f1' },
  phone:    { bg: 'rgba(34,197,94,0.15)',   border: 'rgba(34,197,94,0.5)',   color: '#16a34a' },
  address:  { bg: 'rgba(239,68,68,0.15)',   border: 'rgba(239,68,68,0.5)',   color: '#dc2626' },
  useragent:{ bg: 'rgba(168,85,247,0.15)',  border: 'rgba(168,85,247,0.5)',  color: '#9333ea' },
  geo:      { bg: 'rgba(20,184,166,0.15)',  border: 'rgba(20,184,166,0.5)',  color: '#0d9488' },
};


let cfg = {
  streamerMode:        false,
  emailProtection:     true,
  ipProtection:        true,
  phoneProtection:     true,
  addressProtection:   true,
  geoProtection:       true,
  userAgentProtection: true,
  autofillProtection:  true,
  popupProtection:     true,
  whitelist:           [],
};

let processedNodes = new WeakSet();
let domObserver    = null;
let inputObserver  = null;
let rescanTimer    = null;
let flushTimer     = null;
let pendingNodes   = new Set();
let panicActive    = false;
let screenshotMode = false;
let selectMode     = false;
let initialized    = false;
let settingsLoaded = false;


function applyPreBlock() {
  if (document.body) {
    document.body.classList.add('ss-loading');
  } else {
    const observer = new MutationObserver(() => {
      if (document.body) {
        document.body.classList.add('ss-loading');
        observer.disconnect();
      }
    });
    if (document.documentElement) {
      observer.observe(document.documentElement, { childList: true });
    }
  }
}


(function init() {
  if (initialized) return;
  initialized = true;

  chrome.storage.local.get(null, (stored) => {
    settingsLoaded = true;
    if (stored) cfg = { ...cfg, ...stored };
    
    const whitelisted = isWhitelisted();
    const shouldActivate = cfg.streamerMode && !whitelisted;

    if (shouldActivate) {
      applyPreBlock();
      activateSync();
    } else {
      unblockBody();
    }
  });

  setTimeout(() => {
    if (!settingsLoaded) {
      console.warn('[StreamShield] Settings load timeout, unblocking body');
      unblockBody();
    }
  }, 100);

  chrome.runtime.onMessage.addListener(onMessage);
})();


function isWhitelisted() {
  const host = location.hostname;
  return (cfg.whitelist || []).some(d => host === d || host.endsWith('.' + d));
}


function onMessage(msg, _sender, reply) {
  switch (msg.type) {
    case 'SETTINGS_UPDATED': {
      const wasOn = cfg.streamerMode;
      cfg = { ...cfg, ...msg.settings };
      
      const whitelisted = isWhitelisted();
      const shouldBeActive = cfg.streamerMode && !whitelisted;

      if (shouldBeActive && !wasOn) {
        applyPreBlock();
        activateSync();
      } else if (!shouldBeActive && wasOn) {
        deactivate();
      } else if (shouldBeActive) {
        restoreAll();
        activateSync();
        if (!cfg.userAgentProtection) restoreUserAgentMasks();
      } else {
        deactivate();
      }
      break;
    }
    case 'PANIC_BLUR':       applyPanic(msg.active);        break;
    case 'SCREENSHOT_MODE':  applyScreenshotMode(msg.active); break;
    case 'SELECT_MODE':      setSelectMode(msg.active);     break;
    case 'WHITELIST_UPDATED':
      cfg.whitelist = msg.whitelist || [];
      if (isWhitelisted()) {
        deactivate();
      } else if (cfg.streamerMode) {
        restoreAll();
        activateSync();
      }
      break;
  }
  reply({ ok: true });
  return true;
}


function activateSync() {
  ensureStyles();
  
  if (document.body) {
    performQuickScan();
  }
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => performInitialScan(), { once: true });
  } else {
    performInitialScan();
  }

  startDomObserver();
  startPeriodicRescan();
  if (cfg.autofillProtection) setupInputs();
}

function performQuickScan() {
  scanTextNodesSync(document.body);
  scanAllAttributesSync(document.body);
  scanGeoTablesSync(document.body);
  scanGeoValueElementsSync(document.body);
  scanPopupModalsSync(document.body);
}

function performInitialScan() {
  if (document.body) {
    scanTextNodesSync(document.body);
    scanAllAttributesSync(document.body);
    scanGeoTablesSync(document.body);
    scanGeoValueElementsSync(document.body);
    scanPopupModalsSync(document.body);
  }
  
  requestAnimationFrame(() => {
    unblockBody();
  });
}

function unblockBody() {
  if (document.body) {
    document.body.classList.remove('ss-loading');
    document.body.classList.add('ss-ready');
  }
}

function deactivate() {
  stopDomObserver();
  stopPeriodicRescan();
  stopInputObserver();
  restoreAll();
  removeInputOverlays();
  if (panicActive) applyPanic(false);
  if (screenshotMode) applyScreenshotMode(false);
  if (selectMode) setSelectMode(false);
  unblockBody();
}


function applyPanic(on) {
  panicActive = on;
  document.body.style.filter        = on ? 'blur(10px)' : '';
  document.body.style.transition    = on ? 'filter 0.2s ease' : '';
  document.body.style.pointerEvents = on ? 'none' : '';
}


function applyScreenshotMode(on) {
  screenshotMode = on;
  let overlay = document.getElementById('ss-screenshot-overlay');
  if (on) {
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'ss-screenshot-overlay';
      const label = document.createElement('div');
      label.style.cssText = 'color:#8b5cf6;font-size:24px;font-family:monospace;font-weight:700;letter-spacing:4px;opacity:0.8;';
      label.textContent = 'STREAMSHIELD PROTECTED';
      overlay.appendChild(label);
      document.body.appendChild(overlay);
    }
  } else {
    overlay?.remove();
  }
}


function setSelectMode(on) {
  selectMode = on;
  document.body.style.cursor = on ? 'crosshair' : '';
  if (on) {
    document.addEventListener('click', onSelectClick, true);
    document.addEventListener('keydown', onSelectKey, true);
    showSelectHint(true);
  } else {
    document.removeEventListener('click', onSelectClick, true);
    document.removeEventListener('keydown', onSelectKey, true);
    document.body.style.cursor = '';
    showSelectHint(false);
  }
}

function showSelectHint(on) {
  let hint = document.getElementById('ss-select-hint');
  if (on) {
    if (!hint) {
      hint = document.createElement('div');
      hint.id = 'ss-select-hint';
      hint.textContent = 'Click any element to hide - ESC to cancel';
      document.body.appendChild(hint);
    }
  } else {
    hint?.remove();
  }
}

function onSelectClick(e) {
  e.preventDefault();
  e.stopPropagation();
  const el = e.target;
  if (!el || el === document.body || el === document.documentElement) return;
  if (el.id === 'ss-select-hint') return;
  if (el.hasAttribute(A_HIDDEN)) {
    el.style.filter = el.getAttribute(A_HIDDEN) || '';
    el.removeAttribute(A_HIDDEN);
  } else {
    el.setAttribute(A_HIDDEN, el.style.filter || '');
    el.style.filter = 'blur(8px)';
  }
  setSelectMode(false);
}

function onSelectKey(e) {
  if (e.key === 'Escape') setSelectMode(false);
}


function isWhitelistedPattern(text) {
  return Object.values(WHITELIST_PATTERNS).some(pattern => {
    pattern.lastIndex = 0; // Reset regex
    return pattern.test(text);
  });
}


function scanTextNodesSync(root) {
  if (!root || panicActive) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const p = node.parentElement;
      if (!p) return NodeFilter.FILTER_REJECT;
      
      if (SKIP_TAGS.has(p.tagName)) return NodeFilter.FILTER_REJECT;
      
      if (p.tagName === 'INPUT' || p.tagName === 'TEXTAREA') return NodeFilter.FILTER_REJECT;
      
      if (p.isContentEditable) return NodeFilter.FILTER_REJECT;
      
      if (p.getAttribute(A_SPAN) === '1') return NodeFilter.FILTER_REJECT;
      
      
      if (p.tagName === 'BUTTON' || p.tagName === 'A') return NodeFilter.FILTER_REJECT;
      if (p.getAttribute('role') === 'button') return NodeFilter.FILTER_REJECT;
      
      if (p.closest('nav, header, footer, aside, menu')) return NodeFilter.FILTER_REJECT;
      
      const className = p.className || '';
      if (typeof className === 'string') {
        const lower = className.toLowerCase();
        if (lower.includes('btn') || 
            lower.includes('button') || 
            lower.includes('icon') ||
            lower.includes('logo') ||
            lower.includes('menu') ||
            lower.includes('nav')) {
          return NodeFilter.FILTER_REJECT;
        }
      }
      
      const text = node.nodeValue?.trim() || '';
      if (text.length < 7) return NodeFilter.FILTER_REJECT;
      
      if (p.getAttribute('aria-label') && text.length < 20) return NodeFilter.FILTER_REJECT;
      
      return NodeFilter.FILTER_ACCEPT;
    }
  });
  
  const nodes = [];
  let n;
  while ((n = walker.nextNode())) nodes.push(n);
  for (const textNode of nodes) processTextNode(textNode);
}

function processTextNode(textNode) {
  if (processedNodes.has(textNode)) return;
  const text = textNode.nodeValue;
  if (!text || text.trim().length < 3) { 
    processedNodes.add(textNode); 
    return; 
  }

  if (isWhitelistedPattern(text)) {
    processedNodes.add(textNode);
    return;
  }

  const matches = findAllMatches(text);
  if (!matches.length) { 
    processedNodes.add(textNode); 
    return; 
  }

  const frag = document.createDocumentFragment();
  let cursor = 0;
  for (const { start, end, orig, masked, type } of matches) {
    if (start > cursor) frag.appendChild(document.createTextNode(text.slice(cursor, start)));
    frag.appendChild(createMaskedSpan(orig, masked, type));
    cursor = end;
  }
  if (cursor < text.length) frag.appendChild(document.createTextNode(text.slice(cursor)));

  const parent = textNode.parentElement;
  if (parent) {
    parent.replaceChild(frag, textNode);
    parent.setAttribute(A_MASKED, '1');
  }
}


function findAllMatches(text) {
  const all = [];

  if (cfg.ipProtection) {
    const re = new RegExp(RE_IPV4_RAW.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      if (isValidIPv4(m[1], m[2], m[3], m[4])) {
        if (isLikelyIPAddress(text, m.index, m[0])) {
          all.push({ 
            start: m.index, 
            end: m.index + m[0].length, 
            orig: m[0], 
            masked: maskIPv4(m[0]), 
            type: 'ip' 
          });
        }
      }
    }
    
    const re6 = new RegExp(RE_IPV6.source, 'g');
    while ((m = re6.exec(text)) !== null) {
      if (isLikelyIPv6(text, m.index)) {
        all.push({ 
          start: m.index, 
          end: m.index + m[0].length, 
          orig: m[0], 
          masked: maskIPv6(m[0]), 
          type: 'ip' 
        });
      }
    }
  }

  if (cfg.emailProtection) {
    const re = new RegExp(RE_EMAIL.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      if (isLikelyEmail(m[0])) {
        all.push({ 
          start: m.index, 
          end: m.index + m[0].length, 
          orig: m[0], 
          masked: maskEmail(m[0]), 
          type: 'email' 
        });
      }
    }
  }

  if (cfg.phoneProtection) {
    const re = new RegExp(RE_PHONE.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      const digits = m[0].replace(/\D/g, '');
      if (digits.length >= 10 && isLikelyPhone(text, m.index, m[0])) {
        all.push({ 
          start: m.index, 
          end: m.index + m[0].length, 
          orig: m[0], 
          masked: maskPhone(m[0]), 
          type: 'phone' 
        });
      }
    }
  }

  if (cfg.addressProtection) {
    const re = new RegExp(RE_ADDRESS.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      all.push({ 
        start: m.index, 
        end: m.index + m[0].length, 
        orig: m[0], 
        masked: maskAddress(m[0]), 
        type: 'address' 
      });
    }
  }

  if (cfg.userAgentProtection) {
    const re = new RegExp(RE_USERAGENT.source, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length > 20) {
        all.push({ 
          start: m.index, 
          end: m.index + m[0].length, 
          orig: m[0], 
          masked: '[ User-Agent Hidden ]', 
          type: 'useragent' 
        });
      }
    }
  }

  if (cfg.geoProtection) {
    const re = new RegExp(GEO_INLINE_VALUE_RE);
    let m;
    while ((m = re.exec(text)) !== null) {
      const full = m[0];
      const rawValue = m[2];
      const value = rawValue.trim();
      if (!isLikelyGeoValueText(value)) continue;

      const offset = full.lastIndexOf(value);
      if (offset < 0) continue;

      all.push({
        start: m.index + offset,
        end: m.index + offset + value.length,
        orig: value,
        masked: '[ Location Hidden ]',
        type: 'geo'
      });
    }
  }

  all.sort((a, b) => a.start - b.start);
  const clean = [];
  let lastEnd = 0;
  for (const item of all) {
    if (item.start >= lastEnd) { 
      clean.push(item); 
      lastEnd = item.end; 
    }
  }
  return clean;
}


function isLikelyIPAddress(text, index, ip) {
  const before = text.slice(Math.max(0, index - 20), index).toLowerCase();
  const after = text.slice(index + ip.length, index + ip.length + 20).toLowerCase();
  
  const positiveKeywords = ['ip', 'address', 'your', 'my', 'client', 'server', 'host', 'from'];
  const hasPositive = positiveKeywords.some(kw => 
    before.includes(kw) || after.includes(kw)
  );
  
  const negativePatterns = [
    /version/i,
    /\d+\.\d+\.\d+\.\d+\s*(px|em|rem|%)/i,
    /price|cost|amount/i,
  ];
  
  const hasNegative = negativePatterns.some(pattern => 
    pattern.test(before + ip + after)
  );
  
  if (!hasPositive && !hasNegative) {
    const parts = ip.split('.');
    const first = parseInt(parts[0]);
    
    if (first <= 1) return false;
    
    if (first === 127) return false;
  }
  
  return !hasNegative;
}

function isLikelyIPv6(text, index) {
  const before = text.slice(Math.max(0, index - 15), index).toLowerCase();
  const after = text.slice(index, index + 50).toLowerCase();
  
  const keywords = ['ipv6', 'ip', 'address', 'your', 'client'];
  return keywords.some(kw => before.includes(kw) || after.includes(kw));
}

function isLikelyEmail(email) {
  const parts = email.split('@');
  if (parts.length !== 2) return false;
  
  const [local, domain] = parts;
  
  if (local.length < 2) return false;
  if (!domain.includes('.')) return false;
  
  const tld = domain.split('.').pop();
  if (!tld || tld.length < 2 || tld.length > 6) return false;
  
  const excludeTLDs = ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'min', 'js', 'css'];
  if (excludeTLDs.includes(tld.toLowerCase())) return false;
  
  return true;
}

function isLikelyPhone(text, index, phone) {
  const before = text.slice(Math.max(0, index - 20), index).toLowerCase();
  const after = text.slice(index + phone.length, index + phone.length + 20).toLowerCase();
  
  const keywords = ['phone', 'tel', 'call', 'mobile', 'contact', 'number'];
  const hasKeyword = keywords.some(kw => before.includes(kw) || after.includes(kw));
  
  const negativePatterns = [
    /\d{4}-\d{2}-\d{2}/,
    /\d{2}\/\d{2}\/\d{4}/,
    /(version|v)\s*\d/i,
  ];
  
  const hasNegative = negativePatterns.some(pattern => 
    pattern.test(before + phone + after)
  );
  
  return hasKeyword || (!hasNegative && phone.includes('+'));
}


function isValidIPv4(a, b, c, d) {
  return [a, b, c, d].every(o => { 
    const n = parseInt(o, 10); 
    return n >= 0 && n <= 255; 
  });
}


function maskIPv4(ip) {
  const p = ip.split('.');
  return `${p[0]}.***.***.*`;
}

function maskIPv6(ip) {
  const parts = ip.split(':');
  return (parts[0] || '****') + ':****:****:****';
}

function maskEmail(e) {
  const at = e.indexOf('@');
  if (at < 0) return '***@***.***';
  const local = e.slice(0, at), domain = e.slice(at + 1);
  const dot = domain.lastIndexOf('.');
  const dname = dot >= 0 ? domain.slice(0, dot) : domain;
  const tld   = dot >= 0 ? domain.slice(dot) : '';
  const ml = local.length > 1 ? local[0] + '*'.repeat(Math.min(local.length - 1, 4)) : '*';
  const md = dname.length > 1 ? dname[0] + '*'.repeat(Math.min(dname.length - 1, 3)) : '*';
  return `${ml}@${md}${tld}`;
}

function maskPhone(ph) {
  const prefix = ph.match(/^\+\d{1,3}/);
  const digits = ph.replace(/\D/g, '');
  const stars  = '*'.repeat(Math.max(digits.length - (prefix ? prefix[0].replace('+','').length : 0), 4));
  return prefix ? `${prefix[0]} ${stars}` : stars;
}

function maskAddress(addr) {
  const words = addr.split(' ');
  return words[0] + ' *** ' + words[words.length - 1];
}

function createMaskedSpan(orig, masked, type) {
  const style = TYPE_STYLE[type] || TYPE_STYLE.ip;
  const span = document.createElement('span');
  span.setAttribute(A_SPAN, '1');
  span.setAttribute(A_ORIG, orig);
  span.setAttribute(A_TYPE, type);
  span.setAttribute('title', `Warning: ${type.toUpperCase()} hidden by StreamShield`);
  span.textContent = masked;
  span.style.cssText = [
    `background:${style.bg}`,
    `border:1px solid ${style.border}`,
    `color:${style.color}`,
    'border-radius:4px',
    'padding:1px 5px',
    'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
    'font-size:0.88em',
    'font-weight:600',
    'cursor:help',
    'letter-spacing:0.3px',
    'white-space:nowrap',
    'display:inline-block',
    'line-height:1.4',
    'vertical-align:baseline',
    'transition:opacity 0.15s ease',
  ].join(';');

  span.addEventListener('mouseenter', () => { span.style.opacity = '0.75'; });
  span.addEventListener('mouseleave', () => { span.style.opacity = '1'; });

  return span;
}


function scanAllAttributesSync(root) {
  const elements = root.nodeType === Node.ELEMENT_NODE
    ? [root, ...root.querySelectorAll('*')]
    : [...(root.querySelectorAll?.('*') || [])];

  for (const el of elements) {
    if (!el.getAttribute) continue;
    if (SKIP_TAGS.has(el.tagName)) continue;

    for (const attr of SCAN_ATTRS) {
      const val = el.getAttribute(attr);
      if (!val || val.length < 3) continue;
      if (el.hasAttribute(A_APFX + attr)) continue;
      const masked = maskStringAll(val);
      if (masked !== val) { 
        el.setAttribute(A_APFX + attr, val); 
        el.setAttribute(attr, masked); 
      }
    }

    if (cfg.ipProtection) {
      for (const attr of URL_ATTRS) {
        const val = el.getAttribute(attr);
        if (!val || val.length < 7) continue;
        if (el.hasAttribute(A_APFX + attr)) continue;
        const masked = maskIPsInString(val);
        if (masked !== val) { 
          el.setAttribute(A_APFX + attr, val); 
          el.setAttribute(attr, masked); 
        }
      }
    }
  }
}

function maskStringAll(str) {
  let r = str;
  if (cfg.ipProtection) {
    r = r.replace(new RegExp(RE_IPV4_RAW.source, 'g'), (m, a, b, c, d) => 
      isValidIPv4(a,b,c,d) ? maskIPv4(m) : m
    );
    r = r.replace(new RegExp(RE_IPV6.source, 'g'), maskIPv6);
  }
  if (cfg.emailProtection) {
    r = r.replace(new RegExp(RE_EMAIL.source, 'g'), m => 
      isLikelyEmail(m) ? maskEmail(m) : m
    );
  }
  if (cfg.phoneProtection) {
    r = r.replace(new RegExp(RE_PHONE.source, 'g'), m => 
      m.replace(/\D/g,'').length >= 10 ? maskPhone(m) : m
    );
  }
  return r;
}

function maskIPsInString(str) {
  let r = str;
  r = r.replace(new RegExp(RE_IPV4_RAW.source, 'g'), (m, a, b, c, d) => 
    isValidIPv4(a,b,c,d) ? maskIPv4(m) : m
  );
  r = r.replace(new RegExp(RE_IPV6.source, 'g'), maskIPv6);
  return r;
}


function scanGeoTablesSync(root) {
  if (!root || panicActive || !cfg.geoProtection) return;

  const rows = root.querySelectorAll ? root.querySelectorAll('tr') : [];
  for (const row of rows) {
    const cells = row.querySelectorAll('td, th');
    if (cells.length < 2) continue;
    const kind = getGeoLabelKind(cells[0].textContent);
    if (shouldMaskGeoKind(kind) && !cells[1].hasAttribute(A_GEO)) {
      maskGeoCell(cells[1], kind);
    }
  }

  const dts = root.querySelectorAll ? root.querySelectorAll('dt') : [];
  for (const dt of dts) {
    const dd = dt.nextElementSibling;
    const kind = getGeoLabelKind(dt.textContent);
    if (dd && dd.tagName === 'DD' && shouldMaskGeoKind(kind) && !dd.hasAttribute(A_GEO)) {
      maskGeoCell(dd, kind);
    }
  }

  const allEls = root.querySelectorAll ? root.querySelectorAll('*') : [];
  for (const el of allEls) {
    if (SKIP_TAGS.has(el.tagName)) continue;
    if (el.children.length > 0) continue;
    const text = el.textContent.trim();
    const kind = getGeoLabelKind(text);
    if (!text || text.length > 60 || !shouldMaskGeoKind(kind)) continue;
    const next = el.nextElementSibling;
    if (next && !next.hasAttribute(A_GEO) && next.children.length === 0) {
      const ntext = next.textContent.trim();
      if (ntext && ntext.length > 0 && ntext.length < 150) maskGeoCell(next, kind);
    }
  }
}

function scanGeoValueElementsSync(root) {
  if (!root || panicActive || !cfg.geoProtection || !root.querySelectorAll) return;

  const candidates = new Set();
  for (const selector of GEO_VALUE_SELECTORS) {
    root.querySelectorAll(selector).forEach(el => candidates.add(el));
  }

  if (root.nodeType === Node.ELEMENT_NODE) {
    candidates.add(root);
  }

  for (const el of candidates) {
    const target = findGeoValueTarget(el);
    if (!target) continue;
    maskGeoCell(target, 'geo');
  }
}

function isStrongGeoCandidate(el) {
  if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;
  if (el.hasAttribute(A_GEO) || el.hasAttribute('data-ss-allowed')) return false;
  if (SKIP_TAGS.has(el.tagName)) return false;

  const tag = el.tagName;
  if (['BUTTON', 'A', 'NAV', 'HEADER', 'FOOTER', 'ASIDE', 'MENU', 'INPUT', 'TEXTAREA', 'SELECT', 'OPTION', 'LABEL'].includes(tag)) return false;
  if (el.isContentEditable) return false;
  if ((el.getAttribute('role') || '').toLowerCase() === 'button') return false;
  if (el.querySelector('button, a, input, textarea, select, nav, header, footer')) return false;

  const text = (el.textContent || '').trim();
  if (!text || text.length < 2 || text.length > 180) return false;
  if (isLabelOnlyGeoText(text)) return false;

  const marker = [
    el.id || '',
    el.className || '',
    el.getAttribute('data-testid') || '',
    el.getAttribute('data-field') || '',
    el.getAttribute('data-label') || '',
    el.getAttribute('aria-label') || '',
  ].join(' ').toLowerCase();

  const hasMarker = /\b(geo|location|country|region|state|province|city|timezone|postal|postcode|zipcode|zip|coord|coordinate|latitude|longitude|hostname|reverse|rdns|isp|carrier|asn)\b/.test(marker);
  const hasInlineLabel = GEO_INLINE_RE.test(text);
  const isLeafish = el.children.length === 0 || el.children.length <= 2;

  return isLeafish && hasMarker && !hasInlineLabel;
}

function findGeoValueTarget(el) {
  if (!el || el.nodeType !== Node.ELEMENT_NODE) return null;
  if (isStrongGeoCandidate(el)) return el;

  const ownText = (el.textContent || '').trim();
  if (isLabelOnlyGeoText(ownText)) {
    const next = el.nextElementSibling;
    if (isStrongGeoCandidate(next)) return next;
  }

  const children = el.children ? [...el.children] : [];
  for (const child of children) {
    if (isStrongGeoCandidate(child)) return child;
  }

  const descendants = el.querySelectorAll ? [...el.querySelectorAll('*')] : [];
  for (const node of descendants) {
    if (isStrongGeoCandidate(node)) return node;
  }

  return null;
}

function isLabelOnlyGeoText(text) {
  if (!text) return false;
  const normalized = text.trim().replace(/\s+/g, ' ').toLowerCase();
  return /^(?:my|your|our|the|ip|address|ip address|client|server|host|details|info|data|\s|-)*\b(location|country|region|state|province|city|timezone|time zone|postal code|zip code|postcode|coordinates?|latitude|longitude|lat|lon|lng|hostname|reverse dns|rdns|isp|carrier|asn)\b\s*:?\s*$/.test(normalized);
}

function isLikelyGeoValueText(text) {
  if (!text) return false;
  const value = text.trim();
  if (value.length < 2 || value.length > 120) return false;
  if (isLabelOnlyGeoText(value)) return false;
  if (/^(loading|unknown|n\/a|none|null|undefined)$/i.test(value)) return false;
  return /[a-z0-9]/i.test(value);
}

function getGeoLabelKind(text) {
  if (!text) return '';
  const n = text.trim().toLowerCase().replace(/[:\-()\s]+/g, ' ').trim();
  if (USERAGENT_LABELS.has(n)) return 'useragent';
  if (GEO_LABELS.has(n)) return 'geo';
  return '';
}

function shouldMaskGeoKind(kind) {
  if (kind === 'useragent') return cfg.userAgentProtection;
  if (kind === 'geo') return cfg.geoProtection;
  return false;
}

function isGeoLabel(text) {
  return shouldMaskGeoKind(getGeoLabelKind(text));
}

function maskGeoCell(el, kind = 'geo') {
  if (el.hasAttribute(A_GEO)) return;
  el.setAttribute(A_GEO, el.textContent || '');
  el.setAttribute(A_GEO_KIND, kind);
  const origHTML = el.innerHTML;
  el.setAttribute('data-ss-geo-html', origHTML);
  while (el.firstChild) el.removeChild(el.firstChild);

  const pill = document.createElement('span');
  const style = TYPE_STYLE.geo;
  pill.setAttribute('data-ss-geo-pill', '1');
  pill.setAttribute('title', 'Warning: Location data hidden by StreamShield');
  pill.textContent = 'LOCATION HIDDEN';
  pill.style.cssText = [
    `background:${style.bg}`,
    `border:1px solid ${style.border}`,
    `color:${style.color}`,
    'border-radius:4px',
    'padding:2px 8px',
    'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
    'font-size:0.85em',
    'font-weight:700',
    'cursor:help',
    'letter-spacing:0.5px',
    'display:inline-block',
  ].join(';');
  el.appendChild(pill);
}


function scanPopupModalsSync(root) {
  if (!root || panicActive || !cfg.popupProtection) return;

  const candidates = new Set();

  if (root.nodeType === Node.ELEMENT_NODE && isPopupModalElement(root)) {
    candidates.add(root);
  }

  if (root.querySelectorAll) {
    for (const selector of POPUP_SELECTORS) {
      root.querySelectorAll(selector).forEach(el => candidates.add(el));
    }
  }

  for (const el of candidates) {
    scanTextNodesSync(el);
    scanAllAttributesSync(el);
    scanGeoTablesSync(el);
    scanGeoValueElementsSync(el);
  }
}

function isPopupModalElement(el) {
  if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;
  if (el.tagName === 'DIALOG') return true;

  const role = (el.getAttribute('role') || '').toLowerCase();
  if (role === 'dialog' || role === 'alertdialog') return true;

  if (el.getAttribute('aria-modal') === 'true') return true;
  if (el.hasAttribute('data-modal') || el.hasAttribute('data-popup')) return true;

  const marker = [
    el.id || '',
    el.className || '',
    el.getAttribute('data-state') || '',
    el.getAttribute('data-testid') || '',
  ].join(' ').toLowerCase();

  return ['modal', 'popup', 'popover', 'drawer', 'tooltip', 'dialog', 'sheet'].some(token =>
    marker.includes(token)
  );
}


function restoreAll() {
  document.querySelectorAll(`[${A_SPAN}="1"]`).forEach(span => {
    const orig = span.getAttribute(A_ORIG);
    if (orig) span.replaceWith(document.createTextNode(orig));
  });
  document.querySelectorAll(`[${A_MASKED}]`).forEach(el => el.removeAttribute(A_MASKED));

  document.querySelectorAll('*').forEach(el => {
    if (!el.attributes) return;
    const toRestore = [];
    for (const attr of el.attributes) {
      if (attr.name.startsWith(A_APFX)) {
        toRestore.push({ 
          saved: attr.name, 
          real: attr.name.slice(A_APFX.length), 
          val: attr.value 
        });
      }
    }
    for (const { saved, real, val } of toRestore) { 
      el.setAttribute(real, val); 
      el.removeAttribute(saved); 
    }
  });

  document.querySelectorAll(`[${A_GEO}]`).forEach(el => {
    const origHTML = el.getAttribute('data-ss-geo-html');
    if (origHTML !== null) {
      while (el.firstChild) el.removeChild(el.firstChild);
      el.innerHTML = origHTML;
    }
    el.removeAttribute(A_GEO);
    el.removeAttribute(A_GEO_KIND);
    el.removeAttribute('data-ss-geo-html');
  });

  document.querySelectorAll(`[${A_HIDDEN}]`).forEach(el => {
    el.style.filter = el.getAttribute(A_HIDDEN) || '';
    el.removeAttribute(A_HIDDEN);
  });

  processedNodes = new WeakSet();
}

function restoreGeoElement(el) {
  if (!el || !el.hasAttribute(A_GEO)) return;
  const origHTML = el.getAttribute('data-ss-geo-html');
  if (origHTML !== null) {
    while (el.firstChild) el.removeChild(el.firstChild);
    el.innerHTML = origHTML;
  }
  el.removeAttribute(A_GEO);
  el.removeAttribute(A_GEO_KIND);
  el.removeAttribute('data-ss-geo-html');
}

function restoreUserAgentMasks() {
  document.querySelectorAll(`[${A_SPAN}="1"][${A_TYPE}="useragent"]`).forEach(span => {
    const orig = span.getAttribute(A_ORIG);
    if (orig) span.replaceWith(document.createTextNode(orig));
  });

  document.querySelectorAll(`[${A_GEO_KIND}="useragent"]`).forEach(restoreGeoElement);

  const rows = document.querySelectorAll('tr');
  for (const row of rows) {
    const cells = row.querySelectorAll('td, th');
    if (cells.length >= 2 && getGeoLabelKind(cells[0].textContent) === 'useragent') {
      restoreGeoElement(cells[1]);
    }
  }

  const dts = document.querySelectorAll('dt');
  for (const dt of dts) {
    const dd = dt.nextElementSibling;
    if (dd && dd.tagName === 'DD' && getGeoLabelKind(dt.textContent) === 'useragent') {
      restoreGeoElement(dd);
    }
  }

  const allEls = document.querySelectorAll('*');
  for (const el of allEls) {
    if (el.children.length > 0) continue;
    if (getGeoLabelKind(el.textContent.trim()) !== 'useragent') continue;
    const next = el.nextElementSibling;
    if (next) restoreGeoElement(next);
  }
}


function startDomObserver() {
  if (domObserver) return;
  domObserver = new MutationObserver(mutations => {
    if (!cfg.streamerMode || panicActive) return;
    for (const mut of mutations) {
      if (mut.type === 'childList') {
        mut.addedNodes.forEach(node => {
          if (node.nodeType === Node.ELEMENT_NODE || node.nodeType === Node.TEXT_NODE) {
            if (node.nodeType === Node.ELEMENT_NODE && cfg.popupProtection) {
              scanPopupModalsSync(node);
            }
            pendingNodes.add(node);
            scheduleFlush();
          }
        });
      } else if (mut.type === 'characterData' && mut.target.nodeType === Node.TEXT_NODE) {
        processedNodes = new WeakSet();
        pendingNodes.add(mut.target);
        scheduleFlush();
      }
    }
  });
  domObserver.observe(document.body || document.documentElement, { 
    childList: true, 
    subtree: true, 
    characterData: true 
  });
}

function stopDomObserver() {
  domObserver?.disconnect(); 
  domObserver = null;
  clearTimeout(flushTimer); 
  flushTimer = null;
  pendingNodes.clear();
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    const nodes = [...pendingNodes]; 
    pendingNodes.clear();
    for (const n of nodes) {
      if (n.nodeType === Node.TEXT_NODE) processTextNode(n);
      else if (n.nodeType === Node.ELEMENT_NODE) {
        scanTextNodesSync(n);
        scanAllAttributesSync(n);
        scanGeoTablesSync(n);
        scanGeoValueElementsSync(n);
      }
    }
  }, 20);
}


function startPeriodicRescan() {
  stopPeriodicRescan();
  rescanTimer = setInterval(() => {
    if (!cfg.streamerMode || panicActive) return;
    processedNodes = new WeakSet();
    scanTextNodesSync(document.body);
    scanAllAttributesSync(document.body);
    scanGeoTablesSync(document.body);
    scanGeoValueElementsSync(document.body);
    scanPopupModalsSync(document.body);
  }, 1000);
}

function stopPeriodicRescan() {
  if (rescanTimer) { 
    clearInterval(rescanTimer); 
    rescanTimer = null; 
  }
}


const protectedInputs = new WeakMap();
const inputOverlays   = new WeakMap();

function setupInputs() {
  document.querySelectorAll('input, textarea').forEach(protectInput);
  if (inputObserver) return;
  inputObserver = new MutationObserver(muts => {
    if (!cfg.autofillProtection) return;
    for (const m of muts) {
      m.addedNodes.forEach(n => {
        if (n.nodeType !== Node.ELEMENT_NODE) return;
        if (n.tagName === 'INPUT' || n.tagName === 'TEXTAREA') protectInput(n);
        n.querySelectorAll?.('input, textarea').forEach(protectInput);
      });
    }
  });
  inputObserver.observe(document.body || document.documentElement, { 
    childList: true, 
    subtree: true 
  });
}

function stopInputObserver() { 
  inputObserver?.disconnect(); 
  inputObserver = null; 
}

function protectInput(inp) {
  if (protectedInputs.has(inp)) return;
  if (SKIP_INPUT_TYPES.has((inp.type || '').toLowerCase())) return;
  inp.setAttribute('autocomplete', 'off');
  const onFocus = () => showInputWarning(inp);
  const onBlur  = () => hideInputWarning(inp);
  const onInput = () => { 
    if (cfg.streamerMode && cfg.autofillProtection) showInputWarning(inp); 
  };
  inp.addEventListener('focus', onFocus);
  inp.addEventListener('blur', onBlur);
  inp.addEventListener('input', onInput);
  inp.addEventListener('change', onInput);
  protectedInputs.set(inp, { onFocus, onBlur, onInput });
}

function showInputWarning(inp) {
  if (!cfg.streamerMode || !cfg.autofillProtection || inputOverlays.has(inp)) return;
  const warn = document.createElement('div');
  warn.setAttribute('data-ss-overlay', '1');
  warn.textContent = 'Warning: Sensitive input visible on stream';
  positionWarn(warn, inp);
  document.body.appendChild(warn);
  inputOverlays.set(inp, warn);
  const repos = () => positionWarn(warn, inp);
  window.addEventListener('scroll', repos, { passive: true });
  window.addEventListener('resize', repos, { passive: true });
  warn._repos = repos;
}

function hideInputWarning(inp) {
  const warn = inputOverlays.get(inp);
  if (!warn) return;
  if (warn._repos) {
    window.removeEventListener('scroll', warn._repos);
    window.removeEventListener('resize', warn._repos);
  }
  warn.remove();
  inputOverlays.delete(inp);
}

function positionWarn(warn, inp) {
  const r = inp.getBoundingClientRect();
  warn.style.left = `${Math.max(0, r.left)}px`;
  warn.style.top  = `${Math.max(0, r.top - 36)}px`;
}

function removeInputOverlays() {
  document.querySelectorAll('[data-ss-overlay="1"]').forEach(el => el.remove());
}


function ensureStyles() {
  if (document.getElementById('ss-style')) return;
  const s = document.createElement('style');
  s.id = 'ss-style';
  s.textContent = `
    [data-ss-span="1"]:hover { opacity: 0.7 !important; }
  `;
  (document.head || document.documentElement).appendChild(s);
}
