import { calculateFallbackScore, extractFeatures } from './heuristics.js';

const dbPromise = new Promise((resolve) => {
    const request = indexedDB.open("DNSentinelDB", 1);
    request.onupgradeneeded = (e) => {
        const database = e.target.result;
        if (!database.objectStoreNames.contains("dns_events")) {
            database.createObjectStore("dns_events", { keyPath: "id", autoIncrement: true });
        }
        if (!database.objectStoreNames.contains("risk_profiles")) {
            database.createObjectStore("risk_profiles", { keyPath: "domain" });
        }
        if (!database.objectStoreNames.contains("soar_actions")) {
            database.createObjectStore("soar_actions", { keyPath: "id", autoIncrement: true });
        }
    };
    request.onsuccess = (e) => {
        resolve(e.target.result);
    };
    request.onerror = () => {
        resolve(null);
    };
});

// Load whitelisted domains from storage on startup
let whitelistedDomains = new Set();
chrome.storage.local.get("whitelistedDomains", (result) => {
    if (result.whitelistedDomains) {
        whitelistedDomains = new Set(result.whitelistedDomains);
        console.log("Loaded whitelisted domains:", Array.from(whitelistedDomains));
    }
});

chrome.alarms.create("cleanup", { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
    const database = await dbPromise;
    if (alarm.name === "cleanup" && database) {
        const tx = database.transaction("dns_events", "readwrite");
        const store = tx.objectStore("dns_events");
        const cutoff = Date.now() - (24 * 60 * 60 * 1000);

        const request = store.openCursor();
        request.onsuccess = (e) => {
            const cursor = e.target.result;
            if (cursor) {
                if (cursor.value.timestamp < cutoff) cursor.delete();
                cursor.continue();
            }
        };
    } else if (alarm.name.startsWith("unblock_")) {
        const ruleId1Str = alarm.name.replace("unblock_", "");
        const ruleId1 = parseInt(ruleId1Str, 10);
        const ruleId2 = ruleId1 + 1;
        try {
            chrome.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: [ruleId1, ruleId2]
            });
            console.log(`[Auto-Unblock] Removed RuleIDs: ${ruleId1}, ${ruleId2}`);
        } catch (e) {
            console.error(`Auto-unblock failed for rules ${ruleId1}, ${ruleId2}:`, e);
        }
    }
});

const recentDomains = new Set();
const pendingToasts = new Map(); // tabId -> event

// Helper: Generate deterministic rule IDs from domain name (must be 1-1,000,000)
function generateRuleId(domain, suffix = 0) {
    let hash = 0;
    for (let i = 0; i < domain.length; i++) {
        const char = domain.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
    }
    // Ensure ID is within valid range (1-1,000,000)
    const baseId = (Math.abs(hash) % 500000) + 1; // 1-500000
    return baseId + suffix; // 0-999999 range
}

chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        const url = new URL(details.url);
        const domain = url.hostname;

        // CLEANUP: Ignore internal chrome pages and the extension's own ID noise
        if (!url.protocol.startsWith('http')) return;
        if (domain === chrome.runtime.id) return;

        // Only analyze main_frame navigations (the actual websites the user visits)
        if (details.type === "main_frame" && !recentDomains.has(domain) && !whitelistedDomains.has(domain)) {
            recentDomains.add(domain);
            setTimeout(() => recentDomains.delete(domain), 60000); // 1 min cache
            processDomainAsync(domain, details);
        }
    },
    { urls: ["<all_urls>"] },
    []
);

// Backup listener using tabs API to ensure 100% coverage of cache hits, typed URLs, and redirects
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        try {
            const url = new URL(changeInfo.url);
            const domain = url.hostname;

            if (!url.protocol.startsWith('http')) return;
            if (domain === chrome.runtime.id) return;

            if (!recentDomains.has(domain) && !whitelistedDomains.has(domain)) {
                recentDomains.add(domain);
                setTimeout(() => recentDomains.delete(domain), 30000); // 30s de-duplication

                processDomainAsync(domain, {
                    url: changeInfo.url,
                    tabId: tabId,
                    type: "main_frame"
                });
            }
            updateBadgeForTab(tabId);
        } catch (e) {
            console.error("[Tabs Listener] Error:", e);
        }
    }
});

// Listen for Block/Allow button clicks on threat notifications
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (notificationId.startsWith("threat_")) {
        const domain = notificationId.replace("threat_", "");
        if (buttonIndex === 0) { // Block
            blockDomain(domain); // Use the standard blockDomain function
            chrome.notifications.create({
                type: "basic",
                iconUrl: chrome.runtime.getURL("icons/icon48.png"),
                title: "Domain Blocked",
                message: `DNSentinel has successfully blocked ${domain}.`
            });
        }
        chrome.notifications.clear(notificationId);
    }
});

let GROQ_API_KEY = ""; // Set via the Extension Settings panel (gear icon in popup)
let BACKEND_API_URL = "http://127.0.0.1:8001"; // Default localhost backend

// Check storage for user overridden settings
chrome.storage.local.get(["GROQ_API_KEY", "BACKEND_API_URL"], (result) => {
    if (result.GROQ_API_KEY) {
        GROQ_API_KEY = result.GROQ_API_KEY;
    }
    if (result.BACKEND_API_URL) {
        BACKEND_API_URL = result.BACKEND_API_URL;
    }
});

// React to live settings changes
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local") {
        if (changes.GROQ_API_KEY) {
            GROQ_API_KEY = changes.GROQ_API_KEY.newValue;
        }
        if (changes.BACKEND_API_URL) {
            BACKEND_API_URL = changes.BACKEND_API_URL.newValue;
        }
    }
});

async function askGroqForScore(domain, features) {
    if (!GROQ_API_KEY) return null;
    try {
        const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${GROQ_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                model: "llama-3.1-8b-instant",
                temperature: 0,
                response_format: { type: "json_object" },
                messages: [{
                    role: "user",
                    content: `Assess whether the domain name "${domain}" looks algorithmically generated or like DNS tunnelling. Return ONLY JSON: {"score": <number 0-100>, "reason": "<one sentence>"}`
                }]
            })
        });
        const data = await response.json();
        const result = JSON.parse(data.choices[0].message.content.trim());
        const llmScore = Math.min(Math.max(Number(result.score) || 0, 0), 100);

        // Optional LLM second opinion, averaged with the same structural terms the
        // local heuristic uses. Deterministic (temperature 0, no added noise).
        const structural = Math.min((features.entropy * 15) + (features.digit_ratio * 40), 100);
        const finalScore = (llmScore * 0.5) + (structural * 0.5);

        return {
            ml_score: finalScore / 100,
            isolation_score: 1,
            final_score: finalScore,
            shap_reason: `[LLM second opinion: ${llmScore}] ${result.reason}`
        };
    } catch (e) {
        return null;
    }
}

async function askBackendForAnalysis(domain) {
    try {
        const response = await fetch(`${BACKEND_API_URL}/analyze`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                query: domain,
                source_ip: "127.0.0.1",
                qtype: "A"
            })
        });
        if (response.ok) {
            return await response.json();
        }
    } catch (e) {
        console.warn("Backend /analyze connection error:", e);
    }
    return null;
}

async function processDomainAsync(domain, details) {
    const features = extractFeatures(domain);
    const eventId = Date.now() + "_" + Math.floor(Math.random() * 1000000);

    // 1. INSTANT LOCAL ASSESSMENT (for immediate notification)
    const localScoreData = calculateFallbackScore(features, domain);
    const instantEvent = {
        id: eventId,
        domain,
        url: details.url,
        tabId: details.tabId,
        timestamp: Date.now(),
        features,
        ml_score: localScoreData.ml_score || 0.5,
        isolation_score: 1,
        final_score: localScoreData.final_score,
        shap_reason: "[Local Engine] Analyzing structural features...",
        tier: determineTier(localScoreData.final_score),
        detailsType: details.type
    };

    // Save locally immediately
    saveEvent(instantEvent);

    // Show the notification IMMEDIATELY
    handleSOAR(instantEvent);
    chrome.runtime.sendMessage({ type: "DNS_EVENT", payload: instantEvent }).catch(() => {});
    if (details.tabId && details.tabId !== -1) {
        updateBadgeForTab(details.tabId);
    }

    // 2. BACKGROUND AI REFINEMENT (Asynchronous)
    (async () => {
        let refinedEvent = null;
        const backendData = await askBackendForAnalysis(domain);

        if (backendData) {
            // Map real backend ML features, risk scores and SHAP explainability
            const rawScore = backendData.risk_score !== undefined ? backendData.risk_score : (backendData.confidence * 100);
            const score = Math.min(Math.max(rawScore, 0), 100);

            refinedEvent = {
                ...instantEvent,
                ml_score: backendData.confidence || instantEvent.ml_score,
                final_score: score,
                features: backendData.features || instantEvent.features,
                shap_reason: backendData.explanation || "[Backend Model] Analysis complete.",
                tier: (backendData.risk_level || determineTier(score)).toUpperCase()
            };
        } else {
            // Fallback to Groq AI if backend is offline
            const aiScoreData = await askGroqForScore(domain, features);
            if (aiScoreData) {
                const refinedScore = aiScoreData.final_score;
                refinedEvent = {
                    ...instantEvent,
                    ml_score: aiScoreData.ml_score,
                    final_score: refinedScore,
                    shap_reason: aiScoreData.shap_reason,
                    tier: determineTier(refinedScore)
                };
            }
        }

        if (refinedEvent) {
            saveEvent(refinedEvent);
            // Update the UI if it's still open
            chrome.runtime.sendMessage({ type: "DNS_EVENT", payload: refinedEvent }).catch(() => {});
            if (details.tabId && details.tabId !== -1) {
                updateBadgeForTab(details.tabId);
            }
        }
    })();
}

function determineTier(score) {
    if (score > 90) return "CRITICAL";
    if (score > 80) return "BLOCK";
    if (score > 60) return "ALERT";
    return "MONITOR";
}

async function saveEvent(event) {
    const database = await dbPromise;
    if (!database) return;
    try {
        const tx = database.transaction("dns_events", "readwrite");
        tx.objectStore("dns_events").put(event);
    } catch (e) {
        console.error("Failed to save event to IndexedDB:", e);
    }
}

function handleSOAR(event) {
    if (event.detailsType === "main_frame" && event.tabId !== -1) {
        // Buffer the toast and try to send it immediately
        pendingToasts.set(event.tabId, event);
        chrome.tabs.sendMessage(event.tabId, { type: "SHOW_TOAST", payload: event }).catch(() => {
            // If it fails, it will be picked up when TAB_READY is received
        });
    } else {
        // Silent automatic SOAR for sub_frame and scripts
        if (event.tier === "BLOCK" || event.tier === "CRITICAL" || event.tier === "HIGH") {
            blockDomain(event.domain);
        }
    }

    if ((event.tier === "CRITICAL" || event.tier === "HIGH") && event.tabId !== -1) {
        chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
        chrome.action.setBadgeText({ text: "!" });
    }
}

function reloadTabsForDomain(domain) {
    chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
            if (tab.url) {
                try {
                    const hostname = new URL(tab.url).hostname;
                    if (hostname === domain || hostname.endsWith("." + domain) || domain.endsWith("." + hostname)) {
                        chrome.tabs.reload(tab.id);
                        console.log(`[Reload] Reloaded tab ${tab.id} for domain ${domain}`);
                    }
                } catch (e) {
                    if (tab.url.includes(domain)) {
                        chrome.tabs.reload(tab.id);
                        console.log(`[Reload Fallback] Reloaded tab ${tab.id} for domain ${domain}`);
                    }
                }
            }
        });
    });
}

function isDomainMatch(d1, d2) {
    if (!d1 || !d2) return false;
    const clean1 = d1.toLowerCase().replace(/^www\./, '');
    const clean2 = d2.toLowerCase().replace(/^www\./, '');
    return clean1 === clean2 || clean1.endsWith('.' + clean2) || clean2.endsWith('.' + clean1);
}

function blockDomain(domain) {
    // Remove from whitelist if present
    if (whitelistedDomains.has(domain)) {
        whitelistedDomains.delete(domain);
        chrome.storage.local.set({ whitelistedDomains: Array.from(whitelistedDomains) });
    }

    // Use deterministic IDs based on domain name (must stay within 1-1,000,000)
    const ruleId1 = generateRuleId(domain, 0);
    const ruleId2 = generateRuleId(domain, 1);

    // Use wildcards/|| for robust blocking across subdomains and paths
    const filter = `||${domain}`;

    try {
        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [ruleId1, ruleId2],
            addRules: [{
                id: ruleId1,
                priority: 1,
                action: { type: "block" },
                condition: {
                    urlFilter: filter,
                    resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "stylesheet", "media", "websocket", "other"]
                }
            }, {
                id: ruleId2,
                priority: 1,
                action: { type: "block" },
                condition: {
                    urlFilter: `*://${domain}/*`,
                    resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "script", "image"]
                }
            }]
        });
        console.log(`[Block] Domain: ${domain}, RuleIDs: ${ruleId1}, ${ruleId2}`);
    } catch (e) {
        console.error(`Failed to block ${domain}:`, e);
    }

    // Update event tier in IndexedDB
    dbPromise.then((database) => {
        if (!database) return;
        try {
            const tx = database.transaction("dns_events", "readwrite");
            const store = tx.objectStore("dns_events");
            const request = store.openCursor();
            request.onsuccess = (e) => {
                const cursor = e.target.result;
                if (cursor) {
                    if (isDomainMatch(cursor.value.domain, domain)) {
                        const updated = { ...cursor.value, tier: "BLOCK" };
                        cursor.update(updated);
                        chrome.runtime.sendMessage({ type: "DNS_EVENT", payload: updated }).catch(() => {});
                    }
                    cursor.continue();
                }
            };
        } catch (err) {
            console.error("Failed to update database on block:", err);
        }
    });

    // Reload tabs immediately to enforce block
    reloadTabsForDomain(domain);

    chrome.alarms.create(`unblock_${ruleId1}`, { delayInMinutes: 60 });
}

function allowDomain(domain) {
    // Add to whitelist
    whitelistedDomains.add(domain);

    // Save whitelist to persistent storage
    chrome.storage.local.set({ whitelistedDomains: Array.from(whitelistedDomains) });
    console.log(`[Allow] Added ${domain} to whitelist`);

    // Get the same deterministic IDs that were used to block
    const ruleId1 = generateRuleId(domain, 0);
    const ruleId2 = generateRuleId(domain, 1);

    // Remove block rules using the same deterministic IDs
    try {
        chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [ruleId1, ruleId2]
        });
        console.log(`[Allow] Domain: ${domain}, Removed RuleIDs: ${ruleId1}, ${ruleId2}`);
    } catch (e) {
        console.error(`Failed to remove rules for ${domain}:`, e);
    }

    // Remove from recentDomains so it can be re-analyzed if visited again
    recentDomains.delete(domain);

    // Update event tier in IndexedDB
    dbPromise.then((database) => {
        if (!database) return;
        try {
            const tx = database.transaction("dns_events", "readwrite");
            const store = tx.objectStore("dns_events");
            const request = store.openCursor();
            request.onsuccess = (e) => {
                const cursor = e.target.result;
                if (cursor) {
                    if (isDomainMatch(cursor.value.domain, domain)) {
                        const updated = { ...cursor.value, tier: "MONITOR" };
                        cursor.update(updated);
                        chrome.runtime.sendMessage({ type: "DNS_EVENT", payload: updated }).catch(() => {});
                    }
                    cursor.continue();
                }
            };
        } catch (err) {
            console.error("Failed to update database on allow:", err);
        }
    });

    // Reload tabs immediately to allow page to load
    reloadTabsForDomain(domain);
}

// Handle messages from content script and popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "BLOCK_DOMAIN") {
        blockDomain(msg.domain);
        sendResponse({ status: "blocked", domain: msg.domain });
    } else if (msg.type === "ALLOW_DOMAIN") {
        allowDomain(msg.domain);
        sendResponse({ status: "allowed", domain: msg.domain });
    } else if (msg.type === "ANALYZE_DOMAIN") {
        processDomainAsync(msg.domain, {
            url: msg.url || `https://${msg.domain}/`,
            tabId: msg.tabId || -1,
            type: "main_frame"
        });
        sendResponse({ status: "analyzing", domain: msg.domain });
    } else if (msg.type === "TAB_READY" && sender.tab) {
        const tabId = sender.tab.id;
        if (pendingToasts.has(tabId)) {
            const event = pendingToasts.get(tabId);
            chrome.tabs.sendMessage(tabId, { type: "SHOW_TOAST", payload: event }).catch(() => {});
            pendingToasts.delete(tabId);
        }
    }
});

// Dynamic Icon Badge Updater based on Active Tab domain safety
function updateBadgeForTab(tabId) {
    chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab || !tab.url) return;
        try {
            const url = new URL(tab.url);
            if (!url.protocol.startsWith('http')) {
                chrome.action.setBadgeText({ text: "", tabId });
                return;
            }
            const domain = url.hostname;

            dbPromise.then((database) => {
                if (!database) return;
                const tx = database.transaction("dns_events", "readonly");
                const store = tx.objectStore("dns_events");
                const request = store.getAll();
                request.onsuccess = () => {
                    const all = request.result || [];
                    const ev = all
                        .filter(e => isDomainMatch(e.domain, domain))
                        .sort((a, b) => b.timestamp - a.timestamp)[0];

                    if (ev) {
                        if (['CRITICAL', 'BLOCK', 'HIGH'].includes(ev.tier)) {
                            chrome.action.setBadgeText({ text: "!", tabId });
                            chrome.action.setBadgeBackgroundColor({ color: "#ef4444", tabId });
                        } else if (['ALERT', 'MEDIUM'].includes(ev.tier)) {
                            chrome.action.setBadgeText({ text: "!", tabId });
                            chrome.action.setBadgeBackgroundColor({ color: "#f97316", tabId });
                        } else {
                            chrome.action.setBadgeText({ text: "", tabId });
                            chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId });
                        }
                    } else {
                        chrome.action.setBadgeText({ text: "", tabId });
                    }
                };
            });
        } catch (e) {
            chrome.action.setBadgeText({ text: "", tabId });
        }
    });
}

// Listen for tab switching
chrome.tabs.onActivated.addListener((activeInfo) => {
    updateBadgeForTab(activeInfo.tabId);
});
