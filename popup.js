const keyInput   = document.getElementById("groqKey");
const saveBtn    = document.getElementById("saveBtn");
const clearBtn   = document.getElementById("clearBtn");
const savedMsg   = document.getElementById("savedMsg");
const statusEl   = document.getElementById("status");
const statusText = document.getElementById("status-text");
const enabledToggle = document.getElementById("enabledToggle");
const toggleCopy = document.getElementById("toggleCopy");

chrome.storage.local.get(["groqKey", "scannerEnabled"], ({ groqKey, scannerEnabled }) => {
  if (groqKey) {
    keyInput.value = groqKey;
  }

  const enabled = typeof scannerEnabled === "boolean" ? scannerEnabled : Boolean(groqKey);
  enabledToggle.checked = enabled;
  syncUi({ hasKey: Boolean(groqKey), enabled });
});

saveBtn.addEventListener("click", () => {
  const key = keyInput.value.trim();
  if (!key || !key.startsWith("gsk_")) {
    savedMsg.textContent = "Invalid key format. Groq keys should start with gsk_.";
    savedMsg.style.color = "#ff7c89";
    return;
  }
  chrome.storage.local.set({ groqKey: key, scannerEnabled: true }, () => {
    enabledToggle.checked = true;
    savedMsg.textContent = "Scanner armed. Open a Gmail message to begin.";
    savedMsg.style.color = "#7affc7";
    syncUi({ hasKey: true, enabled: true });
    setTimeout(() => (savedMsg.textContent = ""), 3000);
  });
});

clearBtn.addEventListener("click", () => {
  chrome.storage.local.remove("groqKey", () => {
    chrome.storage.local.set({ scannerEnabled: false }, () => {
      keyInput.value = "";
      enabledToggle.checked = false;
      savedMsg.textContent = "Saved key removed. Protection is now off.";
      savedMsg.style.color = "#ffbf6b";
      syncUi({ hasKey: false, enabled: false });
      setTimeout(() => (savedMsg.textContent = ""), 2500);
    });
  });
});

enabledToggle.addEventListener("change", () => {
  const hasKey = Boolean(keyInput.value.trim());
  const enabled = enabledToggle.checked;

  if (enabled && !hasKey) {
    enabledToggle.checked = false;
    savedMsg.textContent = "Add a Groq API key before enabling protection.";
    savedMsg.style.color = "#ffbf6b";
    syncUi({ hasKey: false, enabled: false });
    return;
  }

  chrome.storage.local.set({ scannerEnabled: enabled }, () => {
    savedMsg.textContent = enabled ? "Protection enabled." : "Protection paused.";
    savedMsg.style.color = enabled ? "#7affc7" : "#ffbf6b";
    syncUi({ hasKey, enabled });
    setTimeout(() => (savedMsg.textContent = ""), 2500);
  });
});

function syncUi({ hasKey, enabled }) {
  const active = hasKey && enabled;
  statusEl.className = "status-panel " + (active ? "active" : "inactive");

  if (!hasKey) {
    statusText.textContent = "Offline. Add your Groq API key to arm protection.";
    toggleCopy.textContent = "Turn on scanning when you want PhishGuard watching Gmail.";
    return;
  }

  statusText.textContent = active
    ? "Online. Gmail email analysis is active with your Groq AI key."
    : "Paused. Your key is saved, but Gmail scanning is turned off.";

  toggleCopy.textContent = active
    ? "Live monitoring is enabled for opened Gmail messages."
    : "Flip the switch back on anytime to resume email analysis.";
}
