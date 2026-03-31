// content.js — PhishGuard
// This file runs inside Gmail as a content script.
// It checks opened emails, sends email data to Groq AI,
// and shows a banner telling the user whether the email looks safe or dangerous.

// Unique ID for the banner shown above the email
const BANNER_ID = "phishguard-banner";
const MAX_BODY_CHARS = 1200;
const FETCH_TIMEOUT_MS = 15000;

// Custom attribute used to mark emails that were already checked
const ANALYZED_ATTR = "data-phishguard-analyzed";

// Save the last email key to avoid analyzing the same email again
let lastEmailKey = null;

// Prevent multiple API requests from running at the same time
let isAnalyzing = false;

// Track whether scanning is enabled from the popup
let scannerEnabled = true;
let activeController = null;

/**
 * Start watching Gmail for page changes.
 * Gmail loads emails dynamically, so we use MutationObserver.
 */
function watchGmail() {
  // Run tryAnalyzeCurrentEmail whenever Gmail DOM changes
  const observer = new MutationObserver(() => tryAnalyzeCurrentEmail());

  // Watch the whole page for added/changed content
  observer.observe(document.body, { childList: true, subtree: true });

  // Also try once immediately when script loads
  tryAnalyzeCurrentEmail();
}

chrome.storage.local.get(["groqKey", "scannerEnabled"], ({ groqKey, scannerEnabled: storedEnabled }) => {
  scannerEnabled = typeof storedEnabled === "boolean" ? storedEnabled : Boolean(groqKey);

  if (!scannerEnabled) {
    removeBanner();
    return;
  }

  resetAnalyzedState();
  tryAnalyzeCurrentEmail();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;

  if (changes.scannerEnabled) {
    scannerEnabled = Boolean(changes.scannerEnabled.newValue);

    if (!scannerEnabled) {
      removeBanner();
      isAnalyzing = false;
      activeController?.abort();
      return;
    }

    resetAnalyzedState();
    tryAnalyzeCurrentEmail();
  }

  if (changes.groqKey && !changes.groqKey.newValue) {
    scannerEnabled = false;
    removeBanner();
    isAnalyzing = false;
    activeController?.abort();
    resetAnalyzedState();
  }
});

/**
 * Find current email(s) on screen and analyze them.
 */
async function tryAnalyzeCurrentEmail() {
  // Stop if an analysis is already in progress
  if (isAnalyzing) return; // don't stack up multiple calls at once
  if (!scannerEnabled) return;

  const { groqKey } = await chrome.storage.local.get("groqKey");
  if (!groqKey) return;

  // Find email body elements that have not been analyzed yet
  const emailContainers = document.querySelectorAll('.a3s.aiL:not([' + ANALYZED_ATTR + '])');

  emailContainers.forEach((container) => {
    // Mark this email body as analyzed so it is not checked again
    container.setAttribute(ANALYZED_ATTR, "true");

    // Extract sender, email, subject, and body text
    const emailData = extractEmailData(container);

    // Stop if no valid email data was found
    if (!emailData) return;

    // Create a simple unique key using sender email and subject
    const key = emailData.senderEmail + "|" + emailData.subject;

    // Skip if this same email was already analyzed
    if (key === lastEmailKey) return;

    // Save this email as the last analyzed one
    lastEmailKey = key;

    // Show loading banner before sending to AI
    injectLoadingBanner(container);

    // Send email to AI for phishing analysis
    analyzeEmail(emailData, container);
  });
}

/**
 * Extract sender name, sender email, subject, and body text from Gmail.
 */
function extractEmailData(bodyContainer) {
  try {
    // Main Gmail content area
    const root = document.querySelector('[role="main"]') || document;

    // Gmail selectors for sender and subject
    const senderNameEl = root.querySelector(".gD");
    const senderEmailEl = root.querySelector(".go");
    const subjectEl = root.querySelector(".hP");

    // Get sender display name
    const sender =
      senderNameEl?.getAttribute("name") ||
      senderNameEl?.textContent?.trim() ||
      "";

    // Get sender email address
    const senderEmail =
      senderEmailEl?.getAttribute("email") ||
      senderEmailEl?.textContent?.trim() ||
      "";

    // Get subject line
    const subject = subjectEl?.textContent?.trim() || "";

    // Get visible body text only, then limit length to 2000 characters
    // innerText removes HTML formatting and gets readable text
    const body = (bodyContainer?.innerText?.trim() || "").slice(0, MAX_BODY_CHARS);

    // If both body and subject are empty, ignore this email
    if (!body && !subject) return null;

    // Return collected email data
    return { sender, senderEmail, subject, body };
  } catch (e) {
    // If something fails, return null
    return null;
  }
}

/**
 * Send the email to Groq AI and get phishing analysis result.
 */
async function analyzeEmail(emailData, container) {
  // Lock analysis so another email is not processed at the same time
  isAnalyzing = true;

  try {
    // Get Groq API key from Chrome local storage
    // The key is saved by the extension popup/settings
    const { groqKey, scannerEnabled: storedEnabled } = await chrome.storage.local.get(["groqKey", "scannerEnabled"]);
    if (typeof storedEnabled === "boolean") {
      scannerEnabled = storedEnabled;
    }

    if (!scannerEnabled) {
      removeBanner();
      return;
    }

    // Show error if user has not added API key yet
    if (!groqKey) {
      injectErrorBanner(container, "Add your free Groq API key in the PhishGuard popup.");
      return;
    }

    // Prompt sent to the AI model
    // It tells the model how to judge phishing and how to format the output
    const prompt = `You are a cybersecurity expert specializing in phishing detection. Analyze this email carefully.

From: ${emailData.sender} <${emailData.senderEmail}>
Subject: ${emailData.subject}
Body: ${emailData.body}

IMPORTANT RULES:
- Legitimate companies (banks, Discover, Chase, Amex, PayPal, Amazon, Netflix, Google, Apple) DO send real payment reminders and account alerts. If the sender email domain matches the real company domain, treat it as SAFE.
- Only flag PHISHING for clear deception: fake domains, requests for passwords/SSN, suspicious unrelated links, or obvious impersonation.
- Do NOT flag as suspicious just because an email mentions payments, bills, or uses words like "action required" — normal in real billing emails.
- Use SUSPICIOUS only if something feels off but you are not certain. Use PHISHING only when clearly a scam.

You MUST reply ONLY with this exact JSON format, no other text, no markdown:
{"verdict":"SAFE","confidence":90,"reasons":["reason 1","reason 2"],"summary":"One plain sentence for a non-technical user."}`;

    // Send request to Groq OpenAI-compatible API
    const controller = new AbortController();
    activeController = controller;
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        // Tell server we are sending JSON
        "Content-Type": "application/json",

        // Add API key for authorization
        "Authorization": `Bearer ${groqKey}`,
        "Accept": "application/json"
      },
      signal: controller.signal,
      body: JSON.stringify({
        // Model used for phishing analysis
        model: "llama-3.1-8b-instant",

        // Low temperature = more stable and less random answers
        temperature: 0.1,

        // Limit output size
        max_tokens: 300,

        // Ask API to return JSON object
        response_format: { type: "json_object" },

        // User message containing the prompt
        messages: [{ role: "user", content: prompt }]
      })
    });
    clearTimeout(timeoutId);

    if (!scannerEnabled) {
      removeBanner();
      return;
    }

    // If API request failed, show the error in the banner
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      injectErrorBanner(container, err?.error?.message || `Error ${response.status}`);
      return;
    }

    // Parse API response body
    const data = await response.json();

    // Get the returned AI message text
    const text = data?.choices?.[0]?.message?.content || "";

    let result;

    try {
      // First try: parse the AI output directly as JSON
      result = JSON.parse(text);
    } catch {
      // If direct parsing fails, try to find a JSON object inside the text
      const match = text.match(/\{[\s\S]*\}/);

      // Use found JSON, otherwise create a fallback suspicious result
      result = match ? JSON.parse(match[0]) : {
        verdict: "SUSPICIOUS",
        confidence: 60,
        reasons: ["Could not fully parse AI response"],
        summary: text.slice(0, 150)
      };
    }

    // Show the final result banner in Gmail
    injectResultBanner(container, normalizeResult(result));

  } catch (err) {
    // Show generic error if fetch fails or something crashes
    if (!scannerEnabled) return;

    injectErrorBanner(
      container,
      err?.name === "AbortError"
        ? "Analysis timed out. Open the message again to retry."
        : "Check your internet connection and try again."
    );
  } finally {
    // Unlock analysis when done
    activeController = null;
    isAnalyzing = false;
  }
}

/**
 * Show loading banner while AI is checking the email.
 */
function injectLoadingBanner(container) {
  if (!scannerEnabled) return;

  // Remove any old banner first
  removeBanner();

  // Create new banner element
  const banner = document.createElement("div");

  // Set ID and CSS classes
  banner.id = BANNER_ID;
  banner.className = "phishguard-banner phishguard-loading";

  const icon = document.createElement("div");
  icon.className = "pg-icon";
  icon.textContent = "🛡️";

  const content = document.createElement("div");
  content.className = "pg-content";

  const label = document.createElement("span");
  label.className = "pg-label";
  label.textContent = "PhishGuard is analyzing this email...";

  content.appendChild(label);
  banner.appendChild(icon);
  banner.appendChild(content);

  // Insert banner above the email body
  container.parentElement?.insertBefore(banner, container);
}

/**
 * Show result banner after AI finishes analysis.
 */
function injectResultBanner(container, result) {
  // Remove old banner first
  removeBanner();

  // Read values from result, with default values if missing
  const verdict = result.verdict || "SUSPICIOUS";
  const confidence = result.confidence ?? 50;
  const summary = result.summary || "Could not determine email safety.";
  const reasons = result.reasons || [];

  // Settings for each verdict type
  // This controls the color, icon, and label shown in the banner
  const config = {
    SAFE:       { cls: "phishguard-safe",       icon: "✅", label: "Looks Safe",         color: "#16a34a" },
    SUSPICIOUS: { cls: "phishguard-suspicious", icon: "⚠️", label: "Suspicious Email",   color: "#d97706" },
    PHISHING:   { cls: "phishguard-phishing",   icon: "🚨", label: "Phishing Detected!",  color: "#dc2626" },
  }[verdict] || { cls: "phishguard-suspicious", icon: "⚠️", label: "Suspicious", color: "#d97706" };

  // Create banner element
  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.className = `phishguard-banner ${config.cls}`;

  const icon = document.createElement("div");
  icon.className = "pg-icon";
  icon.textContent = config.icon;

  const content = document.createElement("div");
  content.className = "pg-content";

  const top = document.createElement("div");
  top.className = "pg-top";

  const label = document.createElement("span");
  label.className = "pg-label";
  label.textContent = config.label;

  const confidenceEl = document.createElement("span");
  confidenceEl.className = "pg-confidence";
  confidenceEl.style.color = config.color;
  confidenceEl.textContent = `${confidence}% confidence`;

  const toggleButton = document.createElement("button");
  toggleButton.className = "pg-toggle";
  toggleButton.type = "button";
  toggleButton.textContent = "Details";

  const closeButton = document.createElement("button");
  closeButton.className = "pg-close";
  closeButton.type = "button";
  closeButton.textContent = "✕";

  const summaryEl = document.createElement("p");
  summaryEl.className = "pg-summary";
  summaryEl.textContent = summary;

  const details = document.createElement("div");
  details.className = "pg-details pg-hidden";

  if (reasons.length > 0) {
    const reasonsList = document.createElement("ul");
    reasonsList.className = "pg-reasons";

    reasons.forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      reasonsList.appendChild(item);
    });

    details.appendChild(reasonsList);
  }

  toggleButton.addEventListener("click", () => {
    const isHidden = details.classList.toggle("pg-hidden");
    toggleButton.textContent = isHidden ? "Details" : "Hide Details";
  });

  closeButton.addEventListener("click", () => banner.remove());

  top.appendChild(label);
  top.appendChild(confidenceEl);
  top.appendChild(toggleButton);
  top.appendChild(closeButton);
  content.appendChild(top);
  content.appendChild(summaryEl);
  content.appendChild(details);
  banner.appendChild(icon);
  banner.appendChild(content);

  // Insert banner above the email body
  container.parentElement?.insertBefore(banner, container);
}

/**
 * Show an error banner if something goes wrong.
 */
function injectErrorBanner(container, message) {
  // Remove old banner first
  removeBanner();

  // Create error banner
  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.className = "phishguard-banner phishguard-error";

  const icon = document.createElement("div");
  icon.className = "pg-icon";
  icon.textContent = "⚙️";

  const content = document.createElement("div");
  content.className = "pg-content";

  const top = document.createElement("div");
  top.className = "pg-top";

  const label = document.createElement("span");
  label.className = "pg-label";
  label.textContent = `PhishGuard: ${message}`;

  const closeButton = document.createElement("button");
  closeButton.className = "pg-close";
  closeButton.type = "button";
  closeButton.textContent = "✕";
  closeButton.addEventListener("click", () => banner.remove());

  top.appendChild(label);
  top.appendChild(closeButton);
  content.appendChild(top);
  banner.appendChild(icon);
  banner.appendChild(content);

  // Insert banner above the email body
  container.parentElement?.insertBefore(banner, container);
}

/**
 * Escape HTML special characters.
 * This prevents unsafe HTML from being inserted into Gmail page.
 * Helps protect against XSS.
 */
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;")   // replace &
    .replace(/</g, "&lt;")    // replace <
    .replace(/>/g, "&gt;")    // replace >
    .replace(/"/g, "&quot;")  // replace "
    .replace(/'/g, "&#039;"); // replace '
}

/**
 * Remove the current banner if it exists.
 */
function removeBanner() {
  document.getElementById(BANNER_ID)?.remove();
}

function resetAnalyzedState() {
  document.querySelectorAll("[" + ANALYZED_ATTR + "]").forEach((node) => {
    node.removeAttribute(ANALYZED_ATTR);
  });
  lastEmailKey = null;
}

function normalizeResult(result) {
  const verdicts = new Set(["SAFE", "SUSPICIOUS", "PHISHING"]);
  const verdict = verdicts.has(result?.verdict) ? result.verdict : "SUSPICIOUS";
  const confidence = Math.max(0, Math.min(100, Number(result?.confidence) || 50));
  const summary = String(result?.summary || "Could not determine email safety.").slice(0, 240);
  const reasons = Array.isArray(result?.reasons)
    ? result.reasons.map((reason) => String(reason).slice(0, 180)).filter(Boolean).slice(0, 5)
    : [];

  return { verdict, confidence, summary, reasons };
}

// Start watching Gmail as soon as this script loads
watchGmail();
