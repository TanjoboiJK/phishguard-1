# PhishGuard: AI Email Safety Checker

A free Chrome extension that automatically checks every Gmail email for phishing and scams using AI. (only scans gmail)

## What it does

Every time you open an email in Gmail, PhishGuard reads it and shows one of these banners:

- ✅ **Safe** : looks like a legitimate email  
- ⚠️ **Suspicious** : something feels off, be careful  
- 🚨 **Phishing** : this is a scam, do not click anything  

Click **Details** on any banner to see exactly why it was flagged.

## How to install

### Step 1: Download the extension

Download and unzip this repo.

### Step 2: Load it in Chrome

1. Open Chrome and go to `chrome://extensions/`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `phishguard` folder

### Step 3: Get a free API key

1. Go to **[console.groq.com/keys](https://console.groq.com/keys)**
2. Sign up for free (no credit card needed so free free )
3. Click **Create API Key**
4. Copy your API key

### Step 4: Add your key

1. Click the 🛡️ **PhishGuard** icon in your Chrome toolbar
2. Paste your API key
3. Click **Save**

That is it. Open any Gmail email and PhishGuard will check it automatically.

## How it works

1. You open an email in Gmail
2. PhishGuard reads the sender, subject, and body
3. It sends the email to Groq AI for analysis
4. The AI decides whether it is safe, suspicious, or phishing
5. A banner appears inside the email with the result

Everything runs in your browser. Your emails are only sent to Groq's API for analysis and nowhere else.

## Files

| File | What it does |
|------|--------------|
| `manifest.json` | Tells Chrome this is an extension |
| `content.js` | Watches Gmail, reads emails, calls Groq AI, and shows the banner |
| `styles.css` | Styles the banner |
| `popup.html` | The settings page when you click the extension icon |
| `popup.js` | Saves and loads your API key |

## Built with

- **Groq API** : free AI inference using Llama 3
- **Chrome Extensions Manifest V3**
- **Vanilla JavaScript** : no frameworks

## License

free to use, modify, and share.
