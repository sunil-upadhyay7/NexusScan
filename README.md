# NexusScan
🔍 Scan Smarter. Stay Safer. Real-time URL security scanner that protects against malicious websites and phishing attacks. Features multi-source threat intelligence, visual risk scoring, scan history, and community-driven safety ratings. Privacy-first design.

---

## 🚀 What Is NexusScan?

NexusScan is a privacy-focused browser extension that delivers **real-time URL threat analysis**. By combining the power of VirusTotal and urlscan.io, it helps you instantly detect malicious websites, phishing attempts, and suspicious network activity—directly in your browser.

---

## ✨ Key Features

- **Real-Time Scanning**  
  Detect threats instantly with one click.

- **Multi-Source Intelligence**  
  Aggregates data from VirusTotal & urlscan.io.

- **Visual Risk Scores**  
  Color-coded risk meter (green/yellow/red).

- **IP & Tech Insights**  
  Simplified tables showing IP addresses and request counts, plus detected frameworks.

- **Scan History & Export**  
  View past scans, export or clear your history.

- **Community Feedback**  
  Rate sites, leave comments, and see collective insights.

- **Bookmark Scanner**  
  Bulk-scan saved bookmarks for safety.

- **Dark/Light Themes**  
  Toggle between modes for comfortable viewing.

- **Privacy-First**  
  All data stored locally—no external tracking.

---
## 📷 Screenshots

### 1. Main Popup
<img width="500" height="599" alt="image" src="https://github.com/user-attachments/assets/212d408b-b593-43df-a9b6-c2bed8e85d26" />

### 2. Threat Analysis
<img width="519" height="622" alt="image" src="https://github.com/user-attachments/assets/b011c5fa-96fe-40ca-b4a4-e1c011f24790" />

### 3. IP Address Table
<img width="522" height="623" alt="image" src="https://github.com/user-attachments/assets/66039be6-728e-45be-a7a0-3e57d142787c" />

### 4. Community Ratings
<img width="488" height="696" alt="image" src="https://github.com/user-attachments/assets/5c8cf404-a741-4af7-819f-cbe742a5d2f8" />

### 5. Bookmark Scanner
<img width="508" height="686" alt="image" src="https://github.com/user-attachments/assets/cb668e62-0011-4502-b226-0adda969f74d" />

## 🛠 Installation & Getting Started
Follow these steps to get NexusScan running in your browser:

### 1. Clone the Repository
- git clone (https://github.com/sunilupd7403/NexusScan)
- cd nexusscan-extension

### 2. Load the Extension
**For Chrome:**
- Go to `chrome://extensions`
- Enable **Developer mode** (top right)
- Click **Load unpacked**
- Select the folder where you cloned this repository

**For Firefox:**
- Go to `about:debugging#/runtime/this-firefox`
- Click **Load Temporary Add-on**
- Select the `manifest.json` file from your cloned folder

### 3. Set Up API Keys
- Click the NexusScan extension icon in your browser’s toolbar to open the popup
- Go to **Settings** (gear icon or “Settings” link)
- Enter your **VirusTotal** and **urlscan.io** API keys
  - *(Need keys? Get them at [VirusTotal](https://www.virustotal.com/gui/join-us) and [urlscan.io](https://urlscan.io/))*
- Click **Save**

### 4. Start Scanning!
- Reload the popup if needed
- The **Scan** button is now enabled—click to analyze any website!
- View risk scores, detailed reports, scan history, and more

> **Note:**  
> You only need to set your API keys once. They are stored locally in your browser for secure, repeated use.

---
## ⚙️ How It Works
1. **Click the NexusScan icon** in your toolbar.  
2. **View the current URL** displayed at the top.  
3. **Press “Scan”** to analyze the site.  
4. **See risk score**, vendor detections, IP table, and tech fingerprint.  
5. **Rate the site** or leave comments under Community tab.  
6. **Export history** or scan your bookmarks for bulk checks.

---

## 🔍 Testing
- **Safe URL**: `https://google.com`, `https://github.com`.  
- **Test Threats**:  
  - `http://testsafebrowsing.appspot.com/s/malware.html`  
  - `http://testsafebrowsing.appspot.com/s/phishing.html`

Verify each feature:
- Popup loads and shows URL  
- Scan initiates and displays results  
- History logs real scans  
- Community feedback saves locally  
- Bookmarks scan in bulk  
- Dark/light toggle works

---

## 🌐 Compatibility

| Browser  | Support    | Notes                           |
|----------|------------|---------------------------------|
| Chrome   | ✅ Full     | MV3 `service_worker` supported  |
| Firefox  | ✅ Full     | Uses MV3 `scripts` array        |
| Edge     | ✅ Full     | Chromium-based support          |

---

## 🔒 Privacy & Security
- **Data Local Only**: No personal data leaves your browser.  
- **Clear Storage**: You control/clear history & feedback.  
- **Open Source**: Inspect code; no hidden tracking.  

---
<div align="center">
❤️ **Made with Privacy and Security in mind. Scan Smarter. Stay Safer.**  
</div>
