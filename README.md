# PhishGuard

PhishGuard is a Chrome extension that scans the current email for possible phishing signals, including spoofed senders, suspicious links, urgent language, and risky email patterns.

## What was created

### Project scaffold

- `package.json` - project metadata, scripts, React, Vite, Tailwind, and Framer Motion dependencies.
- `tsconfig.json` / `tsconfig.node.json` - TypeScript configuration for the React app and Vite tooling.
- `vite.config.ts` - Vite configuration for React.
- `.gitignore` - ignores `node_modules`, `dist`, and typical OS/log files.

### Chrome extension config

- `public/manifest.json` - Chrome Manifest V3 popup extension configuration.
- `public/icons/icon-16.png`, `icon-32.png`, `icon-48.png`, `icon-128.png` - extension icons.

### App source files

- `src/main.tsx` - React app bootstrap.
- `src/App.tsx` - main Chrome extension popup UI and interaction flow.
- `src/index.css` - Tailwind base, custom global styles, dark theme styling.
- `src/types.ts` - TypeScript type definitions for scan status, threats, and results.

## UI behavior implemented

- `Scan Email` button on the startup screen.
- Animated screen transitions using `framer-motion`.
- Phishing detected result screen with:
  - risk score and color-coded meter
  - specific threat signals
  - report / back actions
- Gmail email preview and manual scan flow.
- Styling matches the provided screenshot reference with a polished, dark UI.

## Website

The public landing page is deployed on Vercel:

https://phishguard-site.vercel.app

## Build and verification

Install dependencies:

```bash
npm install
```

Run locally:

```bash
npm run dev
```

Build the extension/site output:

```bash
npm run build
```

The build should create a `dist` folder. This is the folder Chrome loads when testing the extension manually.

## Testing the Extension Before Chrome Web Store Approval

Chrome Web Store review can take time. Until the extension is approved and listed, you can test it locally with Chrome's developer mode.

### 1. Build the extension

From the project folder, run:

```bash
npm install
npm run build
```

After the build finishes, confirm that the project has a `dist` folder.

### 2. Open Chrome Extensions

Open Chrome and go to:

```text
chrome://extensions
```

### 3. Turn on Developer Mode

In the top-right corner of the Extensions page, turn on **Developer mode**.

### 4. Load the unpacked extension

Click **Load unpacked**.

When Chrome asks for a folder, select the project's `dist` folder.

Do not select an individual file inside `dist`; select the whole `dist` folder.

### 5. Test it with an email

Open Gmail or another supported email page in Chrome.

Open an email message, then click the PhishGuard extension icon in the Chrome toolbar. The extension should scan the current email and show whether it looks safe or suspicious.

### 6. Reload after changes

If you edit the extension code, rebuild the `dist` folder:

```bash
npm run build
```

Then return to `chrome://extensions` and click the reload button on the PhishGuard extension card.

Refresh the email page before testing again.

## Troubleshooting

- If **Load unpacked** fails, make sure you selected the `dist` folder and that it contains the extension manifest.
- If the extension icon does not appear, pin it from Chrome's extensions menu.
- If scan results look stale, reload the extension in `chrome://extensions` and refresh the email tab.
- If Chrome says the extension has errors, open the extension card's error details and fix the reported file or manifest issue.
