# PhishGuard Chrome Extension

A React + TypeScript browser extension prototype for scanning emails and flagging phishing attempts.

## What was created

### Project scaffold
- `package.json` - project metadata, scripts, React, Vite, Tailwind, and Framer Motion dependencies.
- `tsconfig.json` / `tsconfig.node.json` - TypeScript configuration for the React app and Vite tooling.
- `vite.config.ts` - Vite configuration for React.
- `.gitignore` - ignores `node_modules`, `dist`, and typical OS/log files.

### Chrome extension config
- `public/manifest.json` - Chrome Manifest V3 popup extension configuration.
- `public/popup.html` - extension popup entrypoint.
- `public/icons/icon-16.png`, `icon-32.png`, `icon-48.png`, `icon-128.png` - generated placeholder extension icons.

### App source files
- `src/main.tsx` - React app bootstrap.
- `src/App.tsx` - main Chrome extension popup UI and interaction flow.
- `src/index.css` - Tailwind base, custom global styles, dark theme styling.
- `src/types.ts` - TypeScript type definitions for scan status, threats, and results.

### Styling and build config
- `tailwind.config.cjs` - Tailwind CSS configuration.
- `postcss.config.cjs` - PostCSS configuration.
- `index.html` - Vite HTML entrypoint for local development.

## UI behavior implemented
- `Scan Email` button on the startup screen.
- Animated screen transitions using `framer-motion`.
- Phishing detected result screen with:
  - risk score and color-coded meter
  - specific threat signals
  - report / back actions
- Safe / phishing result flow toggled on repeated scan actions for demo purposes.
- Styling matches the provided screenshot reference with a polished, dark UI.

## Build and verification
- Dependencies installed with `npm install`.
- Build verified successfully using `npm run build`.
- Fixed ESM compatibility by renaming `postcss.config.js` and `tailwind.config.js` to `.cjs` variants.

## How to run
1. `npm install`
2. `npm run dev`
3. Open the Vite URL to preview the popup UI in the browser.

## Notes
- This project is a UI prototype and does not yet implement live Gmail/Outlook content script scanning.
- The extension popup is configured in `public/manifest.json`, but the build output should be adapted for Chrome extension packaging if installed.
- The current scanning logic is simulated to match the design flow.
