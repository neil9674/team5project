import { AnimatePresence, motion } from 'framer-motion';
import { useMemo, useState } from 'react';
import { analyzeEmail, EmailData } from './emailScanner';
import { ScanResult, ThreatSignal } from './types';

const defaultEmail: EmailData = {
  sender: 'security@paypa1.com',
  subject: 'Urgent: Your account has been limited — verify now',
  body: 'We noticed suspicious activity on your account. Verify immediately to avoid suspension.',
  source: 'Demo',
};

function App() {
  const [status, setStatus] = useState<'idle' | 'safe' | 'phishing'>('idle');
  const [isScanning, setIsScanning] = useState(false);
  const [email, setEmail] = useState<EmailData>(defaultEmail);
  const [error, setError] = useState('');

  const result = useMemo<ScanResult>(() => {
    if (status === 'safe' || status === 'phishing') {
      return analyzeEmail(email);
    }
    return { status: 'idle', score: 0, signals: [] };
  }, [status, email]);

  const onScan = () => {
    setIsScanning(true);
    setError('');
    const chromeApi = (window as any).chrome;

    if (!chromeApi?.tabs?.query || !chromeApi?.tabs?.sendMessage) {
      setError('Extension runtime not available. Load this in Chrome with the extension installed.');
      setIsScanning(false);
      return;
    }

    chromeApi.tabs.query({ active: true, currentWindow: true }, (activeTabs: any[]) => {
      const activeTab = activeTabs?.[0];
      if (!activeTab?.id) {
        setError('Unable to find the active tab.');
        setIsScanning(false);
        return;
      }

      chromeApi.tabs.sendMessage(activeTab.id, { type: 'GET_EMAIL_DATA' }, (response: any) => {
        if (chromeApi.runtime?.lastError) {
          setError('Unable to read email data from the active tab. Make sure Gmail or Outlook is open.');
          setStatus('idle');
          setIsScanning(false);
          return;
        }

        if (!response || !response.email) {
          setError('Unable to read email from the current tab. Open a Gmail or Outlook email message and try again.');
          setStatus('idle');
          setIsScanning(false);
          return;
        }

        setEmail(response.email);
        const scan = analyzeEmail(response.email);
        setStatus(scan.status === 'scanning' || scan.status === 'idle' ? 'safe' : scan.status);
        setIsScanning(false);
      });
    });
  };

  const meterBlocks = Array.from({ length: 10 }, (_, index) => index + 1);
  const scoreLabel = status === 'phishing' ? 'HIGH THREAT' : 'ALL CLEAR';
  const scoreColor = status === 'phishing' ? 'border-red-500 text-red-400' : 'border-emerald-500 text-emerald-400';

  return (
    <div className="min-h-screen bg-surface px-4 py-5 text-text">
      <div className="mx-auto w-full max-w-sm rounded-3xl border border-[#1f2a44] bg-[#0d1325] p-5 shadow-glow">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">PhishGuard</p>
            <p className="text-sm text-slate-400">Email Scanner</p>
          </div>
          <div className="h-10 w-10 rounded-2xl bg-[#0c172d] ring-1 ring-white/10" />
        </div>

        <div className="mt-6 rounded-[28px] border border-[#1f2a44] bg-[#0f1729] p-4">
          <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">Current Email</p>
          <div className="mt-4 flex items-center gap-3 rounded-3xl border border-[#17243a] bg-[#0b1321] p-4">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-slate-800 text-slate-200">
              <span className="text-xl">✉️</span>
            </div>
            <div className="flex-1 text-sm">
              <p className="font-semibold text-white">{(email as any).sender}</p>
              <p className="text-slate-400">{(email as any).subject}</p>
            </div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">{(email as any).source || 'Email'}</p>
          </div>
        </div>

        <AnimatePresence mode="wait">
          {error && (
            <div className="mt-5 rounded-3xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-200">
              {error}
            </div>
          )}
          {status === 'idle' && (
            <motion.div
              key="scan"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              className="mt-6 rounded-3xl border border-[#17243a] bg-[#0f1729] p-6 text-center"
            >
              <div className="mx-auto mb-5 flex h-24 w-24 items-center justify-center rounded-full border border-cyan-400/20 bg-cyan-500/5 text-cyan-300 shadow-lg shadow-cyan-500/10">
                <span className="text-4xl">🎯</span>
              </div>
              <p className="text-sm font-semibold text-white">Ready to scan</p>
              <p className="mt-2 text-xs text-slate-400">Detect phishing attempts, spoofed senders, and malicious links</p>
              <button
                onClick={onScan}
                disabled={isScanning}
                className="mt-6 inline-flex w-full items-center justify-center rounded-3xl bg-gradient-to-r from-cyan-500 to-blue-500 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isScanning ? 'Scanning…' : 'Scan Email'}
              </button>
            </motion.div>
          )}

          {status !== 'idle' && (
            <motion.div
              key="result"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              className="mt-6 space-y-5 rounded-3xl border border-[#17243a] bg-[#0f1729] p-6"
            >
              <div className={`rounded-3xl border p-4 ${status === 'phishing' ? 'border-[#32121f] bg-[#1c0d18]' : 'border-[#0f261c] bg-[#0d1f16]'}`}>
                <div className="flex items-center gap-3 text-white">
                  <div className={`flex h-10 w-10 items-center justify-center rounded-2xl ${status === 'phishing' ? 'bg-red-500/10 text-red-300' : 'bg-emerald-500/10 text-emerald-300'}`}>
                    <span>{status === 'phishing' ? '!' : '✓'}</span>
                  </div>
                  <div>
                    <p className="font-semibold">{status === 'phishing' ? 'Phishing Attempt Detected' : 'Email Looks Safe'}</p>
                    <p className="text-xs text-slate-400">
                      {status === 'phishing'
                        ? 'Do not click links or reply to this email'
                        : 'No issues detected from the latest security scan'}
                    </p>
                  </div>
                </div>
              </div>

              <div className="rounded-3xl border border-[#1f2a44] bg-[#09101f] p-4">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">Risk Level</p>
                    <div className="mt-2 flex items-center gap-2 text-sm font-semibold text-white">
                      <span className={status === 'phishing' ? 'text-red-400' : 'text-emerald-400'}>{result.score}</span>
                      <span className="text-slate-500">/100</span>
                    </div>
                  </div>
                  <div className={`rounded-3xl border px-3 py-2 text-xs font-semibold uppercase ${scoreColor}`}>
                    {scoreLabel}
                  </div>
                </div>
                <div className="mt-4 grid grid-cols-10 gap-2">
                  {meterBlocks.map((block) => {
                    const color = status === 'phishing' ? (block <= 6 ? 'bg-emerald-500' : block <= 8 ? 'bg-amber-500' : 'bg-red-500') : 'bg-emerald-500';
                    return <div key={block} className={`h-2 rounded-full ${color}`} />;
                  })}
                </div>
              </div>

              <div className="space-y-3">
                {result.signals.map((signal) => (
                  <div key={signal.title} className="rounded-3xl border border-[#17243a] bg-[#0d1325] p-4">
                    <div className="flex items-start gap-3">
                      <div className="mt-1 flex h-10 w-10 items-center justify-center rounded-2xl bg-[#111827] text-slate-200">
                        <span>•</span>
                      </div>
                      <div className="flex-1 text-sm">
                        <div className="flex items-center justify-between gap-3">
                          <p className="font-semibold text-white">{signal.title}</p>
                          <span className={`rounded-full px-2 py-1 text-[10px] font-semibold ${signal.level === 'HIGH' ? 'bg-red-500/10 text-red-300' : signal.level === 'MEDIUM' ? 'bg-amber-500/10 text-amber-300' : 'bg-emerald-500/10 text-emerald-300'}`}>
                            {signal.level}
                          </span>
                        </div>
                        <p className="mt-2 text-xs text-slate-400">{signal.detail}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-1 flex gap-3">
                <button className={`flex-1 rounded-3xl border px-4 py-3 text-sm font-semibold hover:opacity-90 ${status === 'phishing' ? 'border-red-500/20 bg-red-500/10 text-red-300' : 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'}`}>
                  {status === 'phishing' ? 'Report' : 'Dismiss'}
                </button>
                <button
                  onClick={() => setStatus('idle')}
                  className="flex-1 rounded-3xl border border-slate-700 bg-slate-900/70 px-4 py-3 text-sm font-semibold text-slate-300 hover:bg-slate-800"
                >
                  Back
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <p className="mt-6 text-center text-xs uppercase tracking-[0.32em] text-slate-500">v1.4.0</p>
      </div>
    </div>
  );
}

export default App;
