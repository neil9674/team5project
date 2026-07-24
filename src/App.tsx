import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState } from "react";
import { ScanResult } from "./types";

function App() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    // Get latest scan result when popup opens
    chrome.runtime.sendMessage(
      { type: "PHISHGUARD_GET_RESULT" },
      (response) => {
        if (response?.result) {
          setResult(response.result);
        }
      }
    );

    // Listen for new scan results
    const listener = (message: any) => {
      if (message.type === "PHISHGUARD_RESULT_UPDATED") {
        setResult(message.result);
      }
    };

    chrome.runtime.onMessage.addListener(listener);

    return () => {
      chrome.runtime.onMessage.removeListener(listener);
    };
  }, []);

  const scanEmail = () => {
    setIsScanning(true);

    chrome.runtime.sendMessage({
      type: "PHISHGUARD_SCAN_EMAIL",
    });

    setTimeout(() => {
      setIsScanning(false);
    }, 1000);
  };


  const scoreLabel =
    result?.status === "phishing"
      ? "HIGH THREAT"
      : result?.status === "safe"
      ? "ALL CLEAR"
      : "WAITING";

  const scoreColor =
    result?.status === "phishing"
      ? "border-red-500 text-red-400"
      : "border-emerald-500 text-emerald-400";


  return (
    <div className="min-h-screen bg-surface px-4 py-5 text-text">

      <div className="mx-auto w-full max-w-sm rounded-3xl border border-[#1f2a44] bg-[#0d1325] p-5 shadow-glow">

        <div className="flex justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-slate-500">
              PhishGuard
            </p>
            <p className="text-sm text-slate-400">
              Email Scanner
            </p>
          </div>
        </div>


        <div className="mt-6 rounded-[28px] border border-[#1f2a44] bg-[#0f1729] p-4">

          <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">
            Current Email
          </p>

          <div className="mt-4 rounded-3xl border border-[#17243a] bg-[#0b1321] p-4">

            <p className="font-semibold text-white">
              {result?.email?.senderEmail || "No email detected"}
            </p>

            <p className="text-slate-400">
              {result?.email?.subject || "Open an email in Gmail"}
            </p>

          </div>

        </div>



        <button
          onClick={scanEmail}
          disabled={isScanning}
          className="mt-6 w-full rounded-3xl bg-gradient-to-r from-cyan-500 to-blue-500 px-5 py-3 font-semibold text-black"
        >
          {isScanning ? "Scanning..." : "Scan Email"}
        </button>



        <AnimatePresence>

        {result && result.status !== "idle" && (

          <motion.div
            initial={{opacity:0,y:15}}
            animate={{opacity:1,y:0}}
            className="mt-6 space-y-5"
          >


            <div className="rounded-3xl border p-4">

              <h2 className="font-semibold text-white">

                {result.status === "phishing"
                  ? "⚠️ Phishing Attempt Detected"
                  : "✅ Email Looks Safe"}

              </h2>

              <p className="text-sm text-slate-400">
                {result.verdict}
              </p>

            </div>



            <div className="rounded-3xl border border-[#1f2a44] bg-[#09101f] p-4">

              <p className="text-xs text-slate-500">
                RISK SCORE
              </p>

              <div className="flex justify-between mt-2">

                <span className="text-xl font-bold text-white">
                  {result.score}/100
                </span>

                <span className={`rounded-xl border px-3 py-1 ${scoreColor}`}>
                  {scoreLabel}
                </span>

              </div>

            </div>



            <div>

              <p className="mb-3 text-xs uppercase text-slate-500">
                Detection Signals
              </p>


              {result.signals.map((signal,index)=>(

                <div
                  key={index}
                  className="mb-3 rounded-3xl border border-[#17243a] bg-[#0d1325] p-4"
                >

                  <div className="flex justify-between">

                    <p className="font-semibold text-white">
                      {signal.title}
                    </p>

                    <span className="text-xs text-slate-400">
                      {signal.level}
                    </span>

                  </div>

                  <p className="mt-2 text-sm text-slate-400">
                    {signal.detail}
                  </p>

                </div>

              ))}

            </div>



            <div className="rounded-3xl border border-[#17243a] p-4">

              <p className="text-xs text-slate-500">
                ML MODEL
              </p>

              <p className="text-white">
                Probability:
                {" "}
                {Math.round(
                  (result.model?.probability || 0) * 100
                )}
                %
              </p>


            </div>


          </motion.div>

        )}

        </AnimatePresence>


      </div>

    </div>
  );
}


export default App;
