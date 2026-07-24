export interface ThreatSignal {
  title: string;
  detail: string;
  level: "LOW" | "MEDIUM" | "HIGH";
}

export interface ScanResult {
  status: "idle" | "safe" | "phishing";
  verdict: string;
  score: number;
  signals: ThreatSignal[];

  email: {
    senderName: string;
    senderEmail: string;
    senderDomain: string;
    subject: string;
    urlCount: number;
    attachmentCount: number;
  } | null;

  model: {
    probability: number;
    isPhishing: boolean;
    threshold: number;
    unavailable: boolean;
  } | null;

  heuristics: {
    score: number;
    signals: ThreatSignal[];
  };
}
