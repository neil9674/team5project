export type ScanStatus = 'idle' | 'scanning' | 'safe' | 'phishing';

export interface ThreatSignal {
  title: string;
  detail: string;
  level: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface ScanResult {
  status: ScanStatus;
  score: number;
  signals: ThreatSignal[];
}
