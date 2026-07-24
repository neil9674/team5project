declare const chrome: {
  runtime: {
    lastError?: { message?: string };
    onMessage: {
      addListener(callback: (message: any) => void): void;
      removeListener(callback: (message: any) => void): void;
    };
  };
  tabs: {
    query(
      queryInfo: { active: boolean; currentWindow: boolean },
      callback: (tabs: Array<{ id?: number; url?: string }>) => void,
    ): void;
    sendMessage(tabId: number, message: unknown, callback: (response?: any) => void): void;
  };
};
