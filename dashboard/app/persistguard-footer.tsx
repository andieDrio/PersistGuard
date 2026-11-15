"use client";

import { useEffect, useState } from "react";

// The year updates in a running browser session, including across New Year.
export function PersistGuardFooter() {
  const [year, setYear] = useState(() => new Date().getFullYear());

  useEffect(() => {
    const refreshYear = () => setYear(new Date().getFullYear());
    refreshYear();
    const interval = window.setInterval(refreshYear, 60_000);
    return () => window.clearInterval(interval);
  }, []);

  return <footer className="persistguard-footer" aria-label="PersistGuard footer">
    <span>Cybersecurity is everyone Responsibility</span>
    <span>Powered by: apm @ {year}</span>
  </footer>;
}
