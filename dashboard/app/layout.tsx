import type { Metadata } from "next";
import "@fontsource-variable/inter";
import "./styles.css";

export const metadata: Metadata = {
  title: "Scan history | PersistGuard",
  description: "Review endpoint inventory scans, findings, and collection coverage.",
};

// Centralized, non-editable footer shared by every dashboard route.
export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) {
  const year = new Date().getFullYear();
  return <html lang="en"><body>
    {children}
    <footer className="persistguard-footer" aria-label="PersistGuard footer">
      <span>Cybersecurity is everyone Responsibility</span>
      <span>Powered by: apm @ {year}</span>
    </footer>
  </body></html>;
}
