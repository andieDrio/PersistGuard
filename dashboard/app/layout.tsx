import type { Metadata } from "next";
import "@fontsource-variable/inter";
import "./styles.css";
import { PersistGuardFooter } from "./persistguard-footer";

export const metadata: Metadata = {
  title: "Scan history | PersistGuard",
  description: "Review endpoint inventory scans, findings, and collection coverage.",
};

// Centralized, non-editable footer shared by every dashboard route.
export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>
    <div className="app-scroll" role="region" aria-label="PersistGuard workspace" tabIndex={0}>{children}</div>
    <PersistGuardFooter />
  </body></html>;
}
