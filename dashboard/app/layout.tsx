import type { Metadata } from "next";
import "@fontsource-variable/inter";
import "./styles.css";

export const metadata: Metadata = {
  title: "Scan history | PersistGuard",
  description: "Review endpoint inventory scans, findings, and collection coverage.",
};

export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
