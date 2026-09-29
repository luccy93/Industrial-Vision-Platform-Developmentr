import type { Metadata } from "next";
import "../styles/globals.css";
import { Header } from "../components/layout/Header";
import { Sidebar } from "../components/layout/Sidebar";

export const metadata: Metadata = {
  title: "Industrial AI Vision Platform — V01",
  description: "Foundation shell for industrial safety intelligence."
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="flex min-h-screen">
          <Sidebar />
          <div className="flex min-w-0 flex-1 flex-col">
            <Header />
            <main className="flex-1 p-6">{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
