import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "APK Stack Analyzer",
  description:
    "Analyze Android APK files to identify technology stacks, frameworks, native libraries, and security indicators.",
  keywords: ["APK analyzer", "Android", "React Native", "Flutter", "security", "reverse engineering"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased">{children}</body>
    </html>
  );
}
