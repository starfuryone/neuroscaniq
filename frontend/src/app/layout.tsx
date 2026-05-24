import type { Metadata } from 'next';
import './globals.css';
import { Toaster } from 'sonner';

export const metadata: Metadata = {
  title: 'NeuroScanIQ — AI-Powered Internet Exposure Intelligence',
  description:
    'Search and monitor internet-connected infrastructure. Defensive cybersecurity intelligence for security teams, researchers, and infrastructure operators.',
  metadataBase: new URL('https://neuroscaniq.local'),
  openGraph: {
    title: 'NeuroScanIQ',
    description: 'AI-Powered Internet Exposure Intelligence',
    type: 'website',
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-ink-950 text-bone-100 antialiased">
        {children}
        <Toaster
          theme="dark"
          position="top-right"
          toastOptions={{
            classNames: {
              toast: '!bg-ink-800 !border !border-ink-700 !text-bone-100',
            },
          }}
        />
      </body>
    </html>
  );
}
