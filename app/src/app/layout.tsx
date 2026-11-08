import type { Metadata } from 'next';
import './globals.css';
import './interactions.css';
import './atmosphere.css';
import './evidence-popover.css';

export const metadata: Metadata = {
  title: 'Xerxes — URL intelligence',
  description: 'Look closer before you click. Investigate URL structure, redirects, phishing signals, and brand impersonation.',
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
