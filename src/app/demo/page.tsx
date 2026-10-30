import { DemoDashboard } from '@/components/scan/demo-dashboard';
import { isDemoModeEnabled } from '@/lib/core/demo-mode';

export const dynamic = 'force-dynamic';

export default function DemoPage() {
  if (!isDemoModeEnabled()) {
    return (
      <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-4 px-6">
        <h1 className="text-2xl font-bold">Demo showcase is disabled</h1>
        <p className="text-muted-foreground">
          Set <code>DEMO_MODE=true</code> in the server environment and restart the development server. Demo fixtures are always disabled in production.
        </p>
        <a className="font-medium text-primary underline" href="/">Return to the live dashboard</a>
      </main>
    );
  }
  return <DemoDashboard />;
}
