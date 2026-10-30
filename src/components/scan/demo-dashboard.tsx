'use client';

import { useEffect, useState } from 'react';
import { Activity, Loader2, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScanDetail } from './scan-detail';
import { ScanList } from './scan-list';
import { apiFetch, type ScanDetail as ScanDetailData, type ScanListItem } from '@/lib/client/types';

const API_BASE = '/api/v1/demo/scans';

export function DemoDashboard() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ScanDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    apiFetch<{ scans: ScanListItem[] }>(API_BASE)
      .then(({ scans: fixtureScans }) => {
        if (cancelled) return;
        setScans(fixtureScans);
        setSelectedId(fixtureScans[0]?.id ?? null);
      })
      .catch((cause) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'Unable to load demo fixtures');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    let cancelled = false;
    apiFetch<ScanDetailData>(`${API_BASE}/${selectedId}`)
      .then((value) => { if (!cancelled) setDetail(value); })
      .catch((cause) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'Unable to load demo scan');
      });
    return () => { cancelled = true; };
  }, [selectedId]);

  const selectScan = (id: string) => {
    setDetail(null);
    setSelectedId(id);
  };

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="border-b bg-background/90 px-4 py-4 sm:px-6">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3">
          <div>
            <h1 className="text-xl font-bold">Demo showcase</h1>
            <p className="text-sm text-muted-foreground">PHP detection, feature inventory, findings, and reports.</p>
          </div>
          <a className="ml-auto text-sm font-medium text-primary underline-offset-4 hover:underline" href="/">
            Return to live dashboard
          </a>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl flex-1 space-y-5 px-4 py-6 sm:px-6">
        <div role="note" className="flex items-start gap-3 rounded-lg border border-amber-400 bg-amber-50 p-4 text-sm text-amber-950 dark:bg-amber-950/40 dark:text-amber-100">
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
          <div>
            <strong className="block">SIMULATED DEMO DATA</strong>
            <span>No live website was scanned and no demo records were written to the scan database. Example findings are not confirmed vulnerabilities.</span>
          </div>
        </div>

        {error && <p role="alert" className="rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-800">{error}</p>}

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[380px_minmax(0,1fr)]">
          <Card className="h-fit">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><Activity className="h-4 w-4" aria-hidden />Sample scan history</CardTitle>
              <CardDescription>Static fixtures covering detected, not detected, and inconclusive PHP results.</CardDescription>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="flex items-center justify-center py-8 text-sm text-muted-foreground"><Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />Loading fixtures…</div>
              ) : (
                <ScanList scans={scans} selectedId={selectedId} onSelect={selectScan} />
              )}
            </CardContent>
          </Card>

          <section aria-label="Selected demo scan">
            {detail ? <ScanDetail scan={detail} apiBase={API_BASE} /> : (
              <div className="flex min-h-[420px] items-center justify-center rounded-xl border border-dashed p-10 text-center text-sm text-muted-foreground">
                {loading ? 'Loading sample scan…' : 'Select a sample scan to inspect its simulated results.'}
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
}
