'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { NewScanForm } from '@/components/scan/new-scan-form';
import { ScanList } from '@/components/scan/scan-list';
import { ScanDetail } from '@/components/scan/scan-detail';
import { apiFetch, type ScanDetail as ScanDetailData, type ScanListItem } from '@/lib/client/types';
import { Activity, Fingerprint, ScanLine, ShieldHalf, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';

const POLL_INTERVAL_MS = 1200;

export default function Home() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ScanDetailData | null>(null);
  const [health, setHealth] = useState<'ok' | 'down' | 'checking'>('checking');
  const anyActive = useRef(false);

  // ---- Health ---------------------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    apiFetch<{ status: string }>('/api/health')
      .then(() => !cancelled && setHealth('ok'))
      .catch(() => !cancelled && setHealth('down'));
    return () => {
      cancelled = true;
    };
  }, []);

  // ---- Scan list polling ------------------------------------------------------
  const refreshScans = useCallback(async () => {
    try {
      const result = await apiFetch<{ scans: ScanListItem[] }>('/api/v1/scans');
      setScans(result.scans);
      anyActive.current = result.scans.some((s) => s.status === 'queued' || s.status === 'running');
    } catch {
      // Transient network errors are tolerated; the next tick retries.
    }
  }, []);

  useEffect(() => {
    // Defer the initial fetch so no state is set synchronously within the effect.
    const kickoff = setTimeout(() => void refreshScans(), 0);
    const timer = setInterval(() => void refreshScans(), POLL_INTERVAL_MS);
    return () => {
      clearTimeout(kickoff);
      clearInterval(timer);
    };
  }, [refreshScans]);

  // ---- Selected scan detail polling -------------------------------------------
  useEffect(() => {
    if (!selectedId) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const result = await apiFetch<ScanDetailData>(`/api/v1/scans/${selectedId}`);
        if (!cancelled) setDetail(result);
      } catch {
        if (!cancelled) setDetail(null);
      }
    };
    const kickoff = setTimeout(() => void poll(), 0);
    const timer = setInterval(() => void poll(), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearTimeout(kickoff);
      clearInterval(timer);
    };
  }, [selectedId]);

  const handleSelectScan = useCallback((id: string) => {
    setSelectedId(id);
    setDetail(null);
  }, []);

  const handleClearSelection = useCallback(() => {
    setSelectedId(null);
    setDetail(null);
  }, []);

  const handleScanCreated = useCallback(
    (id: string) => {
      setSelectedId(id);
      setDetail(null);
      void refreshScans();
    },
    [refreshScans],
  );

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      {/* Header */}
      <header className="sticky top-0 z-20 border-b bg-background/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center gap-3 px-4 py-3 sm:px-6">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldHalf className="h-5 w-5" aria-hidden />
          </div>
          <div className="min-w-0">
            <h1 className="truncate text-base font-bold leading-tight sm:text-lg">
              PHP Feature &amp; Vulnerability Detection
            </h1>
            <p className="truncate text-xs text-muted-foreground">
              Evidence-driven assessment · 12-step pipeline · passive &amp; non-destructive
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1.5 text-xs" aria-live="polite">
            <Activity className={`h-3.5 w-3.5 ${health === 'ok' ? 'text-emerald-600' : health === 'down' ? 'text-red-600' : 'text-muted-foreground'}`} aria-hidden />
            <span className="text-muted-foreground">{health === 'ok' ? 'API online' : health === 'down' ? 'API unreachable' : 'checking…'}</span>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-6">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[380px_minmax(0,1fr)]">
          {/* Left column */}
          <div className="space-y-5">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <ScanLine className="h-4 w-4 text-primary" aria-hidden />
                  New assessment
                </CardTitle>
                <CardDescription>
                  Validate a target, fingerprint PHP technology, discover features, and collect evidence-backed findings.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <NewScanForm onScanCreated={handleScanCreated} />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Recent scans</CardTitle>
                <CardDescription>Reproducible scan history with live status.</CardDescription>
              </CardHeader>
              <CardContent>
                <ScanList scans={scans} selectedId={selectedId} onSelect={handleSelectScan} />
              </CardContent>
            </Card>
          </div>

          {/* Right column: detail */}
          <div>
            {detail ? (
              <ScanDetail scan={detail} />
            ) : (
              <div className="flex h-full min-h-[420px] flex-col items-center justify-center gap-4 rounded-xl border border-dashed p-10 text-center">
                <div className="flex h-14 w-14 items-center justify-center rounded-full bg-muted">
                  <Fingerprint className="h-7 w-7 text-muted-foreground" aria-hidden />
                </div>
                <div className="max-w-md space-y-1.5">
                  <h2 className="text-lg font-semibold">Select a scan to view results</h2>
                  <p className="text-sm text-muted-foreground">
                    The system separates three questions: is PHP likely used, which application features exist, and does
                    evidence demonstrate a weakness? A technology alone is never reported as a vulnerability.
                  </p>
                </div>
                {scans.length > 0 && (
                  <Button variant="outline" size="sm" onClick={() => setSelectedId(scans[0].id)}>
                    View latest scan
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Sticky footer */}
      <footer className="mt-auto border-t bg-muted/40 py-4 pb-[max(1rem,env(safe-area-inset-bottom))]">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-2 px-4 text-xs text-muted-foreground sm:px-6">
          <span>
            PHP Feature &amp; Vulnerability Detection System — authorized use only. Passive checks; no form submission, no brute force, no exploitation.
          </span>
          {selectedId && (
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground">
                  <Trash2 className="mr-1 h-3.5 w-3.5" aria-hidden /> Clear selection
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Clear selected scan?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This only deselects the scan in the dashboard — stored scan history is preserved.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={handleClearSelection}>Clear</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          )}
        </div>
      </footer>
    </div>
  );
}
