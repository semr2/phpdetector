'use client';

import { cn } from '@/lib/utils';
import { ScanStatusBadge, PhpDetectionBadge } from './badges';
import type { PhpDetection, ScanListItem } from '@/lib/client/types';
import { Database, FileSearch, ShieldAlert } from 'lucide-react';

interface ScanListProps {
  scans: ScanListItem[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

export function ScanList({ scans, selectedId, onSelect }: ScanListProps) {
  if (scans.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center">
        <FileSearch className="h-8 w-8 text-muted-foreground/50" aria-hidden />
        <p className="text-sm text-muted-foreground">
          No live scans yet. Enter an authorized target above, or open the separate demo showcase to browse simulated examples.
        </p>
        <a className="text-sm font-medium text-primary underline underline-offset-4" href="/demo">Open demo showcase</a>
      </div>
    );
  }

  return (
    <ul className="space-y-2 max-h-[28rem] overflow-y-auto pr-1 scan-scroll" aria-label="Recent scans">
      {scans.map((scan) => (
        <li key={scan.id}>
          <button
            type="button"
            onClick={() => onSelect(scan.id)}
            aria-pressed={selectedId === scan.id}
            className={cn(
              'w-full rounded-lg border p-3 text-left transition-colors hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              selectedId === scan.id && 'border-primary/60 bg-muted/70',
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-sm font-medium">{scan.targetUrl}</span>
              <ScanStatusBadge status={scan.status} />
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
              <span>{formatDate(scan.createdAt)}</span>
              {scan.mode === 'demo' && (
                <span className="rounded bg-amber-100 px-1.5 py-0.5 font-semibold text-amber-900">SIMULATED</span>
              )}
              <span className="inline-flex items-center gap-1">
                <ShieldAlert className="h-3 w-3" aria-hidden />
                {scan.counts.findings} findings
              </span>
              <span className="inline-flex items-center gap-1">
                <Database className="h-3 w-3" aria-hidden />
                {scan.counts.features} features
              </span>
              {scan.phpDetection && (
                <PhpDetectionBadge detection={scan.phpDetection as PhpDetection} />
              )}
            </div>
            {(scan.status === 'running' || scan.status === 'queued') && (
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-amber-500 transition-all duration-500"
                  style={{ width: `${Math.max(6, scan.progress)}%` }}
                />
              </div>
            )}
          </button>
        </li>
      ))}
    </ul>
  );
}
