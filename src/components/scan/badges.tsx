'use client';

import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { FindingStatus, PhpDetection, ScanStatus, Severity } from '@/lib/client/types';

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'bg-red-600 text-white hover:bg-red-600',
  high: 'bg-orange-600 text-white hover:bg-orange-600',
  medium: 'bg-amber-500 text-white hover:bg-amber-500',
  low: 'bg-lime-600 text-white hover:bg-lime-600',
  info: 'bg-slate-500 text-white hover:bg-slate-500',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge className={cn('uppercase tracking-wide text-[11px] font-bold', SEVERITY_STYLES[severity])}>
      {severity}
    </Badge>
  );
}

const FINDING_STATUS_STYLES: Record<FindingStatus, string> = {
  confirmed: 'border-emerald-600 text-emerald-700 dark:text-emerald-400',
  potential: 'border-amber-600 text-amber-700 dark:text-amber-400',
  inconclusive: 'border-slate-400 text-slate-500',
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <Badge variant="outline" className={cn('text-[11px] font-semibold', FINDING_STATUS_STYLES[status])}>
      {status}
    </Badge>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  return (
    <Badge variant="secondary" className="text-[11px] font-semibold">
      confidence: {confidence}
    </Badge>
  );
}

const PHP_DETECTION_STYLES: Record<PhpDetection, string> = {
  likely: 'bg-emerald-700 text-white hover:bg-emerald-700',
  not_detected: 'bg-slate-600 text-white hover:bg-slate-600',
  inconclusive: 'bg-amber-500 text-white hover:bg-amber-500',
};

export function PhpDetectionBadge({ detection }: { detection: PhpDetection }) {
  return (
    <Badge className={cn('text-[11px] font-bold', PHP_DETECTION_STYLES[detection])}>
      PHP: {detection.replaceAll('_', ' ')}
    </Badge>
  );
}

const SCAN_STATUS_STYLES: Record<ScanStatus, string> = {
  queued: 'border-slate-400 text-slate-600 dark:text-slate-300',
  running: 'border-amber-500 text-amber-700 dark:text-amber-400 animate-pulse',
  completed: 'border-emerald-600 text-emerald-700 dark:text-emerald-400',
  failed: 'border-red-600 text-red-700 dark:text-red-400',
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return (
    <Badge variant="outline" className={cn('text-[11px] font-semibold', SCAN_STATUS_STYLES[status])}>
      {status}
    </Badge>
  );
}
