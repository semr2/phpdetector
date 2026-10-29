'use client';

import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PhpDetectionBadge, ScanStatusBadge } from './badges';
import { PipelineProgress } from './pipeline-progress';
import { FindingsPanel } from './findings-panel';
import { FeaturesPanel } from './features-panel';
import type { ScanDetail, ScanSummary, Severity } from '@/lib/client/types';
import {
  Braces,
  CheckCircle2,
  Fingerprint,
  FileCode2,
  FileDown,
  Globe,
  Printer,
  Radar,
  Timer,
} from 'lucide-react';

interface ScanDetailProps {
  scan: ScanDetail;
  onDeleted?: () => void;
}

const SEVERITY_DOT: Record<Severity, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-600',
  medium: 'bg-amber-500',
  low: 'bg-lime-600',
  info: 'bg-slate-500',
};

function Stat({ value, label, icon }: { value: number | string; label: string; icon: React.ReactNode }) {
  return (
    <div className="rounded-lg border bg-card p-3">
      <div className="flex items-center gap-1.5 text-xs uppercase tracking-wide text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="mt-1 text-2xl font-bold tabular-nums">{value}</div>
    </div>
  );
}

export function ScanDetail({ scan }: ScanDetailProps) {
  const summary: ScanSummary | null = scan.summary;
  const isComplete = scan.status === 'completed';
  const isRunning = scan.status === 'running' || scan.status === 'queued';

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-bold break-all">{scan.targetUrl}</h2>
        <ScanStatusBadge status={scan.status} />
        {scan.mode === 'demo' && (
          <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-medium text-muted-foreground">demo fixture</span>
        )}
        <div className="ml-auto flex flex-wrap gap-2">
          <Button asChild size="sm" variant="outline">
            <a href={`/api/v1/scans/${scan.id}/report?format=json&download=1`} title="Download JSON report">
              <Braces className="mr-1.5 h-4 w-4" aria-hidden /> JSON
            </a>
          </Button>
          <Button asChild size="sm" variant="outline">
            <a href={`/api/v1/scans/${scan.id}/report?format=html`} target="_blank" rel="noopener noreferrer" title="Open standalone HTML report">
              <FileCode2 className="mr-1.5 h-4 w-4" aria-hidden /> HTML report
            </a>
          </Button>
          <Button asChild size="sm" variant="outline">
            <a href={`/api/v1/scans/${scan.id}/report?format=html&download=1`} title="Download HTML report (print to PDF from the opened page)">
              <FileDown className="mr-1.5 h-4 w-4" aria-hidden /> Download
            </a>
          </Button>
        </div>
      </div>

      {/* Pipeline progress */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Radar className="h-4 w-4 text-primary" aria-hidden />
            Scan pipeline
            <span className="ml-auto flex items-center gap-1 text-xs font-normal text-muted-foreground">
              <Timer className="h-3.5 w-3.5" aria-hidden />
              {summary?.durationMs != null ? `${(summary.durationMs / 1000).toFixed(1)}s` : isRunning ? 'in progress…' : '—'}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <PipelineProgress
            status={scan.status}
            currentStep={scan.currentStep}
            progress={scan.progress}
            error={scan.error}
          />
        </CardContent>
      </Card>

      {/* Summary stats + PHP detection */}
      {summary && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat value={summary.pagesCrawled} label="Pages" icon={<Globe className="h-3.5 w-3.5" aria-hidden />} />
          <Stat value={summary.featuresTotal} label="Features" icon={<Braces className="h-3.5 w-3.5" aria-hidden />} />
          <Stat value={summary.findingsTotal} label="Findings" icon={<Radar className="h-3.5 w-3.5" aria-hidden />} />
          <Card className="p-3">
            <div className="flex items-center gap-1.5 text-xs uppercase tracking-wide text-muted-foreground">
              <Fingerprint className="h-3.5 w-3.5" aria-hidden /> PHP detection
            </div>
            <div className="mt-1.5">
              {scan.phpDetection ? (
                <PhpDetectionBadge detection={scan.phpDetection} />
              ) : (
                <span className="text-sm text-muted-foreground">pending…</span>
              )}
            </div>
            {scan.phpFramework && (
              <div className="mt-1 text-xs text-muted-foreground">Stack: {scan.phpFramework}</div>
            )}
          </Card>
        </div>
      )}

      {/* Severity breakdown */}
      {summary && summary.findingsTotal > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-card px-4 py-3">
          <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">By severity</span>
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => (
            <span key={sev} className="inline-flex items-center gap-1.5 text-sm">
              <span className={`h-2.5 w-2.5 rounded-full ${SEVERITY_DOT[sev]}`} aria-hidden />
              <span className="font-semibold tabular-nums">{summary.findingsBySeverity[sev] ?? 0}</span>
              <span className="text-muted-foreground">{sev}</span>
            </span>
          ))}
        </div>
      )}

      {/* PHP evidence */}
      {isComplete && scan.phpEvidence && scan.phpEvidence.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">PHP fingerprint evidence</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1.5">
              {scan.phpEvidence.map((ev, idx) => (
                <li key={idx} className="rounded-md bg-muted/60 p-2 text-xs">
                  <span className="mr-1.5 rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary">
                    {ev.source}
                  </span>
                  {ev.observation}
                </li>
              ))}
            </ul>
            <p className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" aria-hidden />
              PHP usage is a technology fact, not a vulnerability — findings below are backed by dedicated evidence.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Tabs: findings / features */}
      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="features">Feature inventory</TabsTrigger>
        </TabsList>
        <TabsContent value="findings" className="mt-3">
          <FindingsPanel scanId={scan.id} scanComplete={isComplete} />
        </TabsContent>
        <TabsContent value="features" className="mt-3">
          <FeaturesPanel scanId={scan.id} scanComplete={isComplete} />
        </TabsContent>
      </Tabs>

      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <Printer className="h-3.5 w-3.5" aria-hidden />
        Need a PDF? Open the HTML report and use your browser&apos;s print → “Save as PDF” (the report is print-styled).
      </p>
    </div>
  );
}
