'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiFetch, severityRank, type FindingPage, type FindingStatus, type Severity } from '@/lib/client/types';
import { ConfidenceBadge, FindingStatusBadge, SeverityBadge } from './badges';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ChevronDown, ChevronUp, Crosshair, Loader2, ShieldQuestion, Wrench } from 'lucide-react';
import { cn } from '@/lib/utils';

interface FindingsPanelProps {
  scanId: string;
  scanComplete: boolean;
}

export function FindingsPanel({ scanId, scanComplete }: FindingsPanelProps) {
  const [data, setData] = useState<FindingPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<string>('all');
  const [status, setStatus] = useState<string>('all');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ pageSize: '50' });
      if (severity !== 'all') params.set('severity', severity);
      if (status !== 'all') params.set('status', status);
      const result = await apiFetch<FindingPage>(`/api/v1/scans/${scanId}/findings?${params}`);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load findings');
    } finally {
      setLoading(false);
    }
  }, [scanId, severity, status]);

  useEffect(() => {
    void load();
  }, [load, scanComplete]);

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="w-[150px]" aria-label="Filter by severity">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>

        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-[160px]" aria-label="Filter by status">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="confirmed">Confirmed</SelectItem>
            <SelectItem value="potential">Potential</SelectItem>
            <SelectItem value="inconclusive">Inconclusive</SelectItem>
          </SelectContent>
        </Select>

        <span className="ml-auto text-sm text-muted-foreground" aria-live="polite">
          {data ? `${data.total} finding${data.total === 1 ? '' : 's'}` : '…'}
        </span>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-10 text-muted-foreground">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden /> Loading findings…
        </div>
      )}

      {error && !loading && (
        <p role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
          {error}
        </p>
      )}

      {!loading && !error && data && data.findings.length === 0 && (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center">
          <ShieldQuestion className="h-8 w-8 text-muted-foreground/50" aria-hidden />
          <p className="text-sm text-muted-foreground">
            No findings match the current filters — or the passive rule set produced no evidence-backed weaknesses.
          </p>
        </div>
      )}

      {!loading && !error && data && data.findings.length > 0 && (
        <ul className="space-y-2.5">
          {[...data.findings]
            .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
            .map((finding) => {
              const isOpen = expanded.has(finding.id);
              return (
                <li key={finding.id} className="rounded-lg border bg-card">
                  <button
                    type="button"
                    onClick={() => toggle(finding.id)}
                    aria-expanded={isOpen}
                    className="flex w-full items-start gap-2.5 p-3 text-left hover:bg-muted/40 rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <div className="flex flex-1 flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={finding.severity as Severity} />
                      <FindingStatusBadge status={finding.status as FindingStatus} />
                      <ConfidenceBadge confidence={finding.confidence} />
                      <span className="ml-1 text-sm font-medium">{finding.title}</span>
                    </div>
                    <span className="mt-0.5 shrink-0 text-muted-foreground">
                      {isOpen ? <ChevronUp className="h-4 w-4" aria-hidden /> : <ChevronDown className="h-4 w-4" aria-hidden />}
                    </span>
                  </button>

                  {isOpen && (
                    <div className="border-t px-3 pb-3 pt-2.5 space-y-2.5">
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <Crosshair className="h-3.5 w-3.5 shrink-0" aria-hidden />
                        <span className="font-mono break-all">{finding.ruleId}</span>
                        <span aria-hidden>·</span>
                        <span className="font-mono break-all">{finding.affectedUrl}</span>
                      </div>

                      <div>
                        <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                          Evidence
                        </h4>
                        <ul className="space-y-1.5">
                          {finding.evidence.map((ev, idx) => (
                            <li key={idx} className="rounded-md bg-muted/60 p-2 text-xs">
                              <span className="mr-1.5 rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary">
                                {ev.source}
                              </span>
                              <span className="break-all">{ev.observation}</span>
                              <span className="ml-1.5 whitespace-nowrap text-[10px] text-muted-foreground">
                                {new Date(ev.timestamp).toISOString()}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div className={cn('flex items-start gap-2 rounded-md border border-emerald-200 bg-emerald-50/70 p-2.5 text-xs dark:border-emerald-900 dark:bg-emerald-950/30')}>
                        <Wrench className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-700 dark:text-emerald-400" aria-hidden />
                        <span className="text-emerald-900 dark:text-emerald-200">
                          <strong>Remediation:</strong> {finding.remediation}
                        </span>
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
        </ul>
      )}

      {data && data.total > data.findings.length && (
        <div className="flex justify-center">
          <Button variant="outline" size="sm" onClick={() => void load()}>
            Refresh
          </Button>
        </div>
      )}
    </div>
  );
}
