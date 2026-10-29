'use client';

import { useEffect, useState } from 'react';
import { apiFetch, FEATURE_KIND_LABELS, type FeatureItem, type FeatureKind } from '@/lib/client/types';
import { Badge } from '@/components/ui/badge';
import { Loader2, FolderTree } from 'lucide-react';

const KIND_BADGE_STYLES: Partial<Record<FeatureKind, string>> = {
  form_login: 'bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-300',
  form_search: 'bg-cyan-100 text-cyan-800 dark:bg-cyan-950 dark:text-cyan-300',
  form_upload: 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300',
  form_generic: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
  query_param: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300',
  php_route: 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300',
  file_route: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300',
};

interface FeaturesPanelProps {
  scanId: string;
  scanComplete: boolean;
}

export function FeaturesPanel({ scanId, scanComplete }: FeaturesPanelProps) {
  const [features, setFeatures] = useState<FeatureItem[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const detail = await apiFetch<{ counts: { features: number } }>(`/api/v1/scans/${scanId}`);
        if (detail.counts.features > 0 || scanComplete) {
          const result = await apiFetch<{ features: FeatureItem[] }>(`/api/v1/scans/${scanId}/features`);
          if (!cancelled) setFeatures(result.features);
        } else if (!cancelled) {
          setFeatures([]);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load features');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [scanId, scanComplete]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-10 text-muted-foreground">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden /> Loading feature inventory…
      </div>
    );
  }

  if (error) {
    return (
      <p role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300">
        {error}
      </p>
    );
  }

  if (!features || features.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center">
        <FolderTree className="h-8 w-8 text-muted-foreground/50" aria-hidden />
        <p className="text-sm text-muted-foreground">No application features discovered within the crawl bounds.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border max-h-[26rem] overflow-y-auto scan-scroll">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-muted/95 backdrop-blur">
          <tr className="text-left text-xs uppercase tracking-wide text-muted-foreground">
            <th className="px-3 py-2 font-semibold">Type</th>
            <th className="px-3 py-2 font-semibold">Name</th>
            <th className="px-3 py-2 font-semibold">Location</th>
          </tr>
        </thead>
        <tbody>
          {features.map((feature) => (
            <tr key={feature.id} className="border-t">
              <td className="px-3 py-2 align-top">
                <Badge className={`text-[11px] font-semibold ${KIND_BADGE_STYLES[feature.kind] ?? ''}`}>
                  {FEATURE_KIND_LABELS[feature.kind] ?? feature.kind}
                </Badge>
              </td>
              <td className="px-3 py-2 align-top font-medium">{feature.name}</td>
              <td className="px-3 py-2 align-top font-mono text-xs break-all text-muted-foreground">
                {feature.location}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
