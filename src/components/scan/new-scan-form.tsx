'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Loader2, Play, ShieldCheck, TriangleAlert } from 'lucide-react';
import { apiFetch } from '@/lib/client/types';

interface NewScanFormProps {
  onScanCreated: (id: string) => void;
}

export function NewScanForm({ onScanCreated }: NewScanFormProps) {
  const [url, setUrl] = useState('');
  const [demo, setDemo] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await apiFetch<{ id: string; status: string }>('/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify({ url: demo && !url ? 'http://demo.shoplite.local' : url, demo }),
      });
      setUrl('');
      onScanCreated(result.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="target-url">Target URL</Label>
        <div className="flex flex-col sm:flex-row gap-2">
          <Input
            id="target-url"
            placeholder="https://authorized-target.example"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={submitting || demo}
            inputMode="url"
            autoComplete="url"
            className="flex-1"
          />
          <Button type="submit" disabled={submitting} className="sm:w-40">
            {submitting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
                Starting…
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" aria-hidden />
                Start scan
              </>
            )}
          </Button>
        </div>
      </div>

      <div className="flex items-center justify-between gap-4 rounded-lg border border-dashed p-3">
        <div className="space-y-0.5">
          <Label htmlFor="demo-mode" className="flex items-center gap-1.5 text-sm font-medium">
            <ShieldCheck className="h-4 w-4 text-emerald-600" aria-hidden />
            Demo fixture mode
          </Label>
          <p className="text-xs text-muted-foreground">
            Runs the full 12-step pipeline against a built-in offline PHP app — no network requests leave the sandbox.
          </p>
        </div>
        <Switch id="demo-mode" checked={demo} onCheckedChange={setDemo} disabled={submitting} />
      </div>

      {error && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300"
        >
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>{error}</span>
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Only scan targets you are authorized to assess. Checks are passive and non-destructive — forms are never submitted,
        loopback/private/cloud-metadata targets are blocked.
      </p>
    </form>
  );
}
