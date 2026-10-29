'use client';

import { cn } from '@/lib/utils';
import { PIPELINE_STEP_LABELS } from '@/lib/client/types';
import { CheckCircle2, CircleDashed, LoaderCircle, XCircle } from 'lucide-react';

interface PipelineProgressProps {
  status: string;
  currentStep: number;
  progress: number;
  error?: string | null;
}

/**
 * Visualizes the 12-step evidence-driven pipeline (SRS §5) with live step state.
 */
export function PipelineProgress({ status, currentStep, progress, error }: PipelineProgressProps) {
  const steps = PIPELINE_STEP_LABELS;
  const failed = status === 'failed';
  const completed = status === 'completed';
  const active = status === 'running' || status === 'queued';

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
          <div
            className={cn(
              'h-full rounded-full transition-all duration-700',
              failed ? 'bg-red-600' : completed ? 'bg-emerald-600' : 'bg-amber-500',
            )}
            style={{ width: `${failed ? 100 : Math.max(4, progress)}%` }}
            role="progressbar"
            aria-valuenow={progress}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        </div>
        <span className="w-12 shrink-0 text-right text-sm font-semibold tabular-nums">
          {failed ? '—' : `${progress}%`}
        </span>
      </div>

      <ol className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
        {steps.map((label, index) => {
          const stepNumber = index + 1;
          const isDone = completed || stepNumber < currentStep;
          const isCurrent = active && stepNumber === currentStep;
          const isFailed = failed && stepNumber === currentStep;
          return (
            <li
              key={label}
              className={cn(
                'flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs transition-colors',
                isFailed && 'border-red-300 bg-red-50 dark:border-red-900 dark:bg-red-950/40',
                isCurrent && 'border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/40',
                isDone && !isFailed && 'border-emerald-200 bg-emerald-50/60 dark:border-emerald-900 dark:bg-emerald-950/30',
                !isDone && !isCurrent && !isFailed && 'border-border text-muted-foreground',
              )}
            >
              {isFailed ? (
                <XCircle className="h-4 w-4 shrink-0 text-red-600" aria-hidden />
              ) : isCurrent ? (
                <LoaderCircle className="h-4 w-4 shrink-0 animate-spin text-amber-600" aria-hidden />
              ) : isDone ? (
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" aria-hidden />
              ) : (
                <CircleDashed className="h-4 w-4 shrink-0" aria-hidden />
              )}
              <span className="truncate">
                <span className="mr-1 font-semibold tabular-nums">{stepNumber}.</span>
                {label}
              </span>
            </li>
          );
        })}
      </ol>

      {failed && error && (
        <p role="alert" className="mt-3 rounded-md border border-red-200 bg-red-50 p-2.5 text-xs text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300">
          <strong>Scan failed:</strong> {error}
        </p>
      )}
    </div>
  );
}
