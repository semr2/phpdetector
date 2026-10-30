/** Demo fixtures are enabled only by an explicit server-side flag in non-production. */
export function isDemoModeEnabled(
  demoMode = process.env.DEMO_MODE,
  nodeEnv = process.env.NODE_ENV,
): boolean {
  return demoMode?.trim().toLowerCase() === 'true' && nodeEnv !== 'production';
}

export const DEMO_SIMULATION_NOTICE =
  'SIMULATED DEMO DATA — no live website was scanned. Example findings are not confirmed vulnerabilities.';
