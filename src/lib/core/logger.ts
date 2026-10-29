/**
 * Structured JSON logging. Raw print()/console.log with unstructured text is
 * forbidden by the SRS (agent guideline #3). Everything goes through here.
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogRecord {
  ts: string;
  level: LogLevel;
  component: string;
  message: string;
  [key: string]: unknown;
}

function emit(level: LogLevel, component: string, message: string, meta?: Record<string, unknown>): void {
  const record: LogRecord = {
    ts: new Date().toISOString(),
    level,
    component,
    message,
    ...(meta ?? {}),
  };
  const line = JSON.stringify(record);
  if (level === 'error') {
    console.error(line);
  } else if (level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }
}

export function createLogger(component: string) {
  return {
    debug: (message: string, meta?: Record<string, unknown>) =>
      emit('debug', component, message, meta),
    info: (message: string, meta?: Record<string, unknown>) =>
      emit('info', component, message, meta),
    warn: (message: string, meta?: Record<string, unknown>) =>
      emit('warn', component, message, meta),
    error: (message: string, meta?: Record<string, unknown>) =>
      emit('error', component, message, meta),
  };
}
