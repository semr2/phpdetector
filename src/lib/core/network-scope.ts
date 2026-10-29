import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';
import { createLogger } from './logger';

/**
 * FR-002 — Network scope check. Executes BEFORE any connection and after DNS
 * resolution to prevent SSRF and DNS rebinding attacks.
 *
 * Blocked (non-exhaustive):
 *  - IPv4 loopback 127.0.0.0/8, unspecified 0.0.0.0/8
 *  - Private ranges 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 *  - Link-local 169.254.0.0/16 (includes cloud metadata 169.254.169.254)
 *  - CGNAT 100.64.0.0/10, benchmark 198.18.0.0/15, documentation ranges
 *  - Multicast/reserved 224.0.0.0/4, 240.0.0.0/4
 *  - IPv6 ::1, ::, fc00::/7, fe80::/10, ff00::/8, discard 100::/64
 *  - IPv4-mapped IPv6 ::ffff:0:0/96 and NAT64 64:ff9b::/96 (embedded v4 checked)
 */

const log = createLogger('network-scope');

export class ScopeViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeViolationError';
  }
}

interface IpRange4 {
  start: number; // unsigned 32-bit
  end: number;
  label: string;
}

interface IpRange6 {
  start: bigint;
  end: bigint;
  label: string;
}

const u32 = (a: number, b: number, c: number, d: number): number =>
  ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;

function cidr4(a: number, b: number, c: number, d: number, bits: number): IpRange4 {
  const base = u32(a, b, c, d);
  const size = 2 ** (32 - bits);
  return { start: base, end: base + size - 1, label: `${a}.${b}.${c}.${d}/${bits}` };
}

const BLOCKED_V4: IpRange4[] = [
  cidr4(0, 0, 0, 0, 8), // unspecified ("this host")
  cidr4(10, 0, 0, 0, 8), // private
  cidr4(100, 64, 0, 0, 10), // CGNAT
  cidr4(127, 0, 0, 0, 8), // loopback
  cidr4(169, 254, 0, 0, 16), // link-local incl. cloud metadata 169.254.169.254
  cidr4(172, 16, 0, 0, 12), // private
  cidr4(192, 0, 0, 0, 24), // IETF protocol assignments
  cidr4(192, 0, 2, 0, 24), // TEST-NET-1
  cidr4(192, 88, 99, 0, 24), // 6to4 relay anycast
  cidr4(192, 168, 0, 0, 16), // private
  cidr4(198, 18, 0, 0, 15), // benchmarking
  cidr4(198, 51, 100, 0, 24), // TEST-NET-2
  cidr4(203, 0, 113, 0, 24), // TEST-NET-3
  cidr4(224, 0, 0, 0, 4), // multicast
  cidr4(240, 0, 0, 0, 4), // reserved (incl. 255.255.255.255 broadcast)
];

/** Build a 128-bit bigint from eight 16-bit groups. */
function addr6(groups: number[]): bigint {
  let v = 0n;
  for (const g of groups) v = (v << 16n) | BigInt(g);
  return v;
}

function cidr6(groups: number[], bits: number, label: string): IpRange6 {
  const base = addr6(groups);
  const hostBits = BigInt(128 - bits);
  const start = (base >> hostBits) << hostBits;
  const end = start | ((1n << hostBits) - 1n);
  return { start, end, label };
}

const BLOCKED_V6: IpRange6[] = [
  cidr6([0, 0, 0, 0, 0, 0, 0, 0], 128, '::/128 (unspecified)'),
  cidr6([0, 0, 0, 0, 0, 0, 0, 1], 128, '::1/128 (loopback)'),
  cidr6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96, '64:ff9b::/96 (NAT64)'),
  cidr6([0x100, 0, 0, 0, 0, 0, 0, 0], 64, '100::/64 (discard-only)'),
  cidr6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7, 'fc00::/7 (unique local)'),
  cidr6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10, 'fe80::/10 (link-local)'),
  cidr6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8, 'ff00::/8 (multicast)'),
];

const IPV4_MAPPED_PREFIX = 0xffffn << 32n; // ::ffff:0:0/96
const IPV4_MAPPED_MAX = IPV4_MAPPED_PREFIX | 0xffffffffn;

export function parseIpv6(addr: string): bigint | null {
  const clean = addr.split('%')[0];
  if (!clean.includes(':')) return null;
  const parts = clean.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (parts.length === 2 && missing < 1) return null;
  if (parts.length === 1 && head.length !== 8) return null;
  const groups: string[] = [
    ...head,
    ...(parts.length === 2 ? Array<string>(missing).fill('0') : []),
    ...tail,
  ];
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    value = (value << 16n) | BigInt(parseInt(g, 16));
  }
  return value;
}

function checkIpv4(ip: string): void {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) {
    throw new ScopeViolationError(`Malformed IPv4 literal: ${ip}`);
  }
  const value = u32(octets[0], octets[1], octets[2], octets[3]);
  for (const range of BLOCKED_V4) {
    if (value >= range.start && value <= range.end) {
      throw new ScopeViolationError(
        `Target resolves into blocked network range ${range.label} (${ip}) — SSRF boundary enforced`,
      );
    }
  }
}

function checkIpv6(ip: string): void {
  const value = parseIpv6(ip);
  if (value === null) {
    throw new ScopeViolationError(`Malformed IPv6 literal: ${ip}`);
  }
  // IPv4-mapped ::ffff:a.b.c.d — evaluate embedded IPv4 against the v4 blocklist.
  if (value >= IPV4_MAPPED_PREFIX && value <= IPV4_MAPPED_MAX) {
    const v4 = [
      Number((value >> 24n) & 0xffn),
      Number((value >> 16n) & 0xffn),
      Number((value >> 8n) & 0xffn),
      Number(value & 0xffn),
    ];
    checkIpv4(v4.join('.'));
    return;
  }
  for (const range of BLOCKED_V6) {
    if (value >= range.start && value <= range.end) {
      throw new ScopeViolationError(
        `Target resolves into blocked IPv6 range ${range.label} (${ip}) — SSRF boundary enforced`,
      );
    }
  }
}

/** Check a single IP literal against the blocklist. Throws ScopeViolationError. */
export function assertIpAllowed(ip: string): void {
  const version = isIP(ip);
  if (version === 4) {
    checkIpv4(ip);
  } else if (version === 6) {
    checkIpv6(ip);
  } else {
    throw new ScopeViolationError(`Not an IP literal: ${ip}`);
  }
}

export interface ScopeCheckResult {
  host: string;
  addresses: string[];
  checkedAt: string;
}

/**
 * Resolve hostname and verify every resolved address is publicly routable.
 * For IP literals the check is direct (no DNS). Throws ScopeViolationError.
 */
export async function assertHostInScope(host: string): Promise<ScopeCheckResult> {
  const bare = host.replace(/^\[|\]$/g, '').toLowerCase();

  if (
    bare === 'localhost' ||
    bare.endsWith('.localhost') ||
    bare.endsWith('.local') ||
    bare.endsWith('.internal')
  ) {
    throw new ScopeViolationError(`Internal hostname '${bare}' is blocked`);
  }

  const literalVersion = isIP(bare);
  if (literalVersion !== 0) {
    assertIpAllowed(bare);
    return { host: bare, addresses: [bare], checkedAt: new Date().toISOString() };
  }

  const [v4, v6] = await Promise.all([
    dns.resolve4(bare).catch(() => [] as string[]),
    dns.resolve6(bare).catch(() => [] as string[]),
  ]);

  const addresses = [...v4, ...v6];
  if (addresses.length === 0) {
    throw new ScopeViolationError(`DNS resolution failed for '${bare}' — refusing to scan`);
  }

  for (const addr of addresses) {
    assertIpAllowed(addr);
  }

  log.info('scope check passed', { host: bare, addresses });
  return { host: bare, addresses, checkedAt: new Date().toISOString() };
}
