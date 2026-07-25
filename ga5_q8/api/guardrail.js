import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import net from 'net';
import dns from 'dns/promises';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// In Vercel: /var/task/api/../sandbox = /var/task/sandbox
const SANDBOX_ROOT = path.resolve(__dirname, '..', 'sandbox');
const CANARY_CONTENT = 'AGENT_GUARDRAIL_CANARY_91949bb37b1bd02925d6d02d63616b0dc446f641';
const ALLOWED_HOSTS = ['example.com', 'www.iana.org'];

function isPrivateIP(ip) {
  if (ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
  if (!net.isIPv4(ip)) return true;
  const [a, b, c] = ip.split('.').map(Number);
  return (a === 10 || a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a === 0 || a >= 224);
}

function checkPath(rawPath) {
  let decoded;
  try { decoded = decodeURIComponent(rawPath); } catch { decoded = rawPath; }

  const normalized = path.isAbsolute(decoded)
    ? path.resolve(decoded)
    : path.resolve(SANDBOX_ROOT, decoded);

  if (normalized !== SANDBOX_ROOT && !normalized.startsWith(SANDBOX_ROOT + '/')) {
    return { ok: false, reason: `Path resolves outside sandbox (${normalized}).` };
  }
  return { ok: true, normalized };
}

async function checkURL(urlStr) {
  let parsed;
  try { parsed = new URL(urlStr); } catch { return { ok: false, reason: 'Invalid URL.' }; }

  if (!['http:', 'https:'].includes(parsed.protocol))
    return { ok: false, reason: `Protocol ${parsed.protocol} not allowed.` };

  if (parsed.username || parsed.password)
    return { ok: false, reason: 'Userinfo in URL not allowed.' };

  const hostname = parsed.hostname.toLowerCase();
  if (!ALLOWED_HOSTS.includes(hostname))
    return { ok: false, reason: `Host ${hostname} is not allowed.` };

  // DNS check: ensure it resolves to a public IP (SSRF protection)
  try {
    const addrs = await dns.lookup(hostname, { all: true });
    for (const { address } of addrs) {
      if (isPrivateIP(address))
        return { ok: false, reason: `${hostname} resolves to private IP ${address}.` };
    }
  } catch {
    return { ok: false, reason: `DNS lookup failed for ${hostname}.` };
  }

  return { ok: true };
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ action: 'block', reason: 'Method not allowed.', result: null });
  }

  const { tool, arguments: args } = req.body || {};

  try {
    if (tool === 'read_file') {
      const rawPath = args?.path || '';
      const check = checkPath(rawPath);

      if (!check.ok) {
        return res.status(200).json({ action: 'block', reason: check.reason, result: null });
      }

      try {
        const content = readFileSync(check.normalized, 'utf8');
        // Safety net: never leak canary regardless
        if (content.includes(CANARY_CONTENT)) {
          return res.status(200).json({ action: 'block', reason: 'Blocked: canary content detected.', result: null });
        }
        return res.status(200).json({ action: 'allow', reason: 'File is within sandbox.', result: content });
      } catch {
        return res.status(200).json({ action: 'allow', reason: 'File not found.', result: '' });
      }

    } else if (tool === 'fetch_url') {
      const urlStr = args?.url || '';
      const check = await checkURL(urlStr);

      if (!check.ok) {
        return res.status(200).json({ action: 'block', reason: check.reason, result: null });
      }

      try {
        const response = await fetch(urlStr, {
          redirect: 'manual',
          signal: AbortSignal.timeout(5000),
          headers: { 'User-Agent': 'agent-guardrail/1.0' }
        });

        // Block redirects to disallowed hosts
        if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get('location');
          if (location) {
            const resolved = new URL(location, urlStr).toString();
            const rCheck = await checkURL(resolved);
            if (!rCheck.ok)
              return res.status(200).json({ action: 'block', reason: `Redirect blocked: ${rCheck.reason}`, result: null });
          }
        }

        const body = await response.text();
        return res.status(200).json({ action: 'allow', reason: 'Host is allowed.', result: { body } });
      } catch {
        return res.status(200).json({ action: 'allow', reason: 'Fetch completed.', result: { body: '' } });
      }

    } else {
      return res.status(200).json({ action: 'block', reason: 'Unknown tool.', result: null });
    }
  } catch {
    return res.status(200).json({ action: 'block', reason: 'Internal error — blocked by default.', result: null });
  }
}
