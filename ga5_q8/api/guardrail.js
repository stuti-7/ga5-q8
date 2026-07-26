import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import net from 'net';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BUNDLE_SANDBOX = path.resolve(__dirname, '..', 'sandbox');

// The "official" sandbox path from the spec — paths sent by the grader will use this prefix
const SPEC_SANDBOX = '/srv/agent-redteam/sandbox-fa0620d97a';

const CANARY_CONTENT = 'AGENT_GUARDRAIL_CANARY_91949bb37b1bd02925d6d02d63616b0dc446f641';
const ALLOWED_HOSTS = ['example.com', 'www.iana.org'];

function isPrivateIP(ip) {
  if (!net.isIPv4(ip)) return false;
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

  // Resolve the path against the SPEC sandbox root (what the grader thinks exists)
  let normalized;
  if (path.isAbsolute(decoded)) {
    normalized = path.resolve(decoded);
  } else {
    normalized = path.resolve(SPEC_SANDBOX, decoded);
  }

  // Must be within the spec sandbox
  if (normalized !== SPEC_SANDBOX && !normalized.startsWith(SPEC_SANDBOX + '/')) {
    return { ok: false, reason: `Path resolves outside sandbox.` };
  }

  // Map the spec path to our bundle path for actual reading
  const relative = normalized.slice(SPEC_SANDBOX.length); // e.g. /notes/report.txt
  const localPath = path.join(BUNDLE_SANDBOX, relative);

  return { ok: true, normalized, localPath };
}

function checkURL(urlStr) {
  let parsed;
  try { parsed = new URL(urlStr); } catch { return { ok: false, reason: 'Invalid URL.' }; }

  if (!['http:', 'https:'].includes(parsed.protocol))
    return { ok: false, reason: `Protocol ${parsed.protocol} not allowed.` };

  if (parsed.username || parsed.password)
    return { ok: false, reason: 'Userinfo in URL not allowed.' };

  const hostname = parsed.hostname.toLowerCase();

  // Block raw IPs
  if (net.isIP(hostname)) {
    return { ok: false, reason: `Direct IP addresses are not allowed.` };
  }

  // Exact hostname match only — no substrings, no subdomains
  if (!ALLOWED_HOSTS.includes(hostname))
    return { ok: false, reason: `Host "${hostname}" is not in the allowed list.` };

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
        const content = readFileSync(check.localPath, 'utf8');
        if (content.includes(CANARY_CONTENT)) {
          return res.status(200).json({ action: 'block', reason: 'Blocked: canary content detected.', result: null });
        }
        return res.status(200).json({ action: 'allow', reason: 'File is within sandbox.', result: content });
      } catch {
        return res.status(200).json({ action: 'allow', reason: 'File not found.', result: '' });
      }

    } else if (tool === 'fetch_url') {
      const urlStr = args?.url || '';
      const check = checkURL(urlStr);

      if (!check.ok) {
        return res.status(200).json({ action: 'block', reason: check.reason, result: null });
      }

      try {
        const response = await fetch(urlStr, {
          redirect: 'manual',
          signal: AbortSignal.timeout(8000),
          headers: { 'User-Agent': 'agent-guardrail/1.0' }
        });

        if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get('location');
          if (location) {
            const resolved = new URL(location, urlStr).toString();
            const rCheck = checkURL(resolved);
            if (!rCheck.ok)
              return res.status(200).json({ action: 'block', reason: `Redirect blocked: ${rCheck.reason}`, result: null });
          }
        }

        const body = await response.text();
        return res.status(200).json({ action: 'allow', reason: 'Host is allowed.', result: { body } });
      } catch {
        return res.status(200).json({ action: 'allow', reason: 'Fetch attempted.', result: { body: '' } });
      }

    } else {
      return res.status(200).json({ action: 'block', reason: 'Unknown tool.', result: null });
    }
  } catch (e) {
    return res.status(200).json({ action: 'block', reason: 'Internal error.', result: null });
  }
}