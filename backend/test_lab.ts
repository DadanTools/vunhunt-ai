/**
 * VulnHunter AI - Local Authorized Security Test Lab Fixtures
 * Mock-free, deterministic endpoints designed to safely test each detector
 * locally without external requests or risk.
 */

import { Router, Request, Response } from 'express';

export const testLabRouter = Router();

// Test Lab Status / Directory
testLabRouter.get('/', (_req: Request, res: Response) => {
  res.json({
    status: 'online',
    description: 'VulnHunter AI Local Security Test Lab Fixtures',
    endpoints: [
      { path: '/api/lab/headers', description: 'Tests missing security headers & insecure cookies' },
      { path: '/api/lab/secure-endpoint', description: 'Negative test fixture: Fully hardened headers and cookies' },
      { path: '/api/lab/reflected', query: '?q=canary', description: 'Safe reflected input canary check' },
      { path: '/api/lab/cors', description: 'Tests permissive CORS origin reflection' },
      { path: '/api/lab/idor/document/:id', description: 'BOLA/IDOR test objects (id: doc_a_101 vs doc_b_202)' },
      { path: '/api/lab/ssrf-receiver', description: 'SSRF local callback validator receiver' },
      { path: '/api/lab/sensitive-path/.git/config', description: 'Tests sensitive path exposure detection' }
    ]
  });
});

// 1. Insecure Headers & Cookies Fixture
testLabRouter.get('/headers', (_req: Request, res: Response) => {
  // Deliberately omit CSP, X-Frame-Options, HSTS, X-Content-Type-Options
  res.setHeader('Set-Cookie', ['session_id=s3cur3t0k3n_test123; Path=/', 'user_pref=dark; Path=/']);
  res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
  res.setHeader('X-Powered-By', 'PHP/7.4.3');
  res.status(200).send(`<!DOCTYPE html><html><head><title>Insecure Headers Lab</title></head><body><h1>VulnHunter Lab: Vulnerable Headers Target</h1><p>This endpoint deliberately lacks modern security headers for scanner validation.</p></body></html>`);
});

// 2. Negative Test Fixture (Hardened Endpoint)
testLabRouter.get('/secure-endpoint', (_req: Request, res: Response) => {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; object-src 'none'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  res.setHeader('Set-Cookie', 'secure_session=v3ry_s3cur3; Path=/; Secure; HttpOnly; SameSite=Strict');
  res.status(200).send(`<!DOCTYPE html><html><head><title>Hardened Lab</title></head><body><h1>Hardened Target</h1><p>All security headers and secure cookie flags present.</p></body></html>`);
});

// 3. Safe Reflected Canary Fixture
testLabRouter.get('/reflected', (req: Request, res: Response) => {
  const query = req.query.q || req.query.canary || '';
  // Safely reflects string for detector heuristic confirmation
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(`<!DOCTYPE html><html><body><h1>Search Results</h1><p>You searched for: ${query}</p></body></html>`);
});

// 4. Permissive CORS Fixture
testLabRouter.get('/cors', (req: Request, res: Response) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.json({
    status: 'ok',
    message: 'CORS test endpoint with permissive origin reflection'
  });
});

// 5. BOLA / IDOR Dual-Tenant Fixture
// In an IDOR test, Tenant A has token 'token-alice', Tenant B has token 'token-bob'
// doc_a_101 belongs to Alice, doc_b_202 belongs to Bob.
// If Alice accesses Bob's doc without authorization check, IDOR is confirmed!
const documents: Record<string, { owner: string; title: string; content: string }> = {
  'doc_a_101': { owner: 'alice', title: 'Alice Confidential Q3 Strategy', content: 'Internal review of Alice project scope.' },
  'doc_b_202': { owner: 'bob', title: 'Bob Private Payroll Preview', content: 'Sensitive salary details for Bob.' }
};

testLabRouter.get('/idor/document/:id', (req: Request, res: Response) => {
  const docId = req.params.id;
  const authHeader = req.headers.authorization || '';
  const doc = documents[docId];

  if (!doc) {
    res.status(404).json({ error: 'Document not found' });
    return;
  }

  // IDOR vulnerability simulation:
  // If authorization header is provided, it does not check if the user is the owner!
  if (authHeader.includes('token-alice') || authHeader.includes('token-bob')) {
    const caller = authHeader.includes('token-alice') ? 'alice' : 'bob';
    res.json({
      document_id: docId,
      owner: doc.owner,
      requested_by: caller,
      title: doc.title,
      content: doc.content,
      access_granted: true,
      idor_indicator: caller !== doc.owner ? 'VULNERABILITY_CONFIRMED_CROSS_TENANT_READ' : 'AUTHORIZED_OWNER_READ'
    });
    return;
  }

  res.status(401).json({ error: 'Authentication required. Pass Authorization header.' });
});

// 6. Safe Local SSRF Callback Receiver
const ssrfLogs: Array<{ id: string; timestamp: string; ip: string; headers: Record<string, string>; token?: string }> = [];

testLabRouter.all('/ssrf-receiver', (req: Request, res: Response) => {
  const token = (req.query.token as string) || (req.headers['x-ssrf-token'] as string) || undefined;
  const entry = {
    id: 'ssrf-' + Date.now(),
    timestamp: new Date().toISOString(),
    ip: req.ip || req.socket.remoteAddress || 'unknown',
    headers: req.headers as Record<string, string>,
    token
  };
  ssrfLogs.unshift(entry);
  if (ssrfLogs.length > 50) ssrfLogs.pop();

  res.json({
    status: 'recorded',
    receiver: 'VulnHunter AI Safe Local SSRF Receiver',
    entry
  });
});

testLabRouter.get('/ssrf-receiver/logs', (_req: Request, res: Response) => {
  res.json({ count: ssrfLogs.length, logs: ssrfLogs });
});

// 7. Sensitive Path Exposure Fixture
testLabRouter.get('/sensitive-path/.git/config', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/plain');
  res.status(200).send(`[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/authorized-lab/repo.git\n`);
});

testLabRouter.get('/sensitive-path/.env', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/plain');
  res.status(200).send(`# VulnHunter Lab Test File\nDATABASE_URL=sqlite:///data/test.sqlite\nDEBUG=True\n`);
});
