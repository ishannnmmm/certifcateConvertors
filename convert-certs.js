/**
 * convert-certs.js
 *
 * Usage:
 *   node convert-certs.js path/to/input.txt
 *
 * What it does:
 * - Reads an input file which may contain:
 *   * one or more PEM blocks (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)
 *   * or plain base64 certificate blocks (no PEM wrapper)
 *   * optionally lines like `subject=...` / `issuer=...` — ignored for parsing but printed
 * - Normalizes each certificate into proper PEM (64-char lines)
 * - Writes:
 *     ./out/cert-1.pem, cert-2.pem, ...
 *     ./out/certificate.pem        <-- chosen leaf certificate (best-effort)
 *     ./out/certificate_chain.pem  <-- concatenation of remaining certs (intermediates/roots)
 *     ./out/upload-ready.json      <-- JSON with Certificate and CertificateChain (strings)
 * - Optionally runs openssl to print readable details for each cert (if openssl available)
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

if (process.argv.length < 3) {
  console.error('Usage: node convert-certs.js input.txt');
  process.exit(2);
}

const inputPath = process.argv[2];
const raw = fs.readFileSync(inputPath, 'utf8');

function wrap64(str) {
  return str.replace(/(.{1,64})/g, '$1\n').trim();
}

// 1) Extract PEM blocks if present
const pemRegex = /-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/gs;
let matches = Array.from(raw.matchAll(pemRegex)).map(m => m[1].replace(/\r?\n/g, '').trim());

// 2) If no PEM blocks found, search for long base64-like blocks (best-effort)
if (matches.length === 0) {
  // Remove lines that start with subject= or issuer= or other text
  const cleaned = raw
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !/^subject=/i.test(l) && !/^issuer=/i.test(l))
    .join('\n');

  // Find sequences of base64 (A-Z a-z 0-9 + / =) longer than, say, 200 chars
  const base64Regex = /([A-Za-z0-9+/=\s]{200,})/g;
  const base64Matches = Array.from(cleaned.matchAll(base64Regex)).map(m => m[1].replace(/\s+/g, ''));
  matches = base64Matches;
}

// If still none, try to capture any lines between BEGIN/END markers even if broken
if (matches.length === 0) {
  console.warn('No PEM or long base64 blocks found. Attempting line-by-line heuristic...');
  const lines = raw.split(/\r?\n/).map(l => l.trim());
  let buffer = '';
  const potential = [];
  for (const line of lines) {
    if (/^-----BEGIN CERTIFICATE-----$/i.test(line)) {
      buffer = '';
      continue;
    }
    if (/^-----END CERTIFICATE-----$/i.test(line)) {
      if (buffer.length > 0) potential.push(buffer.replace(/\s+/g, ''));
      buffer = '';
      continue;
    }
    // If the line looks like base64, append
    if (/^[A-Za-z0-9+/=]+$/.test(line)) buffer += line;
  }
  matches = potential;
}

if (matches.length === 0) {
  console.error('No certificates found in input file.');
  process.exit(3);
}

const outDir = path.join(process.cwd(), 'out');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);

const pemFiles = [];

matches.forEach((b64, i) => {
  const cleanedB64 = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  const pem = `-----BEGIN CERTIFICATE-----\n${wrap64(cleanedB64)}\n-----END CERTIFICATE-----\n`;
  const fname = path.join(outDir, `cert-${i + 1}.pem`);
  fs.writeFileSync(fname, pem, 'utf8');
  pemFiles.push({ path: fname, pem, rawB64: cleanedB64 });
  console.log(`Wrote ${fname}`);
});

// Helper: try to run openssl to get subject/issuer and determine leaf certificate
function opensslInspect(pemPath) {
  try {
    const res = spawnSync('openssl', ['x509', '-noout', '-subject', '-issuer', '-dates', '-in', pemPath], { encoding: 'utf8' });
    if (res.error) return null;
    return res.stdout.trim();
  } catch (e) {
    return null;
  }
}

// Gather metadata
const meta = pemFiles.map(p => {
  const info = opensslInspect(p.path);
  let subject = null, issuer = null, notBefore = null, notAfter = null;
  if (info) {
    const sub = info.match(/subject=(.*)/);
    const iss = info.match(/issuer=(.*)/);
    const nb = info.match(/notBefore=(.*)/);
    const na = info.match(/notAfter=(.*)/);
    subject = sub ? sub[1].trim() : null;
    issuer = iss ? iss[1].trim() : null;
    notBefore = nb ? nb[1].trim() : null;
    notAfter = na ? na[1].trim() : null;
  }
  return { path: p.path, subject, issuer, notBefore, notAfter, pem: p.pem, rawB64: p.rawB64 };
});

// Attempt to pick leaf cert:
// Heuristics:
// 1) If a cert's issuer matches another cert's subject, it is NOT leaf.
// 2) The cert whose issuer is not equal to any subject -> likely leaf.
// 3) Otherwise fallback to first cert.
let leafIndex = 0;
try {
  const subjects = meta.map((m, i) => ({ subject: m.subject, i })).filter(x => x.subject);
  const subjectStrings = subjects.map(s => s.subject);
  // find candidate whose issuer does not match any subject
  const candidate = meta.find(m => m.issuer && !subjectStrings.includes(m.issuer));
  if (candidate) {
    leafIndex = meta.indexOf(candidate);
  } else {
    // fallback: choose first cert
    leafIndex = 0;
  }
} catch (e) {
  leafIndex = 0;
}

const leaf = meta[leafIndex];
const chainCerts = meta.filter((_, idx) => idx !== leafIndex);

// Write certificate.pem and certificate_chain.pem
const certificatePemPath = path.join(outDir, 'certificate.pem');
fs.writeFileSync(certificatePemPath, leaf.pem, 'utf8');
console.log(`Wrote leaf certificate -> ${certificatePemPath}`);

const chainPemPath = path.join(outDir, 'certificate_chain.pem');
if (chainCerts.length > 0) {
  // Concatenate remaining certs in order (best-effort)
  const combined = chainCerts.map(c => c.pem).join('\n');
  fs.writeFileSync(chainPemPath, combined, 'utf8');
  console.log(`Wrote certificate chain -> ${chainPemPath}`);
} else {
  // empty chain file to avoid errors
  fs.writeFileSync(chainPemPath, '', 'utf8');
  console.log(`No extra certs found; wrote empty chain file -> ${chainPemPath}`);
}

// Create upload-ready JSON object (useful if using SDK)
const uploadJson = {
  Certificate: fs.readFileSync(certificatePemPath, 'utf8'),
  CertificateChain: fs.readFileSync(chainPemPath, 'utf8')
};
const uploadJsonPath = path.join(outDir, 'upload-ready.json');
fs.writeFileSync(uploadJsonPath, JSON.stringify(uploadJson, null, 2), 'utf8');
console.log(`Wrote upload-ready JSON -> ${uploadJsonPath}`);

// Print human-readable details if available
console.log('\nCertificate inspection (using openssl if present):\n');
meta.forEach((m, idx) => {
  console.log(`=== cert-${idx + 1} (${m.path}) ===`);
  if (m.subject || m.issuer) {
    console.log(`Subject: ${m.subject || 'N/A'}`);
    console.log(`Issuer : ${m.issuer || 'N/A'}`);
    if (m.notBefore) console.log(`NotBefore: ${m.notBefore}`);
    if (m.notAfter) console.log(`NotAfter : ${m.notAfter}`);
  } else {
    console.log('openssl not available or could not parse this certificate.');
  }
  console.log('');
});

console.log('Done. Files written to ./out/');
console.log('For AWS Certificate Manager (ACM):\n - Paste certificate.pem content into "Certificate body"\n - Paste certificate_chain.pem content into "Certificate chain"\n (You will also need the private key for uploading a certificate to ACM outside of public CA issuance.)');
