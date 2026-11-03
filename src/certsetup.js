// Turns on web filtering for an install whose setup skipped it: the same steps as the
// installer's "block YouTube and in-page ads" task (installer/post-install.ps1), run by the
// AdHush service (LocalSystem) when the user clicks "Turn on" in the app.
//   1. adhush-core --init-ca creates this PC's own root certificate (private key never leaves it)
//   2. the ca folder is locked to SYSTEM and Administrators
//   3. the certificate is trusted machine-wide; its thumbprint is recorded for the uninstaller
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';

function run(file, args, timeout = 60000) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout }, (err, stdout, stderr) => {
      if (err) reject(new Error((stderr || err.message).trim().split(/\r?\n/).pop()));
      else resolve(stdout.trim());
    });
  });
}

export async function installCertificate({ dataDir, coreBinary }) {
  if (process.platform !== 'win32') throw Object.assign(new Error('only supported on Windows'), { status: 400 });
  if (!coreBinary) throw Object.assign(new Error('the web filter (adhush-core) is missing from this installation'), { status: 500 });
  const pem = (await run(coreBinary, ['--data', dataDir, '--init-ca'])).split(/\r?\n/).pop();
  if (!fs.existsSync(pem)) throw new Error('the certificate was not created');
  const caDir = path.join(dataDir, 'ca');
  await run('icacls.exe', [caDir, '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F']);
  // Adding to the machine-wide Root store needs administrator rights: true for the AdHush service.
  const ps = `$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList '${pem.replace(/'/g, "''")}';
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store 'Root','LocalMachine';
    $s.Open('ReadWrite'); $s.Add($c); $s.Close(); $c.Thumbprint`;
  let thumbprint;
  try {
    thumbprint = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps]);
  } catch (e) {
    throw Object.assign(new Error(/denied/i.test(e.message) ? 'needs administrator rights: this works in the installed AdHush (its service runs as administrator)' : e.message), { status: 403 });
  }
  if (!/^[0-9A-F]{40}$/i.test(thumbprint)) throw new Error(`unexpected certificate thumbprint: ${thumbprint}`);
  fs.writeFileSync(path.join(caDir, 'installed-thumbprint'), thumbprint);
  return thumbprint;
}
