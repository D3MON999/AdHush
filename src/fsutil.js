import fs from 'node:fs';

const RETRYABLE = new Set(['EPERM', 'EBUSY', 'EACCES']);
const pause = new Int32Array(new SharedArrayBuffer(4));

// Write-then-rename so readers never see a half-written file. On Windows the rename fails while
// another process (adhush-core, antivirus) has the target open, so retry briefly and finally
// fall back to writing in place.
export function writeFileAtomic(file, data) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, data);
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      fs.renameSync(tmp, file);
      return;
    } catch (e) {
      if (!RETRYABLE.has(e.code)) throw e;
      Atomics.wait(pause, 0, 0, 25);
    }
  }
  fs.writeFileSync(file, data);
  fs.rmSync(tmp, { force: true });
}
