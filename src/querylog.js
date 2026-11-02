// In-memory ring buffer of recent DNS requests (the "filtering log").
export class QueryLog {
  constructor(size = 5000) {
    this.size = size;
    this.items = [];
    this.seq = 0;
  }

  add(entry) {
    entry.id = ++this.seq;
    this.items.push(entry);
    if (this.items.length > this.size) this.items.splice(0, this.items.length - this.size);
  }

  // Newest first. status: all | blocked | allowed | rewritten | processed
  query({ limit = 200, search = '', status = 'all', sinceId = 0 } = {}) {
    const s = search.trim().toLowerCase();
    const out = [];
    for (let i = this.items.length - 1; i >= 0 && out.length < limit; i--) {
      const e = this.items[i];
      if (e.id <= sinceId) break;
      if (status !== 'all' && e.status !== status) continue;
      if (s && !e.name.includes(s) && !(e.client || '').includes(s) && !(e.rule || '').toLowerCase().includes(s)) continue;
      out.push(e);
    }
    return out;
  }

  clear() {
    this.items = [];
  }

  resize(size) {
    this.size = size;
    if (this.items.length > size) this.items.splice(0, this.items.length - size);
  }
}
