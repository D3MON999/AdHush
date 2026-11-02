// In-memory feed of user-facing events (filter updates, crashes, pause expiry). The tray
// polls GET /api/notifications?since=<id> and turns new entries into Windows toasts.
export class Notifications {
  constructor({ size = 100, enabled = () => true } = {}) {
    this.size = size;
    this.enabled = enabled;
    this.items = [];
    this.last = 0;
  }

  push(level, title, body = '') {
    if (!this.enabled()) return null;
    const item = { id: ++this.last, ts: Date.now(), level, title, body };
    this.items.push(item);
    if (this.items.length > this.size) this.items.splice(0, this.items.length - this.size);
    return item;
  }

  since(id = 0) {
    return { last: this.last, items: this.items.filter((i) => i.id > id) };
  }
}
