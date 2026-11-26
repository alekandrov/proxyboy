// Parser incremental de frames WebSocket (RFC 6455), solo lectura: observa el stream sin modificarlo.
const MAX_MESSAGE = 1024 * 1024; // guardamos hasta 1 MB por mensaje

const OPCODES = { 0: 'continuation', 1: 'text', 2: 'binary', 8: 'close', 9: 'ping', 10: 'pong' };

class FrameParser {
  constructor(onMessage) {
    this.buf = Buffer.alloc(0);
    this.onMessage = onMessage;
    this.fragments = null; // { opcode, chunks, size }
    this.dead = false;
  }

  push(chunk) {
    if (this.dead) return;
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    try {
      while (this._parseOne());
    } catch {
      this.dead = true; // stream que no entendemos: dejamos de parsear, el tráfico sigue
    }
  }

  _parseOne() {
    const b = this.buf;
    if (b.length < 2) return false;
    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return false;
      len = b.readUInt16BE(2); off = 4;
    } else if (len === 127) {
      if (b.length < 10) return false;
      len = Number(b.readBigUInt64BE(2)); off = 10;
    }
    let mask = null;
    if (masked) {
      if (b.length < off + 4) return false;
      mask = b.subarray(off, off + 4); off += 4;
    }
    if (b.length < off + len) return false;
    let payload = Buffer.from(b.subarray(off, off + len));
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    this.buf = b.subarray(off + len);

    if (opcode >= 8) {
      // Frames de control nunca se fragmentan
      this.onMessage({ opcode: OPCODES[opcode] || `op${opcode}`, payload, size: payload.length });
      return true;
    }
    if (opcode !== 0) this.fragments = { opcode, chunks: [], size: 0 };
    if (!this.fragments) return true;
    this.fragments.size += payload.length;
    if (this.fragments.size <= MAX_MESSAGE) this.fragments.chunks.push(payload);
    if (fin) {
      const f = this.fragments;
      this.fragments = null;
      this.onMessage({ opcode: OPCODES[f.opcode], payload: Buffer.concat(f.chunks), size: f.size, truncated: f.size > MAX_MESSAGE });
    }
    return true;
  }
}

module.exports = { FrameParser };
