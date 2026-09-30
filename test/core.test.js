import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseIpv4 } from '../src/index.js';

function buildPacket({ ihl = 5, optionsBytes = new Uint8Array(0) } = {}) {
  // Build a packet with a known shape so the assertions are obvious.
  const headerLength = ihl * 4;
  const buf = new Uint8Array(headerLength);

  // Byte 0: version (4) in the high nibble, IHL in the low nibble.
  buf[0] = (4 << 4) | (ihl & 0x0f);

  // Bytes 2-3: total length. Use a value distinct from the buffer length so
  // we can confirm the parser reads the bytes rather than echoing byteLength.
  buf[2] = 0x01;
  buf[3] = 0xf4; // 500

  // Byte 9: protocol. 17 = UDP.
  buf[9] = 17;

  // Bytes 12-15: source IP 10.0.0.1
  buf[12] = 10;
  buf[13] = 0;
  buf[14] = 0;
  buf[15] = 1;

  // Bytes 16-19: destination IP 192.168.1.1
  buf[16] = 192;
  buf[17] = 168;
  buf[18] = 1;
  buf[19] = 1;

  buf.set(optionsBytes, 20);
  return buf;
}

describe('parseIpv4', () => {
  it('parses a minimal 20-byte header', () => {
    const buf = buildPacket();
    const out = parseIpv4(buf);

    assert.equal(out.version, 4);
    assert.equal(out.ihl, 5);
    assert.equal(out.headerLength, 20);
    assert.equal(out.totalLength, 500);
    assert.equal(out.protocol, 17);
    assert.equal(out.sourceAddress, '10.0.0.1');
    assert.equal(out.destinationAddress, '192.168.1.1');
    assert.equal(out.options, null);
    assert.equal(out.payloadOffset, 20);
  });

  it('parses a header with options and sets the payload offset past them', () => {
    // IHL=6 → 24-byte header → 4 option bytes starting at offset 20.
    const opts = new Uint8Array([0x01, 0x00, 0x00, 0x00]);
    const buf = buildPacket({ ihl: 6, optionsBytes: opts });
    const out = parseIpv4(buf);

    assert.equal(out.ihl, 6);
    assert.equal(out.headerLength, 24);
    assert.equal(out.payloadOffset, 24);
    assert.deepEqual(Array.from(out.options), Array.from(opts));
  });

  it('rejects an empty buffer with a RangeError', () => {
    assert.throws(
      () => parseIpv4(new Uint8Array(0)),
      (err) => err instanceof RangeError && /version\/IHL/.test(err.message)
    );
  });

  it('rejects a buffer shorter than the declared header', () => {
    // Declare IHL=6 (24 bytes) but only give 21.
    const buf = buildPacket({ ihl: 6 });
    const truncated = buf.subarray(0, 21);
    assert.throws(
      () => parseIpv4(truncated),
      (err) => err instanceof RangeError && /IHL=6/.test(err.message)
    );
  });

  it('returns options as null for the minimum IHL', () => {
    const buf = buildPacket({ ihl: 5 });
    const out = parseIpv4(buf);
    assert.equal(out.options, null);
    assert.equal(out.payloadOffset, 20);
  });

  it('throws a TypeError for a non-Uint8Array argument', () => {
    assert.throws(
      () => parseIpv4('not a buffer'),
      (err) => err instanceof TypeError
    );
  });

  it('does not modify the input buffer', () => {
    const buf = buildPacket();
    const snapshot = Uint8Array.from(buf);
    parseIpv4(buf);
    assert.deepEqual(Array.from(buf), Array.from(snapshot));
  });
});
