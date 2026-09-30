/**
 * Decodes an IPv4 datagram buffer into its constituent header fields and
 * a byte offset pointing at the start of the transport-layer payload.
 *
 * Design decisions:
 * - The function accepts a `Uint8Array` view, not a `Buffer`. `Buffer` is a
 *   Node-ism; `Uint8Array` works in browsers and Node alike. We touch only
 *   `byteLength` and indexed access, which both provide.
 * - On truncation we throw a `RangeError` whose message names the byte we were
 *   about to read. This is the minimum useful diagnostic — the caller knows the
 *   buffer was short without having to re-derive the byte count.
 * - We never allocate for the payload. Callers usually want to feed the bytes
 *   straight into a TCP/UDP parser; handing back an offset avoids a copy.
 */
export function parseIpv4(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('parseIpv4 expects a Uint8Array');
  }
  if (buffer.byteLength < 1) {
    throw new RangeError('buffer too short: need at least byte 0 (version/IHL)');
  }

  const versionIhl = buffer[0];
  const version = versionIhl >>> 4;
  const ihl = versionIhl & 0x0f;

  // IHL is measured in 32-bit words; the minimum legal value is 5 (20 bytes).
  // We deliberately do NOT throw on an out-of-range IHL before checking the
  // buffer length: a 0-length buffer is a caller error we can diagnose
  // immediately, while a short IHL field is a packet error we report only
  // once we know we cannot read the full header.
  const headerLength = ihl * 4;

  if (buffer.byteLength < headerLength) {
    throw new RangeError(
      `buffer too short for header: need ${headerLength} bytes (IHL=${ihl}), have ${buffer.byteLength}`
    );
  }

  const totalLength = (buffer[2] << 8) | buffer[3];
  const protocol = buffer[9];

  const sourceAddress = [
    buffer[12], buffer[13], buffer[14], buffer[15]
  ].join('.');
  const destinationAddress = [
    buffer[16], buffer[17], buffer[18], buffer[19]
  ].join('.');

  let options = null;
  if (headerLength > 20) {
    options = buffer.subarray(20, headerLength);
  }

  return {
    version,
    ihl,
    headerLength,
    totalLength,
    protocol,
    sourceAddress,
    destinationAddress,
    options,
    payloadOffset: headerLength
  };
}
