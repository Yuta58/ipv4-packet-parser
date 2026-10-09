# IPv4 Packet Parser

Decodes an IPv4 datagram `Uint8Array` into version, IHL, total length, protocol, source/destination addresses, header options, and the byte offset of the transport payload.

```js
import { parseIpv4 } from './src/index.js';

const datagram = new Uint8Array([
  0x45, // version 4, IHL 5
  0x00, // DSCP/ECN
  0x01, 0xf4, // total length = 500
  0x00, 0x01, // identification
  0x00, 0x00, // flags/fragment offset
  0x40, // TTL = 64
  0x11, // protocol = 17 (UDP)
  0x00, 0x00, // header checksum
  10, 0, 0, 1, // source address 10.0.0.1
  192, 168, 1, 1, // destination address 192.168.1.1
]);

const pkt = parseIpv4(datagram);
console.log(pkt.sourceAddress, pkt.destinationAddress, pkt.payloadOffset);
```

## Why

Hand-rolling the same field offsets every time a parser needs them is busywork
that invites off-by-one errors (the `version`/`IHL` nibble split and the
`IHL * 4` length are the usual offenders). This library centralises that
arithmetic and hands back a plain object.

The trade-off: we validate that the buffer is long enough for the header
*as declared by IHL* and that the argument is a `Uint8Array`, but we do not
check the version nibble (callers demultiplex on it themselves) and we do not
validate checksums, TTL, or that `totalLength` actually fits in the
buffer. Those are higher-layer concerns; this library only reads fields.

## The awkward edge

`options` is `null` when IHL is 5 (no options) and a `Uint8Array` view into
the original buffer otherwise. That view is **not a copy** — it aliases the
input bytes, so mutating the original after parsing is visible through the
returned `options`. This is intentional: the typical next step is forwarding
the bytes to a TCP/UDP parser, where avoiding a copy matters.

If `IHL` declares a header longer than the buffer, `parseIpv4` throws a
`RangeError` whose message names the declared header length and the actual
buffer length. An empty buffer throws a `RangeError` specifically naming the
version/IHL byte.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

