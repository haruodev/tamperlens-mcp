/**
 * The SSRF guard behind `fetchDocument`'s `url` argument.
 *
 * WHY THIS EXISTS. `fetchDocument` fetches a caller-supplied URL, and the
 * server's own header is emphatic that the fetch runs on the caller's machine so
 * "an agent an attacker is steering could aim this at `http://169.254.169.254/…`".
 * The scheme allow-list alone does NOT stop that: `http://127.0.0.1`,
 * `http://169.254.169.254` (cloud metadata) and `http://10.x` are all `http:`
 * and sailed straight through. This module is the missing half — it inspects the
 * DESTINATION IP, not just the scheme, and refuses the non-routable ranges.
 *
 * PINNING, NOT JUST CHECKING (the anti-rebinding part). A check that resolves a
 * hostname, likes the answer, and then hands the hostname to the socket to
 * resolve AGAIN is a TOCTOU hole: a hostile resolver can return a public address
 * to the check and a private one to the connect (DNS rebinding). So the check is
 * done INSIDE the socket's own `lookup` — `guardedLookup` resolves once,
 * validates every address the resolver returned, and hands those same validated
 * addresses to the socket. The connection therefore uses exactly what was
 * validated; there is no second resolution to poison. Because `fetchDocument`
 * follows redirects by hand, every hop is a fresh request with this same lookup,
 * so the guard re-applies per hop for free, alongside the scheme re-check.
 *
 * NO NEW DEPENDENCY. The idiomatic way to pin is undici's `Agent({ connect: {
 * lookup } })`, but undici is not a dependency of this package (it ships two:
 * `@modelcontextprotocol/server` and `zod`) and Node's bundled copy is not an
 * importable module. Node's own `http`/`https` request options take a `lookup`
 * that flows to `net.connect` and pins identically, with nothing added to
 * install — so `fetchDocument` uses those instead of `fetch`. The IP-range math
 * is a few lines by hand rather than a `ipaddr.js`/`ip` dependency, same rule.
 *
 * A literal-IP URL (`http://127.0.0.1/`) never reaches `guardedLookup` — Node
 * skips DNS when the host already parses as an IP — so `fetchDocument` also
 * calls `isBlockedAddress` directly on a literal host per hop. Both paths share
 * this one predicate.
 */
import net from "node:net";
import dns from "node:dns";

/**
 * IPs the operator has DELIBERATELY allowed past the guard.
 *
 * The honest escape hatch for a self-hoster who really does point this at an
 * internal document store, and the seam the test suite uses to fetch from a
 * loopback origin. Empty by default — the secure default is that NOTHING
 * non-routable is reachable. Exact string match on the resolved/literal address,
 * read at call time so a test can set it per case and production never has it.
 */
function allowedIps(): Set<string> {
  const raw = process.env.TAMPERLENS_FETCH_ALLOW_IPS;
  if (!raw) return new Set();
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

/** The bytes of an IPv4 or IPv6 address, or null when it does not parse. Relies
 * on `net.isIP` having already vetted the shape; this only unpacks it. */
export function ipToBytes(ip: string): number[] | null {
  const stripped = ip.split("%")[0]!; // drop any zone id (fe80::1%en0)
  if (net.isIPv4(stripped)) {
    const parts = stripped.split(".").map(Number);
    if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
      return null;
    }
    return parts;
  }
  if (!net.isIPv6(stripped)) return null;

  // Split an embedded IPv4 tail (::ffff:192.168.0.1) into two hextets first, so
  // the rest of the parse only ever deals with `:`-separated hex groups.
  let text = stripped;
  const dot = text.indexOf(".");
  if (dot !== -1) {
    const lastColon = text.lastIndexOf(":");
    const v4 = text.slice(lastColon + 1);
    if (!net.isIPv4(v4)) return null;
    const [a, b, c, d] = v4.split(".").map(Number) as [number, number, number, number];
    const hi = ((a << 8) | b).toString(16);
    const lo = ((c << 8) | d).toString(16);
    text = `${text.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0]!.split(":") : [];
  let groups: string[];
  if (halves.length === 2) {
    const tail = halves[1] ? halves[1]!.split(":") : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    bytes.push((v >> 8) & 0xff, v & 0xff);
  }
  return bytes;
}

/** IPv4 ranges a document fetch must never reach — the RFC 1918 privates, the
 * loopback, the link-local block that carries the cloud metadata endpoints, the
 * unspecified/CGNAT/benchmark/test/multicast/reserved space. */
function isBlockedIpv4(b: number[]): boolean {
  const [b0, b1, b2] = b as [number, number, number, number];
  if (b0 === 0) return true; // 0.0.0.0/8 — "this network", incl. 0.0.0.0
  if (b0 === 10) return true; // 10.0.0.0/8 private
  if (b0 === 127) return true; // 127.0.0.0/8 loopback
  if (b0 === 169 && b1 === 254) return true; // 169.254.0.0/16 link-local + metadata
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true; // 172.16.0.0/12 private
  if (b0 === 192 && b1 === 168) return true; // 192.168.0.0/16 private
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true; // 100.64.0.0/10 CGNAT
  if (b0 === 192 && b1 === 0 && b2 === 0) return true; // 192.0.0.0/24 IETF protocol
  if (b0 === 192 && b1 === 0 && b2 === 2) return true; // 192.0.2.0/24 TEST-NET-1
  if (b0 === 198 && (b1 === 18 || b1 === 19)) return true; // 198.18.0.0/15 benchmark
  if (b0 === 198 && b1 === 51 && b2 === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (b0 === 203 && b1 === 0 && b2 === 113) return true; // 203.0.113.0/24 TEST-NET-3
  if (b0 >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + 255.255.255.255
  return false;
}

/** IPv6 ranges to refuse: the IPv4-mapped forms of the blocked v4 ranges,
 * ::/96 (unspecified, loopback and deprecated IPv4-compatible), link-local,
 * unique-local and multicast. */
function isBlockedIpv6(b: number[]): boolean {
  // ::ffff:a.b.c.d — an IPv4 destination wearing an IPv6 coat; judge the v4.
  if (b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) {
    return isBlockedIpv4([b[12]!, b[13]!, b[14]!, b[15]!]);
  }
  // ::/96 — unspecified (::), loopback (::1) and the deprecated IPv4-compatible
  // block, none of them a global address.
  if (b.slice(0, 12).every((x) => x === 0)) return true;
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if ((b[0]! & 0xfe) === 0xfc) return true; // fc00::/7 unique-local
  if (b[0] === 0xff) return true; // ff00::/8 multicast
  return false;
}

/**
 * Is this destination address one a document fetch must refuse?
 *
 * The single predicate both the literal-host check and `guardedLookup` call, so
 * the answer cannot differ between "the URL was already an IP" and "a hostname
 * resolved to one". An address the operator explicitly allow-listed is let
 * through; anything that fails to parse is refused, because an address this code
 * cannot reason about is not one it should connect to.
 */
export function isBlockedAddress(ip: string): boolean {
  const bare = ip.split("%")[0]!;
  if (allowedIps().has(bare)) return false;
  const bytes = ipToBytes(bare);
  if (bytes === null) return true;
  return bytes.length === 4 ? isBlockedIpv4(bytes) : isBlockedIpv6(bytes);
}

/** The refusal message. Deliberately says nothing about which internal address
 * was resolved — that IP is itself a fact the caller was trying to learn. */
export function blockedUrlError(rawUrl: string): string {
  return (
    `refusing to fetch ${rawUrl}: it resolves to a non-routable or otherwise blocked ` +
    "address (loopback, link-local/metadata, private or reserved). This tool fetches over " +
    "your own network and will not reach an internal service."
  );
}

/** Marks the error `guardedLookup` raises so `fetchDocument` can turn it into the
 * friendly refusal instead of a raw connect failure. */
export const SSRF_BLOCKED_CODE = "ESSRFBLOCKED";

/**
 * A drop-in `lookup` for `http`/`https` request options that resolves the host,
 * refuses if ANY resolved address is blocked, and otherwise hands the socket the
 * SAME addresses it validated — so the connection is pinned to a vetted IP and a
 * rebinding second resolution never happens. It resolves ALL addresses to vet
 * them, then answers in the shape the caller asked for (`options.all`).
 */
export const guardedLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...(options as dns.LookupOptions), all: true }, (err, addresses) => {
    if (err) return callback(err, "", 0);
    for (const a of addresses) {
      if (isBlockedAddress(a.address)) {
        const blocked = new Error("destination address is blocked") as NodeJS.ErrnoException;
        blocked.code = SSRF_BLOCKED_CODE;
        return callback(blocked, "", 0);
      }
    }
    if ((options as dns.LookupAllOptions).all) return callback(null, addresses);
    const first = addresses[0]!;
    return callback(null, first.address, first.family);
  });
};
