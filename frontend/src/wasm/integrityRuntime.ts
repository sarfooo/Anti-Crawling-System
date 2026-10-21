const ENVELOPE_KEY = "local-dev-wasm-envelope-key";

function canonicalJson(value: unknown): string {
  return JSON.stringify(value, Object.keys(value as Record<string, unknown>).sort());
}

function bytesToHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(input: string | Uint8Array): Promise<ArrayBuffer> {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  return crypto.subtle.digest("SHA-256", data);
}

function b64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

async function unwrapSeed(encryptedSeed: string): Promise<string> {
  const envelope = JSON.parse(new TextDecoder().decode(b64UrlDecode(encryptedSeed)));
  const mask = new Uint8Array(await sha256(`${ENVELOPE_KEY}:${envelope.nonce}`));
  const cipher = b64UrlDecode(envelope.ciphertext);
  const plain = cipher.map((byte, index) => byte ^ mask[index % mask.length]);
  return new TextDecoder().decode(plain);
}

export class WasmIntegrityRuntime {
  private deviceId = "";
  private seed = "";
  private fingerprint = {};

  async install(deviceId: string, encryptedSeed: string, fingerprint: Record<string, unknown>): Promise<void> {
    this.deviceId = deviceId;
    this.seed = await unwrapSeed(encryptedSeed);
    this.fingerprint = fingerprint;
  }

  ready(): boolean {
    return Boolean(this.deviceId && this.seed);
  }

  async signedHeaders(method: string, path: string, body = ""): Promise<Record<string, string>> {
    if (!this.ready()) {
      throw new Error("integrity runtime is not installed");
    }
    const timestamp = `${Math.floor(Date.now() / 1000)}`;
    const bodyDigest = bytesToHex(await sha256(body));
    const secretHash = await this.hmac("change-this-pepper-outside-dev", this.seed);
    const signature = await this.hmac(secretHash, `${timestamp}${method.toUpperCase()}${path}${bodyDigest}`);
    return {
      "X-Device-ID": this.deviceId,
      "X-Timestamp": timestamp,
      "X-Fingerprint": canonicalJson(this.fingerprint),
      "X-Signature": signature
    };
  }

  private async hmac(key: string, message: string): Promise<string> {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    return bytesToHex(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message)));
  }
}

export function collectFingerprint(): Record<string, unknown> {
  return {
    userAgent: navigator.userAgent,
    language: navigator.language,
    platform: navigator.platform,
    screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    hardwareConcurrency: navigator.hardwareConcurrency
  };
}
