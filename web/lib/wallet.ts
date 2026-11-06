/**
 * The consumer's wallet, in the browser.
 *
 * The signing key is generated here as non-extractable, so script running on this page can
 * use it but never read it, and it never reaches the DISCOM. Presentations are assembled
 * here too: fields the consumer does not tick never leave the device.
 */

const DB_NAME = "energy-passport-wallet";
const STORE = "wallet";
const KEY_ID = "holder-key";

function b64u(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  view.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jsonB64u(value: unknown): string {
  return b64u(new TextEncoder().encode(JSON.stringify(value)));
}

export async function sha256B64u(text: string): Promise<string> {
  return b64u(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
  });
}

async function dbPut(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).put(value, key);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
  });
}

interface StoredKey {
  pair: CryptoKeyPair;
  did: string;
}

async function holderKey(): Promise<StoredKey> {
  const existing = await dbGet<StoredKey>(KEY_ID);
  if (existing) return existing;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const did = `did:jwk:${jsonB64u({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })}`;
  const stored = { pair, did };
  await dbPut(KEY_ID, stored);
  return stored;
}

async function signCompact(header: object, payload: object): Promise<string> {
  const { pair } = await holderKey();
  const input = `${jsonB64u(header)}.${jsonB64u(payload)}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    pair.privateKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${b64u(signature)}`;
}

export async function walletDid(): Promise<string> {
  return (await holderKey()).did;
}

/** Proof of control for issuance: sign the DISCOM's fresh nonce. */
export function proveControl(nonce: string, audience: string): Promise<string> {
  return signCompact({ alg: "ES256" }, { nonce, aud: audience, iat: Math.floor(Date.now() / 1000) });
}

export async function saveCredential(consumerNo: string, credentialId: string, token: string): Promise<void> {
  await dbPut(`credential:${consumerNo}`, { credentialId, token });
}

export async function loadCredential(
  consumerNo: string,
): Promise<{ credentialId: string; token: string } | undefined> {
  return dbGet(`credential:${consumerNo}`);
}

/** SD-JWT presentation: chosen disclosures plus a key-binding JWT over exactly those. */
export async function buildPresentation(
  issuerJwt: string,
  disclosures: string[],
  nonce: string,
  audience: string,
): Promise<string> {
  const body = `${[issuerJwt, ...disclosures].join("~")}~`;
  const claims = {
    iat: Math.floor(Date.now() / 1000),
    aud: audience,
    nonce,
    sd_hash: await sha256B64u(body),
  };
  return body + (await signCompact({ alg: "ES256", typ: "kb+jwt" }, claims));
}
