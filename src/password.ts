const iterations = 100_000;
const encoder = new TextEncoder();

const toBase64 = (value: Uint8Array) =>
  btoa(String.fromCharCode(...value));

const fromBase64 = (value: string) =>
  Uint8Array.from(atob(value), (character) => character.charCodeAt(0));

async function derive(password: string, pepper: string, salt: Uint8Array) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password + pepper),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", iterations, salt },
      key,
      256
    )
  );
}

export async function hashPassword(password: string, pepper: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, pepper, salt);
  return `pbkdf2-sha256$${iterations}$${toBase64(salt)}$${toBase64(hash)}`;
}

export async function verifyPassword(
  password: string,
  encoded: string,
  pepper: string
) {
  const [algorithm, encodedIterations, encodedSalt, encodedHash] =
    encoded.split("$");
  if (
    algorithm !== "pbkdf2-sha256" ||
    Number(encodedIterations) !== iterations ||
    !encodedSalt ||
    !encodedHash
  ) {
    return false;
  }

  const expected = fromBase64(encodedHash);
  const actual = await derive(password, pepper, fromBase64(encodedSalt));
  if (actual.length !== expected.length) return false;

  let difference = 0;
  for (let index = 0; index < actual.length; index++) {
    difference |= actual[index] ^ expected[index];
  }
  return difference === 0;
}
