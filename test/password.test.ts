import assert from "node:assert/strict";
import test from "node:test";
import { hashPassword, verifyPassword } from "../src/password.ts";

test("password hashes verify only with the original password and pepper", async () => {
  const hash = await hashPassword("correct horse", "secret pepper");

  assert.match(hash, /^pbkdf2-sha256\$100000\$/);
  assert.equal(
    await verifyPassword("correct horse", hash, "secret pepper"),
    true
  );
  assert.equal(await verifyPassword("wrong", hash, "secret pepper"), false);
  assert.equal(await verifyPassword("correct horse", hash, "wrong pepper"), false);
});
