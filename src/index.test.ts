import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { app } from "./index";

const plaintext = "Hello, this is a secret message!";
const sourceBuffer = Buffer.from(plaintext, "utf8");
const sourceFileName = "test.txt";
const passphrase = "mysecretpass123";

function toBlobPart(buffer: Buffer) {
  return new Uint8Array(buffer);
}

describe("Roxify API routes", () => {
  let server: ReturnType<typeof app.listen>;
  let baseUrl = "";
  let encodedNoAes: Buffer;
  let encodedAes: Buffer;

  beforeAll(async () => {
    server = app.listen(0);

    await new Promise<void>((resolve, reject) => {
      server.once("listening", () => resolve());
      server.once("error", reject);
    });

    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to resolve test server address");
    }

    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(() => {
    server.close();
  });

  it("encodes a file without AES", async () => {
    const form = new FormData();
    form.set("file", new Blob([toBlobPart(sourceBuffer)]), sourceFileName);

    const response = await fetch(`${baseUrl}/encode/no-aes`, {
      method: "POST",
      body: form,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("image/png");

    encodedNoAes = Buffer.from(await response.arrayBuffer());
    expect(encodedNoAes.length).toBeGreaterThan(0);
  });

  it("encodes a file with AES", async () => {
    const form = new FormData();
    form.set("file", new Blob([toBlobPart(sourceBuffer)]), sourceFileName);
    form.set("passphrase", passphrase);

    const response = await fetch(`${baseUrl}/encode/aes`, {
      method: "POST",
      body: form,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("image/png");

    encodedAes = Buffer.from(await response.arrayBuffer());
    expect(encodedAes.length).toBeGreaterThan(0);
  });

  it("decodes an unencrypted file without AES", async () => {
    const form = new FormData();
    form.set("file", new Blob([toBlobPart(encodedNoAes)]), "output_no_aes.png");

    const response = await fetch(`${baseUrl}/decode/no-aes`, {
      method: "POST",
      body: form,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain(
      "application/octet-stream",
    );

    const decoded = Buffer.from(await response.arrayBuffer()).toString("utf8");
    expect(decoded).toBe(plaintext);
  });

  it("decodes an encrypted file with AES and reports user errors correctly", async () => {
    const missingPassphraseForm = new FormData();
    missingPassphraseForm.set(
      "file",
      new Blob([toBlobPart(encodedAes)]),
      "output_aes.png",
    );

    const wrongRouteResponse = await fetch(`${baseUrl}/decode/no-aes`, {
      method: "POST",
      body: missingPassphraseForm,
    });

    expect(wrongRouteResponse.status).toBe(400);
    expect(await wrongRouteResponse.json()).toEqual({
      error: "This file is encrypted. Use /decode/aes with passphrase.",
    });

    const wrongPassphraseForm = new FormData();
    wrongPassphraseForm.set(
      "file",
      new Blob([toBlobPart(encodedAes)]),
      "output_aes.png",
    );
    wrongPassphraseForm.set("passphrase", "wrongpassword");

    const wrongPassphraseResponse = await fetch(`${baseUrl}/decode/aes`, {
      method: "POST",
      body: wrongPassphraseForm,
    });

    expect(wrongPassphraseResponse.status).toBe(400);
    expect(await wrongPassphraseResponse.json()).toEqual({
      error: "Incorrect passphrase",
    });

    const validForm = new FormData();
    validForm.set("file", new Blob([toBlobPart(encodedAes)]), "output_aes.png");
    validForm.set("passphrase", passphrase);

    const okResponse = await fetch(`${baseUrl}/decode/aes`, {
      method: "POST",
      body: validForm,
    });

    expect(okResponse.status).toBe(200);
    const decoded = Buffer.from(await okResponse.arrayBuffer()).toString(
      "utf8",
    );
    expect(decoded).toBe(plaintext);
  });

  it("detects whether a file is AES-protected", async () => {
    const noAesForm = new FormData();
    noAesForm.set(
      "file",
      new Blob([toBlobPart(encodedNoAes)]),
      "output_no_aes.png",
    );

    const noAesResponse = await fetch(`${baseUrl}/inspect/aes`, {
      method: "POST",
      body: noAesForm,
    });

    expect(noAesResponse.status).toBe(200);
    expect(await noAesResponse.json()).toEqual({
      encrypted: false,
      encryptedAes: false,
      note: "No passphrase protection detected.",
    });

    const aesForm = new FormData();
    aesForm.set("file", new Blob([toBlobPart(encodedAes)]), "output_aes.png");

    const aesResponse = await fetch(`${baseUrl}/inspect/aes`, {
      method: "POST",
      body: aesForm,
    });

    expect(aesResponse.status).toBe(200);
    expect(await aesResponse.json()).toEqual({
      encrypted: true,
      encryptedAes: true,
      note: "Passphrase protection detected (Roxify AES flow in this API).",
    });
  });
});
