import express from "express";
import multer from "multer";
import { decodePngToBinary, encodeBinaryToPng } from "roxify";

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const port = Number(process.env.PORT ?? 3000);

function normalizeErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Unknown error";
}

function isPassphraseError(message: string) {
  return message.includes("Passphrase") || message.includes("passphrase");
}

function isUserInputError(message: string) {
  return (
    isPassphraseError(message) ||
    message.includes("Incorrect passphrase") ||
    message.includes("invalid") ||
    message.includes("Invalid")
  );
}

/**
 * Centralized error handler for API routes.
 * Determines status code (400 for user input errors, 500 for server errors)
 * and returns uniform JSON error response.
 */
function respondWithApiError(
  res: express.Response,
  error: unknown,
  context?: {
    isPassphraseRequired?: boolean;
  },
) {
  const message = normalizeErrorMessage(error);

  if (context?.isPassphraseRequired && isPassphraseError(message)) {
    return res.status(400).json({
      error: "This file is encrypted. Use /decode/aes with passphrase.",
    });
  }

  const statusCode = isUserInputError(message) ? 400 : 500;
  return res.status(statusCode).json({ error: message });
}

app.use(express.json());

app.get("/", (_req, res) => {
  res.json({
    service: "Roxify API",
    routes: [
      "GET /health",
      "POST /encode/no-aes",
      "POST /encode/aes",
      "POST /decode/no-aes",
      "POST /decode/aes",
      "POST /inspect/aes",
    ],
  });
});

app.get("/health", (_req, res) => {
  return res.status(200).json({ status: "ok" });
});

app.post("/encode/no-aes", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Missing file field "file"' });
    }

    const originalName = req.file.originalname || "input.bin";
    const pngBuffer = await encodeBinaryToPng(req.file.buffer, {
      name: originalName,
      encrypt: "none",
    });

    const outputName = `${originalName}.png`;
    res.setHeader("Content-Type", "image/png");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${outputName}"`,
    );
    return res.send(pngBuffer);
  } catch (error) {
    return respondWithApiError(res, error);
  }
});

app.post("/encode/aes", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Missing file field "file"' });
    }

    const passphrase = req.body?.passphrase;
    if (typeof passphrase !== "string" || !passphrase.trim()) {
      return res
        .status(400)
        .json({ error: "Missing passphrase in form-data body" });
    }

    const originalName = req.file.originalname || "input.bin";
    const pngBuffer = await encodeBinaryToPng(req.file.buffer, {
      name: originalName,
      passphrase: passphrase.trim(),
      encrypt: "aes",
    });

    const outputName = `${originalName}.aes.png`;
    res.setHeader("Content-Type", "image/png");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${outputName}"`,
    );
    return res.send(pngBuffer);
  } catch (error) {
    return respondWithApiError(res, error);
  }
});

app.post("/decode/no-aes", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Missing file field "file"' });
    }

    const result = await decodePngToBinary(req.file.buffer);
    if (!result.buf) {
      return res
        .status(400)
        .json({ error: "Decoded payload is empty or invalid" });
    }

    const outputName = result.meta?.name || "decoded.bin";
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${outputName}"`,
    );
    return res.send(result.buf);
  } catch (error) {
    return respondWithApiError(res, error, { isPassphraseRequired: true });
  }
});

app.post("/decode/aes", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Missing file field "file"' });
    }

    const passphrase = req.body?.passphrase;
    if (typeof passphrase !== "string" || !passphrase.trim()) {
      return res
        .status(400)
        .json({ error: "Missing passphrase in form-data body" });
    }

    const result = await decodePngToBinary(req.file.buffer, {
      passphrase: passphrase.trim(),
    });

    if (!result.buf) {
      return res
        .status(400)
        .json({ error: "Decoded payload is empty or invalid" });
    }

    const outputName = result.meta?.name || "decoded.bin";
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${outputName}"`,
    );
    return res.send(result.buf);
  } catch (error) {
    return respondWithApiError(res, error);
  }
});

app.post("/inspect/aes", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Missing file field "file"' });
    }

    let isEncrypted = false;
    try {
      await decodePngToBinary(req.file.buffer);
    } catch (decodeError) {
      const errMsg = normalizeErrorMessage(decodeError);
      if (isPassphraseError(errMsg)) {
        isEncrypted = true;
      } else {
        throw decodeError;
      }
    }

    return res.json({
      encrypted: isEncrypted,
      encryptedAes: isEncrypted,
      note: isEncrypted
        ? "Passphrase protection detected (Roxify AES flow in this API)."
        : "No passphrase protection detected.",
    });
  } catch (error) {
    return respondWithApiError(res, error);
  }
});

export { app };

export function startServer() {
  return app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });
}

if (import.meta.main) {
  startServer();
}
