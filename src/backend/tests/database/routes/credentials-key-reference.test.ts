import { readFileSync } from "node:fs";
import type { Request, Response } from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { repository, existing } = vi.hoisted(() => {
  const existing: Record<string, unknown> = {
    id: 7,
    userId: "test-user",
    name: "original",
    authType: "key",
    key: "op://vault/item/private key",
    privateKey: "op://vault/item/private key",
    publicKey: null,
    detectedKeyType: null,
    keyPassword: "op://vault/item/passphrase",
    keyType: null,
    certPublicKey: null,
    description: null,
    folder: null,
    tags: "",
  };
  return {
    existing,
    repository: {
      createEncryptedForUser: vi.fn(async (_userId, data) => ({
        id: 8,
        ...data,
      })),
      findDecryptedByIdForUser: vi.fn(async () => existing),
      findById: vi.fn(async () => existing),
      updateEncryptedForUser: vi.fn(async (_userId, _id, fields) => ({
        ...existing,
        ...fields,
      })),
    },
  };
});
vi.mock("../../../database/repositories/factory.js", () => ({
  createCurrentCredentialRepository: () => repository,
}));
vi.mock("../../../utils/auth-manager.js", () => ({
  AuthManager: {
    getInstance: () => ({
      createAuthMiddleware:
        () => (_req: unknown, _res: unknown, next: () => void) =>
          next(),
      createDataAccessMiddleware:
        () => (_req: unknown, _res: unknown, next: () => void) =>
          next(),
    }),
  },
}));
vi.mock("../../../utils/permission-manager.js", () => ({
  PermissionManager: {
    getInstance: () => ({
      requirePermission:
        () => (_req: unknown, _res: unknown, next: () => void) =>
          next(),
    }),
  },
}));
vi.mock("../../../utils/logger.js", () => ({
  authLogger: {
    warn: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    success: vi.fn(),
  },
}));
vi.mock("../../../utils/audit-logger.js", () => ({
  logAudit: vi.fn(),
  getAuditUsername: vi.fn(async () => "tester"),
  getRequestMeta: vi.fn(() => ({})),
}));
vi.mock("../../../utils/shared-host-secrets-manager.js", () => ({
  SharedHostSecretsManager: {
    getInstance: () => ({ resyncHostsForCredential: vi.fn() }),
  },
}));
vi.mock("../../../utils/shared-credential-secrets-manager.js", () => ({
  SharedCredentialSecretsManager: {
    getInstance: () => ({ resyncCredential: vi.fn() }),
  },
}));
vi.mock("../../../database/routes/credential-key-routes.js", () => ({
  registerCredentialKeyRoutes: vi.fn(),
}));
vi.mock("../../../database/routes/credential-deploy-routes.js", () => ({
  registerCredentialDeployRoutes: vi.fn(),
}));
vi.mock("../../../database/routes/credential-bulk-routes.js", () => ({
  registerCredentialBulkRoutes: vi.fn(),
}));

import router from "../../../database/routes/credentials.js";

const ref = "op://vault/item/private key?ssh-format=openssh";
const passphrase = "op://vault/item/passphrase";
const literal = readFileSync(
  "node_modules/ssh2/test/fixtures/keyParser/ppk_rsa",
  "utf8",
);

async function request(
  method: "post" | "put",
  path: string,
  body: Record<string, unknown>,
) {
  const layer = router.stack.find(
    (entry) =>
      entry.route?.path === path &&
      (entry.route as unknown as { methods: Record<string, boolean> }).methods[
        method
      ],
  );
  if (!layer?.route) throw new Error(`Missing ${method} ${path}`);
  const req = {
    body,
    params: path === "/" ? {} : { id: "7" },
    userId: "test-user",
  } as unknown as Request;
  const res = {
    statusCode: 200,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(data: unknown) {
      this.data = data;
      return this;
    },
    data: undefined as unknown,
  } as Response & { data: unknown };
  // Authentication/permission are isolated here; execute the actual registered route handler.
  await layer.route.stack.at(-1)!.handle(req, res, () => {});
  return res;
}

beforeEach(() => {
  vi.clearAllMocks();
  repository.findDecryptedByIdForUser.mockImplementation(async () => existing);
  repository.findById.mockImplementation(async () => existing);
});

describe("credential key-reference write paths", () => {
  it("creates a key credential with an unchanged reference and no derived key metadata", async () => {
    const res = await request("post", "/", {
      name: "pilot",
      authType: "key",
      key: ref,
      keyPassword: passphrase,
    });
    expect(res.statusCode).toBe(201);
    expect(repository.createEncryptedForUser).toHaveBeenCalledWith(
      "test-user",
      expect.objectContaining({
        key: ref,
        privateKey: ref,
        keyPassword: passphrase,
        publicKey: null,
        detectedKeyType: null,
      }),
    );
  });

  it("updates a literal key to a reference and clears old derived metadata", async () => {
    repository.findDecryptedByIdForUser.mockResolvedValueOnce({
      ...existing,
      key: literal,
      privateKey: literal,
      publicKey: "old-public",
      detectedKeyType: "ssh-rsa",
    });
    const res = await request("put", "/:id", {
      key: ref,
      keyPassword: passphrase,
    });
    expect(res.statusCode).toBe(200);
    expect(repository.updateEncryptedForUser).toHaveBeenCalledWith(
      "test-user",
      7,
      expect.objectContaining({
        key: ref,
        privateKey: ref,
        keyPassword: passphrase,
        publicKey: null,
        detectedKeyType: null,
      }),
    );
  });

  it("duplicates a referenced credential without resolving or parsing its key", async () => {
    const res = await request("post", "/:id/duplicate", { name: "copy" });
    expect(res.statusCode).toBe(201);
    expect(repository.createEncryptedForUser).toHaveBeenCalledWith(
      "test-user",
      expect.objectContaining({
        key: existing.key,
        privateKey: existing.key,
        keyPassword: passphrase,
        publicKey: null,
        detectedKeyType: null,
      }),
    );
  });

  it("duplicates with a new encoded reference override without normalizing it", async () => {
    const override =
      "  op://vault%20name/item/private%20key?ssh-format=openssh  ";
    const res = await request("post", "/:id/duplicate", {
      name: "copy",
      key: override,
    });
    expect(res.statusCode).toBe(201);
    expect(repository.createEncryptedForUser).toHaveBeenCalledWith(
      "test-user",
      expect.objectContaining({
        key: override,
        privateKey: override,
        publicKey: null,
        detectedKeyType: null,
      }),
    );
  });

  it.each([
    ["post", "/", { name: "bad", authType: "key", key: "op://vault/item" }],
    ["put", "/:id", { key: "op://vault/item/field/extra" }],
    ["post", "/:id/duplicate", { name: "bad", key: "op://vault/item/%ZZ" }],
    ["post", "/", { name: "bad", authType: "key", key: "op://vault/item/%00" }],
    ["put", "/:id", { key: "op://vault/item/%" }],
    ["post", "/:id/duplicate", { name: "bad", key: "op://vault/item/%20" }],
  ] as const)(
    "rejects malformed references on %s %s",
    async (method, path, body) => {
      const res = await request(method, path, body);
      expect(res.statusCode).toBe(400);
      expect(repository.createEncryptedForUser).not.toHaveBeenCalled();
      expect(repository.updateEncryptedForUser).not.toHaveBeenCalled();
    },
  );

  it("preserves literal key validation on create and update", async () => {
    expect(
      (
        await request("post", "/", {
          name: "literal",
          authType: "key",
          key: literal,
        })
      ).statusCode,
    ).toBe(201);
    expect((await request("put", "/:id", { key: literal })).statusCode).toBe(
      200,
    );
    expect(repository.updateEncryptedForUser).toHaveBeenCalledWith(
      "test-user",
      7,
      expect.objectContaining({
        publicKey: expect.stringContaining("ssh-rsa "),
        detectedKeyType: "ssh-rsa",
      }),
    );
    expect(
      (
        await request("post", "/", {
          name: "invalid",
          authType: "key",
          key: "not a key",
        })
      ).statusCode,
    ).toBe(400);
    expect(
      (await request("put", "/:id", { key: "not a key" })).statusCode,
    ).toBe(400);
  });

  it("rejects malformed key references when changing password auth to key auth", async () => {
    repository.findDecryptedByIdForUser.mockResolvedValueOnce({
      ...existing,
      authType: "password",
      key: null,
    });
    const res = await request("put", "/:id", {
      authType: "key",
      key: "op://vault/item",
    });
    expect(res.statusCode).toBe(400);
    expect(repository.updateEncryptedForUser).not.toHaveBeenCalled();
  });

  it("accepts a key reference when changing password auth to key auth", async () => {
    repository.findDecryptedByIdForUser.mockResolvedValueOnce({
      ...existing,
      authType: "password",
      key: null,
    });
    const res = await request("put", "/:id", {
      authType: "key",
      key: ref,
    });
    expect(res.statusCode).toBe(200);
    expect(repository.updateEncryptedForUser).toHaveBeenCalledWith(
      "test-user",
      7,
      expect.objectContaining({
        key: ref,
        privateKey: ref,
        publicKey: null,
        detectedKeyType: null,
      }),
    );
  });

  it("validates literal keys on duplication", async () => {
    repository.findDecryptedByIdForUser.mockResolvedValueOnce({
      ...existing,
      key: literal,
      keyPassword: null,
    });
    expect(
      (await request("post", "/:id/duplicate", { name: "literal copy" }))
        .statusCode,
    ).toBe(201);
    expect(repository.createEncryptedForUser).toHaveBeenCalledWith(
      "test-user",
      expect.objectContaining({
        publicKey: expect.stringContaining("ssh-rsa "),
        detectedKeyType: "ssh-rsa",
      }),
    );
    repository.findDecryptedByIdForUser.mockResolvedValueOnce({
      ...existing,
      key: "not a key",
      keyPassword: null,
    });
    expect(
      (await request("post", "/:id/duplicate", { name: "invalid copy" }))
        .statusCode,
    ).toBe(400);
  });

  it("does not skip literal key validation when passphrase is a reference", async () => {
    expect(
      (
        await request("post", "/", {
          name: "literal",
          authType: "key",
          key: literal,
          keyPassword: passphrase,
        })
      ).statusCode,
    ).toBe(400);
  });
});
