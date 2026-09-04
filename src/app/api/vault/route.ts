import type { NextRequest } from "next/server";
import { ApiError, noStoreJson, parseJson, requireSameOrigin, responseForError } from "@/lib/server/api";
import { requireUser } from "@/lib/server/auth";
import { db, getVaultConfig } from "@/lib/server/db";
import { vaultConfigSchema } from "@/lib/server/schemas";

export async function GET(request: NextRequest) {
  try {
    const user = requireUser(request);
    return noStoreJson({ vault: getVaultConfig(user.id) });
  } catch (error) {
    return responseForError(error);
  }
}

export async function POST(request: NextRequest) {
  try {
    requireSameOrigin(request);
    const user = requireUser(request);
    const input = await parseJson(request, vaultConfigSchema);
    if (getVaultConfig(user.id)) throw new ApiError(409, "Vault is already initialized");
    db.prepare("UPDATE users SET vault_data = ? WHERE id = ?").run(JSON.stringify(input), user.id);
    return noStoreJson({ vault: input }, 201);
  } catch (error) {
    return responseForError(error);
  }
}

export async function PUT(request: NextRequest) {
  try {
    requireSameOrigin(request);
    const user = requireUser(request);
    const input = await parseJson(request, vaultConfigSchema);
    if (!getVaultConfig(user.id)) throw new ApiError(404, "Vault is not initialized");
    db.prepare("UPDATE users SET vault_data = ? WHERE id = ?").run(JSON.stringify(input), user.id);
    return noStoreJson({ vault: input });
  } catch (error) {
    return responseForError(error);
  }
}
