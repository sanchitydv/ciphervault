import type { NextRequest } from "next/server";
import { ApiError, noStoreJson, requireSameOrigin, responseForError } from "@/lib/server/api";
import { requireUser } from "@/lib/server/auth";
import { db, findFile } from "@/lib/server/db";
import { removeEncryptedFile } from "@/lib/server/storage";

type RouteContext = { params: Promise<{ id: string }> };

export async function DELETE(request: NextRequest, context: RouteContext) {
  try {
    requireSameOrigin(request);
    const user = requireUser(request);
    const { id } = await context.params;
    const file = findFile(user.id, id);
    if (!file) throw new ApiError(404, "Encrypted file not found");

    db.prepare("DELETE FROM encrypted_files WHERE id = ? AND user_id = ?").run(id, user.id);
    await removeEncryptedFile(user.id, id);
    return noStoreJson({ ok: true });
  } catch (error) {
    return responseForError(error);
  }
}
