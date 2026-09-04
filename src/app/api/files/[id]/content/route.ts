import { createHash } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";
import { ApiError, responseForError } from "@/lib/server/api";
import { requireUser } from "@/lib/server/auth";
import { findFile } from "@/lib/server/db";
import { readEncryptedFile } from "@/lib/server/storage";

type RouteContext = { params: Promise<{ id: string }> };

export async function GET(request: NextRequest, context: RouteContext) {
  try {
    const user = requireUser(request);
    const { id } = await context.params;
    const file = findFile(user.id, id);
    if (!file) throw new ApiError(404, "Encrypted file not found");
    const bytes = await readEncryptedFile(user.id, id);
    const checksum = createHash("sha256").update(bytes).digest("hex");
    if (checksum !== file.checksum) throw new ApiError(409, "Stored ciphertext failed its checksum");

    return new NextResponse(new Uint8Array(bytes), {
      headers: {
        "Content-Type": "application/vnd.ciphervault.encrypted",
        "Content-Length": String(bytes.byteLength),
        "Content-Disposition": `attachment; filename="${id}.cvlt"`,
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (error) {
    return responseForError(error);
  }
}
