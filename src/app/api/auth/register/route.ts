import { NextResponse, type NextRequest } from "next/server";
import { parseJson, requireSameOrigin, responseForError } from "@/lib/server/api";
import {
  createSession,
  createUser,
  hashPassword,
  normalizeEmail,
  setSessionCookie,
} from "@/lib/server/auth";
import { findUserByEmail } from "@/lib/server/db";
import { credentialsSchema } from "@/lib/server/schemas";

export async function POST(request: NextRequest) {
  try {
    requireSameOrigin(request);
    const input = await parseJson(request, credentialsSchema);
    const email = normalizeEmail(input.email);
    if (findUserByEmail(email)) {
      return NextResponse.json({ error: "An account already exists for this email" }, { status: 409 });
    }

    const passwordHash = await hashPassword(input.password);
    const user = createUser(email, passwordHash);
    const token = createSession(user.id, request);
    const response = NextResponse.json({ user }, { status: 201 });
    response.headers.set("Cache-Control", "no-store");
    setSessionCookie(response, token);
    return response;
  } catch (error) {
    return responseForError(error);
  }
}
