import { NextResponse, type NextRequest } from "next/server";
import { parseJson, requireSameOrigin, responseForError } from "@/lib/server/api";
import {
  checkLoginRateLimit,
  clearLoginFailures,
  createSession,
  loginLookupKey,
  normalizeEmail,
  recordLoginFailure,
  setSessionCookie,
  verifyPasswordWithFallback,
} from "@/lib/server/auth";
import { findUserByEmail, toPublicUser } from "@/lib/server/db";
import { credentialsSchema } from "@/lib/server/schemas";

export async function POST(request: NextRequest) {
  try {
    requireSameOrigin(request);
    const input = await parseJson(request, credentialsSchema);
    const email = normalizeEmail(input.email);
    const lookupKey = loginLookupKey(request, email);
    checkLoginRateLimit(lookupKey);

    const user = findUserByEmail(email);
    const valid = await verifyPasswordWithFallback(user?.password_hash, input.password);
    if (!user || !valid) {
      recordLoginFailure(lookupKey);
      return NextResponse.json({ error: "Invalid email or password" }, { status: 401 });
    }

    clearLoginFailures(lookupKey);
    const token = createSession(user.id, request);
    const response = NextResponse.json({ user: toPublicUser(user) });
    response.headers.set("Cache-Control", "no-store");
    setSessionCookie(response, token);
    return response;
  } catch (error) {
    return responseForError(error);
  }
}
