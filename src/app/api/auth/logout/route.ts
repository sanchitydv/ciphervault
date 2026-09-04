import { NextResponse, type NextRequest } from "next/server";
import { requireSameOrigin, responseForError } from "@/lib/server/api";
import { clearSession, deleteSession, SESSION_COOKIE } from "@/lib/server/auth";

export async function POST(request: NextRequest) {
  try {
    requireSameOrigin(request);
    const token = request.cookies.get(SESSION_COOKIE)?.value;
    if (token) deleteSession(token);
    const response = NextResponse.json({ ok: true });
    clearSession(response);
    return response;
  } catch (error) {
    return responseForError(error);
  }
}
