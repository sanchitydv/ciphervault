import type { NextRequest } from "next/server";
import { noStoreJson, responseForError } from "@/lib/server/api";
import { requireUser } from "@/lib/server/auth";

export async function GET(request: NextRequest) {
  try {
    return noStoreJson({ user: requireUser(request) });
  } catch (error) {
    return responseForError(error);
  }
}
