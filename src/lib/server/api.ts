import { NextResponse, type NextRequest } from "next/server";
import { ZodError, type ZodType } from "zod";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export function requireSameOrigin(request: NextRequest): void {
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    throw new ApiError(403, "Cross-site request rejected");
  }
  if (!origin) return;

  try {
    if (new URL(origin).host !== request.nextUrl.host) {
      throw new ApiError(403, "Request origin rejected");
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(403, "Request origin rejected");
  }
}

export async function parseJson<T>(request: NextRequest, schema: ZodType<T>): Promise<T> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.startsWith("application/json")) {
    throw new ApiError(415, "Content-Type must be application/json");
  }

  try {
    return schema.parse(await request.json());
  } catch (error) {
    if (error instanceof ZodError) {
      throw new ApiError(400, error.issues[0]?.message ?? "Invalid request");
    }
    if (error instanceof SyntaxError) {
      throw new ApiError(400, "Invalid JSON payload");
    }
    throw error;
  }
}

export function responseForError(error: unknown): NextResponse {
  if (error instanceof ApiError) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }

  if (error instanceof ZodError) {
    return NextResponse.json(
      { error: error.issues[0]?.message ?? "Invalid request" },
      { status: 400 },
    );
  }

  // Cryptographic and database details are intentionally not sent to clients.
  console.error("Unexpected API error", error instanceof Error ? error.message : "unknown");
  return NextResponse.json({ error: "Request failed" }, { status: 500 });
}

export function noStoreJson(value: unknown, status = 200): NextResponse {
  const response = NextResponse.json(value, { status });
  response.headers.set("Cache-Control", "no-store");
  return response;
}
