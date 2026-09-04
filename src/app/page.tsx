import { cookies } from "next/headers";
import { AuthScreen } from "@/components/auth-screen";
import { VaultDashboard } from "@/components/vault-dashboard";
import { SESSION_COOKIE, getUserBySessionToken } from "@/lib/server/auth";
import { getVaultConfig, listFiles } from "@/lib/server/db";

export const dynamic = "force-dynamic";

export default async function Home() {
  const cookieStore = await cookies();
  const user = getUserBySessionToken(cookieStore.get(SESSION_COOKIE)?.value);

  if (!user) return <AuthScreen />;

  const vault = getVaultConfig(user.id);
  const files = listFiles(user.id);
  return <VaultDashboard user={user} initialVault={vault} initialFiles={files} />;
}
