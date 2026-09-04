import { LockKeyhole } from "lucide-react";

export function Brand({ inverse = false }: { inverse?: boolean }) {
  return (
    <div className={`brand ${inverse ? "brandInverse" : ""}`} aria-label="CipherVault">
      <span className="brandMark" aria-hidden="true">
        <LockKeyhole size={19} strokeWidth={2.4} />
      </span>
      <span>CipherVault</span>
    </div>
  );
}
