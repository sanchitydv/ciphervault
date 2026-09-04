"use client";

import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type FormEvent,
  type RefObject,
} from "react";
import {
  ArrowDownToLine,
  CheckCircle2,
  ChevronRight,
  FileKey2,
  FileText,
  HardDrive,
  KeyRound,
  LoaderCircle,
  Lock,
  LogOut,
  RefreshCw,
  ShieldCheck,
  Trash2,
  UploadCloud,
  X,
} from "lucide-react";
import { Brand } from "@/components/brand";
import { apiRequest } from "@/lib/client/api";
import {
  createVault,
  decryptFile,
  decryptFilename,
  lockKey,
  openFileKey,
  prepareUpload,
  rewrapVault,
  unlockVault,
} from "@/lib/client/crypto";
import type { EncryptedFileRecord, PublicUser, VaultConfig } from "@/lib/types";

type Props = {
  user: PublicUser;
  initialVault: VaultConfig | null;
  initialFiles: EncryptedFileRecord[];
};

const MAX_FILE_BYTES = 50 * 1024 * 1024;

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** unit).toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatDate(timestamp: number): string {
  return new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    year: new Date(timestamp).getFullYear() === new Date().getFullYear() ? undefined : "numeric",
  }).format(timestamp);
}

export function VaultDashboard({ user, initialVault, initialFiles }: Props) {
  const [vault, setVault] = useState(initialVault);
  const [files, setFiles] = useState(initialFiles);
  const [unlocked, setUnlocked] = useState(false);
  const [names, setNames] = useState<Record<string, string>>({});
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busyFile, setBusyFile] = useState<string | null>(null);
  const masterKeyRef = useRef<Uint8Array | null>(null);

  useEffect(() => {
    const timer = notice ? window.setTimeout(() => setNotice(""), 4000) : undefined;
    return () => {
      if (timer) window.clearTimeout(timer);
    };
  }, [notice]);

  useEffect(
    () => () => {
      masterKeyRef.current?.fill(0);
    },
    [],
  );

  async function logout() {
    masterKeyRef.current?.fill(0);
    await apiRequest("/api/auth/logout", { method: "POST", body: "{}" });
    window.location.reload();
  }

  async function handleUnlock(passphrase: string) {
    if (!vault) return;
    setError("");
    const masterKey = await unlockVault(vault, passphrase);
    masterKeyRef.current = masterKey;
    const resolvedNames = await Promise.all(
      files.map(async (file) => {
        try {
          return [file.id, await decryptFilename(file, masterKey)] as const;
        } catch {
          return [file.id, "Unreadable encrypted filename"] as const;
        }
      }),
    );
    setNames(Object.fromEntries(resolvedNames));
    setUnlocked(true);
  }

  async function handleLock() {
    await lockKey(masterKeyRef.current);
    masterKeyRef.current = null;
    setNames({});
    setUnlocked(false);
  }

  if (!vault) {
    return (
      <SetupVault
        user={user}
        onLogout={logout}
        onComplete={(config, masterKey) => {
          setVault(config);
          masterKeyRef.current = masterKey;
          setUnlocked(true);
          setNotice("Your encrypted vault is ready");
        }}
      />
    );
  }

  if (!unlocked) {
    return <UnlockVault user={user} error={error} onError={setError} onUnlock={handleUnlock} onLogout={logout} />;
  }

  const totalBytes = files.reduce((sum, file) => sum + file.plainSize, 0);

  return (
    <div className="dashboardShell">
      <header className="topbar">
        <Brand />
        <div className="topbarActions">
          <span className="securePill"><span /> End-to-end encrypted</span>
          <button className="iconTextButton" onClick={handleLock}><Lock size={16} /> Lock vault</button>
          <button className="avatarButton" title={user.email} aria-label="Signed-in account">
            {user.email.slice(0, 1).toUpperCase()}
          </button>
        </div>
      </header>

      <main className="dashboardMain">
        <section className="welcomeRow">
          <div>
            <span className="eyebrow darkEyebrow">Personal encrypted storage</span>
            <h1>Good to see you.</h1>
            <p>Your files are unlocked locally for this browser session.</p>
          </div>
          <div className="welcomeActions">
            <ChangePassphrase masterKeyRef={masterKeyRef} onChanged={setVault} onNotice={setNotice} />
            <button className="secondaryButton" onClick={logout}><LogOut size={16} /> Sign out</button>
          </div>
        </section>

        {notice ? <div className="toast successToast"><CheckCircle2 size={18} />{notice}</div> : null}
        {error ? <div className="toast errorToast"><X size={18} />{error}<button onClick={() => setError("")} aria-label="Dismiss"><X size={15} /></button></div> : null}

        <section className="statsGrid" aria-label="Vault summary">
          <article className="statCard"><div className="statIcon blue"><FileKey2 /></div><div><span>Encrypted files</span><strong>{files.length}</strong><small>All client encrypted</small></div></article>
          <article className="statCard"><div className="statIcon green"><HardDrive /></div><div><span>Original size</span><strong>{formatBytes(totalBytes)}</strong><small>Ciphertext stored remotely</small></div></article>
          <article className="statCard"><div className="statIcon amber"><ShieldCheck /></div><div><span>Crypto suite</span><strong className="compactStat">XChaCha20</strong><small>Argon2id key derivation</small></div></article>
        </section>

        <UploadPanel
          masterKeyRef={masterKeyRef}
          onUploaded={(file, clearName) => {
            setFiles((current) => [file, ...current]);
            setNames((current) => ({ ...current, [file.id]: clearName }));
            setNotice("File encrypted and uploaded");
          }}
          onError={setError}
        />

        <section className="filesSection">
          <div className="sectionHeading">
            <div><h2>Your files</h2><p>Filenames are revealed only while your vault is unlocked.</p></div>
            <span>{files.length} {files.length === 1 ? "item" : "items"}</span>
          </div>
          {files.length === 0 ? (
            <div className="emptyState"><div><FileText size={26} /></div><h3>Your vault is empty</h3><p>Drop a file into the encrypted upload area to get started.</p></div>
          ) : (
            <div className="fileTable" role="table" aria-label="Encrypted files">
              <div className="fileTableHeader" role="row"><span>Name</span><span>Size</span><span>Added</span><span>Protection</span><span aria-label="Actions" /></div>
              {files.map((file) => (
                <FileRow
                  key={file.id}
                  file={file}
                  name={names[file.id] ?? "Decrypting filename…"}
                  busy={busyFile === file.id}
                  masterKeyRef={masterKeyRef}
                  onBusy={setBusyFile}
                  onDelete={() => {
                    setFiles((current) => current.filter((item) => item.id !== file.id));
                    setNames((current) => {
                      const next = { ...current };
                      delete next[file.id];
                      return next;
                    });
                    setNotice("Encrypted file deleted");
                  }}
                  onError={setError}
                />
              ))}
            </div>
          )}
        </section>
      </main>
      <footer className="dashboardFooter"><span><ShieldCheck size={15} /> CipherVault format v1</span><span>Your plaintext never reaches this server.</span></footer>
    </div>
  );
}

function SetupVault({ user, onLogout, onComplete }: {
  user: PublicUser;
  onLogout: () => Promise<void>;
  onComplete: (config: VaultConfig, masterKey: Uint8Array) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (passphrase.length < 15) return setError("Use at least 15 characters for your vault passphrase");
    if (passphrase !== confirm) return setError("The passphrases do not match");
    setBusy(true);
    setError("");
    let masterKey: Uint8Array | null = null;
    try {
      const created = await createVault(passphrase);
      masterKey = created.masterKey;
      const response = await apiRequest<{ vault: VaultConfig }>("/api/vault", { method: "POST", body: JSON.stringify(created.config) });
      onComplete(response.vault, masterKey);
      masterKey = null;
    } catch (caught) {
      masterKey?.fill(0);
      setError(caught instanceof Error ? caught.message : "Could not create the vault");
      setBusy(false);
    }
  }

  return (
    <main className="centeredPage">
      <header className="simpleHeader"><Brand /><button className="secondaryButton" onClick={onLogout}><LogOut size={16} /> Sign out</button></header>
      <section className="setupCard">
        <div className="stepPill">Step 2 of 2</div>
        <div className="largeSecurityIcon"><KeyRound /></div>
        <span className="eyebrow darkEyebrow">Create your key</span>
        <h1>Set up your private vault</h1>
        <p className="setupLead">Signed in as <strong>{user.email}</strong>. This separate passphrase protects the key that encrypts your files.</p>
        <form className="setupForm" onSubmit={submit}>
          <label><span>Vault passphrase</span><input type="password" autoComplete="new-password" minLength={15} maxLength={128} value={passphrase} onChange={(event) => setPassphrase(event.target.value)} placeholder="Use a long, unique passphrase" required /></label>
          <label><span>Confirm passphrase</span><input type="password" autoComplete="new-password" minLength={15} maxLength={128} value={confirm} onChange={(event) => setConfirm(event.target.value)} placeholder="Repeat your passphrase" required /></label>
          {error ? <div className="formError" role="alert">{error}</div> : null}
          <button className="primaryButton wideButton" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={18} /> Deriving your secure key…</> : <>Create encrypted vault <ChevronRight size={18} /></>}</button>
        </form>
        <div className="recoveryWarning"><ShieldCheck size={19} /><div><strong>There is no passphrase recovery.</strong><span>The server never receives this passphrase or your plaintext key. Store it in a password manager.</span></div></div>
      </section>
    </main>
  );
}

function UnlockVault({ user, error, onError, onUnlock, onLogout }: {
  user: PublicUser;
  error: string;
  onError: (message: string) => void;
  onUnlock: (passphrase: string) => Promise<void>;
  onLogout: () => Promise<void>;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    onError("");
    try {
      await onUnlock(passphrase);
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "Unable to unlock the vault");
      setBusy(false);
    }
  }

  return (
    <main className="centeredPage lockPage">
      <header className="simpleHeader"><Brand /><button className="secondaryButton" onClick={onLogout}><LogOut size={16} /> Sign out</button></header>
      <section className="unlockCard">
        <div className="lockRings"><div><Lock size={29} /></div></div>
        <span className="eyebrow darkEyebrow">Encrypted vault</span>
        <h1>Unlock your files</h1>
        <p>Your encrypted data is ready. Enter the vault passphrase for <strong>{user.email}</strong>.</p>
        <form onSubmit={submit} className="setupForm">
          <label><span>Vault passphrase</span><input autoFocus type="password" autoComplete="current-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} placeholder="Enter your vault passphrase" required /></label>
          {error ? <div className="formError" role="alert">{error}</div> : null}
          <button className="primaryButton wideButton" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={18} /> Unlocking locally…</> : <><KeyRound size={18} /> Unlock vault</>}</button>
        </form>
        <p className="localOnly"><span /> Key derivation and decryption happen only in this browser.</p>
      </section>
    </main>
  );
}

function UploadPanel({ masterKeyRef, onUploaded, onError }: {
  masterKeyRef: RefObject<Uint8Array | null>;
  onUploaded: (file: EncryptedFileRecord, clearName: string) => void;
  onError: (message: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [stage, setStage] = useState("");

  async function processFile(file: File) {
    const masterKey = masterKeyRef.current;
    if (!masterKey) return onError("Lock state changed. Unlock the vault and try again.");
    if (file.size > MAX_FILE_BYTES) return onError("Files are limited to 50 MB in this version");
    setProgress(0);
    setStage("Encrypting locally");
    onError("");
    try {
      const id = crypto.randomUUID();
      const prepared = await prepareUpload(file, id, masterKey, setProgress);
      setStage("Uploading ciphertext");
      const form = new FormData();
      Object.entries(prepared.metadata).forEach(([key, value]) => form.set(key, String(value)));
      form.set("content", prepared.encryptedContent, `${id}.cvlt`);
      const response = await apiRequest<{ file: EncryptedFileRecord }>("/api/files", { method: "POST", body: form });
      onUploaded(response.file, file.name);
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "Encrypted upload failed");
    } finally {
      setProgress(null);
      setStage("");
      if (inputRef.current) inputRef.current.value = "";
    }
  }

  function acceptSelection(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) void processFile(file);
  }

  function acceptDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) void processFile(file);
  }

  return (
    <section className="uploadCard">
      <div className="uploadCopy"><span className="eyebrow darkEyebrow">Add to your vault</span><h2>Encrypt a file</h2><p>The file is split into authenticated chunks and encrypted before upload.</p></div>
      <div className={`dropZone ${dragging ? "dragging" : ""} ${progress !== null ? "processing" : ""}`} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={acceptDrop} onClick={() => progress === null && inputRef.current?.click()} role="button" tabIndex={0} onKeyDown={(event) => { if ((event.key === "Enter" || event.key === " ") && progress === null) inputRef.current?.click(); }}>
        <input ref={inputRef} type="file" onChange={acceptSelection} hidden />
        {progress === null ? (
          <><div className="uploadIcon"><UploadCloud size={25} /></div><div className="dropCopy"><strong>Drop a file here, or <span>browse</span></strong><small>Up to 50 MB · Any file type</small></div><ShieldCheck className="dropShield" size={18} /></>
        ) : (
          <div className="progressContent"><div><span>{stage}</span><strong>{Math.round(progress * 100)}%</strong></div><div className="progressTrack"><span style={{ width: `${Math.max(3, progress * 100)}%` }} /></div><small>Keep this tab open until the encrypted upload completes.</small></div>
        )}
      </div>
    </section>
  );
}

function FileRow({ file, name, busy, masterKeyRef, onBusy, onDelete, onError }: {
  file: EncryptedFileRecord;
  name: string;
  busy: boolean;
  masterKeyRef: RefObject<Uint8Array | null>;
  onBusy: (id: string | null) => void;
  onDelete: () => void;
  onError: (message: string) => void;
}) {
  async function download() {
    const masterKey = masterKeyRef.current;
    if (!masterKey) return onError("Unlock the vault before downloading");
    onBusy(file.id);
    onError("");
    let fileKey: Uint8Array | null = null;
    try {
      const response = await fetch(`/api/files/${file.id}/content`, { credentials: "same-origin" });
      if (!response.ok) {
        const body = await response.json().catch(() => ({ error: "Download failed" })) as { error?: string };
        throw new Error(body.error ?? "Download failed");
      }
      fileKey = await openFileKey(file, masterKey);
      const plaintext = await decryptFile(await response.blob(), fileKey);
      const url = URL.createObjectURL(plaintext);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = name;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "Unable to decrypt this file");
    } finally {
      await lockKey(fileKey);
      onBusy(null);
    }
  }

  async function remove() {
    if (!window.confirm(`Permanently delete “${name}” from this vault?`)) return;
    onBusy(file.id);
    onError("");
    try {
      await apiRequest(`/api/files/${file.id}`, { method: "DELETE", body: "{}" });
      onDelete();
    } catch (caught) {
      onError(caught instanceof Error ? caught.message : "Could not delete the file");
    } finally {
      onBusy(null);
    }
  }

  return (
    <div className="fileRow" role="row">
      <div className="fileNameCell"><span className="fileTypeIcon"><FileText size={20} /></span><div><strong title={name}>{name}</strong><small>ID {file.id.slice(0, 8)}</small></div></div>
      <span>{formatBytes(file.plainSize)}</span>
      <span>{formatDate(file.createdAt)}</span>
      <span className="protectedLabel"><ShieldCheck size={15} /> Authenticated</span>
      <div className="rowActions">
        <button onClick={download} disabled={busy} title="Decrypt and download" aria-label={`Download ${name}`}>{busy ? <LoaderCircle className="spin" size={18} /> : <ArrowDownToLine size={18} />}</button>
        <button onClick={remove} disabled={busy} className="dangerIcon" title="Delete" aria-label={`Delete ${name}`}><Trash2 size={17} /></button>
      </div>
    </div>
  );
}

function ChangePassphrase({ masterKeyRef, onChanged, onNotice }: {
  masterKeyRef: RefObject<Uint8Array | null>;
  onChanged: (config: VaultConfig) => void;
  onNotice: (message: string) => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (passphrase.length < 15) return setError("Use at least 15 characters");
    if (passphrase !== confirm) return setError("The passphrases do not match");
    const masterKey = masterKeyRef.current;
    if (!masterKey) return setError("The vault is locked");
    setBusy(true);
    try {
      const config = await rewrapVault(masterKey, passphrase);
      const response = await apiRequest<{ vault: VaultConfig }>("/api/vault", { method: "PUT", body: JSON.stringify(config) });
      onChanged(response.vault);
      setPassphrase("");
      setConfirm("");
      setError("");
      dialogRef.current?.close();
      onNotice("Vault passphrase changed without re-encrypting file data");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not change the passphrase");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button className="secondaryButton" onClick={() => dialogRef.current?.showModal()}><RefreshCw size={16} /> Change passphrase</button>
      <dialog className="modal" ref={dialogRef}>
        <form onSubmit={submit}>
          <button type="button" className="modalClose" onClick={() => dialogRef.current?.close()} aria-label="Close"><X size={18} /></button>
          <div className="modalIcon"><KeyRound size={21} /></div>
          <span className="eyebrow darkEyebrow">Key management</span>
          <h2>Change vault passphrase</h2>
          <p>A new wrapping key will protect your existing master key. Your files do not need to be re-encrypted.</p>
          <label><span>New vault passphrase</span><input type="password" autoComplete="new-password" value={passphrase} onChange={(event) => setPassphrase(event.target.value)} minLength={15} maxLength={128} required /></label>
          <label><span>Confirm new passphrase</span><input type="password" autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} minLength={15} maxLength={128} required /></label>
          {error ? <div className="formError">{error}</div> : null}
          <button className="primaryButton wideButton" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={18} /> Rewrapping key…</> : "Update passphrase"}</button>
        </form>
      </dialog>
    </>
  );
}
