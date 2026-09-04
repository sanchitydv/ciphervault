"use client";

import { useState, type FormEvent } from "react";
import { ArrowRight, Check, Eye, EyeOff, Fingerprint, KeyRound, ShieldCheck } from "lucide-react";
import { apiRequest } from "@/lib/client/api";
import { Brand } from "@/components/brand";

type Mode = "login" | "register";

const securityPoints = [
  "Files encrypted before they leave your device",
  "A unique encryption key for every file",
  "Authenticated streams detect any modification",
];

export function AuthScreen() {
  const [mode, setMode] = useState<Mode>("register");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await apiRequest(`/api/auth/${mode}`, {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      window.location.reload();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to continue");
      setSubmitting(false);
    }
  }

  function switchMode(nextMode: Mode) {
    setMode(nextMode);
    setError("");
  }

  return (
    <main className="authPage">
      <section className="authStory">
        <div className="storyInner">
          <Brand inverse />
          <div className="storyCopy">
            <span className="eyebrow">Zero-knowledge file storage</span>
            <h1>Your files.<br />Your keys.<br /><em>Your privacy.</em></h1>
            <p>
              CipherVault encrypts every file inside your browser. The server stores opaque data—not
              your documents, filenames, or vault key.
            </p>
            <ul className="securityList">
              {securityPoints.map((point) => (
                <li key={point}><span><Check size={14} /></span>{point}</li>
              ))}
            </ul>
          </div>
          <div className="storyFooter">
            <ShieldCheck size={18} />
            XChaCha20-Poly1305 · Argon2id · Authenticated chunks
          </div>
        </div>
      </section>

      <section className="authFormSide">
        <div className="mobileBrand"><Brand /></div>
        <div className="authCard">
          <div className="authIcon" aria-hidden="true">
            {mode === "register" ? <Fingerprint size={27} /> : <KeyRound size={25} />}
          </div>
          <p className="authKicker">{mode === "register" ? "Create your account" : "Welcome back"}</p>
          <h2>{mode === "register" ? "Start your private vault" : "Sign in to CipherVault"}</h2>
          <p className="authLead">
            {mode === "register"
              ? "Your account password signs you in. You will create a separate vault passphrase next."
              : "Use your account credentials. Your vault remains locked until you enter its passphrase."}
          </p>

          <div className="segmented" role="tablist" aria-label="Authentication mode">
            <button type="button" role="tab" aria-selected={mode === "register"} onClick={() => switchMode("register")}>Create account</button>
            <button type="button" role="tab" aria-selected={mode === "login"} onClick={() => switchMode("login")}>Sign in</button>
          </div>

          <form onSubmit={submit} className="authForm">
            <label>
              <span>Email address</span>
              <input type="email" name="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" required maxLength={254} />
            </label>
            <label>
              <span>Account password</span>
              <div className="passwordField">
                <input type={showPassword ? "text" : "password"} name="password" autoComplete={mode === "register" ? "new-password" : "current-password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 15 characters" minLength={15} maxLength={128} required />
                <button type="button" onClick={() => setShowPassword((shown) => !shown)} aria-label={showPassword ? "Hide password" : "Show password"}>
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </label>
            {error ? <div className="formError" role="alert">{error}</div> : null}
            <button className="primaryButton wideButton" type="submit" disabled={submitting}>
              {submitting ? "Securing your session…" : mode === "register" ? "Create secure account" : "Sign in"}
              {submitting ? null : <ArrowRight size={18} />}
            </button>
          </form>

          <p className="privacyNote">
            Account passwords are protected with memory-hard Argon2id hashing and never stored in plaintext.
          </p>
        </div>
      </section>
    </main>
  );
}
