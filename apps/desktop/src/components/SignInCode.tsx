import { useState, type FormEvent } from "react";
import { call, errorText } from "../api";
import { Dots } from "./common";

/**
 * Antigravity's Google sign-in ends on a page of Antigravity's that shows a code, not on a redirect
 * t3boat could take: the code is pasted here and goes to T3 on the machine. A code T3 refuses
 * shows its words and the field stays for another try. Cancel ends the sign-in.
 */
export function SignInCode({ machineId, agent, className }: { machineId: string; agent: string; className: string }) {
  const [code, setCode] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const value = code.trim();
    if (!value || sending) return;
    setSending(true);
    setError(null);
    try {
      // On success the machine stops asking and this goes away.
      await call("answer_sign_in", { id: machineId, code: value });
    } catch (err) {
      setError(errorText(err));
      setSending(false);
    }
  };

  const cancel = () => {
    call("answer_sign_in", { id: machineId, code: null }).catch((err) => setError(errorText(err)));
  };

  return (
    <form className={`code-form ${className}`} onSubmit={submit}>
      <span className="code-hint">Sign in with Google, then paste the code the {agent} page shows</span>
      <span className="code-row">
        <input
          className="code-input"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="Code"
          aria-label={`Code from the ${agent} page`}
          autoFocus
          autoComplete="off"
          spellCheck={false}
          disabled={sending}
        />
        <button className="btn btn-sm btn-solid" type="submit" disabled={!code.trim() || sending} aria-busy={sending}>
          {sending ? <Dots /> : "Send"}
        </button>
        <button className="btn btn-link" type="button" onClick={cancel} disabled={sending}>
          Cancel
        </button>
      </span>
      {error ? <span className="code-error">{error}</span> : null}
    </form>
  );
}
