import { FormEvent, useCallback, useEffect, useState } from 'react';
import { api, DocumentRecord, User } from './api';

interface DashboardStats {
  documentCount: number;
  userCount: number | null;
}

interface AuthResponse {
  token: string;
  user: User;
}

function readableSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function readableDate(value: string): string {
  return new Date(`${value.replace(' ', 'T')}Z`).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('snovasys-token'));
  const [user, setUser] = useState<User | null>(null);
  const [documents, setDocuments] = useState<DocumentRecord[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const clearSession = useCallback(() => {
    sessionStorage.removeItem('snovasys-token');
    setToken(null);
    setUser(null);
    setDocuments([]);
    setStats(null);
  }, []);

  const refreshWorkspace = useCallback(async (activeToken: string) => {
    const [me, documentResult, dashboard] = await Promise.all([
      api<{ user: User }>('/auth/me', { token: activeToken }),
      api<{ documents: DocumentRecord[] }>('/documents', { token: activeToken }),
      api<DashboardStats>('/dashboard', { token: activeToken }),
    ]);
    setUser(me.user);
    setDocuments(documentResult.documents);
    setStats(dashboard);
  }, []);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }
    refreshWorkspace(token)
      .catch((cause: unknown) => {
        clearSession();
        setError(cause instanceof Error ? cause.message : 'Unable to load your workspace.');
      })
      .finally(() => setLoading(false));
  }, [clearSession, refreshWorkspace, token]);

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    const values = new FormData(event.currentTarget);
    const body = Object.fromEntries(values.entries());
    try {
      const result = await api<AuthResponse>(`/auth/${authMode}`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      sessionStorage.setItem('snovasys-token', result.token);
      setUser(result.user);
      setToken(result.token);
      await refreshWorkspace(result.token);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to authenticate.');
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    if (token) {
      try {
        await api<void>('/auth/logout', { method: 'POST', token });
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : 'Unable to sign out.');
        return;
      }
    }
    clearSession();
    setNotice('');
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token) return;
    const form = event.currentTarget;
    const values = new FormData(form);
    if (!values.get('file')) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await api<{ document: DocumentRecord }>('/documents', {
        method: 'POST',
        token,
        body: values,
      });
      form.reset();
      await refreshWorkspace(token);
      setNotice('Your document was uploaded.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to upload the document.');
    } finally {
      setBusy(false);
    }
  }

  async function handleDownload(document: DocumentRecord) {
    if (!token) return;
    setError('');
    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL || '/api'}/documents/${document.id}/download`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) {
        const body = await response.json() as { error?: string };
        throw new Error(body.error || 'Unable to download the document.');
      }
      const fileUrl = URL.createObjectURL(await response.blob());
      const link = window.document.createElement('a');
      link.href = fileUrl;
      link.download = document.original_name;
      link.click();
      URL.revokeObjectURL(fileUrl);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to download the document.');
    }
  }

  async function handleDelete(document: DocumentRecord) {
    if (!token || !window.confirm(`Delete "${document.original_name}"? This cannot be undone.`)) return;
    setError('');
    setNotice('');
    try {
      await api<void>(`/documents/${document.id}`, { method: 'DELETE', token });
      await refreshWorkspace(token);
      setNotice('The document was deleted.');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to delete the document.');
    }
  }

  if (loading) {
    return <main className="loading-screen"><span className="brand-mark">S</span><p>Opening your workspace…</p></main>;
  }

  if (!user) {
    return (
      <main className="auth-layout">
        <section className="auth-aside">
          <a className="brand" href="#"><span className="brand-mark">S</span> snovasys</a>
          <div className="aside-copy">
            <span className="eyebrow">YOUR WORK, IN ORDER</span>
            <h1>A calmer place for your important documents.</h1>
            <p>One secure workspace, organized around the people who need it.</p>
          </div>
          <span className="aside-note">Simple by design. Secure by default.</span>
        </section>
        <section className="auth-main">
          <div className="auth-card">
            <span className="eyebrow">{authMode === 'login' ? 'WELCOME BACK' : 'GET STARTED'}</span>
            <h2>{authMode === 'login' ? 'Sign in to your workspace' : 'Create your account'}</h2>
            <p className="muted">{authMode === 'login' ? 'Your documents are right where you left them.' : 'Join your team’s document workspace.'}</p>
            {error && <div className="message error" role="alert">{error}</div>}
            <form className="auth-form" onSubmit={handleAuth}>
              {authMode === 'register' && (
                <label>
                  Full name
                  <input name="name" autoComplete="name" placeholder="Alex Morgan" maxLength={100} required />
                </label>
              )}
              <label>
                Email address
                <input name="email" type="email" autoComplete="email" placeholder="you@company.com" required />
              </label>
              <label>
                Password
                <input name="password" type="password" autoComplete={authMode === 'login' ? 'current-password' : 'new-password'} minLength={8} maxLength={72} placeholder="At least 8 characters" required />
              </label>
              <button className="button primary wide" disabled={busy}>{busy ? 'Please wait…' : authMode === 'login' ? 'Sign in' : 'Create account'}<span aria-hidden="true">→</span></button>
            </form>
            <p className="auth-switch">
              {authMode === 'login' ? 'New to Snovasys?' : 'Already have an account?'}
              {' '}<button className="text-button" onClick={() => { setError(''); setAuthMode(authMode === 'login' ? 'register' : 'login'); }}>
                {authMode === 'login' ? 'Create an account' : 'Sign in'}
              </button>
            </p>
          </div>
          <span className="copyright">© 2026 Snovasys</span>
        </section>
      </main>
    );
  }

  const role = user.roles.includes('admin') ? 'Admin' : user.roles.includes('manager') ? 'Manager' : 'User';
  const canUpload = user.permissions.includes('documents.upload');
  const canReadAny = user.permissions.includes('documents.read_any');
  const canDeleteAny = user.permissions.includes('documents.delete_any');

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#"><span className="brand-mark">S</span> snovasys</a>
        <div className="side-label">WORKSPACE</div>
        <a className="nav-item active" href="#workspace"><span className="nav-icon">▦</span> Overview</a>
        <a className="nav-item" href="#documents"><span className="nav-icon">▤</span> Documents</a>
        <div className="sidebar-bottom">
          <div className="help-card"><span className="help-icon">✳</span><strong>All in one place</strong><p>Your team's documents, safe and organized.</p></div>
          <div className="profile">
            <div className="avatar">{user.name.trim().charAt(0).toUpperCase()}</div>
            <div className="profile-copy"><strong>{user.name}</strong><span>{role}</span></div>
            <button className="logout-button" onClick={handleLogout} aria-label="Sign out" title="Sign out">↗</button>
          </div>
        </div>
      </aside>

      <main className="main-content" id="workspace">
        <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> Overview</div><div className="secure-label"><span /> Secure workspace</div></header>
        <div className="content-wrap">
          <section className="welcome-row">
            <div><span className="eyebrow">{role.toUpperCase()} WORKSPACE</span><h1>Good to see you, {user.name.split(' ')[0]}.</h1><p>Here’s what’s happening with your documents.</p></div>
            <div className="today-chip">{new Date().toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })}</div>
          </section>

          {(error || notice) && <div className={`message ${error ? 'error' : 'success'}`} role={error ? 'alert' : 'status'}>{error || notice}<button onClick={() => { setError(''); setNotice(''); }} aria-label="Dismiss">×</button></div>}

          <section className="stats-grid" aria-label="Workspace statistics">
            <article className="stat-card"><div className="stat-icon lavender">▤</div><span className="stat-label">{canReadAny ? 'ALL DOCUMENTS' : 'YOUR DOCUMENTS'}</span><strong>{stats?.documentCount ?? documents.length}</strong><span className="stat-foot">in your workspace</span></article>
            {stats?.userCount !== null && stats?.userCount !== undefined && <article className="stat-card"><div className="stat-icon peach">♙</div><span className="stat-label">TEAM MEMBERS</span><strong>{stats.userCount}</strong><span className="stat-foot">registered accounts</span></article>}
            <article className="stat-card accent-card"><div className="accent-orbit">✳</div><span className="stat-label">YOUR ACCESS</span><strong>{role}</strong><span className="stat-foot">role-based permissions</span></article>
          </section>

          <section className="documents-section" id="documents">
            <div className="section-heading"><div><span className="eyebrow">YOUR LIBRARY</span><h2>Documents <span className="count-pill">{documents.length}</span></h2></div>
              {canUpload && <form className="upload-form" onSubmit={handleUpload}><label className="file-picker" title="PDF, TXT, PNG, or JPEG; maximum 20 MiB"><span>＋</span> Choose file<input name="file" type="file" accept=".pdf,.txt,.png,.jpg,.jpeg,application/pdf,text/plain,image/png,image/jpeg" required /></label><button className="button primary upload-button" disabled={busy}>{busy ? 'Uploading…' : 'Upload document'}</button></form>}
            </div>
            <div className="document-table">
              <div className="table-head"><span>NAME</span>{canReadAny && <span>OWNER</span>}<span>ADDED</span><span>SIZE</span><span className="actions-heading">ACTIONS</span></div>
              {documents.length === 0 ? <div className="empty-state"><div className="empty-icon">▤</div><strong>No documents yet</strong><p>{canUpload ? 'Choose a document above to add it to your workspace.' : 'Documents shared with your workspace will appear here.'}</p></div> :
                documents.map((document) => {
                  const canDelete = document.owner_id === user.id || canDeleteAny;
                  return <div className="document-row" key={document.id}>
                    <div className="document-name"><div className={`file-icon ${document.mime_type.includes('pdf') ? 'pdf' : 'generic'}`}>{document.mime_type.includes('pdf') ? 'PDF' : 'DOC'}</div><div><strong title={document.original_name}>{document.original_name}</strong><span>{document.mime_type || 'File'}</span></div></div>
                    {canReadAny && <div className="table-cell owner-cell"><span className="mini-avatar">{(document.owner_name || user.name).charAt(0).toUpperCase()}</span>{document.owner_name || user.name}</div>}
                    <span className="table-cell">{readableDate(document.created_at)}</span><span className="table-cell">{readableSize(document.size_bytes)}</span>
                    <div className="row-actions"><button onClick={() => handleDownload(document)} title="Download document" aria-label={`Download ${document.original_name}`}>↓</button>{canDelete && <button className="delete-action" onClick={() => handleDelete(document)} title="Delete document" aria-label={`Delete ${document.original_name}`}>×</button>}</div>
                  </div>;
                })}
            </div>
            <p className="security-note"><span>✓</span> Your documents are protected by role-based access controls.</p>
          </section>
        </div>
      </main>
    </div>
  );
}
