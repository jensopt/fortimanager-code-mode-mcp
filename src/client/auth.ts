/**
 * FortiManager Authentication Providers
 *
 * Token-based (stateless) and session-based (login/logout) auth strategies.
 */

import { FmgApiError, type FmgClientConfig, type JsonRpcRequest, type JsonRpcResponse } from './types.js';

// ─── Auth Provider Interface ────────────────────────────────────────

/** Authentication provider that produces headers/session for requests */
export interface AuthProvider {
  /** Get authentication headers for an HTTP request */
  getAuthHeaders(): Record<string, string>;

  /** Get session ID for inclusion in JSON-RPC body (null for token auth) */
  getSession(): string | null;

  /** Initialize the auth provider (e.g., login for session-based) */
  initialize?(): Promise<void>;

  /** Clean up the auth provider (e.g., logout for session-based) */
  dispose?(): Promise<void>;
}

/** Sends a raw JSON-RPC envelope to FMG (no auth handling) */
export type JsonRpcPost = (request: JsonRpcRequest) => Promise<JsonRpcResponse>;

// ─── Token Auth Provider ────────────────────────────────────────────

/**
 * Stateless token-based authentication.
 * Uses the `Authorization: Bearer <token>` header.
 * No login/logout lifecycle needed.
 */
export class TokenAuthProvider implements AuthProvider {
  private readonly token: string;

  constructor(config: FmgClientConfig) {
    this.token = config.apiToken ?? '';
  }

  getAuthHeaders(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
    };
  }

  getSession(): string | null {
    return null;
  }
}

// ─── Session Auth Provider ──────────────────────────────────────────

/**
 * Session-based authentication for a regular admin with JSON API access (rpc-permit).
 * Logs in via `exec /sys/login/user`, puts the session ID in every request body,
 * and logs out when disposed.
 */
export class SessionAuthProvider implements AuthProvider {
  private session: string | null = null;
  private pending: Promise<void> | null = null;

  constructor(
    private readonly username: string,
    private readonly password: string,
    private readonly post: JsonRpcPost,
  ) {}

  getAuthHeaders(): Record<string, string> {
    return {};
  }

  getSession(): string | null {
    return this.session;
  }

  /** Log in if there is no session yet (concurrent callers share one login) */
  async initialize(): Promise<void> {
    if (this.session) return;
    await this.login();
  }

  /** Log in again unless another caller already replaced the stale session */
  async relogin(staleSession: string | null): Promise<void> {
    if (this.session !== staleSession) return;
    this.session = null;
    await this.login();
  }

  private login(): Promise<void> {
    this.pending ??= this.doLogin().finally(() => {
      this.pending = null;
    });
    return this.pending;
  }

  private async doLogin(): Promise<void> {
    const url = '/sys/login/user';
    const response = await this.post({
      id: 0,
      method: 'exec',
      params: [{ url, data: { user: this.username, passwd: this.password } }],
      session: null,
    });
    const status = response.result[0]?.status;
    if (!response.session || status?.code !== 0) {
      throw new FmgApiError(
        `Login failed for admin "${this.username}": ${status?.message ?? 'no session returned'}` +
          ' (check password, JSON API access/rpc-permit, trusted hosts, 2FA)',
        status?.code ?? -1,
        url,
        'exec',
        status,
      );
    }
    this.session = response.session;
  }

  async dispose(): Promise<void> {
    if (!this.session) return;
    const session = this.session;
    this.session = null;
    try {
      await this.post({ id: 0, method: 'exec', params: [{ url: '/sys/logout' }], session });
    } catch (err: unknown) {
      console.error('Error during logout:', err);
    }
  }
}

// ─── Factory ────────────────────────────────────────────────────────

/**
 * Create the auth provider for the config: API token when set,
 * otherwise a session login with username/password.
 */
export function createAuthProvider(config: FmgClientConfig, post: JsonRpcPost): AuthProvider {
  if (config.apiToken) return new TokenAuthProvider(config);
  if (config.username && config.password) {
    return new SessionAuthProvider(config.username, config.password, post);
  }
  throw new Error('No FortiManager credentials: set an API token or username/password.');
}
