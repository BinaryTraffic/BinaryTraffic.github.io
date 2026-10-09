import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL, decodeClientDataJSON } from '@simplewebauthn/server/helpers';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
} from '@simplewebauthn/types';

interface Env {
  DB: D1Database;
  SETUP_CODE: string;
}

const RP_NAME = 'smkn apps';
const RP_ID = 'git.smkn.net';
const ORIGIN = 'https://git.smkn.net';
const SESSION_DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days

function generateId(): string {
  return crypto.randomUUID();
}

function generateSessionId(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function getSession(request: Request, env: Env): Promise<string | null> {
  const cookie = request.headers.get('Cookie');
  if (!cookie) return null;

  const sessionMatch = cookie.match(/session=([^;]+)/);
  if (!sessionMatch) return null;

  const sessionId = sessionMatch[1];
  const now = Date.now();

  const session = await env.DB.prepare(
    'SELECT user_id FROM sessions WHERE session_id = ? AND expires_at > ?'
  ).bind(sessionId, now).first<{ user_id: string }>();

  return session?.user_id || null;
}

async function createSession(userId: string, env: Env): Promise<string> {
  const sessionId = generateSessionId();
  const expiresAt = Date.now() + SESSION_DURATION;

  await env.DB.prepare(
    'INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)'
  ).bind(sessionId, userId, expiresAt).run();

  return sessionId;
}

function createSessionCookie(sessionId: string): string {
  const maxAge = Math.floor(SESSION_DURATION / 1000);
  return `session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}; Path=/`;
}

function clearSessionCookie(): string {
  return 'session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/';
}

async function cleanupExpired(env: Env): Promise<void> {
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM challenges WHERE expires_at < ?').bind(now),
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now),
  ]);
}

// CORS headers for responses
function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
  };
}

function jsonResponse(data: any, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(),
    },
  });
}

// Registration flow: Step 1 - Generate options
async function handleRegisterOptions(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as { username: string; setupCode: string };

    // Verify setup code for new user registration (fail closed if the secret is unset)
    if (!env.SETUP_CODE || typeof body.setupCode !== 'string' || body.setupCode !== env.SETUP_CODE) {
      return jsonResponse({ error: 'セットアップコードが正しくありません' }, 401);
    }
    if (typeof body.username !== 'string' || !body.username.trim() || body.username.length > 64) {
      return jsonResponse({ error: 'ユーザー名が正しくありません' }, 400);
    }

    // Check if username already exists
    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE username = ?'
    ).bind(body.username).first();

    if (existing) {
      return jsonResponse({ error: 'このユーザー名は既に使用されています' }, 400);
    }

    const userId = generateId();
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: new TextEncoder().encode(userId),
      userName: body.username,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
    });

    // Store challenge temporarily
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    await env.DB.prepare(
      'INSERT INTO challenges (challenge, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(options.challenge, userId, expiresAt).run();

    return jsonResponse({ options, userId });
  } catch (error) {
    console.error('Register options error:', error);
    return jsonResponse({ error: '登録オプションの生成に失敗しました' }, 500);
  }
}

// Registration flow: Step 2 - Verify response
async function handleRegisterVerify(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as {
      userId: string;
      username: string;
      response: RegistrationResponseJSON;
    };

    // Get stored challenge
    const challengeRow = await env.DB.prepare(
      'SELECT challenge FROM challenges WHERE user_id = ? AND expires_at > ?'
    ).bind(body.userId, Date.now()).first<{ challenge: string }>();

    if (!challengeRow) {
      return jsonResponse({ error: 'チャレンジが見つからないか、有効期限が切れています' }, 400);
    }

    // Verify registration
    const verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return jsonResponse({ error: '登録の検証に失敗しました' }, 400);
    }

    const { credential } = verification.registrationInfo;

    // Store user and credential
    const now = Date.now();
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)'
      ).bind(body.userId, body.username, now),
      env.DB.prepare(
        'INSERT INTO credentials (id, user_id, credential_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(
        generateId(),
        body.userId,
        credential.id, // base64url (matches AuthenticationResponseJSON.id)
        isoBase64URL.fromBuffer(credential.publicKey),
        credential.counter,
        JSON.stringify(body.response.response.transports || []),
        now
      ),
      env.DB.prepare(
        'DELETE FROM challenges WHERE user_id = ?'
      ).bind(body.userId),
    ]);

    // Create session
    const sessionId = await createSession(body.userId, env);

    return new Response(JSON.stringify({ verified: true }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': createSessionCookie(sessionId),
        ...corsHeaders(),
      },
    });
  } catch (error) {
    console.error('Register verify error:', error);
    return jsonResponse({ error: '登録の検証処理に失敗しました' }, 500);
  }
}

// Login flow: Step 1 - Generate options
async function handleLoginOptions(request: Request, env: Env): Promise<Response> {
  try {
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'required',
    });

    // Store challenge without user_id (discoverable credential)
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    await env.DB.prepare(
      'INSERT INTO challenges (challenge, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(options.challenge, null, expiresAt).run();

    return jsonResponse({ options });
  } catch (error) {
    console.error('Login options error:', error);
    return jsonResponse({ error: 'ログインオプションの生成に失敗しました' }, 500);
  }
}

// Login flow: Step 2 - Verify response
async function handleLoginVerify(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as {
      response: AuthenticationResponseJSON;
    };

    // Get credential from database
    const credentialRow = await env.DB.prepare(
      'SELECT c.id, c.user_id, c.credential_id, c.public_key, c.counter, c.transports, u.username FROM credentials c JOIN users u ON c.user_id = u.id WHERE c.credential_id = ?'
    ).bind(body.response.id).first<{
      id: string;
      user_id: string;
      credential_id: string;
      public_key: string;
      counter: number;
      transports: string;
      username: string;
    }>();

    if (!credentialRow) {
      return jsonResponse({ error: '認証情報が見つかりません' }, 400);
    }

    // Get the exact challenge the authenticator signed (issued by /api/login/options)
    const clientChallenge = decodeClientDataJSON(body.response.response.clientDataJSON).challenge;
    const challengeRow = await env.DB.prepare(
      'SELECT challenge FROM challenges WHERE challenge = ? AND user_id IS NULL AND expires_at > ?'
    ).bind(clientChallenge, Date.now()).first<{ challenge: string }>();

    if (!challengeRow) {
      return jsonResponse({ error: 'チャレンジが見つからないか、有効期限が切れています' }, 400);
    }

    // Verify authentication
    const verification = await verifyAuthenticationResponse({
      response: body.response,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: credentialRow.credential_id,
        publicKey: isoBase64URL.toBuffer(credentialRow.public_key),
        counter: credentialRow.counter,
        transports: JSON.parse(credentialRow.transports || '[]') as AuthenticatorTransportFuture[],
      },
    });

    if (!verification.verified) {
      return jsonResponse({ error: '認証の検証に失敗しました' }, 400);
    }

    // Update counter
    await env.DB.prepare(
      'UPDATE credentials SET counter = ? WHERE id = ?'
    ).bind(verification.authenticationInfo.newCounter, credentialRow.id).run();

    // Clean up challenge
    await env.DB.prepare(
      'DELETE FROM challenges WHERE challenge = ?'
    ).bind(challengeRow.challenge).run();

    // Create session
    const sessionId = await createSession(credentialRow.user_id, env);

    return new Response(JSON.stringify({ verified: true, username: credentialRow.username }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': createSessionCookie(sessionId),
        ...corsHeaders(),
      },
    });
  } catch (error) {
    console.error('Login verify error:', error);
    return jsonResponse({ error: 'ログインの検証処理に失敗しました' }, 500);
  }
}

// Add device: Step 1 - Generate options (for logged-in users)
async function handleAddDeviceOptions(request: Request, env: Env): Promise<Response> {
  try {
    const userId = await getSession(request, env);
    if (!userId) {
      return jsonResponse({ error: '認証が必要です' }, 401);
    }

    // Get user info
    const user = await env.DB.prepare(
      'SELECT username FROM users WHERE id = ?'
    ).bind(userId).first<{ username: string }>();

    if (!user) {
      return jsonResponse({ error: 'ユーザーが見つかりません' }, 404);
    }

    // Get existing credentials to exclude
    const existingCreds = await env.DB.prepare(
      'SELECT credential_id FROM credentials WHERE user_id = ?'
    ).bind(userId).all<{ credential_id: string }>();

    const excludeCredentials = existingCreds.results.map(row => ({
      id: row.credential_id,
    }));

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: new TextEncoder().encode(userId),
      userName: user.username,
      attestationType: 'none',
      excludeCredentials,
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
    });

    // Store challenge
    const expiresAt = Date.now() + 5 * 60 * 1000;
    await env.DB.prepare(
      'INSERT INTO challenges (challenge, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(options.challenge, userId, expiresAt).run();

    return jsonResponse({ options });
  } catch (error) {
    console.error('Add device options error:', error);
    return jsonResponse({ error: 'デバイス追加オプションの生成に失敗しました' }, 500);
  }
}

// Add device: Step 2 - Verify response
async function handleAddDeviceVerify(request: Request, env: Env): Promise<Response> {
  try {
    const userId = await getSession(request, env);
    if (!userId) {
      return jsonResponse({ error: '認証が必要です' }, 401);
    }

    const body = await request.json() as {
      response: RegistrationResponseJSON;
    };

    // Get challenge
    const challengeRow = await env.DB.prepare(
      'SELECT challenge FROM challenges WHERE user_id = ? AND expires_at > ?'
    ).bind(userId, Date.now()).first<{ challenge: string }>();

    if (!challengeRow) {
      return jsonResponse({ error: 'チャレンジが見つかりません' }, 400);
    }

    // Verify registration
    const verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return jsonResponse({ error: 'デバイスの検証に失敗しました' }, 400);
    }

    const { credential } = verification.registrationInfo;

    // Store new credential
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO credentials (id, user_id, credential_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(
        generateId(),
        userId,
        credential.id, // base64url (matches AuthenticationResponseJSON.id)
        isoBase64URL.fromBuffer(credential.publicKey),
        credential.counter,
        JSON.stringify(body.response.response.transports || []),
        Date.now()
      ),
      env.DB.prepare(
        'DELETE FROM challenges WHERE user_id = ?'
      ).bind(userId),
    ]);

    return jsonResponse({ verified: true });
  } catch (error) {
    console.error('Add device verify error:', error);
    return jsonResponse({ error: 'デバイス追加の検証に失敗しました' }, 500);
  }
}

// Get current user info
async function handleMe(request: Request, env: Env): Promise<Response> {
  try {
    const userId = await getSession(request, env);
    if (!userId) {
      return jsonResponse({ authenticated: false }, 401);
    }

    const user = await env.DB.prepare(
      'SELECT username, created_at FROM users WHERE id = ?'
    ).bind(userId).first<{ username: string; created_at: number }>();

    if (!user) {
      return jsonResponse({ authenticated: false }, 401);
    }

    // Get credential count
    const credCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM credentials WHERE user_id = ?'
    ).bind(userId).first<{ count: number }>();

    return jsonResponse({
      authenticated: true,
      username: user.username,
      credentialCount: credCount?.count || 0,
    });
  } catch (error) {
    console.error('Me endpoint error:', error);
    return jsonResponse({ error: 'ユーザー情報の取得に失敗しました' }, 500);
  }
}

// Logout
async function handleLogout(request: Request, env: Env): Promise<Response> {
  try {
    const cookie = request.headers.get('Cookie');
    if (cookie) {
      const sessionMatch = cookie.match(/session=([^;]+)/);
      if (sessionMatch) {
        await env.DB.prepare(
          'DELETE FROM sessions WHERE session_id = ?'
        ).bind(sessionMatch[1]).run();
      }
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': clearSessionCookie(),
        ...corsHeaders(),
      },
    });
  } catch (error) {
    console.error('Logout error:', error);
    return jsonResponse({ error: 'ログアウトに失敗しました' }, 500);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(),
      });
    }

    // Periodic cleanup
    if (Math.random() < 0.1) {
      await cleanupExpired(env);
    }

    // Route handling
    if (url.pathname === '/api/register/options' && request.method === 'POST') {
      return handleRegisterOptions(request, env);
    }
    if (url.pathname === '/api/register/verify' && request.method === 'POST') {
      return handleRegisterVerify(request, env);
    }
    if (url.pathname === '/api/login/options' && request.method === 'POST') {
      return handleLoginOptions(request, env);
    }
    if (url.pathname === '/api/login/verify' && request.method === 'POST') {
      return handleLoginVerify(request, env);
    }
    if (url.pathname === '/api/add-device/options' && request.method === 'POST') {
      return handleAddDeviceOptions(request, env);
    }
    if (url.pathname === '/api/add-device/verify' && request.method === 'POST') {
      return handleAddDeviceVerify(request, env);
    }
    if (url.pathname === '/api/me' && request.method === 'GET') {
      return handleMe(request, env);
    }
    if (url.pathname === '/api/logout' && request.method === 'POST') {
      return handleLogout(request, env);
    }

    return jsonResponse({ error: 'Not Found' }, 404);
  },
};
