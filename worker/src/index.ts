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
  RESEND_API_KEY: string;
  MAIL_FROM?: string;
  SETUP_CODE?: string; // Optional admin fallback
}

const RP_NAME = 'smkn apps';
const RP_ID = 'git.smkn.net';
const ORIGIN = 'https://git.smkn.net';
const SESSION_DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days (ms)
// __Host- prefix: browser enforces Secure, Path=/ and no Domain, and the
// distinct name cannot collide with other cookies on git.smkn.net
// (e.g. a leftover Clerk "__session" cookie).
const SESSION_COOKIE = '__Host-smkn_session';

// Parse the Cookie header and return the value of an exact cookie name.
function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get('Cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      const value = part.slice(idx + 1).trim();
      return value || null;
    }
  }
  return null;
}

function generateId(): string {
  return crypto.randomUUID();
}

function generateSessionId(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function getSession(request: Request, env: Env): Promise<string | null> {
  const sessionId = getCookie(request, SESSION_COOKIE);
  if (!sessionId) return null;

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
  return `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}; Path=/`;
}

function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`;
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
    'Cache-Control': 'no-store',
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

// Email verification helpers

function generateOTP(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function hashOTP(code: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(code);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyOTP(code: string, hash: string): Promise<boolean> {
  const codeHash = await hashOTP(code);
  return codeHash === hash;
}

function getClientIP(request: Request): string {
  return request.headers.get('CF-Connecting-IP') || 
         request.headers.get('X-Forwarded-For')?.split(',')[0].trim() ||
         'unknown';
}

async function checkRateLimit(env: Env, recipient: string, channel: string, ip: string): Promise<boolean> {
  const now = Date.now();
  const fiveMinutesAgo = now - 5 * 60 * 1000;
  const oneHourAgo = now - 60 * 60 * 1000;

  // Check recent sends for this recipient (max 3 per 5 minutes)
  const recipientCount = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM verification_sends WHERE recipient = ? AND channel = ? AND sent_at > ?'
  ).bind(recipient, channel, fiveMinutesAgo).first<{ count: number }>();

  if (recipientCount && recipientCount.count >= 3) {
    return false;
  }

  // Check recent sends for this IP (max 10 per hour)
  if (ip !== 'unknown') {
    const ipCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM verification_sends WHERE ip_address = ? AND sent_at > ?'
    ).bind(ip, oneHourAgo).first<{ count: number }>();

    if (ipCount && ipCount.count >= 10) {
      return false;
    }
  }

  return true;
}

async function sendEmailOTP(env: Env, email: string, code: string, isRecovery: boolean): Promise<boolean> {
  const from = env.MAIL_FROM || 'smkn apps <noreply@smkn.net>';
  const subject = isRecovery ? 'パスキー復旧コード - smkn apps' : '認証コード - smkn apps';
  const text = `認証コード: ${code}\n\nこのコードは10分間有効です。\n\nこのメールに心当たりがない場合は無視してください。`;
  const html = `
    <div style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1f2330;">${isRecovery ? 'パスキー復旧' : 'アカウント登録'}</h2>
      <p>認証コードは:</p>
      <div style="background: #f6f7fb; border: 2px solid #3b6cf6; border-radius: 8px; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 4px; margin: 20px 0;">
        ${code}
      </div>
      <p style="color: #6b7180; font-size: 14px;">このコードは10分間有効です。</p>
      <p style="color: #6b7180; font-size: 14px;">このメールに心当たりがない場合は無視してください。</p>
      <hr style="border: none; border-top: 1px solid #e3e6ee; margin: 30px 0;">
      <p style="color: #9aa1b2; font-size: 12px;">smkn apps - https://git.smkn.net</p>
    </div>
  `;

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to: email,
        subject,
        text,
        html,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('Resend API error:', response.status, errorData);
      return false;
    }

    const result = await response.json() as { id?: string };
    console.log('Email sent via Resend', { id: result.id });
    return true;
  } catch (error: any) {
    console.error('Email send error:', error?.message ?? error);
    return false;
  }
}

// Email verification: Send code
async function handleVerifySend(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as { email: string; username: string };
    
    if (typeof body.email !== 'string' || !body.email.includes('@')) {
      return jsonResponse({ error: 'メールアドレスが正しくありません' }, 400);
    }
    if (typeof body.username !== 'string' || !body.username.trim() || body.username.length > 64) {
      return jsonResponse({ error: 'ユーザー名が正しくありません' }, 400);
    }

    const email = body.email.toLowerCase().trim();
    const username = body.username.trim();

    // Check if email already exists
    const existingEmail = await env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();

    if (existingEmail) {
      return jsonResponse({ error: 'このメールアドレスは既に使用されています' }, 400);
    }

    // Check if username already exists
    const existingUser = await env.DB.prepare(
      'SELECT id FROM users WHERE username = ?'
    ).bind(username).first();

    if (existingUser) {
      return jsonResponse({ error: 'このユーザー名は既に使用されています' }, 400);
    }

    // Rate limiting
    const ip = getClientIP(request);
    const canSend = await checkRateLimit(env, email, 'email', ip);
    if (!canSend) {
      return jsonResponse({ error: '送信回数が上限に達しました。しばらく待ってから再度お試しください' }, 429);
    }

    // Generate and store code
    const code = generateOTP();
    const codeHash = await hashOTP(code);
    const codeId = generateId();
    const now = Date.now();
    const expiresAt = now + 10 * 60 * 1000; // 10 minutes

    await env.DB.batch([
      // Store verification code
      env.DB.prepare(
        'INSERT INTO verification_codes (id, channel, recipient, code_hash, attempts, max_attempts, user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(codeId, 'email', email, codeHash, 0, 5, null, expiresAt, now),
      // Track send for rate limiting
      env.DB.prepare(
        'INSERT INTO verification_sends (id, channel, recipient, ip_address, sent_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(generateId(), 'email', email, ip, now),
      // Clean up old codes
      env.DB.prepare(
        'DELETE FROM verification_codes WHERE expires_at < ?'
      ).bind(now),
    ]);

    // Send email
    const sent = await sendEmailOTP(env, email, code, false);
    if (!sent) {
      return jsonResponse({ error: 'メールの送信に失敗しました' }, 500);
    }

    return jsonResponse({ 
      success: true,
      codeId,
      expiresAt,
    });
  } catch (error) {
    console.error('Verify send error:', error);
    return jsonResponse({ error: 'コードの送信に失敗しました' }, 500);
  }
}

// Email verification: Verify code
async function handleVerifyCheck(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as { codeId: string; code: string };

    if (!body.codeId || !body.code || body.code.length !== 6) {
      return jsonResponse({ error: 'コードが正しくありません' }, 400);
    }

    const now = Date.now();

    // Get verification code
    const codeRow = await env.DB.prepare(
      'SELECT * FROM verification_codes WHERE id = ? AND channel = ? AND user_id IS NULL AND expires_at > ?'
    ).bind(body.codeId, 'email', now).first<{
      id: string;
      recipient: string;
      code_hash: string;
      attempts: number;
      max_attempts: number;
    }>();

    if (!codeRow) {
      return jsonResponse({ error: 'コードが見つからないか、有効期限が切れています' }, 400);
    }

    // Check attempts
    if (codeRow.attempts >= codeRow.max_attempts) {
      return jsonResponse({ error: '試行回数が上限に達しました。新しいコードを発行してください' }, 429);
    }

    // Verify code
    const isValid = await verifyOTP(body.code, codeRow.code_hash);

    if (!isValid) {
      // Increment attempts
      await env.DB.prepare(
        'UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?'
      ).bind(body.codeId).run();

      const remaining = codeRow.max_attempts - codeRow.attempts - 1;
      return jsonResponse({ 
        error: `コードが正しくありません。残り${remaining}回試行できます`,
      }, 400);
    }

    // Code is valid - generate verification token
    const verificationToken = generateSessionId();

    // Store verification token in the code record (reuse the same record)
    await env.DB.prepare(
      'UPDATE verification_codes SET code_hash = ? WHERE id = ?'
    ).bind(verificationToken, body.codeId).run();

    return jsonResponse({
      verified: true,
      verificationToken,
      email: codeRow.recipient,
    });
  } catch (error) {
    console.error('Verify check error:', error);
    return jsonResponse({ error: 'コードの検証に失敗しました' }, 500);
  }
}

// Registration flow: Step 1 - Generate options (now requires verification token)
async function handleRegisterOptions(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as { 
      username: string; 
      verificationToken: string;
      setupCode?: string; // Optional admin fallback
    };

    let email: string | null = null;

    // Admin fallback: allow SETUP_CODE if enabled
    if (body.setupCode && env.SETUP_CODE) {
      if (body.setupCode !== env.SETUP_CODE) {
        return jsonResponse({ error: 'セットアップコードが正しくありません' }, 401);
      }
      // SETUP_CODE path: no email required
    } else {
      // Normal path: require verification token
      if (!body.verificationToken) {
        return jsonResponse({ error: 'メール認証が必要です' }, 401);
      }

      // Get email from verification token
      const now = Date.now();
      const verificationRow = await env.DB.prepare(
        'SELECT recipient FROM verification_codes WHERE code_hash = ? AND channel = ? AND user_id IS NULL AND expires_at > ?'
      ).bind(body.verificationToken, 'email', now).first<{ recipient: string }>();

      if (!verificationRow) {
        return jsonResponse({ error: '認証トークンが無効です' }, 401);
      }

      email = verificationRow.recipient;

      // Check if email already registered (double-check)
      const existingEmail = await env.DB.prepare(
        'SELECT id FROM users WHERE email = ?'
      ).bind(email).first();

      if (existingEmail) {
        return jsonResponse({ error: 'このメールアドレスは既に使用されています' }, 400);
      }
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

    // Store challenge temporarily (store email in challenge for later retrieval)
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    const challengeData = JSON.stringify({ email });
    await env.DB.prepare(
      'INSERT INTO challenges (challenge, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(options.challenge, `${userId}:${challengeData}`, expiresAt).run();

    return jsonResponse({ options, userId, email });
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
      email?: string;
      response: RegistrationResponseJSON;
    };

    // Get stored challenge
    const challengeRow = await env.DB.prepare(
      'SELECT user_id FROM challenges WHERE user_id LIKE ? AND expires_at > ?'
    ).bind(`${body.userId}:%`, Date.now()).first<{ user_id: string }>();

    if (!challengeRow) {
      return jsonResponse({ error: 'チャレンジが見つからないか、有効期限が切れています' }, 400);
    }

    // Extract email from challenge data
    const [userId, challengeDataStr] = challengeRow.user_id.split(':', 2);
    let email: string | null = null;
    try {
      const challengeData = JSON.parse(challengeDataStr || '{}');
      email = challengeData.email || body.email || null;
    } catch {
      email = body.email || null;
    }

    // Get actual challenge
    const actualChallenge = await env.DB.prepare(
      'SELECT challenge FROM challenges WHERE user_id = ?'
    ).bind(challengeRow.user_id).first<{ challenge: string }>();

    if (!actualChallenge) {
      return jsonResponse({ error: 'チャレンジが見つかりません' }, 400);
    }

    // Verify registration
    const verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: actualChallenge.challenge,
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
        'INSERT INTO users (id, username, email, created_at) VALUES (?, ?, ?, ?)'
      ).bind(body.userId, body.username, email, now),
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
      ).bind(challengeRow.user_id),
      // Clean up verification code if email was used
      email ? env.DB.prepare(
        'DELETE FROM verification_codes WHERE recipient = ? AND channel = ?'
      ).bind(email, 'email') : env.DB.prepare('SELECT 1'), // No-op if no email
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

// Recovery: Send email code for existing user
async function handleRecoverySend(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as { email: string };
    
    if (typeof body.email !== 'string' || !body.email.includes('@')) {
      return jsonResponse({ error: 'メールアドレスが正しくありません' }, 400);
    }

    const email = body.email.toLowerCase().trim();

    // Check if email exists
    const user = await env.DB.prepare(
      'SELECT id, username FROM users WHERE email = ?'
    ).bind(email).first<{ id: string; username: string }>();

    if (!user) {
      // Don't reveal if email exists or not
      return jsonResponse({ success: true, message: 'メールアドレスが登録されている場合、コードを送信しました' });
    }

    // Rate limiting
    const ip = getClientIP(request);
    const canSend = await checkRateLimit(env, email, 'email', ip);
    if (!canSend) {
      return jsonResponse({ error: '送信回数が上限に達しました。しばらく待ってから再度お試しください' }, 429);
    }

    // Generate and store code
    const code = generateOTP();
    const codeHash = await hashOTP(code);
    const codeId = generateId();
    const now = Date.now();
    const expiresAt = now + 10 * 60 * 1000; // 10 minutes

    await env.DB.batch([
      // Store verification code with user_id for recovery
      env.DB.prepare(
        'INSERT INTO verification_codes (id, channel, recipient, code_hash, attempts, max_attempts, user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(codeId, 'email', email, codeHash, 0, 5, user.id, expiresAt, now),
      // Track send for rate limiting
      env.DB.prepare(
        'INSERT INTO verification_sends (id, channel, recipient, ip_address, sent_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(generateId(), 'email', email, ip, now),
      // Clean up old codes
      env.DB.prepare(
        'DELETE FROM verification_codes WHERE expires_at < ?'
      ).bind(now),
    ]);

    // Send email
    const sent = await sendEmailOTP(env, email, code, true);
    if (!sent) {
      return jsonResponse({ error: 'メールの送信に失敗しました' }, 500);
    }

    return jsonResponse({ 
      success: true,
      codeId,
      expiresAt,
    });
  } catch (error) {
    console.error('Recovery send error:', error);
    return jsonResponse({ error: 'コードの送信に失敗しました' }, 500);
  }
}

// Recovery: Verify code and return registration options
async function handleRecoveryVerify(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as { codeId: string; code: string };

    if (!body.codeId || !body.code || body.code.length !== 6) {
      return jsonResponse({ error: 'コードが正しくありません' }, 400);
    }

    const now = Date.now();

    // Get verification code (must have user_id set for recovery)
    const codeRow = await env.DB.prepare(
      'SELECT * FROM verification_codes WHERE id = ? AND channel = ? AND user_id IS NOT NULL AND expires_at > ?'
    ).bind(body.codeId, 'email', now).first<{
      id: string;
      recipient: string;
      code_hash: string;
      attempts: number;
      max_attempts: number;
      user_id: string;
    }>();

    if (!codeRow) {
      return jsonResponse({ error: 'コードが見つからないか、有効期限が切れています' }, 400);
    }

    // Check attempts
    if (codeRow.attempts >= codeRow.max_attempts) {
      return jsonResponse({ error: '試行回数が上限に達しました。新しいコードを発行してください' }, 429);
    }

    // Verify code
    const isValid = await verifyOTP(body.code, codeRow.code_hash);

    if (!isValid) {
      // Increment attempts
      await env.DB.prepare(
        'UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?'
      ).bind(body.codeId).run();

      const remaining = codeRow.max_attempts - codeRow.attempts - 1;
      return jsonResponse({ 
        error: `コードが正しくありません。残り${remaining}回試行できます`,
      }, 400);
    }

    // Code is valid - get user info and generate registration options
    const user = await env.DB.prepare(
      'SELECT username FROM users WHERE id = ?'
    ).bind(codeRow.user_id).first<{ username: string }>();

    if (!user) {
      return jsonResponse({ error: 'ユーザーが見つかりません' }, 404);
    }

    // Get existing credentials to exclude
    const existingCreds = await env.DB.prepare(
      'SELECT credential_id FROM credentials WHERE user_id = ?'
    ).bind(codeRow.user_id).all<{ credential_id: string }>();

    const excludeCredentials = existingCreds.results.map(row => ({
      id: row.credential_id,
    }));

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: new TextEncoder().encode(codeRow.user_id),
      userName: user.username,
      attestationType: 'none',
      excludeCredentials,
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
    });

    // Store challenge
    const expiresAt = now + 5 * 60 * 1000;
    await env.DB.prepare(
      'INSERT INTO challenges (challenge, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(options.challenge, codeRow.user_id, expiresAt).run();

    return jsonResponse({ 
      verified: true,
      options,
      userId: codeRow.user_id,
    });
  } catch (error) {
    console.error('Recovery verify error:', error);
    return jsonResponse({ error: 'コードの検証に失敗しました' }, 500);
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
    const sessionId = getCookie(request, SESSION_COOKIE);
    if (sessionId) {
      await env.DB.prepare(
        'DELETE FROM sessions WHERE session_id = ?'
      ).bind(sessionId).run();
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
    
    // Email verification
    if (url.pathname === '/api/verify/send' && request.method === 'POST') {
      return handleVerifySend(request, env);
    }
    if (url.pathname === '/api/verify/check' && request.method === 'POST') {
      return handleVerifyCheck(request, env);
    }
    
    // Recovery
    if (url.pathname === '/api/recover/send' && request.method === 'POST') {
      return handleRecoverySend(request, env);
    }
    if (url.pathname === '/api/recover/verify' && request.method === 'POST') {
      return handleRecoveryVerify(request, env);
    }
    
    // Registration
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
