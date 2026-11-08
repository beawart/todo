window.PlanSurfOneDrive = (() => {
  const filePath = '/me/drive/special/approot:/PlanSurfDailySpark.enc.json:/content';
  const scopes = ['Files.ReadWrite.AppFolder'];
  const iterations = 310000;
  const format = 'plansurf-dailyspark-encrypted';
  let client;
  let initialized;

  const clientId = () => window.PLAN_SURF_CONFIG?.microsoftClientId?.trim() || '';
  const getClient = async () => {
    if (!clientId()) {
      throw new Error('Add your Microsoft Entra application client ID to config.js before signing in.');
    }
    if (!window.msal?.PublicClientApplication) {
      throw new Error('Microsoft sign-in library failed to load. Check your internet connection and reload.');
    }
    if (!client) {
      client = new window.msal.PublicClientApplication({
        auth: {
          clientId: clientId(),
          authority: 'https://login.microsoftonline.com/consumers',
          redirectUri: `${window.location.origin}${window.location.pathname}`
        },
        cache: { cacheLocation: 'localStorage' }
      });
    }
    if (!initialized) {
      initialized = client.initialize().then(() => client.handleRedirectPromise());
    }
    await initialized;
    return client;
  };

  const accountFor = app => app.getActiveAccount() || app.getAllAccounts()[0] || null;
  const account = async () => accountFor(await getClient());

  const accessToken = async () => {
    const app = await getClient();
    const signedIn = accountFor(app);
    if (!signedIn) throw new Error('Sign in to Microsoft before syncing.');
    try {
      const result = await app.acquireTokenSilent({ account: signedIn, scopes });
      return result.accessToken;
    } catch (error) {
      if (error?.name === 'InteractionRequiredAuthError') {
        await app.acquireTokenRedirect({ account: signedIn, scopes });
      }
      throw error;
    }
  };

  const graphRequest = async (method, body) => {
    const response = await fetch(`https://graph.microsoft.com/v1.0${filePath}`, {
      method,
      headers: {
        Authorization: `Bearer ${await accessToken()}`,
        ...(body ? { 'Content-Type': 'application/json' } : {})
      },
      ...(body ? { body } : {}),
      cache: 'no-store'
    });
    if (response.status === 404 && method === 'GET') return null;
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      throw new Error(payload?.error?.message || `OneDrive request failed (${response.status}).`);
    }
    return method === 'GET' ? response.json() : true;
  };

  const toBase64 = bytes => {
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary);
  };

  const fromBase64 = value => Uint8Array.from(atob(value), character => character.charCodeAt(0));
  const deriveKey = async (passphrase, salt, count) => {
    const material = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: count, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  };

  const encrypt = async (data, passphrase) => {
    if (!passphrase) throw new Error('Enter a passphrase to encrypt your backup.');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt, iterations);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(JSON.stringify(data))
    );
    return JSON.stringify({
      format,
      version: 1,
      kdf: 'PBKDF2-SHA-256',
      iterations,
      salt: toBase64(salt),
      iv: toBase64(iv),
      ciphertext: toBase64(new Uint8Array(ciphertext))
    });
  };

  const decrypt = async (envelope, passphrase) => {
    if (!passphrase) throw new Error('Enter the passphrase used for this backup.');
    if (
      envelope?.format !== format ||
      envelope.version !== 1 ||
      envelope.kdf !== 'PBKDF2-SHA-256' ||
      !Number.isInteger(envelope.iterations) ||
      envelope.iterations < 100000 ||
      envelope.iterations > 1000000
    ) {
      throw new Error('The OneDrive file is not a supported encrypted planner backup.');
    }
    let plaintext;
    try {
      const key = await deriveKey(passphrase, fromBase64(envelope.salt), envelope.iterations);
      plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(envelope.iv) },
        key,
        fromBase64(envelope.ciphertext)
      );
    } catch (error) {
      throw new Error('Could not decrypt the backup. Check your passphrase and try again.');
    }
    try {
      return JSON.parse(new TextDecoder().decode(plaintext));
    } catch {
      throw new Error('The decrypted OneDrive backup is not valid planner data.');
    }
  };

  return {
    async initialize() {
      const app = await getClient();
      const signedIn = accountFor(app);
      if (signedIn) app.setActiveAccount(signedIn);
      return signedIn;
    },
    async signIn() {
      const app = await getClient();
      await app.loginRedirect({ scopes });
    },
    async signOut() {
      const app = await getClient();
      const signedIn = accountFor(app);
      if (signedIn) await app.logoutRedirect({ account: signedIn });
    },
    async load(passphrase) {
      const envelope = await graphRequest('GET');
      return envelope ? decrypt(envelope, passphrase) : null;
    },
    async save(data, passphrase) {
      const encrypted = await encrypt(data, passphrase);
      await graphRequest('PUT', encrypted);
    }
  };
})();
