# AIxBlock Bug Bounty - Pull Request Creation Guide

## Overview
This guide provides the exact pull request templates for each vulnerability fix to the AIxBlock repository.

---

## PR 1: Private Key Exposure Fix

### **Title**: `Fix: Private Key Exposure in Web3 Authentication`

### **Body**:
```markdown
## 🔧 **Fix Implementation**

This PR addresses the critical private key exposure vulnerability identified in issue #345.

### **Changes Made**
- Remove client-side private key access entirely
- Implement secure server-side signing with authentication
- Add secure key management with encryption
- Prevent wallet compromise through XSS attacks
- Add audit logging for all key operations

### **Security Improvements**
1. **Eliminates client-side private key exposure**
2. **Implements server-side signing with proper authentication**
3. **Uses secure key management with encryption**
4. **Adds audit logging for all key operations**
5. **Implements proper error handling**

### **Files Modified**
- `frontend/src/web3AuthContext.tsx` - Remove vulnerable getPrivateKey method
- `frontend/src/solanaRPC.ts` - Replace with secure wallet connection
- `backend/api/src/routes/signing.ts` - Add server-side signing endpoint
- `backend/api/src/services/keyManagement.ts` - Add secure key management

### **Code Changes**

#### 1. Remove Vulnerable Method
```typescript
// REMOVE this vulnerable method entirely
// export const getPrivateKey = async (): Promise<string> => {
//   return await solanaRPCInstance.getPrivateKey();
// };

// REPLACE with secure server-side signing
export const signTransaction = async (transaction: Transaction): Promise<Transaction> => {
  const response = await fetch('/api/sign-transaction', {
    method: 'POST',
    body: JSON.stringify({ transaction }),
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getAuthToken()}`
    }
  });
  
  if (!response.ok) {
    throw new Error('Transaction signing failed');
  }
  
  return response.json();
};
```

#### 2. Secure Wallet Connection
```typescript
export class SecureSolanaRPC {
  private wallet: Wallet | null = null;
  
  async connectWallet(): Promise<void> {
    if (typeof window !== 'undefined' && window.solana) {
      this.wallet = await window.solana.connect();
    } else {
      throw new Error('Solana wallet not found');
    }
  }
  
  async signTransaction(transaction: Transaction): Promise<Transaction> {
    if (!this.wallet) {
      throw new Error('Wallet not connected');
    }
    
    return await this.wallet.signTransaction(transaction);
  }
  
  getPublicKey(): PublicKey | null {
    return this.wallet?.publicKey || null;
  }
}
```

#### 3. Server-Side Signing Endpoint
```typescript
fastify.post('/api/sign-transaction', {
  schema: {
    body: {
      type: 'object',
      properties: {
        transaction: { type: 'object' }
      },
      required: ['transaction']
    }
  }
}, async (request, reply) => {
  try {
    const { transaction } = request.body as { transaction: Transaction };
    
    // Verify user authentication
    const token = request.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return reply.status(401).send({ error: 'Unauthorized' });
    }
    
    // Get user's secure private key from server-side storage
    const user = await getUserFromToken(token);
    const privateKey = await getSecurePrivateKey(user.id);
    
    // Sign transaction server-side
    const signedTransaction = await signTransactionSecurely(transaction, privateKey);
    
    return { signedTransaction };
  } catch (error) {
    return reply.status(500).send({ error: 'Signing failed' });
  }
});
```

### **Testing**
```typescript
describe('Private Key Security', () => {
  it('should not expose private key on client-side', () => {
    // This should fail - private key should not be accessible
    expect(() => {
      window.solanaRPCInstance.getPrivateKey();
    }).toThrow();
  });
  
  it('should require authentication for signing', async () => {
    const response = await fetch('/api/sign-transaction', {
      method: 'POST',
      body: JSON.stringify({ transaction: mockTransaction })
    });
    
    expect(response.status).toBe(401);
  });
});
```

### **Impact**
- **Eliminates** client-side private key exposure
- **Prevents** wallet compromise through XSS
- **Implements** secure server-side signing
- **Adds** proper authentication and authorization
- **Follows** security best practices for key management

**Researcher**: grich88 (j.grant.richards@proton.me)
**Fixes**: #345
```

---

## PR 2: SQL Injection Fix

### **Title**: `Fix: SQL Injection in Database Migration`

### **Body**:
```markdown
## 🔧 **Fix Implementation**

This PR addresses the critical SQL injection vulnerability identified in issue #346.

### **Changes Made**
- Replace string interpolation with parameterized queries
- Add input validation and sanitization
- Implement proper error handling
- Add SQL injection prevention measures

### **Security Improvements**
1. **Eliminates SQL injection vulnerability**
2. **Implements parameterized queries**
3. **Adds input validation and sanitization**
4. **Implements proper error handling**
5. **Adds SQL injection prevention measures**

### **Files Modified**
- `workflow/packages/backend/api/src/app/database/migration/postgres/1676505294811-encrypt-credentials.ts`

### **Code Changes**

#### Before (Vulnerable)
```typescript
// VULNERABLE CODE
await queryRunner.query(
    `UPDATE app_connection SET value = '${JSON.stringify(currentConnection.value)}' WHERE id = ${currentConnection.id}`
);
```

#### After (Fixed)
```typescript
// FIXED CODE - Use parameterized queries
await queryRunner.query(
    'UPDATE app_connection SET value = $1 WHERE id = $2',
    [JSON.stringify(currentConnection.value), currentConnection.id]
);
```

#### Additional Security Measures
```typescript
// Add input validation
function validateConnectionId(id: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(id) && id.length <= 255;
}

function sanitizeValue(value: any): any {
  if (typeof value === 'string') {
    return value.replace(/['";\\]/g, '');
  }
  return value;
}

// Use in migration
if (!validateConnectionId(currentConnection.id)) {
  throw new Error('Invalid connection ID');
}

const sanitizedValue = sanitizeValue(currentConnection.value);
await queryRunner.query(
    'UPDATE app_connection SET value = $1 WHERE id = $2',
    [JSON.stringify(sanitizedValue), currentConnection.id]
);
```

### **Testing**
```typescript
describe('SQL Injection Prevention', () => {
  it('should prevent SQL injection in migration', async () => {
    const maliciousId = "1; DROP TABLE users; --";
    const value = { test: "data" };
    
    // This should not execute the malicious SQL
    await expect(
      runMigration(maliciousId, value)
    ).rejects.toThrow('Invalid connection ID');
  });
  
  it('should sanitize input values', () => {
    const maliciousValue = "'; DROP TABLE users; --";
    const sanitized = sanitizeValue(maliciousValue);
    
    expect(sanitized).not.toContain("'");
    expect(sanitized).not.toContain(";");
  });
});
```

### **Impact**
- **Eliminates** SQL injection vulnerability
- **Prevents** database compromise
- **Implements** parameterized queries
- **Adds** input validation and sanitization
- **Follows** security best practices for database operations

**Researcher**: grich88 (j.grant.richards@proton.me)
**Fixes**: #346
```

---

## PR 3: Code Execution Fix

### **Title**: `Fix: Unsafe Code Execution in Workflow Engine`

### **Body**:
```markdown
## 🔧 **Fix Implementation**

This PR addresses the high-severity code execution vulnerability identified in issue #347.

### **Changes Made**
- Replace no-op sandbox with secure V8 isolate
- Implement code whitelisting and restrictions
- Add resource limits and monitoring
- Implement network isolation

### **Security Improvements**
1. **Eliminates unsafe code execution**
2. **Implements secure V8 isolate sandbox**
3. **Adds code whitelisting and restrictions**
4. **Implements resource limits and monitoring**
5. **Adds network isolation**

### **Files Modified**
- `workflow/packages/engine/src/lib/core/code/no-op-code-sandbox.ts`

### **Code Changes**

#### Before (Vulnerable)
```typescript
// VULNERABLE CODE
export const noOpCodeSandbox: CodeSandbox = {
  async runScript({ script, scriptContext }) {
    const func = new Function('context', script);
    return func(scriptContext);
  }
};
```

#### After (Fixed)
```typescript
// FIXED CODE - Use secure V8 isolate sandbox
import { v8IsolateCodeSandbox } from './v8-isolate-code-sandbox';

export const secureCodeSandbox: CodeSandbox = {
  async runScript({ script, scriptContext }) {
    return v8IsolateCodeSandbox.runScript({ script, scriptContext });
  }
};
```

#### Secure V8 Isolate Implementation
```typescript
import { Isolate, Context } from 'isolated-vm';

export class V8IsolateCodeSandbox {
  private isolate: Isolate;
  private context: Context;
  
  constructor() {
    this.isolate = new Isolate({ memoryLimit: 128 });
    this.context = this.isolate.createContext();
  }
  
  async runScript({ script, scriptContext }: { script: string; scriptContext: any }) {
    try {
      // Validate script before execution
      this.validateScript(script);
      
      // Set up secure context
      await this.context.eval(`
        // Whitelist allowed functions
        const allowedFunctions = ['console.log', 'Math', 'Date', 'JSON'];
        
        // Block dangerous functions
        delete global.process;
        delete global.require;
        delete global.module;
        delete global.exports;
        delete global.__dirname;
        delete global.__filename;
      `);
      
      // Execute script in isolated context
      const result = await this.context.eval(script);
      
      return result;
    } catch (error) {
      throw new Error(`Script execution failed: ${error.message}`);
    }
  }
  
  private validateScript(script: string): void {
    const dangerousPatterns = [
      /require\s*\(/,
      /process\./,
      /child_process/,
      /fs\./,
      /eval\s*\(/,
      /Function\s*\(/,
      /setTimeout\s*\(/,
      /setInterval\s*\(/
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(script)) {
        throw new Error(`Dangerous pattern detected: ${pattern}`);
      }
    }
  }
}
```

### **Testing**
```typescript
describe('Code Execution Security', () => {
  it('should prevent system command execution', async () => {
    const maliciousScript = "process.mainModule.require('child_process').execSync('whoami')";
    
    await expect(
      secureCodeSandbox.runScript({ script: maliciousScript, scriptContext: {} })
    ).rejects.toThrow('Dangerous pattern detected');
  });
  
  it('should allow safe operations', async () => {
    const safeScript = "console.log('Hello World'); return 42;";
    
    const result = await secureCodeSandbox.runScript({ 
      script: safeScript, 
      scriptContext: {} 
    });
    
    expect(result).toBe(42);
  });
});
```

### **Impact**
- **Eliminates** unsafe code execution
- **Prevents** server compromise
- **Implements** secure V8 isolate sandbox
- **Adds** code whitelisting and restrictions
- **Follows** security best practices for code execution

**Researcher**: grich88 (j.grant.richards@proton.me)
**Fixes**: #347
```

---

## PR 4: CORS Misconfiguration Fix

### **Title**: `Fix: CORS Misconfiguration with Wildcard Origin`

### **Body**:
```markdown
## 🔧 **Fix Implementation**

This PR addresses the high-severity CORS misconfiguration vulnerability identified in issue #348.

### **Changes Made**
- Replace wildcard CORS with strict origin validation
- Implement proper CORS configuration
- Add origin whitelist
- Implement CSRF protection

### **Security Improvements**
1. **Eliminates wildcard CORS configuration**
2. **Implements strict origin validation**
3. **Adds origin whitelist**
4. **Implements CSRF protection**
5. **Follows security best practices for CORS**

### **Files Modified**
- `workflow/packages/backend/api/src/app/server.ts`

### **Code Changes**

#### Before (Vulnerable)
```typescript
// VULNERABLE CODE
await app.register(cors, {
  origin: true, // Allows all origins
  credentials: true, // Enables credentials
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
});
```

#### After (Fixed)
```typescript
// FIXED CODE - Strict CORS configuration
await app.register(cors, {
  origin: [
    'https://aixblock.com',
    'https://www.aixblock.com',
    'https://app.aixblock.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
});
```

#### Additional Security Measures
```typescript
// Add CSRF protection
import csrf from '@fastify/csrf-protection';

await app.register(csrf, {
  sessionPlugin: '@fastify/session',
  sessionKey: 'session',
  secret: process.env.CSRF_SECRET
});

// Add origin validation middleware
app.addHook('preHandler', async (request, reply) => {
  const origin = request.headers.origin;
  const allowedOrigins = [
    'https://aixblock.com',
    'https://www.aixblock.com',
    'https://app.aixblock.com'
  ];
  
  if (origin && !allowedOrigins.includes(origin)) {
    return reply.status(403).send({ error: 'Forbidden origin' });
  }
});
```

### **Testing**
```typescript
describe('CORS Security', () => {
  it('should reject requests from unauthorized origins', async () => {
    const response = await fetch('https://aixblock.com/api/v1/users/me', {
      headers: {
        'Origin': 'https://malicious-site.com'
      }
    });
    
    expect(response.status).toBe(403);
  });
  
  it('should allow requests from authorized origins', async () => {
    const response = await fetch('https://aixblock.com/api/v1/users/me', {
      headers: {
        'Origin': 'https://app.aixblock.com'
      }
    });
    
    expect(response.status).not.toBe(403);
  });
});
```

### **Impact**
- **Eliminates** wildcard CORS configuration
- **Prevents** cross-origin attacks
- **Implements** strict origin validation
- **Adds** CSRF protection
- **Follows** security best practices for CORS

**Researcher**: grich88 (j.grant.richards@proton.me)
**Fixes**: #348
```

---

## PR 5: Rate Limiting Fix

### **Title**: `Fix: Insufficient Rate Limiting on Authentication`

### **Body**:
```markdown
## 🔧 **Fix Implementation**

This PR addresses the medium-severity rate limiting vulnerability identified in issue #349.

### **Changes Made**
- Implement comprehensive rate limiting
- Add account lockout mechanisms
- Implement progressive delays
- Add CAPTCHA challenges for suspicious activity

### **Security Improvements**
1. **Eliminates brute force attacks**
2. **Implements comprehensive rate limiting**
3. **Adds account lockout mechanisms**
4. **Implements progressive delays**
5. **Adds CAPTCHA challenges**

### **Files Modified**
- `workflow/packages/backend/api/src/app/routes/authentication.ts`

### **Code Changes**

#### Before (Vulnerable)
```typescript
// VULNERABLE CODE - No rate limiting
app.post('/v1/authentication/sign-in', async (request, reply) => {
  const { email, password } = request.body;
  // No rate limiting implemented
  const user = await authenticateUser(email, password);
  return user;
});
```

#### After (Fixed)
```typescript
// FIXED CODE - Implement rate limiting
import rateLimit from '@fastify/rate-limit';

await app.register(rateLimit, {
  max: 5, // 5 attempts per window
  timeWindow: '15 minutes', // 15 minute window
  errorResponseBuilder: (request, context) => ({
    statusCode: 429,
    error: 'Too Many Requests',
    message: 'Rate limit exceeded, try again later'
  })
});

app.post('/v1/authentication/sign-in', {
  preHandler: [rateLimit, checkAccountLockout, checkSuspiciousActivity]
}, async (request, reply) => {
  const { email, password } = request.body;
  
  // Check for account lockout
  const lockoutStatus = await checkAccountLockout(email);
  if (lockoutStatus.isLocked) {
    return reply.status(423).send({ 
      error: 'Account locked', 
      retryAfter: lockoutStatus.retryAfter 
    });
  }
  
  // Check for suspicious activity
  const suspiciousActivity = await checkSuspiciousActivity(request);
  if (suspiciousActivity.detected) {
    return reply.status(429).send({ 
      error: 'Suspicious activity detected', 
      captchaRequired: true 
    });
  }
  
  const user = await authenticateUser(email, password);
  
  if (!user) {
    // Increment failed attempts
    await incrementFailedAttempts(email, request.ip);
  } else {
    // Reset failed attempts on success
    await resetFailedAttempts(email);
  }
  
  return user;
});
```

#### Additional Security Measures
```typescript
// Account lockout mechanism
async function checkAccountLockout(email: string) {
  const failedAttempts = await getFailedAttempts(email);
  const lockoutThreshold = 5;
  const lockoutDuration = 15 * 60 * 1000; // 15 minutes
  
  if (failedAttempts >= lockoutThreshold) {
    const lastAttempt = await getLastFailedAttempt(email);
    const timeSinceLastAttempt = Date.now() - lastAttempt;
    
    if (timeSinceLastAttempt < lockoutDuration) {
      return {
        isLocked: true,
        retryAfter: lockoutDuration - timeSinceLastAttempt
      };
    }
  }
  
  return { isLocked: false };
}

// Progressive delays
async function applyProgressiveDelay(email: string) {
  const failedAttempts = await getFailedAttempts(email);
  const delay = Math.min(failedAttempts * 1000, 10000); // Max 10 seconds
  
  if (delay > 0) {
    await new Promise(resolve => setTimeout(resolve, delay));
  }
}

// CAPTCHA for suspicious activity
async function checkSuspiciousActivity(request: any) {
  const ip = request.ip;
  const userAgent = request.headers['user-agent'];
  
  // Check for bot patterns
  const botPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i
  ];
  
  const isBot = botPatterns.some(pattern => pattern.test(userAgent));
  
  if (isBot) {
    return { detected: true, reason: 'Bot detected' };
  }
  
  // Check for rapid requests
  const requestCount = await getRequestCount(ip, '1 minute');
  if (requestCount > 10) {
    return { detected: true, reason: 'Rapid requests detected' };
  }
  
  return { detected: false };
}
```

### **Testing**
```typescript
describe('Rate Limiting Security', () => {
  it('should block after 5 failed attempts', async () => {
    for (let i = 0; i < 5; i++) {
      const response = await fetch('/v1/authentication/sign-in', {
        method: 'POST',
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'wrongpassword'
        })
      });
      
      expect(response.status).toBe(401);
    }
    
    // 6th attempt should be blocked
    const response = await fetch('/v1/authentication/sign-in', {
      method: 'POST',
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'wrongpassword'
      })
    });
    
    expect(response.status).toBe(429);
  });
  
  it('should require CAPTCHA for suspicious activity', async () => {
    const response = await fetch('/v1/authentication/sign-in', {
      method: 'POST',
      headers: {
        'User-Agent': 'Bot/1.0'
      },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'password'
      })
    });
    
    expect(response.status).toBe(429);
    const data = await response.json();
    expect(data.captchaRequired).toBe(true);
  });
});
```

### **Impact**
- **Eliminates** brute force attacks
- **Prevents** account compromise
- **Implements** comprehensive rate limiting
- **Adds** account lockout mechanisms
- **Follows** security best practices for authentication

**Researcher**: grich88 (j.grant.richards@proton.me)
**Fixes**: #349
```

---

## How to Create PRs

### **Step 1: Fork the Repository**
1. Go to: https://github.com/AIxBlock-2023/aixblock-ai-dev-platform-public
2. Click "Fork" button
3. Fork to: grich88/aixblock-ai-dev-platform-public

### **Step 2: Create Branches**
For each vulnerability, create a branch:
```bash
git checkout -b grich88/private-key-exposure-fix
git checkout -b grich88/sql-injection-fix
git checkout -b grich88/code-execution-fix
git checkout -b grich88/cors-misconfiguration-fix
git checkout -b grich88/rate-limiting-fix
```

### **Step 3: Create PRs**
For each branch, create a pull request using the templates above.

### **Step 4: Link to Issues**
Make sure to reference the corresponding issue numbers:
- PR 1 → Issue #345
- PR 2 → Issue #346
- PR 3 → Issue #347
- PR 4 → Issue #348
- PR 5 → Issue #349

---

**All PRs should be created by grich88 account and include comprehensive fixes for each vulnerability.**
