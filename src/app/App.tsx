import React, { useState } from 'react';
import { Copy, Check, Key, Lock, Shield, Trash2, Info, ChevronDown, ChevronUp } from 'lucide-react';
import { SignJWT, importPKCS8, generateKeyPair, exportJWK } from 'jose';

interface GeneratedTokens {
  clientAssertion: string;
  parDPoP: string;
  tokenDPoP: string;
  userinfoDPoP: string;
  dpopPublicJwk: string;
}

export default function App() {
  const [clientId, setClientId] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [accessToken, setAccessToken] = useState('');
  const [tokens, setTokens] = useState<GeneratedTokens | null>(null);
  const [dpopKeyPair, setDpopKeyPair] = useState<any>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showInfo, setShowInfo] = useState(false);

  const generateJti = () => {
    return crypto.randomUUID();
  };

  const now = () => Math.floor(Date.now() / 1000);

  const calculateAth = async (accessToken: string): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(accessToken);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Base64url encode
    let binary = '';
    hashArray.forEach(byte => binary += String.fromCharCode(byte));
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  const generateTokens = async () => {
    setError(null);
    setLoading(true);

    try {
      if (!clientId || !privateKey) {
        throw new Error('Client ID and Private Key are required');
      }

      // Generate DPoP key pair (ES256) only if not already generated
      let currentDpopKeyPair = dpopKeyPair;
      if (!currentDpopKeyPair) {
        currentDpopKeyPair = await generateKeyPair('ES256');
        setDpopKeyPair(currentDpopKeyPair);
      }
      const dpopPublicJwk = await exportJWK(currentDpopKeyPair.publicKey);
      
      // Import the signing private key
      const signingKey = await importPKCS8(privateKey, 'ES256');

      const timestamp = now();
      const ASSERTION_LIFETIME_SEC = 120; // 2 minutes

      // 1. Generate Client Assertion
      const clientAssertion = await new SignJWT({
        iss: clientId,
        sub: clientId,
        aud: 'https://stg-id.singpass.gov.sg/fapi',
        iat: timestamp,
        exp: timestamp + ASSERTION_LIFETIME_SEC,
        jti: generateJti(),
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
        .sign(signingKey);

      // 2. Generate PAR DPoP
      const parDPoP = await new SignJWT({
        jti: generateJti(),
        htm: 'POST',
        htu: 'https://stg-id.singpass.gov.sg/fapi/par',
        iat: timestamp,
        exp: timestamp + ASSERTION_LIFETIME_SEC,
      })
        .setProtectedHeader({
          alg: 'ES256',
          typ: 'dpop+jwt',
          jwk: dpopPublicJwk,
        })
        .sign(currentDpopKeyPair.privateKey);

      // 3. Generate TOKEN DPoP
      const tokenDPoP = await new SignJWT({
        jti: generateJti(),
        htm: 'POST',
        htu: 'https://stg-id.singpass.gov.sg/fapi/token',
        iat: timestamp,
        exp: timestamp + ASSERTION_LIFETIME_SEC,
      })
        .setProtectedHeader({
          alg: 'ES256',
          typ: 'dpop+jwt',
          jwk: dpopPublicJwk,
        })
        .sign(currentDpopKeyPair.privateKey);

      // 4. Generate USERINFO DPoP (needs ath if access token provided)
      const userinfoPayload: any = {
        jti: generateJti(),
        htm: 'GET',
        htu: 'https://stg-id.singpass.gov.sg/fapi/userinfo',
        iat: timestamp,
        exp: timestamp + ASSERTION_LIFETIME_SEC,
      };

      if (accessToken) {
        const ath = await calculateAth(accessToken);
        userinfoPayload.ath = ath;
      }

      const userinfoDPoP = await new SignJWT(userinfoPayload)
        .setProtectedHeader({
          alg: 'ES256',
          typ: 'dpop+jwt',
          jwk: dpopPublicJwk,
        })
        .sign(currentDpopKeyPair.privateKey);

      setTokens({
        clientAssertion,
        parDPoP,
        tokenDPoP,
        userinfoDPoP,
        dpopPublicJwk: JSON.stringify(dpopPublicJwk, null, 2),
      });
    } catch (err: any) {
      setError(err.message || 'Failed to generate tokens');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text: string, label: string) => {
    try {
      // Use textarea fallback method (more reliable in various contexts)
      const textArea = document.createElement('textarea');
      textArea.value = text;
      
      // Make the textarea invisible but accessible
      textArea.style.position = 'absolute';
      textArea.style.opacity = '0';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      
      try {
        const successful = document.execCommand('copy');
        if (successful) {
          setCopied(label);
          setTimeout(() => setCopied(null), 2000);
        } else {
          console.error('Copy command was unsuccessful');
        }
      } catch (err) {
        console.error('execCommand failed:', err);
      }
      
      document.body.removeChild(textArea);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const clearTokens = () => {
    setTokens(null);
    setDpopKeyPair(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-6">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <div className="flex items-center justify-center gap-3">
            <Shield className="w-10 h-10 text-blue-600" />
            <h1 className="text-3xl font-bold text-slate-900">Singpass API Token Generator</h1>
          </div>
          <p className="text-slate-600">
            Generate Client Assertions and DPoP tokens for Singpass API testing
          </p>
        </div>

        {/* Instructions */}
        <div className="bg-blue-50 rounded-xl shadow-sm border border-blue-200">
          <button
            onClick={() => setShowInfo(!showInfo)}
            className="w-full p-4 flex items-center justify-between hover:bg-blue-100 transition-colors rounded-xl"
          >
            <div className="flex items-center gap-2">
              <Info className="w-5 h-5 text-blue-600" />
              <h2 className="font-semibold text-blue-900">How to Use with Postman</h2>
            </div>
            {showInfo ? (
              <ChevronUp className="w-5 h-5 text-blue-600" />
            ) : (
              <ChevronDown className="w-5 h-5 text-blue-600" />
            )}
          </button>
          
          {showInfo && (
            <div className="px-4 pb-4 space-y-4 text-sm text-slate-700">
              <div className="space-y-2">
                <h3 className="font-semibold text-slate-900">📋 Setup Instructions</h3>
                <ol className="list-decimal list-inside space-y-2 ml-2">
                  <li>
                    <strong>Enter Client ID:</strong> Your Singpass client identifier
                  </li>
                  <li>
                    <strong>Enter Private Signing Key:</strong> Paste your ES256 private key in PEM PKCS8 format
                    <div className="mt-1 ml-6 text-xs bg-white p-2 rounded border border-slate-200 font-mono">
                      -----BEGIN PRIVATE KEY-----<br/>
                      MIGHAgEAMBMGByqGSM49...<br/>
                      -----END PRIVATE KEY-----
                    </div>
                  </li>
                  <li>
                    <strong>Click "Generate Tokens":</strong> This creates all tokens with a 120-second expiry
                  </li>
                </ol>
              </div>

              <div className="space-y-2">
                <h3 className="font-semibold text-slate-900">🔄 Singpass API Flow (Postman)</h3>
                <div className="space-y-3">
                  <div className="bg-white p-3 rounded border border-slate-200">
                    <p className="font-semibold text-blue-700">Step 1: PAR Endpoint</p>
                    <p className="text-xs mt-1">POST https://stg-id.singpass.gov.sg/fapi/par</p>
                    <ul className="mt-2 space-y-1 text-xs ml-4">
                      <li>• Add header: <code className="bg-slate-100 px-1 rounded">DPoP: [PAR DPoP token]</code></li>
                      <li>• Add body param: <code className="bg-slate-100 px-1 rounded">client_assertion: [Client Assertion]</code></li>
                      <li>• Add body param: <code className="bg-slate-100 px-1 rounded">client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt-bearer</code></li>
                      <li>• Add other required PAR parameters (scope, redirect_uri, etc.)</li>
                    </ul>
                  </div>

                  <div className="bg-white p-3 rounded border border-slate-200">
                    <p className="font-semibold text-blue-700">Step 2: TOKEN Endpoint</p>
                    <p className="text-xs mt-1">POST https://stg-id.singpass.gov.sg/fapi/token</p>
                    <ul className="mt-2 space-y-1 text-xs ml-4">
                      <li>• Add header: <code className="bg-slate-100 px-1 rounded">DPoP: [TOKEN DPoP token]</code></li>
                      <li>• Add body param: <code className="bg-slate-100 px-1 rounded">client_assertion: [Client Assertion]</code></li>
                      <li>• Add body param: <code className="bg-slate-100 px-1 rounded">client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt-bearer</code></li>
                      <li>• Add body param: <code className="bg-slate-100 px-1 rounded">code: [authorization code from PAR]</code></li>
                      <li>• Response will include an <strong>access_token</strong> - save this!</li>
                    </ul>
                  </div>

                  <div className="bg-white p-3 rounded border border-slate-200">
                    <p className="font-semibold text-blue-700">Step 3: USERINFO Endpoint (Optional)</p>
                    <p className="text-xs mt-1">GET https://stg-id.singpass.gov.sg/fapi/userinfo</p>
                    <ul className="mt-2 space-y-1 text-xs ml-4">
                      <li>• First, paste the <strong>access_token</strong> from Step 2 into the "Access Token" field above</li>
                      <li>• Click "Generate Tokens" again to create a USERINFO DPoP with the <code className="bg-slate-100 px-1 rounded">ath</code> claim</li>
                      <li>• Add header: <code className="bg-slate-100 px-1 rounded">DPoP: [USERINFO DPoP token]</code></li>
                      <li>• Add header: <code className="bg-slate-100 px-1 rounded">Authorization: DPoP [access_token]</code></li>
                    </ul>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <h3 className="font-semibold text-slate-900">💡 Important Notes</h3>
                <ul className="space-y-1 ml-4">
                  <li>• All tokens expire in <strong>120 seconds</strong> - regenerate if expired</li>
                  <li>• The same <strong>DPoP key pair</strong> is reused for all requests until you click "Clear Tokens"</li>
                  <li>• Use the <strong>Copy button</strong> next to each token to quickly paste into Postman</li>
                  <li>• Click "Generate Tokens" multiple times to get fresh timestamps without changing the DPoP key</li>
                  <li>• Click "Clear Tokens" to reset everything and generate a new DPoP key pair</li>
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* Input Section */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 space-y-4">
          <div className="flex items-center gap-2 mb-4">
            <Key className="w-5 h-5 text-slate-600" />
            <h2 className="font-semibold text-slate-900">Configuration</h2>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Client ID *
              </label>
              <input
                type="text"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Enter your client ID"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Private Signing Key (PEM PKCS8) *
              </label>
              <textarea
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                rows={6}
                placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Access Token (for USERINFO DPoP ath parameter)
              </label>
              <input
                type="text"
                value={accessToken}
                onChange={(e) => setAccessToken(e.target.value)}
                className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                placeholder="Optional: Enter access token for ath calculation"
              />
            </div>
          </div>

          <button
            onClick={generateTokens}
            disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-400 text-white font-medium py-3 px-6 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            <Lock className="w-5 h-5" />
            {loading ? 'Generating...' : 'Generate Tokens'}
          </button>

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
              {error}
            </div>
          )}
        </div>

        {/* Generated Tokens */}
        {tokens && (
          <div className="space-y-4">
            {/* Client Assertion */}
            <TokenDisplay
              title="Client Assertion"
              subtitle="aud: https://stg-id.singpass.gov.sg/fapi"
              token={tokens.clientAssertion}
              label="clientAssertion"
              copied={copied}
              onCopy={copyToClipboard}
            />

            {/* DPoP Public JWK */}
            <TokenDisplay
              title="DPoP Public JWK"
              subtitle="Generated key pair for DPoP proof tokens"
              token={tokens.dpopPublicJwk}
              label="dpopPublicJwk"
              copied={copied}
              onCopy={copyToClipboard}
              mono={false}
            />

            {/* PAR DPoP */}
            <TokenDisplay
              title="PAR DPoP"
              subtitle="htu: https://stg-id.singpass.gov.sg/fapi/par | htm: POST"
              token={tokens.parDPoP}
              label="parDPoP"
              copied={copied}
              onCopy={copyToClipboard}
            />

            {/* TOKEN DPoP */}
            <TokenDisplay
              title="TOKEN DPoP"
              subtitle="htu: https://stg-id.singpass.gov.sg/fapi/token | htm: POST"
              token={tokens.tokenDPoP}
              label="tokenDPoP"
              copied={copied}
              onCopy={copyToClipboard}
            />

            {/* USERINFO DPoP */}
            <TokenDisplay
              title="USERINFO DPoP"
              subtitle={`htu: https://stg-id.singpass.gov.sg/fapi/userinfo | htm: GET${accessToken ? ' | includes ath' : ''}`}
              token={tokens.userinfoDPoP}
              label="userinfoDPoP"
              copied={copied}
              onCopy={copyToClipboard}
            />
          </div>
        )}

        {/* Clear Tokens Button */}
        {tokens && (
          <button
            onClick={clearTokens}
            className="w-full bg-red-600 hover:bg-red-700 text-white font-medium py-3 px-6 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            <Trash2 className="w-5 h-5" />
            Clear Tokens
          </button>
        )}
      </div>
    </div>
  );
}

interface TokenDisplayProps {
  title: string;
  subtitle: string;
  token: string;
  label: string;
  copied: string | null;
  onCopy: (text: string, label: string) => void;
  mono?: boolean;
}

function TokenDisplay({
  title,
  subtitle,
  token,
  label,
  copied,
  onCopy,
  mono = true,
}: TokenDisplayProps) {
  return (
    <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="font-semibold text-slate-900">{title}</h3>
          <p className="text-sm text-slate-600 mt-1">{subtitle}</p>
        </div>
        <button
          onClick={() => onCopy(token, label)}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
        >
          {copied === label ? (
            <>
              <Check className="w-4 h-4 text-green-600" />
              <span className="text-sm text-green-600">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-4 h-4 text-slate-600" />
              <span className="text-sm text-slate-600">Copy</span>
            </>
          )}
        </button>
      </div>
      <div className={`bg-slate-50 rounded-lg p-4 overflow-x-auto ${mono ? 'font-mono' : ''} text-sm text-slate-800 break-all`}>
        {token}
      </div>
    </div>
  );
}