import React, { useState } from 'react';
import { Scanner } from '@yudiel/react-qr-scanner';

// Página independiente para escanear y desencriptar tokens QR SIN dependencias externas
// - Usa getUserMedia + BarcodeDetector (si está disponible)
// - Alternativa: ingresar manualmente el token
// - Desencripta con WebCrypto (AES-256-GCM) usando la misma estructura que el backend:
//   token base64url decodificado = [iv(8 bytes)] + [ciphertext] + [authTag(16 bytes)]

// Helpers base64url <-> bytes
const base64UrlToUint8Array = (base64Url) => {
  let base64 = (base64Url || '').replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const hexToUint8Array = (hex) => {
  const clean = (hex || '').trim();
  if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('Clave HEX inválida');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes;
};

const decryptQRDataBrowser = async ({ tokenBase64Url, hexKey }) => {
  if (!tokenBase64Url) throw new Error('Token QR vacío');
  if (!hexKey) throw new Error('Falta QR_ENCRYPTION_KEY en HEX');

  const data = base64UrlToUint8Array(tokenBase64Url);
  if (data.length < 8 + 16 + 1) throw new Error('Token demasiado corto');

  const iv = data.slice(0, 8); // IV_LENGTH = 8 en backend
  const authTag = data.slice(data.length - 16); // 16 bytes
  const cipherOnly = data.slice(8, data.length - 16);

  // WebCrypto espera ciphertext+tag concatenados en decrypt
  const cipherWithTag = new Uint8Array(cipherOnly.length + authTag.length);
  cipherWithTag.set(cipherOnly, 0);
  cipherWithTag.set(authTag, cipherOnly.length);

  const keyRaw = hexToUint8Array(hexKey);
  if (keyRaw.length !== 32) {
    // AES-256 requiere 32 bytes
    throw new Error('QR_ENCRYPTION_KEY debe tener 64 chars hex (32 bytes)');
  }

  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    keyRaw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );

  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    cryptoKey,
    cipherWithTag,
  );

  const decoder = new TextDecoder();
  const jsonStr = decoder.decode(new Uint8Array(decrypted));
  return JSON.parse(jsonStr);
};

const SimpleBox = ({ children, style }) => (
  <div style={{ padding: 12, border: '1px solid #ddd', borderRadius: 8, ...style }}>{children}</div>
);

const OtroQRStandalone = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState('');
  const [token, setToken] = useState('');
  const [envKeyHex, setEnvKeyHex] = useState('');
  const [payload, setPayload] = useState(null);
  const [busy, setBusy] = useState(false);
  const startScanning = () => {
    setScanError('');
    setPayload(null);
    setToken('');
    setIsScanning(true);
  };

  const stopScanning = () => {
    setIsScanning(false);
  };

  const handleScan = (result) => {
    if (!result || result.length === 0) return;
    const scanned = result[0]?.rawValue || '';
    if (!scanned) return;
    setToken(scanned);
    setIsScanning(false);
  };

  const handleScannerError = (err) => {
    setScanError(err?.message || 'Error de cámara');
    setIsScanning(false);
  };

  const onDecrypt = async () => {
    try {
      setBusy(true);
      setScanError('');
      setPayload(null);
      const data = await decryptQRDataBrowser({
        tokenBase64Url: token.trim(),
        hexKey: envKeyHex.trim(),
      });
      setPayload(data);
    } catch (err) {
      setScanError(err?.message || 'Error al desencriptar');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', padding: 16 }}>
      <h2 style={{ marginTop: 0 }}>Lector y Desencriptador QR (Standalone)</h2>
      <p style={{ color: '#555' }}>
        No usa UI ni servicios del proyecto. Ingrese la clave AES-256 en HEX y escanee o pegue el
        token.
      </p>

      <SimpleBox style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <label htmlFor="key" style={{ minWidth: 160, fontWeight: 600 }}>
            QR_ENCRYPTION_KEY (HEX 64 chars)
          </label>
          <input
            id="key"
            type="text"
            placeholder={'e.g. ' + 'a'.repeat(64)}
            value={envKeyHex}
            onChange={(e) => setEnvKeyHex(e.target.value)}
            style={{
              flex: 1,
              minWidth: 280,
              padding: 8,
              border: '1px solid #ccc',
              borderRadius: 6,
            }}
          />
        </div>
      </SimpleBox>

      <SimpleBox style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 12 }}>
          <button onClick={startScanning} disabled={isScanning} style={{ padding: '8px 12px' }}>
            Iniciar escaneo
          </button>
          <button onClick={stopScanning} disabled={!isScanning} style={{ padding: '8px 12px' }}>
            Detener
          </button>
        </div>
        {isScanning && (
          <div
            style={{ border: '1px solid #ccc', borderRadius: 8, overflow: 'hidden', maxWidth: 420 }}
          >
            <div style={{ width: '100%', height: 300 }}>
              <Scanner
                onScan={handleScan}
                onError={handleScannerError}
                constraints={{ facingMode: 'environment' }}
                styles={{
                  container: { width: '100%', height: '100%' },
                  video: { width: '100%', height: '100%', objectFit: 'cover' },
                }}
              />
            </div>
          </div>
        )}
      </SimpleBox>

      <SimpleBox style={{ marginBottom: 16 }}>
        <label htmlFor="token" style={{ display: 'block', fontWeight: 600, marginBottom: 8 }}>
          Token (base64url del QR)
        </label>
        <textarea
          id="token"
          rows={4}
          style={{ width: '100%', padding: 8, border: '1px solid #ccc', borderRadius: 6 }}
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="Pega aquí el token del QR (no una URL)"
        />
        <div style={{ marginTop: 8 }}>
          <button
            onClick={onDecrypt}
            disabled={busy || !token || !envKeyHex}
            style={{ padding: '8px 12px' }}
          >
            {busy ? 'Desencriptando...' : 'Desencriptar'}
          </button>
        </div>
      </SimpleBox>

      {scanError && (
        <SimpleBox
          style={{ background: '#fee', borderColor: '#f99', color: '#a00', marginBottom: 16 }}
        >
          {scanError}
        </SimpleBox>
      )}

      {payload && (
        <SimpleBox>
          <div style={{ fontWeight: 600, marginBottom: 8 }}>Payload desencriptado:</div>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {JSON.stringify(payload, null, 2)}
          </pre>
        </SimpleBox>
      )}
    </div>
  );
};

export const getServerSideProps = async () => {
  return { props: {} };
};

export default OtroQRStandalone;
