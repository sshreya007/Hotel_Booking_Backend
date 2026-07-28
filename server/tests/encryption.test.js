
const { encryptField, decryptField } = require('../src/utils/encryption');

describe('field encryption', () => {
  it('encrypts and decrypts a value round-trip', () => {
    const plaintext = '+1-555-0100';
    const encrypted = encryptField(plaintext);
    expect(encrypted).not.toContain(plaintext);
    expect(decryptField(encrypted)).toBe(plaintext);
  });

  it('produces different ciphertext for the same plaintext each time (random IV)', () => {
    const a = encryptField('same value');
    const b = encryptField('same value');
    expect(a).not.toBe(b);
    expect(decryptField(a)).toBe('same value');
    expect(decryptField(b)).toBe('same value');
  });

  it('fails to decrypt tampered ciphertext (authenticity check)', () => {
    const encrypted = JSON.parse(encryptField('sensitive data'));
    encrypted.data = encrypted.data.slice(0, -2) + '00'; // corrupt the ciphertext
    expect(() => decryptField(JSON.stringify(encrypted))).toThrow();
  });

  it('returns null for null input', () => {
    expect(encryptField(null)).toBeNull();
    expect(decryptField(null)).toBeNull();
  });
});
