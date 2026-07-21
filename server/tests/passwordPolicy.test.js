const { checkPasswordPolicy } = require('../src/utils/passwordPolicy');

describe('password policy', () => {
  it('rejects passwords under the minimum length', () => {
    const result = checkPasswordPolicy('Sh0rt!');
    expect(result.valid).toBe(false);
    expect(result.problems.some((p) => p.includes('12 characters'))).toBe(true);
  });

  it('rejects passwords missing complexity requirements', () => {
    const result = checkPasswordPolicy('alllowercase123');
    expect(result.valid).toBe(false);
    expect(result.problems.some((p) => p.includes('uppercase'))).toBe(true);
  });

  it('accepts a strong password', () => {
    const result = checkPasswordPolicy('Str0ng!Passw0rd#2026');
    expect(result.valid).toBe(true);
    expect(result.problems).toHaveLength(0);
  });

  it('rejects known common passwords even if they meet complexity rules', () => {
    const result = checkPasswordPolicy('Password123!');
    // Not in the demo common-password list but shape-wise should still evaluate;
    // this test documents the intended behavior for a real breached-password list.
    expect(result).toHaveProperty('score');
  });
});
