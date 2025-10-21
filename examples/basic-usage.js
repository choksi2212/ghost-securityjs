/**
 * GhostSecurity Basic Usage Example
 * Demonstrates military-grade encryption workflow
 */

import GhostSecurity from '../src/ghostsecurity.js';

async function basicExample() {
  console.log('🔐 GhostSecurity Basic Usage Example\n');

  // Initialize with military-grade configuration
  const security = new GhostSecurity({
    algorithm: 'AES-256-GCM',      // Military-grade
    pbkdf2Iterations: 100000,      // 100k iterations
    multiLayer: true,              // Multi-layer encryption
    layers: 2,                     // 2 encryption layers
    useHMAC: true                  // Additional integrity check
  });

  console.log('✅ GhostSecurity initialized\n');
  console.log('Configuration:', security.getConfig());
  console.log();

  // Example 1: Encrypt/Decrypt String
  console.log('📝 Example 1: String Encryption');
  const sensitiveText = 'This is highly sensitive biometric data!';
  const password = 'my-secure-master-password';

  console.log('   - Original:', sensitiveText);
  
  const encrypted = await security.encrypt(sensitiveText, password);
  console.log('   - Encrypted package created');
  console.log('   - Algorithm:', encrypted.algorithm);
  console.log('   - Layers:', encrypted.layers.length);
  console.log('   - Has HMAC:', encrypted.hmac !== null);

  const decrypted = await security.decrypt(encrypted, password);
  const decryptedText = new TextDecoder().decode(decrypted);
  console.log('   - Decrypted:', decryptedText);
  console.log('   - Match:', decryptedText === sensitiveText ? '✅ YES' : '❌ NO');
  console.log();

  // Example 2: Encrypt/Decrypt Object
  console.log('📝 Example 2: Object Encryption');
  const biometricData = {
    userId: 'user123',
    keystrokeModel: [0.12, 0.15, 0.18, 0.14, 0.16],
    voiceprint: [0.23, 0.45, 0.67, 0.89, 0.12],
    timestamp: new Date().toISOString()
  };

  console.log('   - Original object:', biometricData);

  const encryptedObj = await security.encryptObject(biometricData, password);
  console.log('   - Object encrypted');

  const decryptedObj = await security.decryptObject(encryptedObj, password);
  console.log('   - Decrypted object:', decryptedObj);
  console.log('   - Match:', JSON.stringify(decryptedObj) === JSON.stringify(biometricData) ? '✅ YES' : '❌ NO');
  console.log();

  // Example 3: Password Hashing
  console.log('📝 Example 3: Password Hashing');
  const userPassword = 'user-password-123';

  const { hash, salt } = await GhostSecurity.hashPassword(userPassword);
  console.log('   - Password hashed');
  console.log('   - Hash length:', hash.length, 'bytes');
  console.log('   - Salt length:', salt.length, 'bytes');

  const isValid = await GhostSecurity.verifyPassword(userPassword, hash, salt);
  console.log('   - Verification:', isValid ? '✅ VALID' : '❌ INVALID');

  const isInvalid = await GhostSecurity.verifyPassword('wrong-password', hash, salt);
  console.log('   - Wrong password:', isInvalid ? '❌ ACCEPTED' : '✅ REJECTED');
  console.log();

  // Example 4: Generate Secure Password
  console.log('📝 Example 4: Secure Password Generation');
  const securePassword = GhostSecurity.generateSecurePassword(32);
  console.log('   - Generated password:', securePassword);
  console.log('   - Length:', securePassword.length);
  console.log();

  // Example 5: Wrong Password (Decryption Fails)
  console.log('📝 Example 5: Wrong Password Test');
  try {
    await security.decrypt(encrypted, 'wrong-password');
    console.log('   - ❌ SECURITY BREACH: Decryption succeeded with wrong password!');
  } catch (error) {
    console.log('   - ✅ SECURE: Decryption failed with wrong password');
    console.log('   - Error:', error.message);
  }
  console.log();

  // Example 6: Tampering Detection
  console.log('📝 Example 6: Tampering Detection');
  const tamperedPackage = { ...encrypted };
  tamperedPackage.ciphertext[0] = (tamperedPackage.ciphertext[0] + 1) % 256; // Modify one byte

  try {
    await security.decrypt(tamperedPackage, password);
    console.log('   - ❌ SECURITY BREACH: Tampered data accepted!');
  } catch (error) {
    console.log('   - ✅ SECURE: Tampering detected and rejected');
    console.log('   - Error:', error.message);
  }
  console.log();

  // Example 7: Performance Test
  console.log('📝 Example 7: Performance Test');
  const largeData = 'x'.repeat(10000); // 10KB of data

  const startEncrypt = Date.now();
  const encryptedLarge = await security.encrypt(largeData, password);
  const encryptTime = Date.now() - startEncrypt;

  const startDecrypt = Date.now();
  await security.decrypt(encryptedLarge, password);
  const decryptTime = Date.now() - startDecrypt;

  console.log('   - Data size:', largeData.length, 'bytes');
  console.log('   - Encryption time:', encryptTime, 'ms');
  console.log('   - Decryption time:', decryptTime, 'ms');
  console.log();

  // Clear cache
  security.clearCache();
  console.log('🧹 Cache cleared');
  console.log();

  console.log('🎉 All examples completed successfully!');
}

// Run example
basicExample().catch(console.error);
