const AES = require('./aes.js');

// FIPS-197 Appendix B test vector
const plaintext = "3243f6a8885a308d313198a2e0370734";
const key       = "2b7e151628aed2a6abf7158809cf4f3c";
const expectedCipher = "3925841d02dc09fbdc118597196a0b32";

const pBytes = AES.hexStringToBytes(plaintext);
const kBytes = AES.hexStringToBytes(key);

const encLog = AES.encryptDetailed(pBytes, kBytes);
console.log("Ciphertext computed:", encLog.ciphertext);
console.log("Expected           :", expectedCipher.toUpperCase());
console.log("MATCH:", encLog.ciphertext === expectedCipher.toUpperCase());

// Decrypt back
const cBytes = AES.hexStringToBytes(encLog.ciphertext);
const decLog = AES.decryptDetailed(cBytes, kBytes);
console.log("Decrypted plaintext:", decLog.plaintext);
console.log("Expected plaintext :", plaintext.toUpperCase());
console.log("MATCH:", decLog.plaintext === plaintext.toUpperCase());

// Test 2: FIPS-197 Appendix C.1 (128 bit)
const p2 = "00112233445566778899aabbccddeeff";
const k2 = "000102030405060708090a0b0c0d0e0f";
const exp2 = "69c4e0d86a7b0430d8cdb78070b4c55a";
const enc2 = AES.encryptDetailed(AES.hexStringToBytes(p2), AES.hexStringToBytes(k2));
console.log("\nTest2 cipher:", enc2.ciphertext, "expected:", exp2.toUpperCase(), "MATCH:", enc2.ciphertext===exp2.toUpperCase());
const dec2 = AES.decryptDetailed(AES.hexStringToBytes(enc2.ciphertext), AES.hexStringToBytes(k2));
console.log("Test2 decrypt:", dec2.plaintext, "expected:", p2.toUpperCase(), "MATCH:", dec2.plaintext===p2.toUpperCase());

// check round keys count
console.log("\nRound keys count:", encLog.keyExpansion.roundKeys.length, "words logged:", encLog.keyExpansion.words.length);
