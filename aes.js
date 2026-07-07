const AES = (() => {

  // 1. KONSTANTA: S-BOX, INVERSE S-BOX, RCON
  const SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
  ];

  const INV_SBOX = new Array(256);
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

  const RCON = [
    0x00, // indeks 0 tidak dipakai
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
  ];

    // 2. UTILITAS GF(2^8) & FORMAT

  // Perkalian di GF(2^8) dengan polinomial ireducible x^8+x^4+x^3+x+1 (0x11B)
  function gmul(a, b) {
    let p = 0;
    for (let counter = 0; counter < 8; counter++) {
      if (b & 1) p ^= a;
      const hiBitSet = a & 0x80;
      a = (a << 1) & 0xff;
      if (hiBitSet) a ^= 0x1b;
      b >>= 1;
    }
    return p & 0xff;
  }

  const toHex2 = (b) => b.toString(16).toUpperCase().padStart(2, '0');

  function cloneState(state) {
    return state.map(row => row.slice());
  }

  function stateToHexMatrix(state) {
    return state.map(row => row.map(toHex2));
  }

  // 16 byte -> state 4x4 (kolom demi kolom)
  function bytesToState(bytes) {
    const state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let i = 0; i < 16; i++) {
      state[i % 4][Math.floor(i / 4)] = bytes[i];
    }
    return state;
  }

  // state 4x4 -> 16 byte (kolom demi kolom)
  function stateToBytes(state) {
    const bytes = new Array(16);
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        bytes[c * 4 + r] = state[r][c];
      }
    }
    return bytes;
  }

  function bytesToHexString(bytes) {
    return bytes.map(toHex2).join('');
  }

  function hexStringToBytes(hex) {
    const clean = hex.replace(/\s+/g, '');
    const bytes = [];
    for (let i = 0; i < clean.length; i += 2) {
      bytes.push(parseInt(clean.substr(i, 2), 16));
    }
    return bytes;
  }

  // Teks biasa (maks 16 char) -> 16 byte, padding 0x00 di akhir bila kurang
  function textToBytes(text) {
    const bytes = [];
    for (let i = 0; i < 16; i++) {
      bytes.push(i < text.length ? text.charCodeAt(i) & 0xff : 0x00);
    }
    return bytes;
  }

   // 3. OPERASI DASAR AES (byte-level, dipakai untuk key expansion & state)

  function subWord(word) {           // word = array 4 byte
    return word.map(b => SBOX[b]);
  }

  function rotWord(word) {            // rotasi kiri 1 byte
    return [word[1], word[2], word[3], word[0]];
  }

  function xorWords(w1, w2) {
    return [w1[0]^w2[0], w1[1]^w2[1], w1[2]^w2[2], w1[3]^w2[3]];
  }

   // 4. KEY EXPANSION (dengan log lengkap tiap word W0..W43)
  function keyExpansionDetailed(keyBytes) {
    const Nk = 4, Nr = 10, Nb = 4;
    const totalWords = Nb * (Nr + 1); // 44

    const initialKeyState = bytesToState(keyBytes);

    // W[i] disimpan sebagai array 4 byte (kolom)
    const W = new Array(totalWords);
    for (let i = 0; i < Nk; i++) {
      W[i] = [keyBytes[4*i], keyBytes[4*i+1], keyBytes[4*i+2], keyBytes[4*i+3]];
    }

    const wordLog = [];
    // catat W0..W3 (langsung dari kunci)
    for (let i = 0; i < Nk; i++) {
      wordLog.push({
        index: i,
        result: W[i].slice(),
        isG: false,
        source: 'Diambil langsung dari kunci (K' + i + ')'
      });
    }

    for (let i = Nk; i < totalWords; i++) {
      let temp = W[i-1].slice();
      let gDetail = null;

      if (i % Nk === 0) {
        const rotResult = rotWord(temp);
        const subResult = subWord(rotResult);
        const rconWord = [RCON[i / Nk], 0x00, 0x00, 0x00];
        const xorResult = xorWords(subResult, rconWord);
        gDetail = {
          input: temp.slice(),
          rotWord: rotResult,
          subWord: subResult,
          rconIndex: i / Nk,
          rconWord: rconWord,
          gResult: xorResult
        };
        temp = xorResult;
      }

      const prevW = W[i - Nk];
      const result = xorWords(prevW, temp);
      W[i] = result;

      wordLog.push({
        index: i,
        isG: i % Nk === 0,
        gDetail: gDetail,
        wIMinusNk: prevW.slice(),
        temp: temp.slice(),
        result: result.slice()
      });
    }

    // Susun Round Keys RK0..RK10, tiap RK adalah 4 word -> state 4x4
    const roundKeys = [];
    for (let rk = 0; rk <= Nr; rk++) {
      const words = [W[rk*4], W[rk*4+1], W[rk*4+2], W[rk*4+3]];
      // state[r][c] = words[c][r]
      const state = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
      for (let c = 0; c < 4; c++)
        for (let r = 0; r < 4; r++)
          state[r][c] = words[c][r];
      roundKeys.push(state);
    }

    return {
      initialKeyState,
      words: wordLog,
      roundKeys // array of 11 state 4x4 (RK0..RK10)
    };
  }

   // 5. TRANSFORMASI STATE
  function subBytes(state) {
    return state.map(row => row.map(b => SBOX[b]));
  }
  function invSubBytes(state) {
    return state.map(row => row.map(b => INV_SBOX[b]));
  }

  function shiftRows(state) {
    // baris r digeser kiri sebanyak r
    const s = cloneState(state);
    for (let r = 1; r < 4; r++) {
      const row = s[r];
      s[r] = [...row.slice(r), ...row.slice(0, r)];
    }
    return s;
  }
  function invShiftRows(state) {
    // baris r digeser kanan sebanyak r
    const s = cloneState(state);
    for (let r = 1; r < 4; r++) {
      const row = s[r];
      const shift = 4 - r;
      s[r] = [...row.slice(shift), ...row.slice(0, shift)];
    }
    return s;
  }

  function mixColumns(state) {
    const s = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c = 0; c < 4; c++) {
      const a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
      s[0][c] = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3;
      s[1][c] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3;
      s[2][c] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3);
      s[3][c] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2);
    }
    return s;
  }
  function invMixColumns(state) {
    const s = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c = 0; c < 4; c++) {
      const a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
      s[0][c] = gmul(a0,0x0e) ^ gmul(a1,0x0b) ^ gmul(a2,0x0d) ^ gmul(a3,0x09);
      s[1][c] = gmul(a0,0x09) ^ gmul(a1,0x0e) ^ gmul(a2,0x0b) ^ gmul(a3,0x0d);
      s[2][c] = gmul(a0,0x0d) ^ gmul(a1,0x09) ^ gmul(a2,0x0e) ^ gmul(a3,0x0b);
      s[3][c] = gmul(a0,0x0b) ^ gmul(a1,0x0d) ^ gmul(a2,0x09) ^ gmul(a3,0x0e);
    }
    return s;
  }

  function addRoundKey(state, roundKeyState) {
    const s = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let r = 0; r < 4; r++)
      for (let c = 0; c < 4; c++)
        s[r][c] = state[r][c] ^ roundKeyState[r][c];
    return s;
  }

  // 6. ENKRIPSI LENGKAP (dengan log tiap ronde)
    function encryptDetailed(plainBytes, keyBytes) {
    const ke = keyExpansionDetailed(keyBytes);
    const RK = ke.roundKeys; // RK[0..10]

    const log = { keyExpansion: ke, rounds: [] };

    let state = bytesToState(plainBytes);
    log.initialRound = {
      inputState: cloneState(state)
    };
    state = addRoundKey(state, RK[0]);
    log.initialRound.afterAddRoundKey = cloneState(state);

    for (let round = 1; round <= 9; round++) {
      const before1 = cloneState(state);
      const afterSub = subBytes(state);
      const before2 = cloneState(afterSub);
      const afterShift = shiftRows(afterSub);
      const before3 = cloneState(afterShift);
      const afterMix = mixColumns(afterShift);
      const before4 = cloneState(afterMix);
      const afterAdd = addRoundKey(afterMix, RK[round]);

      log.rounds.push({
        roundNum: round,
        subBytes: { before: before1, after: before2 },
        shiftRows: { before: before2, after: before3 },
        mixColumns: { before: before3, after: before4 },
        addRoundKey: { before: before4, after: cloneState(afterAdd), roundKey: RK[round] }
      });

      state = afterAdd;
    }

    // Round 10 (final)
    {
      const before1 = cloneState(state);
      const afterSub = subBytes(state);
      const before2 = cloneState(afterSub);
      const afterShift = shiftRows(afterSub);
      const before3 = cloneState(afterShift);
      const afterAdd = addRoundKey(afterShift, RK[10]);

      log.finalRound = {
        roundNum: 10,
        subBytes: { before: before1, after: before2 },
        shiftRows: { before: before2, after: before3 },
        addRoundKey: { before: before3, after: cloneState(afterAdd), roundKey: RK[10] }
      };

      state = afterAdd;
    }

    const cipherBytes = stateToBytes(state);
    log.ciphertext = bytesToHexString(cipherBytes);
    log.ciphertextBytes = cipherBytes;
    return log;
  }

    // 7. DEKRIPSI LENGKAP (Inverse Cipher standar FIPS-197, dengan log)
   function decryptDetailed(cipherBytes, keyBytes) {
    const ke = keyExpansionDetailed(keyBytes);
    const RK = ke.roundKeys; // RK[0..10]

    const log = { keyExpansion: ke, rounds: [] };

    let state = bytesToState(cipherBytes);
    log.initialStep = {
      inputState: cloneState(state)
    };
    state = addRoundKey(state, RK[10]);
    log.initialStep.afterAddRoundKey = cloneState(state);

    for (let round = 9; round >= 1; round--) {
      const before1 = cloneState(state);
      const afterInvShift = invShiftRows(state);
      const before2 = cloneState(afterInvShift);
      const afterInvSub = invSubBytes(afterInvShift);
      const before3 = cloneState(afterInvSub);
      const afterAdd = addRoundKey(afterInvSub, RK[round]);
      const before4 = cloneState(afterAdd);
      const afterInvMix = invMixColumns(afterAdd);

      log.rounds.push({
        roundNum: round,
        invShiftRows: { before: before1, after: before2 },
        invSubBytes: { before: before2, after: before3 },
        addRoundKey: { before: before3, after: before4, roundKey: RK[round] },
        invMixColumns: { before: before4, after: cloneState(afterInvMix) }
      });

      state = afterInvMix;
    }

    // Final round (ronde 0)
    {
      const before1 = cloneState(state);
      const afterInvShift = invShiftRows(state);
      const before2 = cloneState(afterInvShift);
      const afterInvSub = invSubBytes(afterInvShift);
      const before3 = cloneState(afterInvSub);
      const afterAdd = addRoundKey(afterInvSub, RK[0]);

      log.finalRound = {
        roundNum: 0,
        invShiftRows: { before: before1, after: before2 },
        invSubBytes: { before: before2, after: before3 },
        addRoundKey: { before: before3, after: cloneState(afterAdd), roundKey: RK[0] }
      };

      state = afterAdd;
    }

    const plainBytes = stateToBytes(state);
    log.plaintext = bytesToHexString(plainBytes);
    log.plaintextBytes = plainBytes;
    return log;
  }

  // API PUBLIK
    return {
    SBOX, INV_SBOX, RCON,
    gmul,
    toHex2,
    stateToHexMatrix,
    bytesToState,
    stateToBytes,
    bytesToHexString,
    hexStringToBytes,
    textToBytes,
    keyExpansionDetailed,
    encryptDetailed,
    decryptDetailed
  };
})();

if (typeof module !== 'undefined') module.exports = AES;
