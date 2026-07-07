(() => {
  'use strict';

    // STATE APLIKASI
  let currentMode = 'encrypt';   // 'encrypt' | 'decrypt'
  let currentFormat = 'text';    // 'text' | 'hex'  (hanya berlaku utk plaintext saat mode encrypt)

  // ELEMEN DOM
   const el = {
    modeButtons: document.querySelectorAll('.segmented__btn'),
    formatButtons: document.querySelectorAll('.format-toggle__btn'),
    inputTextLabel: document.getElementById('input-text-label'),
    inputText: document.getElementById('input-text'),
    inputTextHint: document.getElementById('input-text-hint'),
    inputKey: document.getElementById('input-key'),
    btnRandomKey: document.getElementById('btn-random-key'),
    errorSlot: document.getElementById('error-slot'),
    btnProcess: document.getElementById('btn-process'),
    btnProcessLabel: document.getElementById('btn-process-label'),
    btnReset: document.getElementById('btn-reset'),
    outputBlock: document.getElementById('output-block'),
    outputLabel: document.getElementById('output-label'),
    outputText: document.getElementById('output-text'),
    btnCopy: document.getElementById('btn-copy'),
    copyToast: document.getElementById('copy-toast'),
    toggleDetail: document.getElementById('toggle-detail'),
    emptyState: document.getElementById('empty-state'),
    resultShell: document.getElementById('result-shell'),
    roundNav: document.getElementById('round-nav'),
    detailContainer: document.getElementById('detail-container'),
  };

  // HELPERS UI
  function showError(msg) {
    el.errorSlot.textContent = msg;
    el.errorSlot.hidden = false;
  }
  function clearError() {
    el.errorSlot.textContent = '';
    el.errorSlot.hidden = true;
  }

  function isValidHex(str, len) {
    const re = new RegExp(`^[0-9a-fA-F]{${len}}$`);
    return re.test(str);
  }

  function randomKeyHex() {
    let out = '';
    const chars = '0123456789ABCDEF';
    for (let i = 0; i < 32; i++) out += chars[Math.floor(Math.random() * 16)];
    return out;
  }

    // RENDER: TABEL STATE MATRIX (4x4)

  // hexMatrix: array 4x4 string hex ("3A")
  // prevHexMatrix (optional): dipakai untuk mendeteksi sel yang berubah
  // opClass (optional): 'op-color-sub' | 'op-color-shift' | 'op-color-mix' | 'op-color-key'
  function renderMatrix(hexMatrix, prevHexMatrix, opClass, small) {
    let html = `<table class="state-matrix${small ? ' small' : ''}">`;
    for (let r = 0; r < 4; r++) {
      html += '<tr>';
      for (let c = 0; c < 4; c++) {
        const val = hexMatrix[r][c];
        let cls = '';
        if (opClass) cls += opClass;
        if (prevHexMatrix && prevHexMatrix[r][c] !== val) cls += ' changed';
        html += `<td class="${cls}">${val}</td>`;
      }
      html += '</tr>';
    }
    html += '</table>';
    return html;
  }

  function stateHex(state) { return AES.stateToHexMatrix(state); }

  function matrixCard(caption, hexMatrix, prevHexMatrix, opClass, small) {
    return `<div class="matrix-card">
      <div class="matrix-card__cap">${caption}</div>
      ${renderMatrix(hexMatrix, prevHexMatrix, opClass, small)}
    </div>`;
  }

  function matrixPair(capBefore, beforeState, capAfter, afterState, opClass) {
    const beforeHex = stateHex(beforeState);
    const afterHex = stateHex(afterState);
    return `<div class="matrix-pair">
      ${matrixCard(capBefore, beforeHex, null, null, false)}
      <span class="matrix-arrow">&#8594;</span>
      ${matrixCard(capAfter, afterHex, beforeHex, opClass, false)}
    </div>`;
  }

    // RENDER: KEY EXPANSION SECTION
  function renderKeyExpansion(ke) {
    const initHex = stateHex(ke.initialKeyState);

    let wordsHtml = '';
    ke.words.forEach(w => {
      const bytesHtml = w.result.map(AES.toHex2).map(b => `<span class="word-byte">${b}</span>`).join('');
      if (!w.isG && w.index < 4) {
        wordsHtml += `<div class="word-row">
          <span class="word-row__idx">W[${w.index}]</span>
          <span class="word-bytes">${bytesHtml}</span>
          <span class="word-row__note">${w.source}</span>
        </div>`;
      } else if (w.isG) {
        const g = w.gDetail;
        const rotB = g.input.map(AES.toHex2);
        const rotAfter = g.rotWord.map(AES.toHex2);
        const subAfter = g.subWord.map(AES.toHex2);
        const rconB = g.rconWord.map(AES.toHex2);
        const xorB = g.gResult.map(AES.toHex2);
        wordsHtml += `<div class="word-row" style="display:block;border-bottom:1px dashed var(--border);padding:10px 0;">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px;">
            <span class="word-row__idx">W[${w.index}]</span>
            <span class="word-row__note">= W[${w.index - 4}] &oplus; g(W[${w.index - 1}])</span>
          </div>
          <div class="g-func-box">
            <div class="g-func-box__title">FUNGSI g — diterapkan pada W[${w.index - 1}]</div>
            <div class="g-func-step"><span class="g-func-step__name">RotWord</span>
              <span class="word-bytes">${rotB.map(b=>`<span class="word-byte">${b}</span>`).join('')}</span>
              <span class="word-op">&#8594;</span>
              <span class="word-bytes">${rotAfter.map(b=>`<span class="word-byte">${b}</span>`).join('')}</span>
            </div>
            <div class="g-func-step"><span class="g-func-step__name">SubWord (S&#8209;Box)</span>
              <span class="word-bytes">${subAfter.map(b=>`<span class="word-byte">${b}</span>`).join('')}</span>
            </div>
            <div class="g-func-step"><span class="g-func-step__name">XOR Rcon[${g.rconIndex}]</span>
              <span class="word-bytes">${rconB.map(b=>`<span class="word-byte">${b}</span>`).join('')}</span>
              <span class="word-op">=&gt;</span>
              <span class="word-bytes">${xorB.map(b=>`<span class="word-byte">${b}</span>`).join('')}</span>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
            <span class="word-row__note" style="min-width:auto;">Hasil W[${w.index}] = W[${w.index-4}] (${w.wIMinusNk.map(AES.toHex2).join('')}) &oplus; g-result (${g.gResult.map(AES.toHex2).join('')}) =</span>
            <span class="word-bytes">${bytesHtml}</span>
          </div>
        </div>`;
      } else {
        wordsHtml += `<div class="word-row">
          <span class="word-row__idx">W[${w.index}]</span>
          <span class="word-row__note">= W[${w.index-4}] &oplus; W[${w.index-1}] &#8594;</span>
          <span class="word-bytes">${bytesHtml}</span>
        </div>`;
      }
    });

    let rkGrid = '';
    ke.roundKeys.forEach((rk, i) => {
      rkGrid += `<div class="rk-item">
        <span class="rk-item__label">RK${i}</span>
        ${renderMatrix(stateHex(rk), null, null, true)}
      </div>`;
    });

    return `
    <div class="section" id="section-keyexp" data-nav="Key Expansion">
      <div class="section__header">
        <span class="section__title"><span class="section__chevron">&#9660;</span>Key Expansion</span>
        <span class="section__badge">W[0] &#8594; W[43] · RK0&#8211;RK10</span>
      </div>
      <div class="section__body">
        <div class="op-block">
          <div class="op-block__desc">State awal kunci (16 byte kunci disusun sebagai matriks 4&times;4, kolom demi kolom):</div>
          ${matrixCard('Key State Awal', initHex, null, null, false)}
        </div>
        <div class="op-block">
          <div class="op-block__desc">Pembangkitan setiap word kunci ronde W[0] hingga W[43]. Word dengan indeks kelipatan 4 melalui fungsi <b>g</b> (RotWord &#8594; SubWord &#8594; XOR Rcon) sebelum di-XOR dengan W[i&#8722;4].</div>
          <details class="words-details">
            <summary>&#9654; Tampilkan proses lengkap W[0] .. W[43] (klik untuk buka/tutup)</summary>
            <div style="margin-top:8px;">${wordsHtml}</div>
          </details>
        </div>
        <div class="op-block">
          <div class="op-block__desc">Round Key hasil akhir (RK0 s/d RK10), masing-masing sebagai matriks 4&times;4 hex:</div>
          <div class="rk-grid">${rkGrid}</div>
        </div>
      </div>
    </div>`;
  }

  // RENDER: ENKRIPSI
  function renderEncryption(log) {
    let html = '';

    // Initial Round
    html += `<div class="section" id="section-initial" data-nav="Initial Round">
      <div class="section__header">
        <span class="section__title"><span class="section__chevron">&#9660;</span>Initial Round</span>
        <span class="section__badge">AddRoundKey (RK0)</span>
      </div>
      <div class="section__body">
        <div class="op-block op-key">
          <span class="op-block__label"><span class="dot"></span>AddRoundKey — RK0</span>
          <div class="op-block__desc">State plaintext di-XOR langsung dengan Round Key ke-0 (kunci asli).</div>
          ${matrixPair('State Plaintext', log.initialRound.inputState, 'Setelah AddRoundKey', log.initialRound.afterAddRoundKey, 'op-color-key')}
        </div>
      </div>
    </div>`;

    // Round 1-9
    log.rounds.forEach(rnd => {
      html += `<div class="section" id="section-round-${rnd.roundNum}" data-nav="Round ${rnd.roundNum}">
        <div class="section__header">
          <span class="section__title"><span class="section__chevron">&#9660;</span>Round ${rnd.roundNum}</span>
          <span class="section__badge">SubBytes &#8594; ShiftRows &#8594; MixColumns &#8594; AddRoundKey</span>
        </div>
        <div class="section__body">
          <div class="op-block op-sub">
            <span class="op-block__label"><span class="dot"></span>SubBytes</span>
            ${matrixPair('Sebelum', rnd.subBytes.before, 'Sesudah (via S&#8209;Box)', rnd.subBytes.after, 'op-color-sub')}
          </div>
          <div class="op-block op-shift">
            <span class="op-block__label"><span class="dot"></span>ShiftRows</span>
            ${matrixPair('Sebelum', rnd.shiftRows.before, 'Sesudah (pergeseran baris)', rnd.shiftRows.after, 'op-color-shift')}
          </div>
          <div class="op-block op-mix">
            <span class="op-block__label"><span class="dot"></span>MixColumns</span>
            ${matrixPair('Sebelum', rnd.mixColumns.before, 'Sesudah (perkalian GF(2&#8309;))', rnd.mixColumns.after, 'op-color-mix')}
          </div>
          <div class="op-block op-key">
            <span class="op-block__label"><span class="dot"></span>AddRoundKey — RK${rnd.roundNum}</span>
            ${matrixPair('Sebelum', rnd.addRoundKey.before, 'Sesudah (XOR RK'+rnd.roundNum+')', rnd.addRoundKey.after, 'op-color-key')}
          </div>
        </div>
      </div>`;
    });

    // Final round 10
    const fr = log.finalRound;
    html += `<div class="section" id="section-round-10" data-nav="Round 10 (Final)">
      <div class="section__header">
        <span class="section__title"><span class="section__chevron">&#9660;</span>Round 10 (Final)</span>
        <span class="section__badge">SubBytes &#8594; ShiftRows &#8594; AddRoundKey (tanpa MixColumns)</span>
      </div>
      <div class="section__body">
        <div class="op-block op-sub">
          <span class="op-block__label"><span class="dot"></span>SubBytes</span>
          ${matrixPair('Sebelum', fr.subBytes.before, 'Sesudah', fr.subBytes.after, 'op-color-sub')}
        </div>
        <div class="op-block op-shift">
          <span class="op-block__label"><span class="dot"></span>ShiftRows</span>
          ${matrixPair('Sebelum', fr.shiftRows.before, 'Sesudah', fr.shiftRows.after, 'op-color-shift')}
        </div>
        <div class="op-block op-key">
          <span class="op-block__label"><span class="dot"></span>AddRoundKey — RK10</span>
          ${matrixPair('Sebelum', fr.addRoundKey.before, 'Sesudah = State Akhir', fr.addRoundKey.after, 'op-color-key')}
        </div>
        <div class="ciphertext-result">
          <div class="ciphertext-result__label">CIPHERTEXT (HEX)</div>
          <div class="ciphertext-result__value">${log.ciphertext}</div>
        </div>
      </div>
    </div>`;

    return html;
  }

    // RENDER: DEKRIPSI
  function renderDecryption(log) {
    let html = '';

    html += `<div class="section" id="section-initial" data-nav="AddRoundKey RK10">
      <div class="section__header">
        <span class="section__title"><span class="section__chevron">&#9660;</span>Langkah Awal</span>
        <span class="section__badge">AddRoundKey (RK10)</span>
      </div>
      <div class="section__body">
        <div class="op-block op-key">
          <span class="op-block__label"><span class="dot"></span>AddRoundKey — RK10</span>
          <div class="op-block__desc">State ciphertext di-XOR dengan Round Key ke-10 (kebalikan dari langkah terakhir enkripsi).</div>
          ${matrixPair('State Ciphertext', log.initialStep.inputState, 'Setelah AddRoundKey', log.initialStep.afterAddRoundKey, 'op-color-key')}
        </div>
      </div>
    </div>`;

    log.rounds.forEach(rnd => {
      html += `<div class="section" id="section-round-${rnd.roundNum}" data-nav="Round ${rnd.roundNum}">
        <div class="section__header">
          <span class="section__title"><span class="section__chevron">&#9660;</span>Round ${rnd.roundNum}</span>
          <span class="section__badge">InvShiftRows &#8594; InvSubBytes &#8594; AddRoundKey &#8594; InvMixColumns</span>
        </div>
        <div class="section__body">
          <div class="op-block op-shift">
            <span class="op-block__label"><span class="dot"></span>InvShiftRows</span>
            ${matrixPair('Sebelum', rnd.invShiftRows.before, 'Sesudah', rnd.invShiftRows.after, 'op-color-shift')}
          </div>
          <div class="op-block op-sub">
            <span class="op-block__label"><span class="dot"></span>InvSubBytes</span>
            ${matrixPair('Sebelum', rnd.invSubBytes.before, 'Sesudah (via Inverse S&#8209;Box)', rnd.invSubBytes.after, 'op-color-sub')}
          </div>
          <div class="op-block op-key">
            <span class="op-block__label"><span class="dot"></span>AddRoundKey — RK${rnd.roundNum}</span>
            ${matrixPair('Sebelum', rnd.addRoundKey.before, 'Sesudah (XOR RK'+rnd.roundNum+')', rnd.addRoundKey.after, 'op-color-key')}
          </div>
          <div class="op-block op-mix">
            <span class="op-block__label"><span class="dot"></span>InvMixColumns</span>
            ${matrixPair('Sebelum', rnd.invMixColumns.before, 'Sesudah (invers GF(2&#8309;))', rnd.invMixColumns.after, 'op-color-mix')}
          </div>
        </div>
      </div>`;
    });

    const fr = log.finalRound;
    html += `<div class="section" id="section-round-0" data-nav="Round 0 (Final)">
      <div class="section__header">
        <span class="section__title"><span class="section__chevron">&#9660;</span>Final Round (Ronde 0)</span>
        <span class="section__badge">InvShiftRows &#8594; InvSubBytes &#8594; AddRoundKey (RK0)</span>
      </div>
      <div class="section__body">
        <div class="op-block op-shift">
          <span class="op-block__label"><span class="dot"></span>InvShiftRows</span>
          ${matrixPair('Sebelum', fr.invShiftRows.before, 'Sesudah', fr.invShiftRows.after, 'op-color-shift')}
        </div>
        <div class="op-block op-sub">
          <span class="op-block__label"><span class="dot"></span>InvSubBytes</span>
          ${matrixPair('Sebelum', fr.invSubBytes.before, 'Sesudah', fr.invSubBytes.after, 'op-color-sub')}
        </div>
        <div class="op-block op-key">
          <span class="op-block__label"><span class="dot"></span>AddRoundKey — RK0</span>
          ${matrixPair('Sebelum', fr.addRoundKey.before, 'Sesudah = State Akhir', fr.addRoundKey.after, 'op-color-key')}
        </div>
        <div class="ciphertext-result">
          <div class="ciphertext-result__label">PLAINTEXT (HEX)</div>
          <div class="ciphertext-result__value">${log.plaintext}</div>
        </div>
      </div>
    </div>`;

    return html;
  }

    // COLLAPSIBLE SECTIONS + ROUND NAV
  function attachSectionToggles() {
    el.detailContainer.querySelectorAll('.section__header').forEach(header => {
      header.addEventListener('click', () => {
        header.closest('.section').classList.toggle('is-open');
      });
    });
  }

  function buildRoundNav() {
    const sections = el.detailContainer.querySelectorAll('.section');
    el.roundNav.innerHTML = '';
    sections.forEach((sec, i) => {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'round-nav__chip' + (i === 0 ? ' is-active' : '');
      chip.textContent = sec.dataset.nav;
      chip.addEventListener('click', () => {
        el.roundNav.querySelectorAll('.round-nav__chip').forEach(c => c.classList.remove('is-active'));
        chip.classList.add('is-active');
        sec.classList.add('is-open');
        sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      el.roundNav.appendChild(chip);
    });
  }

  function openFirstSection() {
    const first = el.detailContainer.querySelector('.section');
    if (first) first.classList.add('is-open');
  }

  // MODE / FORMAT SWITCHING
  function setMode(mode) {
    currentMode = mode;
    el.modeButtons.forEach(b => {
      const active = b.dataset.mode === mode;
      b.classList.toggle('is-active', active);
      b.setAttribute('aria-selected', active ? 'true' : 'false');
    });

    if (mode === 'encrypt') {
      el.inputTextLabel.textContent = 'Plaintext';
      el.btnProcessLabel.textContent = 'JALANKAN ENKRIPSI';
      el.btnProcess.classList.remove('mode-decrypt');
      el.inputText.placeholder = 'Contoh: ATTACKATDAWN12XY';
      document.querySelector('.format-toggle').style.display = 'flex';
    } else {
      el.inputTextLabel.textContent = 'Ciphertext (Hex, 32 karakter)';
      el.btnProcessLabel.textContent = 'JALANKAN DEKRIPSI';
      el.btnProcess.classList.add('mode-decrypt');
      el.inputText.placeholder = '3925841d02dc09fbdc118597196a0b32';
      // Dekripsi selalu dari hex ciphertext
      currentFormat = 'hex';
      document.querySelector('.format-toggle').style.display = 'none';
    }
    updateHint();
    clearError();
  }

  function setFormat(format) {
    currentFormat = format;
    el.formatButtons.forEach(b => b.classList.toggle('is-active', b.dataset.format === format));
    updateHint();
  }

  function updateHint() {
    if (currentMode === 'decrypt') {
      el.inputTextHint.textContent = 'Masukkan ciphertext sebagai 32 karakter heksadesimal (16 byte).';
    } else if (currentFormat === 'text') {
      el.inputTextHint.textContent = 'Maks. 16 karakter teks (akan di-pad dengan 0x00) — atau masukkan 32 karakter hex.';
    } else {
      el.inputTextHint.textContent = 'Masukkan plaintext sebagai 32 karakter heksadesimal (16 byte).';
    }
  }

  el.modeButtons.forEach(b => b.addEventListener('click', () => setMode(b.dataset.mode)));
  el.formatButtons.forEach(b => b.addEventListener('click', () => setFormat(b.dataset.format)));

  el.btnRandomKey.addEventListener('click', () => {
    el.inputKey.value = randomKeyHex();
    clearError();
  });

   // PROSES UTAMA
  function getPlainOrCipherBytes() {
    const raw = el.inputText.value.trim();

    if (currentMode === 'decrypt') {
      if (!isValidHex(raw, 32)) {
        throw new Error('Ciphertext harus berupa 32 karakter heksadesimal (16 byte).');
      }
      return AES.hexStringToBytes(raw);
    }

    // Encrypt mode
    if (currentFormat === 'hex') {
      if (!isValidHex(raw, 32)) {
        throw new Error('Plaintext (mode Hex) harus berupa 32 karakter heksadesimal (16 byte).');
      }
      return AES.hexStringToBytes(raw);
    } else {
      if (raw.length === 0) throw new Error('Plaintext tidak boleh kosong.');
      if (raw.length > 16) throw new Error('Plaintext teks maksimal 16 karakter untuk satu blok AES.');
      return AES.textToBytes(raw);
    }
  }

  function getKeyBytes() {
    const raw = el.inputKey.value.trim();
    if (!isValidHex(raw, 32)) {
      throw new Error('Kunci harus berupa 32 karakter heksadesimal (16 byte / 128-bit).');
    }
    return AES.hexStringToBytes(raw);
  }

  function process() {
    clearError();
    let dataBytes, keyBytes;
    try {
      dataBytes = getPlainOrCipherBytes();
      keyBytes = getKeyBytes();
    } catch (err) {
      showError(err.message);
      return;
    }

    let log, resultHex, keyExp, mainHtml;

    if (currentMode === 'encrypt') {
      log = AES.encryptDetailed(dataBytes, keyBytes);
      resultHex = log.ciphertext;
      el.outputLabel.textContent = 'Ciphertext (Hex)';
      mainHtml = renderKeyExpansion(log.keyExpansion) + renderEncryption(log);
    } else {
      log = AES.decryptDetailed(dataBytes, keyBytes);
      resultHex = log.plaintext;
      el.outputLabel.textContent = 'Plaintext (Hex)';
      mainHtml = renderKeyExpansion(log.keyExpansion) + renderDecryption(log);
    }

    el.outputText.value = resultHex;
    el.outputBlock.hidden = false;

    el.detailContainer.innerHTML = mainHtml;
    attachSectionToggles();
    buildRoundNav();
    openFirstSection();

    el.emptyState.hidden = true;
    el.resultShell.hidden = !el.toggleDetail.checked;
    el.resultShell.style.display = el.toggleDetail.checked ? '' : 'none';
    if (!el.toggleDetail.checked) el.resultShell.hidden = true;
  }

  el.btnProcess.addEventListener('click', process);

  el.btnReset.addEventListener('click', () => {
    el.inputText.value = '';
    el.inputKey.value = '';
    clearError();
    el.outputBlock.hidden = true;
    el.outputText.value = '';
    el.detailContainer.innerHTML = '';
    el.roundNav.innerHTML = '';
    el.emptyState.hidden = false;
    el.resultShell.hidden = true;
  });

  el.btnCopy.addEventListener('click', () => {
    if (!el.outputText.value) return;
    navigator.clipboard.writeText(el.outputText.value).then(() => {
      el.copyToast.classList.add('show');
      setTimeout(() => el.copyToast.classList.remove('show'), 1400);
    }).catch(() => {
      el.outputText.select();
      document.execCommand('copy');
    });
  });

  el.toggleDetail.addEventListener('change', () => {
    if (el.detailContainer.innerHTML.trim() === '') return;
    const show = el.toggleDetail.checked;
    el.resultShell.hidden = !show;
  });

    // INIT
  setMode('encrypt');
  setFormat('text');
})();
