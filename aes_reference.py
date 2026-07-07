import argparse
import secrets
import sys

# 1. KONSTANTA: S-BOX, INVERSE S-BOX, RCON
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

Nk, Nb, Nr = 4, 4, 10  # AES-128: 4 word kunci, 4 word per state, 10 ronde


# 2. UTILITAS GF(2^8) DAN FORMAT
def gmul(a, b):
    """Perkalian di GF(2^8) dengan polinomial ireducible x^8+x^4+x^3+x+1 (0x11B)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def hex2(b):
    return format(b, "02X")


def bytes_to_state(data):
    """16 byte -> state 4x4, kolom demi kolom (state[r][c] = data[r + 4c])."""
    return [[data[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = state[r][c]
    return out


def hex_to_bytes(s):
    s = s.strip().replace(" ", "")
    if len(s) != 32:
        raise ValueError("Panjang hex harus 32 karakter (16 byte).")
    return [int(s[i:i + 2], 16) for i in range(0, 32, 2)]


def bytes_to_hex(b):
    return "".join(hex2(x) for x in b)


def text_to_bytes(text):
    if len(text) > 16:
        raise ValueError("Teks maksimal 16 karakter untuk satu blok AES.")
    data = [ord(c) & 0xFF for c in text]
    data += [0x00] * (16 - len(data))
    return data


def clone(state):
    return [row[:] for row in state]


def fmt_state(state, indent="  "):
    lines = []
    for r in range(4):
        lines.append(indent + " ".join(hex2(state[r][c]) for c in range(4)))
    return "\n".join(lines)


def fmt_word(word):
    return "".join(hex2(b) for b in word)


# 3. OPERASI DASAR (byte-level, dipakai key expansion & state)
def sub_word(word):
    return [SBOX[b] for b in word]


def rot_word(word):
    return [word[1], word[2], word[3], word[0]]


def xor_words(a, b):
    return [a[i] ^ b[i] for i in range(4)]


# 4. KEY EXPANSION (menghasilkan W[0..43] dan RK0..RK10)
def key_expansion(key_bytes, verbose=False):
    total_words = Nb * (Nr + 1)  # 44
    W = [None] * total_words

    for i in range(Nk):
        W[i] = key_bytes[4 * i:4 * i + 4]

    if verbose:
        print("\n=== KEY EXPANSION ===")
        for i in range(Nk):
            print(f"  W[{i}] = {fmt_word(W[i])}  (langsung dari kunci)")

    for i in range(Nk, total_words):
        temp = W[i - 1][:]
        if i % Nk == 0:
            rotated = rot_word(temp)
            subbed = sub_word(rotated)
            rcon_word = [RCON[i // Nk], 0x00, 0x00, 0x00]
            g_result = xor_words(subbed, rcon_word)
            if verbose:
                print(f"  -- fungsi g pada W[{i-1}] --")
                print(f"     RotWord : {fmt_word(temp)} -> {fmt_word(rotated)}")
                print(f"     SubWord : {fmt_word(subbed)}")
                print(f"     XOR Rcon[{i//Nk}] ({fmt_word(rcon_word)}) -> {fmt_word(g_result)}")
            temp = g_result
        W[i] = xor_words(W[i - Nk], temp)
        if verbose:
            print(f"  W[{i}] = W[{i-Nk}] ({fmt_word(W[i-Nk])}) XOR temp ({fmt_word(temp)}) "
                  f"= {fmt_word(W[i])}")

    round_keys = []
    for rk in range(Nr + 1):
        words = W[rk * 4: rk * 4 + 4]
        state = [[words[c][r] for c in range(4)] for r in range(4)]
        round_keys.append(state)
        if verbose:
            print(f"\n  Round Key {rk}:")
            print(fmt_state(state, "    "))

    return round_keys, W


# 5. TRANSFORMASI STATE
def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state):
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state):
    s = clone(state)
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    return s


def inv_shift_rows(state):
    s = clone(state)
    for r in range(1, 4):
        shift = 4 - r
        s[r] = s[r][shift:] + s[r][:shift]
    return s


def mix_columns(state):
    s = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
        s[0][c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        s[1][c] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        s[2][c] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        s[3][c] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)
    return s


def inv_mix_columns(state):
    s = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
        s[0][c] = gmul(a0, 0x0E) ^ gmul(a1, 0x0B) ^ gmul(a2, 0x0D) ^ gmul(a3, 0x09)
        s[1][c] = gmul(a0, 0x09) ^ gmul(a1, 0x0E) ^ gmul(a2, 0x0B) ^ gmul(a3, 0x0D)
        s[2][c] = gmul(a0, 0x0D) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0E) ^ gmul(a3, 0x0B)
        s[3][c] = gmul(a0, 0x0B) ^ gmul(a1, 0x0D) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0E)
    return s


def add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


# 6. ENKRIPSI / DEKRIPSI LENGKAP (satu blok, 128-bit)
def encrypt_block(plain_bytes, key_bytes, verbose=False):
    RK, _ = key_expansion(key_bytes, verbose=verbose)

    state = bytes_to_state(plain_bytes)
    if verbose:
        print("\n=== ENKRIPSI ===")
        print("State Plaintext:")
        print(fmt_state(state))

    state = add_round_key(state, RK[0])
    if verbose:
        print("\nInitial Round - setelah AddRoundKey (RK0):")
        print(fmt_state(state))

    for rnd in range(1, 10):
        state = sub_bytes(state)
        if verbose:
            print(f"\nRound {rnd} - setelah SubBytes:")
            print(fmt_state(state))
        state = shift_rows(state)
        if verbose:
            print(f"Round {rnd} - setelah ShiftRows:")
            print(fmt_state(state))
        state = mix_columns(state)
        if verbose:
            print(f"Round {rnd} - setelah MixColumns:")
            print(fmt_state(state))
        state = add_round_key(state, RK[rnd])
        if verbose:
            print(f"Round {rnd} - setelah AddRoundKey (RK{rnd}):")
            print(fmt_state(state))

    state = sub_bytes(state)
    if verbose:
        print("\nRound 10 (final) - setelah SubBytes:")
        print(fmt_state(state))
    state = shift_rows(state)
    if verbose:
        print("Round 10 (final) - setelah ShiftRows:")
        print(fmt_state(state))
    state = add_round_key(state, RK[10])
    if verbose:
        print("Round 10 (final) - setelah AddRoundKey (RK10) = CIPHERTEXT:")
        print(fmt_state(state))

    return state_to_bytes(state)


def decrypt_block(cipher_bytes, key_bytes, verbose=False):
    RK, _ = key_expansion(key_bytes, verbose=verbose)

    state = bytes_to_state(cipher_bytes)
    if verbose:
        print("\n=== DEKRIPSI ===")
        print("State Ciphertext:")
        print(fmt_state(state))

    state = add_round_key(state, RK[10])
    if verbose:
        print("\nLangkah awal - setelah AddRoundKey (RK10):")
        print(fmt_state(state))

    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        if verbose:
            print(f"\nRound {rnd} - setelah InvShiftRows:")
            print(fmt_state(state))
        state = inv_sub_bytes(state)
        if verbose:
            print(f"Round {rnd} - setelah InvSubBytes:")
            print(fmt_state(state))
        state = add_round_key(state, RK[rnd])
        if verbose:
            print(f"Round {rnd} - setelah AddRoundKey (RK{rnd}):")
            print(fmt_state(state))
        state = inv_mix_columns(state)
        if verbose:
            print(f"Round {rnd} - setelah InvMixColumns:")
            print(fmt_state(state))

    state = inv_shift_rows(state)
    if verbose:
        print("\nFinal Round (0) - setelah InvShiftRows:")
        print(fmt_state(state))
    state = inv_sub_bytes(state)
    if verbose:
        print("Final Round (0) - setelah InvSubBytes:")
        print(fmt_state(state))
    state = add_round_key(state, RK[0])
    if verbose:
        print("Final Round (0) - setelah AddRoundKey (RK0) = PLAINTEXT:")
        print(fmt_state(state))

    return state_to_bytes(state)


# 7. SELF-TEST (FIPS-197 test vectors)
def selftest():
    vectors = [
        ("3243f6a8885a308d313198a2e0370734",
         "2b7e151628aed2a6abf7158809cf4f3c",
         "3925841d02dc09fbdc118597196a0b32"),
        ("00112233445566778899aabbccddeeff",
         "000102030405060708090a0b0c0d0e0f",
         "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ]
    ok_all = True
    for i, (p, k, c) in enumerate(vectors, 1):
        pb, kb = hex_to_bytes(p), hex_to_bytes(k)
        enc = bytes_to_hex(encrypt_block(pb, kb))
        dec = bytes_to_hex(decrypt_block(hex_to_bytes(enc), kb))
        ok = (enc.lower() == c.lower()) and (dec.lower() == p.lower())
        ok_all &= ok
        print(f"Test vector {i}: enkripsi {'OK' if enc.lower()==c.lower() else 'GAGAL'}, "
              f"dekripsi {'OK' if dec.lower()==p.lower() else 'GAGAL'}")
        print(f"  plaintext  : {p.upper()}")
        print(f"  key        : {k.upper()}")
        print(f"  ciphertext : {enc}  (harapan: {c.upper()})")
        print(f"  hasil dekripsi kembali ke plaintext: {dec}")
    print("\nSEMUA TEST VECTOR " + ("BERHASIL ✔" if ok_all else "GAGAL ✘"))
    return ok_all


# 8. CLI
def main():
    parser = argparse.ArgumentParser(
        description="Implementasi referensi AES-128 (Python murni) untuk verifikasi CIPHERBOARD."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--encrypt", action="store_true", help="Jalankan mode enkripsi")
    group.add_argument("--decrypt", action="store_true", help="Jalankan mode dekripsi")
    group.add_argument("--selftest", action="store_true", help="Jalankan uji FIPS-197 test vector")

    parser.add_argument("--plaintext", type=str, help="Plaintext (hex 32 karakter atau teks biasa, maks 16 char)")
    parser.add_argument("--ciphertext", type=str, help="Ciphertext (hex 32 karakter)")
    parser.add_argument("--key", type=str, help="Kunci AES-128 (hex 32 karakter)")
    parser.add_argument("--random-key", action="store_true", help="Buat kunci acak 128-bit")
    parser.add_argument("--steps", action="store_true", help="Cetak seluruh State Matrix tiap langkah")

    args = parser.parse_args()

    if args.selftest or (not args.encrypt and not args.decrypt):
        selftest()
        return

    if args.random_key:
        key_hex = secrets.token_hex(16)
        print(f"Kunci acak dibuat: {key_hex.upper()}")
    else:
        if not args.key:
            print("Error: --key wajib diisi (hex 32 karakter).", file=sys.stderr)
            sys.exit(1)
        key_hex = args.key

    try:
        key_bytes = hex_to_bytes(key_hex)
    except ValueError as e:
        print(f"Error kunci: {e}", file=sys.stderr)
        sys.exit(1)

    if args.encrypt:
        if not args.plaintext:
            print("Error: --plaintext wajib diisi.", file=sys.stderr)
            sys.exit(1)
        raw = args.plaintext.strip()
        try:
            plain_bytes = hex_to_bytes(raw) if len(raw) == 32 and all(c in "0123456789abcdefABCDEF" for c in raw) else text_to_bytes(raw)
        except ValueError as e:
            print(f"Error plaintext: {e}", file=sys.stderr)
            sys.exit(1)
        result = encrypt_block(plain_bytes, key_bytes, verbose=args.steps)
        print(f"\nCIPHERTEXT (hex): {bytes_to_hex(result)}")

    elif args.decrypt:
        if not args.ciphertext:
            print("Error: --ciphertext wajib diisi.", file=sys.stderr)
            sys.exit(1)
        try:
            cipher_bytes = hex_to_bytes(args.ciphertext)
        except ValueError as e:
            print(f"Error ciphertext: {e}", file=sys.stderr)
            sys.exit(1)
        result = decrypt_block(cipher_bytes, key_bytes, verbose=args.steps)
        print(f"\nPLAINTEXT (hex): {bytes_to_hex(result)}")


if __name__ == "__main__":
    main()
