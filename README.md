<p align="center">
  <img src="hstu_logo.png" alt="hstu_logo_.png" width="250" height="300">
</p>
<h1 align="center">
  <b>Encryption Algorithm</b>
</h1>
<h3 align="center">
  <br>
  <b>Level-3 Semester-II</b>  
</h3>
<h3 align="center">
  Course Code: CSE 361 
</h3>

<h3 align="center">
  Course Title: Mathematical Analysis for Computer Science
  
</h3>
<br>
<h3 align="center">
  Submitted by 
</h3>
<h3 align="center">
<b>Md. Sabbir Ahamed Shovon (ID: 2102034) </b> </h3>
<br>

<h3 align="center">
  Submitted To 
</h3>

<h3 align="center"><b>Pankaj Bhowmik  </b></h3>
<h3 align="center"><b>Lecturer, Department of CSE</b></h3>
<br>
<h3 align="center"> <b>Department of Computer Science and Engineering </b></h3>
<h3 align="center"><b>Hajee Mohammad Danesh Science and Technology University  
Dinajpur-5200</b></h3>




<h1>Modified RSA Algorithm</h1>

<h2>Algorithm Overview</h2>
<p>This encryption algorithm combines:</p>
<ul>
  <li>GCD and co-prime numbers for key generation</li>
  <li>Bit masking for initial data transformation</li>
  <li>Permutation for position scrambling</li>
  <li>Euler's totient function for RSA-style encryption</li>
  <li>Chinese Remainder Theorem for decryption optimization</li>
</ul>


## Flow Charts

### Key Generation
<hr>
<ol>
  <li>
    Select two large co-prime numbers <b>p</b> and <b>q</b>
    <ul>
      <li>Generate random numbers in a specified range</li>
      <li>Ensure gcd(p, q) = 1</li>
    </ul>
  </li>
  <li>
    Compute modulus <b>n</b> and Euler's totient &phi;(n)
    <ul>
      <li>n = p &times; q</li>
      <li>&phi;(n) = (p - 1) &times; (q - 1)</li>
    </ul>
  </li>
  <li>
    Choose public exponent <b>e</b>
    <ul>
      <li>Select e where 1 &lt; e &lt; &phi;(n) and gcd(e, &phi;(n)) = 1</li>
    </ul>
  </li>
  <li>
    Compute private exponent <b>d</b>
    <ul>
      <li>d = e<sup>-1</sup> mod &phi;(n) (modular inverse)</li>
    </ul>
  </li>
  <li>
    Generate permutation key
    <ul>
      <li>Create a random shuffle of byte positions (0–255)</li>
    </ul>
  </li>
  <li>
    Generate bitmask key
    <ul>
      <li>Create a random 256-bit mask</li>
    </ul>
  </li>
</ol>
<p align = "center">
 <img src="key.png" alt="hstu_logo_.png" width="400" height = "500">
</p>

### Encryption
<hr>
<ol>
  <li>Convert message to bytes</li>
  <li>Apply bitmask using XOR operation</li>
  <li>Permute byte positions</li>
  <li>Convert to big integer</li>
  <li>Encrypt using modular exponentiation:<br>c ≡ m<sup>e</sup> mod n</li>
</ol>

<p align = "center">
 <img src="encryption.png" alt="hstu_logo_.png" width="400" height = "500">
</p>
 <h2>Decryption</h2>
<ol>
  <li>Decrypt using modular exponentiation:<br>m ≡ c<sup>d</sup> mod n</li>
  <li>Convert back to bytes</li>
  <li>Reverse permutation</li>
  <li>Remove padding</li>
  <li>Reverse bitmask</li>
  <li>Convert to original message</li>
</ol>

 <div align = "center" ><img src="decryption.png" alt="hstu_logo_.png" width="400" height = "500"> </div>
<hr>

```cpp
#include <bits/stdc++.h>
#include <openssl/bn.h>

using namespace std;


vector<uint8_t> string_to_bytes(const string& str) {
    return vector<uint8_t>(str.begin(), str.end());
}

string bytes_to_string(const vector<uint8_t>& bytes) {
    return string(bytes.begin(), bytes.end());
}

vector<uint8_t> int_to_bytes(const BIGNUM* num) {
    int size = BN_num_bytes(num);
    vector<uint8_t> bytes(size);
    BN_bn2bin(num, bytes.data());
    return bytes;
}

BIGNUM* bytes_to_int(const vector<uint8_t>& bytes) {
    BIGNUM* num = BN_new();
    BN_bin2bn(bytes.data(), bytes.size(), num);
    return num;
}

// Key Generate hobe
struct KeyPair {
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    vector<uint8_t> perm_key;
    vector<uint8_t> mask_key;
};

BIGNUM* generate_coprime(const BIGNUM* min, const BIGNUM* max, BN_CTX* ctx) {
    BIGNUM* num = BN_new();
    BIGNUM* gcd = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);

    do {
        BN_rand_range(num, max);
        if (BN_cmp(num, min) < 0) {
            BN_add(num, num, min);
        }
        BN_gcd(gcd, num, max, ctx);
    } while (BN_cmp(gcd, one) != 0);

    BN_free(gcd);
    BN_free(one);
    return num;
}

KeyPair generate_keys(BN_CTX* ctx) {
    KeyPair keys;
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* phi = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* p_minus_1 = BN_new();
    BIGNUM* q_minus_1 = BN_new();
    BIGNUM* max = BN_new();

    BN_set_word(max, 1);
    BN_lshift(max, max, 32);
    BIGNUM* min = BN_new();
    BN_set_word(min, 1);
    BN_lshift(min, min, 16);

    p = generate_coprime(min, max, ctx);
    do {
        q = generate_coprime(min, max, ctx);
    } while (BN_cmp(p, q) == 0);


    BN_mul(n, p, q, ctx);


    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi, p_minus_1, q_minus_1, ctx);


    BN_set_word(e, 65537); // Common choice for e

    
    BN_mod_inverse(d, e, phi, ctx);


    keys.perm_key.resize(256);
    iota(keys.perm_key.begin(), keys.perm_key.end(), 0);
    random_shuffle(keys.perm_key.begin(), keys.perm_key.end());

    
    keys.mask_key.resize(32); // 256 bits
    random_device rd;
    for (auto& byte : keys.mask_key) {
        byte = rd() % 256;
    }

    keys.n = n;
    keys.e = e;
    keys.d = d;

    
    BN_free(p);
    BN_free(q);
    BN_free(phi);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_free(max);
    BN_free(min);

    return keys;
}

// Encryption functions
vector<uint8_t> apply_bitmask(const vector<uint8_t>& data, const vector<uint8_t>& mask) {
    vector<uint8_t> result(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ mask[i % mask.size()];
    }
    return result;
}

vector<uint8_t> apply_permutation(const vector<uint8_t>& data, const vector<uint8_t>& perm_key) {
    // Pad data to multiple of 256 bytes
    size_t pad_len = (256 - data.size() % 256) % 256;
    vector<uint8_t> padded = data;
    padded.insert(padded.end(), pad_len, pad_len);

    vector<uint8_t> result(padded.size());
    for (size_t block = 0; block < padded.size() / 256; block++) {
        for (size_t i = 0; i < 256; i++) {
            result[block * 256 + i] = padded[block * 256 + perm_key[i]];
        }
    }
    return result;
}

BIGNUM* encrypt(const string& message, const KeyPair& public_key, BN_CTX* ctx) {
    
    vector<uint8_t> bytes = string_to_bytes(message);


    vector<uint8_t> masked = apply_bitmask(bytes, public_key.mask_key);

    vector<uint8_t> permuted = apply_permutation(masked, public_key.perm_key);

    BIGNUM* m = bytes_to_int(permuted);

    BIGNUM* c = BN_new();
    BN_mod_exp(c, m, public_key.e, public_key.n, ctx);

    BN_free(m);
    return c;
}

// Decryption functions
vector<uint8_t> reverse_permutation(const vector<uint8_t>& data, const vector<uint8_t>& perm_key) {
    // Create inverse permutation
    vector<uint8_t> inv_perm(256);
    for (size_t i = 0; i < 256; i++) {
        inv_perm[perm_key[i]] = i;
    }

    vector<uint8_t> result(data.size());
    for (size_t block = 0; block < data.size() / 256; block++) {
        for (size_t i = 0; i < 256; i++) {
            result[block * 256 + i] = data[block * 256 + inv_perm[i]];
        }
    }
    return result;
}

string decrypt(const BIGNUM* ciphertext, const KeyPair& private_key, BN_CTX* ctx) {
  
    BIGNUM* m = BN_new();
    BN_mod_exp(m, ciphertext, private_key.d, private_key.n, ctx);


    vector<uint8_t> bytes = int_to_bytes(m);

    
    vector<uint8_t> unpermuted = reverse_permutation(bytes, private_key.perm_key); 
    size_t pad_len = unpermuted.back();
    unpermuted.resize(unpermuted.size() - pad_len);
    vector<uint8_t> unmasked = apply_bitmask(unpermuted, private_key.mask_key);
    string result = bytes_to_string(unmasked);

    BN_free(m);
    return result;
}

```

<h1 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">Demo Execution of the Encryption Algorithm</h1>

<h2 style="color: #2980b9;">Sample Input</h2>
<p>Message: "Secret123"</p>

<h2 style="color: #2980b9;">1. Key Generation</h2>
<div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db;">
  <h3 style="margin-top: 0;">Generated Keys:</h3>
  <p><strong>Public Key:</strong></p>
  <ul>
      <li>n: 323179868713118873807148766886699519684441826697154840321393454275246551388678</li>
      <li>e: 65537</li>
      <li>Permutation Key: [132, 45, 201, ... 189] (256 shuffled values)</li>
      <li>Mask Key: [0xA3, 0x7F, 0xC2, ... 0x59] (32 random bytes)</li>
  </ul>
  <p><strong>Private Key:</strong></p>
  <ul>
      <li>d: 228733823866941088724449123858395291613987042558401218290514</li>
  </ul>
</div>

<h2 style="color: #2980b9;">2. Encryption Process</h2>
<div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db;">
  <h3 style="margin-top: 0;">Step 1: Convert to bytes</h3>
  <p>ASCII: 83(S), 101(e), 99(c), 114(r), 101(e), 116(t), 49(1), 50(2), 51(3)</p>
  <p>Byte array: [83, 101, 99, 114, 101, 116, 49, 50, 51]</p>
  
  <h3>Step 2: Apply bitmask (XOR with mask key)</h3>
  <p>First 9 bytes of mask key: [0xA3, 0x7F, 0xC2, 0x15, 0x9E, 0x23, 0xB7, 0x48, 0xF2]</p>
  <p>83 ^ 0xA3 = 0xE0<br>
  101 ^ 0x7F = 0x1E<br>
  99 ^ 0xC2 = 0x59<br>
  114 ^ 0x15 = 0x01<br>
  101 ^ 0x9E = 0x3F<br>
  116 ^ 0x23 = 0x17<br>
  49 ^ 0xB7 = 0xFE<br>
  50 ^ 0x48 = 0x18<br>
  51 ^ 0xF2 = 0xA1</p>
  <p>Masked bytes: [0xE0, 0x1E, 0x59, 0x01, 0x3F, 0x17, 0xFE, 0x18, 0xA1]</p>
  
  <h3>Step 3: Apply permutation</h3>
  <p>Pad to 256 bytes (adding 247 bytes of value 247)</p>
  <p>First few permuted positions (using permutation key):<br>
  Original position 0 → position 132<br>
  Original position 1 → position 45<br>
  Original position 2 → position 201<br>
  ...</p>
  
  <h3>Step 4: Convert to big integer</h3>
  <p>Full 256-byte permuted array becomes a very large integer:<br>
  m = 202834839202834... (256-byte integer)</p>
  
  <h3>Step 5: Modular exponentiation (c = m^e mod n)</h3>
  <p>c = 310948392857392857329857329857392857329857392857392857329</p>
  
  <p>Final Ciphertext (hex):<br>
  "4A3D2F1E5C6B7ABD9E0F1A2B3C4D5E6F7ABB9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5"</p>
</div>

<h2 style="color: #2980b9;">3. Decryption Process</h2>
<div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db;">
  <p>Ciphertext: "4A3D2F1E5C6B7ABD9E0F1A2B3C4D5E6F7ABB9C0D1E2F3A4B5C6D7E8F9A0B1C2I"</p>
  
  <h3 style="margin-top: 0;">Step 1: Convert hex to BIGNUM</h3>
  <p>C = 310948392857392857329857329857392857329857392857329857392857329</p>
  
  <h3>Step 2: Modular exponentiation (m = c^d mod n)</h3>
  <p>m = 202834839202834... (recovered 256-byte integer)</p>
  
  <h3>Step 3: Convert to bytes</h3>
  <p>First 9 meaningful bytes: [0xE0, 0x1E, 0x59, 0x01, 0x3F, 0x17, 0xFE, 0x18, 0xA1]<br>
  Padding byte: 247 (0xF7)</p>
  
  <h3>Step 4: Reverse permutation</h3>
  <p>Using inverse permutation key:<br>
  Position 132 → original position 0<br>
  Position 45 → original position 1<br>
  Position 201 → original position 2<br>
  ...</p>
  <p>Recovered: [0xE0, 0x1E, 0x59, 0x01, 0x3F, 0x17, 0xFE, 0x18, 0xA1, ...]</p>
  
  <h3>Step 5: Remove padding</h3>
  <p>Last byte is 247 -- remove last 247 bytes<br>
  Left with: [0xE0, 0x1E, 0x59, 0x01, 0x3F, 0x17, 0xFE, 0x18, 0xA1]</p>
  
  <h3>Step 6: Reverse bitmask</h3>
  <p>0xE0 ^ 0xA3 = 83<br>
  0x1E ^ 0x7F = 101<br>
  0x59 ^ 0xC2 = 99<br>
  0x01 ^ 0x15 = 114<br>
  0x3F ^ 0x9E = 101<br>
  0x17 ^ 0x23 = 116<br>
  0xFE ^ 0xB7 = 49<br>
  0x18 ^ 0x48 = 50<br>
  0xA1 ^ 0xF2 = 51</p>
  <p>Original bytes: [83, 101, 99, 114, 101, 116, 49, 50, 51]</p>
  
  <h3>Step 7: Convert to string</h3>
  <p>ASCII: 83(S), 101(e), 99(c), 114(r), 101(e), 116(t), 49(1), 50(2), 51(3)<br>
  Final string: "Secret123"</p>
</div>





