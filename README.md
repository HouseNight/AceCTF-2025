![image](https://hackmd.io/_uploads/BJJ-z4yiye.png)

Nick name: n0g_1ong

- [ ] * Forensic:
- Broken Secrets
- Virtual Hard Disk
- Another Reading between the Lines?
- Deep Memory Dive
- [ ] * Cryptography:
    - Super Secure Encryption
- Custom Encoding Scheme
- [ ] * Steganography:
- Cryptic Pixels

    
    
        Broken Secrets
        
`You’ve found a suspicious file, but it seems broken and cannot be opened normally. Your goal is to uncover its secrets.`

After unzip the file you will get "_ folder "

you will see the "not_so_suspicious_file" in .\word\media

use hxd and we realize that the file signature is not right so i write a script to slove it:
```
# Replace the first 4 bytes with a standard PNG signature
corrected_signature = b"\x89PNG"
modified_content = corrected_signature + file_content[4:]

# save a new file
modified_file_path = "/mnt/data/fixed_not_suspicious.png"
with open(modified_file_path, "wb") as f:
    f.write(modified_content)

modified_file_path
```
and we get a picture

![fixed_not_suspicious](https://hackmd.io/_uploads/HkmqVE1oyx.png)

Flag: ACECTF{h34d3r_15_k3y}


    Virtual Hard Disk
    
```
One of the first things I learnt when I started learning to hack was linux. It was fun until I hit a ceiling of understanding about the differences in Operating Systems, what's a Shell, Kernel, etc.

But once I got better I started developing a liking towards the terminal and how the Linux operating system is better than say Windows, or worse in some cases. How none of them is superior, nor the other inferior. We shall find out with this challenge.

Be careful, a lot of fake galfs around.
```
so first i strings the file and get a lots of fake flag and it not right

so i use autospy and get the flag:

CTCHHW{7t3_h1hw3p3sq3_s37i33r_a0l_4li_a3}

key: cryforme

use vigenere cipher, get flag: 
ACECTF{7h3_d1ff3r3nc3_b37w33n_y0u_4nd_m3}


    Another Reading between the Lines?

```
Question: Is this another one of those hidden in plain sight typical normie challenges?
Answer: No.

This challenge is very simple, here you have a file named hidden and all you need to do is get the flag. My focus for this year's CTF is not just the beginning but also ending on a high note, I won't rely on overused "read between the line" challenges and would rather have you guys do some research.
```

we will get the blank file with nothing space or special character 
after finding some solution i get the video solve this similar challenge on youtube

and i use hxd to watch the hex of the file, first i use notepad++ to check, use end of line view

and i see some LF, CRLF a lot after thinking i try to set LF = 0, CRLF = 1

i edit it in Hxd by 0D 0A = 1, 0A = 0, and we get the binary:

"010000010100001101000101010000110101010001000110011110110110111000110000010111110111001000110011001101000110010000110001011011100011011001011111011000100110010100110111011101110011001100110011011011100101111100110111011010000011001101011111011011000011000101101110001100110011010101111101"

decode it and we get flag:

ACECTF{n0_r34d1n6_be7w33n_7h3_l1n35}


    Deep Memory Dive


> A gamer was experiencing severe lag while playing. They decided to disable unnecessary startup applications to free up system resources. However, after investigating the system, they noticed an unusual entry in the Startup registry.
> 
> The flag is divided in different parts. Investigate the dump and gather all the flags.


we get the dump file

first i use notepad++ and it take a minute to read it, and i find the strings: ACECTF

and i get:
![image](https://hackmd.io/_uploads/SyXNaVki1l.png)
some part of flag:

after that i use Volatility to find more flag
and i get this
![image](https://hackmd.io/_uploads/H1CE0Vyoke.png)

so go back to notepad++ and find string last_part

and yes!! Flag: 
ACECTF{3xplor1n6_th3_c0nc3al3d_r1ddl3s}

    Super Secure Encryption
    
> I'm doing a big favour with this one... I'm handing out my super secure functionality to the outer world to stumble upon & explore. Though, I still remember one of my colleagues once saying that nothing in this world is secure nowadays but my script right here stands on the contrary. I'll give you the access to my arsenal and see if you can prove me wrong.`

i get that AES and i don't know how solve so i use chatgpt and this solution just use xor so i know just xor the encrypted_msg_hex vs plaintext i will get the key.

and i write a script:

```
from binascii import unhexlify

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Ciphertexts from your output
encrypted_msg_hex = "d71f4a2fd1f9362c21ad33c7735251d0a671185a1b90ecba27713d350611eb8179ec67ca7052aa8bad60466b83041e6c02dbfee738c2a3"
encrypted_flag_hex = "c234661fa5d63e627bef28823d052e95f65d59491580edfa1927364a5017be9445fa39986859a3"

# First plain text as we know
plaintext = b'This is just a test message and can totally be ignored.'

# convert hex to bytes
encrypted_msg = unhexlify(encrypted_msg_hex)
encrypted_flag = unhexlify(encrypted_flag_hex)

# find keystream
keystream = xor_bytes(encrypted_msg, plaintext)

# decode flag
flag = xor_bytes(encrypted_flag, keystream)

print("Flag:", flag.decode(errors='ignore'))


# Flag: ACECTF{n07h1n6_15_53cur3_1n_7h15_w0rld}

```

    Custom Encoding Scheme

> Cryptography
I wanted to create a custom encoding for a crypto challenge but turns out, I didn't have anough time on my hands. So, what I did here is - Well instead of explaining it to you why don't I give you the script?

i write a script:

```
# Base64 
t1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Known plaintext (chuỗi gốc) – phải khớp với chuỗi đã dùng trong quá trình mã hóa
plaintext = "I TOLD YOU THAT BASE64 DECODING IS NO GOOD"

# Danh sách các dòng output (42 dòng, mỗi dòng 2 ký tự) từ hàm e1
encoded_lines = [
    "SU", "IB", "VE", "Tz", "TE", "RF", "IE", "WT", "T1", "VU",
    "IE", "VG", "SH", "Qb", "VD", "IH", "Qm", "QY", "Uz", "RU",
    "Nj", "NH", "IF", "RP", "RX", "Q3", "Tz", "RE", "ST", "Tl",
    "R1", "IP", "SW", "Uz", "ID", "Tg", "Tz", "IA", "R2", "T8",
    "T3", "RN"
]

# Hàm chuyển 1 ký tự thành chuỗi nhị phân 8-bit
def char_to_bin(c):
    return f"{ord(c):08b}"

# Hàm trích xuất chuỗi b (gồm 42 nhóm 4 bit) từ known plaintext và output mã hóa
def extract_b(plaintext, encoded_lines):
    if len(plaintext) < 42:
        raise ValueError("Plaintext phải có ít nhất 42 ký tự!")
    b_chunks = []
    
    for i in range(42):
        y = plaintext[i]
        z = char_to_bin(y)         # z is an 8-bit binary code
        a = z[:6]                  # 6 bits first
        suffix = z[6:]             # 2 last bit
        
        # Change the output
        r = encoded_lines[i]
        # The first part of the output (r[0]) is created from a
        e = t1.index(r[0])
       # Check if there is a match
        if a != f"{e:06b}":
            raise ValueError(f"Mismatch ở vị trí {i}: a = {a}, e = {e:06b}")
        
        # The second part of the output (r[1]) is created from d = suffix + b_i
        g = t1.index(r[1])
        # Ta có: int(suffix + b_i, 2) = g, with a 2-bit suffix.
        # Then: b_i = g - (int(suffix,2) << 4)
        unknown_val = g - (int(suffix, 2) << 4)
        if unknown_val < 0 or unknown_val > 15:
            raise ValueError(f"Giá trị không hợp lệ ở vị trí {i}: unknown_val = {unknown_val}")
       # Convert unknown_val to a 4-bit string
        b_i = f"{unknown_val:04b}"
        b_chunks.append(b_i)
    
    # Convert all 4-bit groups to string b (length 42*4 = 168 bits)
    return "".join(b_chunks)

b_extracted = extract_b(plaintext, encoded_lines)
print("Extracted b string:")
print(b_extracted)


```
we get the binary: 
'010000010100001101000101010000110101010001000110011110110011011101101000001101000011011101011111011101110011010000110101010111110110001100110000001100000110110001111101
'
decode it 

Flag: ACECTF{7h47_w45_c00l}