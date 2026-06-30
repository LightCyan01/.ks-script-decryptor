# Karigurashi Ren'ai -`.ks` script decryptor

Decrypts the encrypted Kirikiri/KAG scenario scripts mainly used for Karigurashi
Ren'ai (NekoNyan) but can work on other asa project games ex: koikari, renai royale, etc.

## The cipher

| Property | Value |
|---|---|
| Algorithm | whole-file **repeating-key XOR** |
| Key length | **31 bytes** (= 2⁵−1) |
| Key scope | **one key per file** - `Data.xp3/scenario/main/en_US/0_0408.ks` and `Adult.xp3/en_US/scenario/0_0408.ks` base and adult patch use different keys |
| Plaintext | **UTF-8** KAG script (`[tag …]`, `@command`, `*label`, dialogue) |
| Marker | none - no BOM, no Kirikiri `FE FE` header; the whole file is XORed |

How it was identified: autocorrelation of the ciphertext spikes at shift 31 and
62, and `cipher(Data) ⊕ cipher(Adult)` for base and adult is cleanly
periodic-31 and both the signature of a 31-byte repeating XOR.


## Usage

```bash
# one file -> stdout
python3 decrypt_ks.py (Folder)/0_0408.ks

# one file -> output file
python3 decrypt_ks.py (Folder)/0_0408.ks out.ks

# a whole folder, recursive, in parallel
python3 decrypt_ks.py --dir Data --out (Folder)/Data
python3 decrypt_ks.py --dir Adult --out (Folder)/Adult -j 8
# -j is the number of parallel worker processes.

# apply a known 31-byte key instead of cracking (hex, 62 chars)
python3 decrypt_ks.py --key d6ec1b2e...5c (Folder)/0_0408.ks
```

You must use [GARbro](https://github.com/crskycode/GARbro) and extract the .ks files to a folder

## Output columns (`--dir`)

```
0_0408.ks   utf8=True text=1.0 kag=2463
```
* `utf8`  - decrypted bytes are valid UTF-8
* `text`  - fraction of bytes that are printable ASCII / UTF-8 (1.0 = clean)
* `kag`   - count of KAG tokens (`[ ] @ * text= vo= [<<] [>>]`)

Anything with `utf8=True` and `text>0.97` is a confident, correct decryption;
low-confidence rows are flagged.

## Decrypted format

Standard KAG3. Example:
```
@SC_StartProcess bg=bg30a bgm=bgm7
*Start
[杏 vo=vo2_0001 text="???"]
[>>]Hey, do you remember Takkun?[<<][c]
```
`@…` engine commands · `*…` labels/jump targets · `[…]` tags (character name +
`vo=` voice + on-screen `text=`) · `[>>] … [<<]` dialogue body · `[c]` click-wait.

## Sources
- GARbro CryptAlgorithms.cs  
  https://github.com/morkt/GARbro/blob/master/ArcFormats/KiriKiri/CryptAlgorithms.cs
  
- KirikiriTools  
  https://github.com/arcusmaximus/KirikiriTools
  
- Kirikiroid2 XOR-key write-up  
  https://github.com/zeas2/Kirikiroid2_patch/issues/31

