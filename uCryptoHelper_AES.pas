//unit uCryptoHelper_AES;
//
//interface
//
//uses
//  System.SysUtils, System.Classes, System.NetEncoding, Windows;
//
//{ Přenositelné šifrování pouze heslem (bez DPAPI)
//  - PBKDF2-HMAC-SHA256 z hesla + salt (výchozí 200k iterací)
//  - AES-256/CBC (CryptoAPI, import sy. klíče)
//  - IV + Salt + HMAC(SHA-256) pro integritu
//  - Kontejner se vrací jako Base64 string (bezpečné pro soubor/DB)
//
//  EncryptTextPBKDF2 -> vrací Base64 kontejner
//  DecryptTextPBKDF2 -> vrátí plaintext
//
//  Kompatibilita: Delphi 2009+ (Unicode). Pro starší bude nutné upravit System.* jednotky.
//}
//
//type
//  TPasswordCrypto = class
//  public
//    class function EncryptTextPBKDF2(const PlainText, Password: string;
//      Iterations: Integer = 200000): string;
//    class function DecryptTextPBKDF2(const ContainerBase64, Password: string): string;
//  end;
//
//implementation
//
//{ ===== WinAPI CryptoAPI deklarace (bez Winapi.WinCrypt) ===== }
//
//const
//  PROV_RSA_AES        = 24;
//  CALG_AES_256        = $00006610;
//  CALG_SHA_256        = $0000800C;
//
//  CRYPT_VERIFYCONTEXT = $F0000000;
//
//  KP_IV               = 1;
//  KP_MODE             = 4;
//  CRYPT_MODE_CBC      = 1;
//
//  HP_HASHVAL          = $0002;
//
//  PLAINTEXTKEYBLOB    = $8;
//  CUR_BLOB_VERSION    = 2;
//
//type
//  BYTE  = System.Byte;
//  PBYTE = ^BYTE;
//
//  HCRYPTPROV  = ULONG_PTR;  PHCRYPTPROV = ^HCRYPTPROV;
//  HCRYPTKEY   = ULONG_PTR;  PHCRYPTKEY  = ^HCRYPTKEY;
//  HCRYPTHASH  = ULONG_PTR;  PHCRYPTHASH = ^HCRYPTHASH;
//  ALG_ID      = ULONG;
//
//  BLOBHEADER = packed record
//    bType: BYTE;
//    bVersion: BYTE;
//    reserved: WORD;
//    aiKeyAlg: ALG_ID;
//  end;
//
//function CryptAcquireContext(phProv: PHCRYPTPROV; pszContainer, pszProvider: LPCWSTR;
//  dwProvType, dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll' name 'CryptAcquireContextW';
//function CryptCreateHash(hProv: HCRYPTPROV; Algid: ALG_ID; hKey: HCRYPTKEY;
//  dwFlags: DWORD; phHash: PHCRYPTHASH): BOOL; stdcall; external 'advapi32.dll';
//function CryptHashData(hHash: HCRYPTHASH; pbData: PBYTE; dwDataLen, dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';
//function CryptGetHashParam(hHash: HCRYPTHASH; dwParam: DWORD; pbData: PBYTE;
//  var pdwDataLen: DWORD; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';
//function CryptImportKey(hProv: HCRYPTPROV; pbData: PBYTE; dwDataLen: DWORD;
//  hPubKey: HCRYPTKEY; dwFlags: DWORD; phKey: PHCRYPTKEY): BOOL; stdcall; external 'advapi32.dll';
//function CryptEncrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; Final: BOOL;
//  dwFlags: DWORD; pbData: PBYTE; var pdwDataLen, dwBufLen: DWORD): BOOL; stdcall; external 'advapi32.dll';
//function CryptDecrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; Final: BOOL;
//  dwFlags: DWORD; pbData: PBYTE; var pdwDataLen: DWORD): BOOL; stdcall; external 'advapi32.dll';
//function CryptDestroyHash(hHash: HCRYPTHASH): BOOL; stdcall; external 'advapi32.dll';
//function CryptDestroyKey(hKey: HCRYPTKEY): BOOL; stdcall; external 'advapi32.dll';
//function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';
//function CryptGenRandom(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: PBYTE): BOOL; stdcall; external 'advapi32.dll';
//function CryptSetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; pbData: PBYTE; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';
//
//{ ===== Zeroize ===== }
//
//procedure SecureZero(p: Pointer; len: SIZE_T); inline;
//begin
//  if (p <> nil) and (len > 0) then
//    FillChar(p^, len, 0);
//end;
//
//procedure WipeBytes(var B: TBytes); inline;
//begin
//  if Length(B) > 0 then
//    SecureZero(@B[0], Length(B));
//  SetLength(B, 0);
//end;
//
//procedure WipeString(var S: string); inline;
//begin
//  if S <> '' then
//    SecureZero(PChar(S), Length(S) * SizeOf(Char));
//  S := '';
//end;
//
//{ ===== Byte helpers ===== }
//
//function Concat2(const A, B: TBytes): TBytes;
//begin
//  SetLength(Result, Length(A)+Length(B));
//  if Length(A)>0 then Move(A[0], Result[0], Length(A));
//  if Length(B)>0 then Move(B[0], Result[Length(A)], Length(B));
//end;
//
//function Concat3(const A, B, C: TBytes): TBytes;
//begin
//  Result := Concat2(Concat2(A,B), C);
//end;
//
//{ ===== Random ===== }
//
//function GenerateRandomBytes(Count: Integer): TBytes;
//var
//  Prov: HCRYPTPROV;
//begin
//  SetLength(Result, Count);
//  if Count = 0 then Exit;
//  if not CryptAcquireContext(@Prov, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
//    RaiseLastOSError;
//  try
//    if not CryptGenRandom(Prov, Count, PBYTE(Result)) then
//      RaiseLastOSError;
//  finally
//    CryptReleaseContext(Prov, 0);
//  end;
//end;
//
//{ ===== SHA-256 / HMAC-SHA256 ===== }
//
//function SHA256_Bytes(const Data: TBytes): TBytes;
//var
//  Prov: HCRYPTPROV;
//  Hash: HCRYPTHASH;
//  L: DWORD;
//begin
//  if not CryptAcquireContext(@Prov, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
//    RaiseLastOSError;
//  try
//    if not CryptCreateHash(Prov, CALG_SHA_256, 0, 0, @Hash) then
//      RaiseLastOSError;
//    try
//      if (Length(Data)>0) and (not CryptHashData(Hash, PBYTE(Data), Length(Data), 0)) then
//        RaiseLastOSError;
//      L := 32;
//      SetLength(Result, L);
//      if not CryptGetHashParam(Hash, HP_HASHVAL, PBYTE(Result), L, 0) then
//        RaiseLastOSError;
//      SetLength(Result, L);
//    finally
//      CryptDestroyHash(Hash);
//    end;
//  finally
//    CryptReleaseContext(Prov, 0);
//  end;
//end;
//
//function HMAC_SHA256(const Key, Data: TBytes): TBytes;
//const
//  BLOCK = 64;
//var
//  K, K0, Ipad, Opad, Inner, InnerHash, Outer: TBytes;
//  i: Integer;
//begin
//  if Length(Key) > BLOCK then
//    K := SHA256_Bytes(Key)
//  else
//    K := Copy(Key, 0, Length(Key));
//
//  SetLength(K0, BLOCK);
//  if Length(K)>0 then Move(K[0], K0[0], Length(K));
//  SetLength(Ipad, BLOCK);
//  SetLength(Opad, BLOCK);
//  for i := 0 to BLOCK-1 do
//  begin
//    Ipad[i] := K0[i] xor $36;
//    Opad[i] := K0[i] xor $5C;
//  end;
//
//  Inner     := Concat2(Ipad, Data);
//  InnerHash := SHA256_Bytes(Inner);
//  Outer     := Concat2(Opad, InnerHash);
//  Result    := SHA256_Bytes(Outer);
//
//  WipeBytes(K);
//  WipeBytes(K0);
//  WipeBytes(Ipad);
//  WipeBytes(Opad);
//  WipeBytes(Inner);
//  WipeBytes(InnerHash);
//  WipeBytes(Outer);
//end;
//
//{ ===== PBKDF2-HMAC-SHA256 ===== }
//
//function PBKDF2_HMAC_SHA256(const Password: string; const Salt: TBytes;
//  Iterations, DKLen: Integer): TBytes;
//var
//  PW: TBytes; // UTF-8 password
//  i, j, blocks, offset: Integer;
//  U, TBlock, SaltCounter: TBytes;
//  counter: DWORD;
//begin
//  if (Iterations <= 0) or (DKLen <= 0) then
//    raise Exception.Create('PBKDF2: neplatné parametry.');
//
//  PW := TEncoding.UTF8.GetBytes(Password); // PBKDF2 standardně s UTF-8
//  try
//    blocks := (DKLen + 31) div 32; // SHA-256 = 32 B
//    SetLength(Result, blocks * 32);
//    offset := 0;
//
//    for i := 1 to blocks do
//    begin
//      // Salt || INT_32_BE(i)
//      SetLength(SaltCounter, Length(Salt)+4);
//      if Length(Salt)>0 then Move(Salt[0], SaltCounter[0], Length(Salt));
//      counter := htonl(i); // big-endian
//      Move(counter, SaltCounter[Length(Salt)], 4);
//
//      // U1 = HMAC(PW, Salt||i)
//      U := HMAC_SHA256(PW, SaltCounter);
//      TBlock := Copy(U, 0, Length(U));
//
//      // U2..Uc
//      for j := 2 to Iterations do
//      begin
//        U := HMAC_SHA256(PW, U);
//        // T = T xor U
//        PInteger(@TBlock[0])^ := PInteger(@TBlock[0])^ xor PInteger(@U[0])^;
//        PInteger(@TBlock[4])^ := PInteger(@TBlock[4])^ xor PInteger(@U[4])^;
//        PInteger(@TBlock[8])^ := PInteger(@TBlock[8])^ xor PInteger(@U[8])^;
//        PInteger(@TBlock[12])^:= PInteger(@TBlock[12])^xor PInteger(@U[12])^;
//        PInteger(@TBlock[16])^:= PInteger(@TBlock[16])^xor PInteger(@U[16])^;
//        PInteger(@TBlock[20])^:= PInteger(@TBlock[20])^xor PInteger(@U[20])^;
//        PInteger(@TBlock[24])^:= PInteger(@TBlock[24])^xor PInteger(@U[24])^;
//        PInteger(@TBlock[28])^:= PInteger(@TBlock[28])^xor PInteger(@U[28])^;
//      end;
//
//      Move(TBlock[0], Result[offset], 32);
//      Inc(offset, 32);
//
//      WipeBytes(U);
//      WipeBytes(TBlock);
//      WipeBytes(SaltCounter);
//    end;
//
//    SetLength(Result, DKLen);
//  finally
//    WipeBytes(PW);
//  end;
//end;
//
//{ Pomocná htons/htonl pro big-endian counter v PBKDF2 }
//function Swap32(x: DWORD): DWORD; inline;
//begin
//  Result := ((x and $FF) shl 24) or ((x and $FF00) shl 8) or
//            ((x and $FF0000) shr 8) or ((x shr 24) and $FF);
//end;
//
//function htonl(x: DWORD): DWORD; inline;
//begin
//  Result := Swap32(x);
//end;
//
//{ ===== Import AES klíče z raw 32 bytů (PBKDF2) ===== }
//
//procedure ImportAes256Key(const RawKey32: TBytes; out Prov: HCRYPTPROV; out Key: HCRYPTKEY);
//var
//  hdr: BLOBHEADER;
//  blob: TBytes;
//  keyLen: DWORD;
//begin
//  if Length(RawKey32) <> 32 then
//    raise Exception.Create('AES-256 vyžaduje 32 bytový klíč.');
//
//  if not CryptAcquireContext(@Prov, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
//    RaiseLastOSError;
//
//  keyLen := 32;
//  SetLength(blob, SizeOf(BLOBHEADER) + SizeOf(DWORD) + keyLen);
//
//  hdr.bType    := PLAINTEXTKEYBLOB;
//  hdr.bVersion := CUR_BLOB_VERSION;
//  hdr.reserved := 0;
//  hdr.aiKeyAlg := CALG_AES_256;
//
//  Move(hdr, blob[0], SizeOf(BLOBHEADER));
//  Move(keyLen, blob[SizeOf(BLOBHEADER)], SizeOf(DWORD));
//  Move(RawKey32[0], blob[SizeOf(BLOBHEADER) + SizeOf(DWORD)], keyLen);
//
//  if not CryptImportKey(Prov, PBYTE(blob), Length(blob), 0, 0, @Key) then
//  begin
//    CryptReleaseContext(Prov, 0);
//    RaiseLastOSError;
//  end;
//
//  WipeBytes(blob);
//end;
//
//{ ===== Kontejner formát =====
//  Magic: 'PCSF' (Password Container Secure Format)
//  Version: 1
//  Layout (little-endian):
//    4B   Magic 'PCSF'
//    1B   Version = 1
//    1B   SaltLen (typ. 16)
//    1B   IVLen   (typ. 16)
//    4B   Iterations (DWORD)
//    4B   CipherLen (DWORD)
//    ..   Salt[SaltLen]
//    ..   IV[IVLen]
//    ..   Cipher[CipherLen]
//    32B  HMAC_SHA256(MacKey, Salt || IV || Iterations(LE) || Cipher)
//  Keys:
//    DK = PBKDF2-HMAC-SHA256(Password, Salt, Iter, 64)
//    EncKey = DK[0..31], MacKey = DK[32..63]
//}
//
//class function TPasswordCrypto.EncryptTextPBKDF2(const PlainText, Password: string;
//  Iterations: Integer): string;
//const
//  MAGIC: array[0..3] of AnsiChar = ('P','C','S','F');
//  VERSION: Byte = 1;
//  SALT_LEN = 16;
//  IV_LEN   = 16;
//var
//  Salt, IV, DK, EncKey, MacKey: TBytes;
//  Prov: HCRYPTPROV;
//  Key: HCRYPTKEY;
//  Mode: DWORD;
//  Plain, Cipher, Mix, Hmac: TBytes;
//  BufLen, BufCap: DWORD;
//  bSalt, bIV: Byte;
//  IterLE, CipherLen: DWORD;
//  MS: TMemoryStream;
//  Container: TBytes;
//begin
//  if (Password = '') then
//    raise Exception.Create('Heslo nesmí být prázdné.');
//
//  Salt := GenerateRandomBytes(SALT_LEN);
//  IV   := GenerateRandomBytes(IV_LEN);
//  DK   := PBKDF2_HMAC_SHA256(Password, Salt, Iterations, 64);
//  EncKey := Copy(DK, 0, 32);
//  MacKey := Copy(DK, 32, 32);
//
//  ImportAes256Key(EncKey, Prov, Key);
//  try
//    Mode := CRYPT_MODE_CBC;
//    if not CryptSetKeyParam(Key, KP_MODE, @Mode, 0) then RaiseLastOSError;
//    if not CryptSetKeyParam(Key, KP_IV, PBYTE(IV), 0) then RaiseLastOSError;
//
//    Plain := TEncoding.UTF8.GetBytes(PlainText);
//    Cipher := Copy(Plain, 0, Length(Plain));
//    BufLen := Length(Cipher);
//    BufCap := BufLen + 16;
//    SetLength(Cipher, BufCap);
//    if not CryptEncrypt(Key, 0, True, 0, PBYTE(Cipher), BufLen, BufCap) then
//      RaiseLastOSError;
//    SetLength(Cipher, BufLen);
//  finally
//    CryptDestroyKey(Key);
//    CryptReleaseContext(Prov, 0);
//    WipeBytes(Plain);
//  end;
//
//  // HMAC(Salt||IV||IterationsLE||Cipher)
//  IterLE := DWORD(Iterations);
//  Mix := Concat3(Salt, IV, TBytes(@IterLE)^); // pozor: takto nelze; uděláme korektně níže
//  // korektní sestavení Mix:
//  SetLength(Mix, Length(Salt)+Length(IV)+4+Length(Cipher));
//  if Length(Salt)>0 then Move(Salt[0], Mix[0], Length(Salt));
//  if Length(IV)>0 then Move(IV[0], Mix[Length(Salt)], Length(IV));
//  Move(IterLE, Mix[Length(Salt)+Length(IV)], 4);
//  if Length(Cipher)>0 then
//    Move(Cipher[0], Mix[Length(Salt)+Length(IV)+4], Length(Cipher));
//
//  Hmac := HMAC_SHA256(MacKey, Mix);
//
//  // Postav kontejner
//  bSalt := Length(Salt);
//  bIV   := Length(IV);
//  CipherLen := Length(Cipher);
//
//  MS := TMemoryStream.Create;
//  try
//    MS.WriteBuffer(MAGIC, SizeOf(MAGIC));
//    MS.WriteBuffer(VERSION, SizeOf(VERSION));
//    MS.WriteBuffer(bSalt, SizeOf(bSalt));
//    MS.WriteBuffer(bIV, SizeOf(bIV));
//    MS.WriteBuffer(Iterations, SizeOf(Iterations)); // LE
//    MS.WriteBuffer(CipherLen, SizeOf(CipherLen));
//    if bSalt>0 then MS.WriteBuffer(Salt[0], bSalt);
//    if bIV>0   then MS.WriteBuffer(IV[0], bIV);
//    if CipherLen>0 then MS.WriteBuffer(Cipher[0], CipherLen);
//    MS.WriteBuffer(Hmac[0], 32);
//
//    SetLength(Container, MS.Size);
//    MS.Position := 0;
//    if MS.Size>0 then
//      MS.ReadBuffer(Container[0], MS.Size);
//  finally
//    MS.Free;
//  end;
//
//  // Base64 out
//  Result := TNetEncoding.Base64.EncodeBytesToString(Container);
//
//  // wipe
//  WipeBytes(Salt); WipeBytes(IV); WipeBytes(DK);
//  WipeBytes(EncKey); WipeBytes(MacKey);
//  WipeBytes(Cipher); WipeBytes(Mix); WipeBytes(Hmac);
//  WipeBytes(Container);
//end;
//
//class function TPasswordCrypto.DecryptTextPBKDF2(const ContainerBase64, Password: string): string;
//const
//  MAGIC: array[0..3] of AnsiChar = ('P','C','S','F');
//var
//  Data: TBytes;
//  p: Integer;
//  MagicRead: array[0..3] of AnsiChar;
//  Version: Byte;
//  bSalt, bIV: Byte;
//  Iterations: DWORD;
//  CipherLen: DWORD;
//  Salt, IV, Cipher, HmacStored: TBytes;
//  DK, EncKey, MacKey, Mix, HmacCalc, OutBytes: TBytes;
//  Prov: HCRYPTPROV;
//  Key: HCRYPTKEY;
//  Mode: DWORD;
//  BufLen: DWORD;
//begin
//  if ContainerBase64 = '' then
//    raise Exception.Create('Kontejner je prázdný.');
//
//  Data := TNetEncoding.Base64.DecodeStringToBytes(ContainerBase64);
//  p := 0;
//
//  if Length(Data) < 4+1+1+1+4+4+32 then
//    raise Exception.Create('Poškozený kontejner.');
//
//  Move(Data[p], MagicRead[0], 4); Inc(p, 4);
//  if not CompareMem(@MagicRead[0], @MAGIC[0], 4) then
//    raise Exception.Create('Neznámý formát (MAGIC).');
//
//  Version := Data[p]; Inc(p, 1);
//  if Version <> 1 then
//    raise Exception.Create('Nepodporovaná verze.');
//
//  bSalt := Data[p]; Inc(p, 1);
//  bIV   := Data[p]; Inc(p, 1);
//
//  Move(Data[p], Iterations, 4); Inc(p, 4);
//  Move(Data[p], CipherLen, 4); Inc(p, 4);
//
//  if (bSalt=0) or (bIV=0) or (CipherLen=0) then
//    raise Exception.Create('Neplatné délky.');
//
//  if Cardinal(p) + bSalt + bIV + CipherLen + 32 > Cardinal(Length(Data)) then
//    raise Exception.Create('Poškozený kontejner (rozsahy).');
//
//  SetLength(Salt, bSalt);
//  SetLength(IV, bIV);
//  SetLength(Cipher, CipherLen);
//  SetLength(HmacStored, 32);
//
//  if bSalt>0 then begin Move(Data[p], Salt[0], bSalt); Inc(p, bSalt); end;
//  if bIV>0   then begin Move(Data[p], IV[0], bIV); Inc(p, bIV); end;
//  if CipherLen>0 then begin Move(Data[p], Cipher[0], CipherLen); Inc(p, CipherLen); end;
//  Move(Data[p], HmacStored[0], 32); Inc(p, 32);
//
//  // KDF
//  DK := PBKDF2_HMAC_SHA256(Password, Salt, Integer(Iterations), 64);
//  EncKey := Copy(DK, 0, 32);
//  MacKey := Copy(DK, 32, 32);
//
//  // Ověřit HMAC
//  SetLength(Mix, Length(Salt)+Length(IV)+4+Length(Cipher));
//  if Length(Salt)>0 then Move(Salt[0], Mix[0], Length(Salt));
//  if Length(IV)>0 then Move(IV[0], Mix[Length(Salt)], Length(IV));
//  Move(Iterations, Mix[Length(Salt)+Length(IV)], 4);
//  if Length(Cipher)>0 then
//    Move(Cipher[0], Mix[Length(Salt)+Length(IV)+4], Length(Cipher));
//
//  HmacCalc := HMAC_SHA256(MacKey, Mix);
//  if (Length(HmacCalc)<>32) or (not CompareMem(@HmacCalc[0], @HmacStored[0], 32)) then
//    raise Exception.Create('Autentizace selhala: neplatný HMAC nebo heslo.');
//
//  // Decrypt
//  ImportAes256Key(EncKey, Prov, Key);
//  try
//    Mode := CRYPT_MODE_CBC;
//    if not CryptSetKeyParam(Key, KP_MODE, @Mode, 0) then RaiseLastOSError;
//    if not CryptSetKeyParam(Key, KP_IV, PBYTE(IV), 0) then RaiseLastOSError;
//
//    BufLen := Length(Cipher);
//    if not CryptDecrypt(Key, 0, True, 0, PBYTE(Cipher), BufLen) then
//      RaiseLastOSError;
//
//    SetLength(Cipher, BufLen);
//    OutBytes := Copy(Cipher, 0, Length(Cipher));
//    Result := TEncoding.UTF8.GetString(OutBytes);
//  finally
//    CryptDestroyKey(Key);
//    CryptReleaseContext(Prov, 0);
//    WipeBytes(OutBytes);
//  end;
//
//  // wipe
//  WipeBytes(Data);
//  WipeBytes(Salt); WipeBytes(IV); WipeBytes(Cipher); WipeBytes(HmacStored);
//  WipeBytes(DK); WipeBytes(EncKey); WipeBytes(MacKey);
//  WipeBytes(Mix); WipeBytes(HmacCalc);
//end;
//
//end.
//
//
//
//
//
//
//
//


unit uCryptoHelper_AES;

interface

uses
  System.SysUtils, System.Classes, System.NetEncoding, Windows;// Winapi.WinCrypt;

type
  TEncryptionHelper = class
  private
    class function GetHashSHA256(const AData: string): TBytes;
  public
    class function EncryptText(const APlainText, APassword: string): string;
    class function DecryptText(const AEncryptedBase64, APassword: string): string;
  end;

  // Nahrazuje potřebu jednotky Winapi.WinCrypt
const
  PROV_RSA_AES = 24;
  CALG_AES_256 = $00006610;
  CALG_SHA_256 = $0000800c;
  HP_HASHVAL = $0002;
  CRYPT_EXPORTABLE = $00000001;
  CRYPT_VERIFYCONTEXT = $F0000000;

type
  BYTE        = System.Byte;
  PBYTE       = ^BYTE;

  HCRYPTPROV  = ULONG_PTR;
  PHCRYPTPROV = ^HCRYPTPROV;

  HCRYPTKEY   = ULONG_PTR;
  PHCRYPTKEY  = ^HCRYPTKEY;

  HCRYPTHASH  = ULONG_PTR;
  PHCRYPTHASH = ^HCRYPTHASH;

  ALG_ID      = ULONG;

  // CryptoAPI funkce – ruční deklarace
  function CryptAcquireContext(phProv: PHCRYPTPROV; pszContainer, pszProvider: LPCWSTR;
    dwProvType, dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll' name 'CryptAcquireContextW';

  function CryptCreateHash(hProv: HCRYPTPROV; Algid: ALG_ID; hKey: HCRYPTKEY;
    dwFlags: DWORD; phHash: PHCRYPTHASH): BOOL; stdcall; external 'advapi32.dll';

  function CryptHashData(hHash: HCRYPTHASH; pbData: PBYTE; dwDataLen: DWORD;
    dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';

  function CryptGetHashParam(hHash: HCRYPTHASH; dwParam: DWORD; pbData: PBYTE;
    var pdwDataLen: DWORD; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';

  function CryptDeriveKey(hProv: HCRYPTPROV; Algid: ALG_ID; hBaseData: HCRYPTHASH;
    dwFlags: DWORD; phKey: PHCRYPTKEY): BOOL; stdcall; external 'advapi32.dll';

  function CryptEncrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; Final: BOOL;
    dwFlags: DWORD; pbData: PBYTE; var pdwDataLen: DWORD; dwBufLen: DWORD): BOOL; stdcall; external 'advapi32.dll';

  function CryptDecrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; Final: BOOL;
    dwFlags: DWORD; pbData: PBYTE; var pdwDataLen: DWORD): BOOL; stdcall; external 'advapi32.dll';

  function CryptDestroyHash(hHash: HCRYPTHASH): BOOL; stdcall; external 'advapi32.dll';
  function CryptDestroyKey(hKey: HCRYPTKEY): BOOL; stdcall; external 'advapi32.dll';
  function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';

implementation

class function TEncryptionHelper.GetHashSHA256(const AData: string): TBytes;
var
  HashProv: HCRYPTPROV;
  Hash: HCRYPTHASH;
  Buffer: array[0..31] of Byte;
  Data: TBytes;
  HashSize: DWORD;
begin
  Result := nil;

  if not CryptAcquireContext(@HashProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    raise Exception.Create('Cryptographic context not acquired');

  if not CryptCreateHash(HashProv, CALG_SHA_256, 0, 0, @Hash) then
  begin
    CryptReleaseContext(HashProv, 0);
    raise Exception.Create('Failed to create hash');
  end;

  Data := TEncoding.UTF8.GetBytes(AData);
  if not CryptHashData(Hash, @Data[0], Length(Data), 0) then
  begin
    CryptDestroyHash(Hash);
    CryptReleaseContext(HashProv, 0);
    raise Exception.Create('Failed to hash data');
  end;

  HashSize := SizeOf(Buffer);
  if not CryptGetHashParam(Hash, HP_HASHVAL, @Buffer[0], HashSize, 0) then
  begin
    CryptDestroyHash(Hash);
    CryptReleaseContext(HashProv, 0);
    raise Exception.Create('Failed to get hash value');
  end;

  SetLength(Result, HashSize);
  Move(Buffer, Result[0], HashSize);

  CryptDestroyHash(Hash);
  CryptReleaseContext(HashProv, 0);
end;

class function TEncryptionHelper.EncryptText(const APlainText, APassword: string): string;
var
  Prov: HCRYPTPROV;
  Hash: HCRYPTHASH;
  Key: HCRYPTKEY;
  Buffer: TBytes;
  BufLen: DWORD;
begin
  Result := '';

  // 🛡️ Kontrola vstupního textu
  if APlainText.Trim = '' then
    raise Exception.Create('Šifrovaný text nesmí být prázdný.');

  // Získání bajtů z textu
  Buffer := TEncoding.UTF8.GetBytes(APlainText);
  BufLen := Length(Buffer);

  // Přidání prostoru pro padding (až 16 bajtů pro AES)
  SetLength(Buffer, BufLen + 16);

  // 🔐 Inicializace CryptoAPI
  if not CryptAcquireContext(@Prov, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    RaiseLastOSError;

  try
    if not CryptCreateHash(Prov, CALG_SHA_256, 0, 0, @Hash) then
      RaiseLastOSError;

    try
      if not CryptHashData(Hash, @APassword[1], Length(APassword) * SizeOf(Char), 0) then
        RaiseLastOSError;

      if not CryptDeriveKey(Prov, CALG_AES_256, Hash, CRYPT_EXPORTABLE, @Key) then
        RaiseLastOSError;

      try
        if not CryptEncrypt(Key, 0, True, 0, PBYTE(Buffer), BufLen, Length(Buffer)) then
          RaiseLastOSError;

        SetLength(Buffer, BufLen);
        Result := TNetEncoding.Base64.EncodeBytesToString(Buffer);

      finally
        CryptDestroyKey(Key);
      end;

    finally
      CryptDestroyHash(Hash);
    end;

  finally
    CryptReleaseContext(Prov, 0);
  end;
end;


class function TEncryptionHelper.DecryptText(const AEncryptedBase64, APassword: string): string;
var
  Prov: HCRYPTPROV;
  Hash: HCRYPTHASH;
  Key: HCRYPTKEY;
  Buffer: TBytes;
  BufLen: DWORD;
begin
  Result := '';

  // 🛡️ Ověření vstupu
  if AEncryptedBase64.Trim = '' then
    raise Exception.Create('Vstupní šifrovaný řetězec je prázdný.');

  try
    // Dekódování Base64
    Buffer := TNetEncoding.Base64.DecodeStringToBytes(AEncryptedBase64);
  except
    raise Exception.Create('Zašifrovaný řetězec není validní Base64.');
  end;

  // Kontrola dat
  if Length(Buffer) = 0 then
    raise Exception.Create('Zašifrovaný buffer je prázdný.');

  BufLen := Length(Buffer);

  // CryptoAPI inicializace
  if not CryptAcquireContext(@Prov, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    RaiseLastOSError;

  try
    if not CryptCreateHash(Prov, CALG_SHA_256, 0, 0, @Hash) then
      RaiseLastOSError;

    try
      if not CryptHashData(Hash, @APassword[1], Length(APassword) * SizeOf(Char), 0) then
        RaiseLastOSError;

      if not CryptDeriveKey(Prov, CALG_AES_256, Hash, CRYPT_EXPORTABLE, @Key) then
        RaiseLastOSError;

      try
        if not CryptDecrypt(Key, 0, True, 0, PBYTE(Buffer), BufLen) then
          RaiseLastOSError;

        SetLength(Buffer, BufLen);
        Result := TEncoding.UTF8.GetString(Buffer);

      finally
        CryptDestroyKey(Key);
      end;

    finally
      CryptDestroyHash(Hash);
    end;

  finally
    CryptReleaseContext(Prov, 0);
  end;
end;

end.

//✔️ Používáš správné CryptoAPI funkce
//✔️ Vše je přehledně odděleno v TEncryptionHelper
//✔️ Klíč se odvozuje přes SHA-256 (CryptHashData)
//✔️ Zpracování šifrování/dešifrování je věcně správné
//✔️ Base64 je správně zakódován/převeden přes TNetEncoding
