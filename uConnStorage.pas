{
 - Účel: bezpečné uložení connection stringů do souboru .sec.
 - Technika: AES-256/CBC + salt + IV + HMAC-SHA256, formát souboru, self-wipe bufferů.
 - API:
     - SaveEncryptedConnectStringToDat_HMAC(ConnStr, Password, AppName, FileName)
     - LoadEncryptedConnectStringFromDat_HMAC(Password, AppName, FileName)
     - (případně ...ToFile_HMAC/FromFile_HMAC(Password, FullPath) pro UNC/SMB)
 - Použití: vezmeš master heslo (z DPAPI nebo ručně zadané), uložíš/načteš .sec.
 - Pozn.: Reverzibilní—musí umět dešifrovat zpět.
}

unit uConnStorage;

interface

uses
  System.SysUtils, System.Classes, System.IOUtils, Windows, System.NetEncoding;

{ Vrátí plnou cestu %APPDATA%\AppName\FileName a zajistí existenci složky }
function GetConnFilePath(const AppName,
                               FileName: string): string;

{ Uloží zašifrovaný connection string (.sec) do %APPDATA%\AppName\FileName
  Šifrování: AES-256/CBC + Salt + IV + HMAC-SHA256 (autentizace)
  Password je master heslo v plaintextu (např. z DPAPI helperu). }
procedure SaveEncryptedConnectStringToDat_HMAC(const ConnStr,
                                                     Password,
                                                     AppName,
                                                     FileName: string);

{ Načte a ověří .sec ze %APPDATA%\AppName\FileName a vrátí plaintext ConnectString.
  Při chybě HMAC/hesla/poškození vyhodí výjimku. }
function LoadEncryptedConnectStringFromDat_HMAC(const Password,
                                                      AppName,
                                                      FileName: string): string;

{ Uloží .sec do libovolné cesty (např. \\server\share\erp.sec)}
procedure SaveEncryptedConnectStringToFile_HMAC(const ConnStr,
                                                      Password,
                                                      FullPath: string);

{ Načte .sec z libovolné cesty}
function LoadEncryptedConnectStringFromFile_HMAC(const Password,
                                                       FullPath: string): string;




{ Uloží šifrovaný ConnectString do Base64 textu (pro DB) }
function EncryptConnectStringToBase64_HMAC(const ConnStr, Password: string): string;

{ Načte (dešifruje) ConnectString z Base64 textu }
function DecryptConnectStringFromBase64_HMAC(const Password, Base64Blob: string): string;

{ Nevyhazující varianty (vrací False a naplní Err zprávu) }
function TryEncryptConnectStringToBase64_HMAC(const ConnStr, Password: string; out Base64Blob, Err: string): Boolean;
function TryDecryptConnectStringFromBase64_HMAC(const Password, Base64Blob: string; out ConnStr, Err: string): Boolean;


implementation

{ =============== WinAPI / CryptoAPI deklarace =============== }

const
  PROV_RSA_AES        = 24;
  CALG_AES_256        = $00006610;
  CALG_SHA_256        = $0000800C;

  CRYPT_VERIFYCONTEXT = $F0000000;
  CRYPT_EXPORTABLE    = $00000001;

  KP_IV               = 1;
  KP_MODE             = 4;
  CRYPT_MODE_CBC      = 1;

  HP_HASHVAL          = $0002;

type
  BYTE  = System.Byte;
  PBYTE = ^BYTE;

  HCRYPTPROV  = ULONG_PTR;  PHCRYPTPROV = ^HCRYPTPROV;
  HCRYPTKEY   = ULONG_PTR;  PHCRYPTKEY  = ^HCRYPTKEY;
  HCRYPTHASH  = ULONG_PTR;  PHCRYPTHASH = ^HCRYPTHASH;
  ALG_ID      = ULONG;

function CryptAcquireContext(phProv: PHCRYPTPROV; pszContainer, pszProvider: LPCWSTR;
  dwProvType, dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll' name 'CryptAcquireContextW';
function CryptCreateHash(hProv: HCRYPTPROV; Algid: ALG_ID; hKey: HCRYPTKEY;
  dwFlags: DWORD; phHash: PHCRYPTHASH): BOOL; stdcall; external 'advapi32.dll';
function CryptHashData(hHash: HCRYPTHASH; pbData: PBYTE; dwDataLen, dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';
function CryptGetHashParam(hHash: HCRYPTHASH; dwParam: DWORD; pbData: PBYTE;
  var pdwDataLen: DWORD; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';
function CryptDeriveKey(hProv: HCRYPTPROV; Algid: ALG_ID; hBaseData: HCRYPTHASH;
  dwFlags: DWORD; phKey: PHCRYPTKEY): BOOL; stdcall; external 'advapi32.dll';
function CryptEncrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; Final: BOOL;
  dwFlags: DWORD; pbData: PBYTE; var pdwDataLen, dwBufLen: DWORD): BOOL; stdcall; external 'advapi32.dll';
function CryptDecrypt(hKey: HCRYPTKEY; hHash: HCRYPTHASH; Final: BOOL;
  dwFlags: DWORD; pbData: PBYTE; var pdwDataLen: DWORD): BOOL; stdcall; external 'advapi32.dll';
function CryptDestroyHash(hHash: HCRYPTHASH): BOOL; stdcall; external 'advapi32.dll';
function CryptDestroyKey(hKey: HCRYPTKEY): BOOL; stdcall; external 'advapi32.dll';
function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';
function CryptGenRandom(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: PBYTE): BOOL; stdcall; external 'advapi32.dll';
function CryptSetKeyParam(hKey: HCRYPTKEY; dwParam: DWORD; pbData: PBYTE; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';

{ ================== Utility: zeroize (bez externals) ================== }

procedure SecureZero(p: Pointer; len: SIZE_T); inline;
begin
  if (p <> nil) and (len > 0) then
    FillChar(p^, len, 0);
end;

procedure WipeBytes(var B: TBytes); inline;
begin
  if Length(B) > 0 then
    SecureZero(@B[0], Length(B));
  SetLength(B, 0);
end;

procedure WipeString(var S: string); inline;
begin
  if S <> '' then
    SecureZero(PChar(S), Length(S) * SizeOf(Char));
  S := '';
end;

{ ================== Byte helpers ================== }

function Concat2(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A)+Length(B));
  if Length(A)>0 then Move(A[0], Result[0], Length(A));
  if Length(B)>0 then Move(B[0], Result[Length(A)], Length(B));
end;

function Concat3(const A, B, C: TBytes): TBytes;
begin
  Result := Concat2(Concat2(A,B), C);
end;

{ ================== Cesty ================== }

function GetConnFilePath(const AppName, FileName: string): string;
var
  base, dir: string;
begin
  base := GetEnvironmentVariable('APPDATA');
  if base = '' then
    base := TPath.GetHomePath; // fallback
  dir := TPath.Combine(base, AppName);
  ForceDirectories(dir);
  Result := TPath.Combine(dir, FileName);
end;

{ ================== Krypto utility ================== }

function GenerateRandomBytes(Count: Integer): TBytes;
var
  Prov: HCRYPTPROV;
begin
  SetLength(Result, Count);
  if Count = 0 then Exit;
  if not CryptAcquireContext(@Prov, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    RaiseLastOSError;
  try
    if not CryptGenRandom(Prov, Count, PBYTE(Result)) then
      RaiseLastOSError;
  finally
    CryptReleaseContext(Prov, 0);
  end;
end;

function SHA256_Bytes(const Data: TBytes): TBytes;
var
  Prov: HCRYPTPROV;
  Hash: HCRYPTHASH;
  L: DWORD;
begin
  if not CryptAcquireContext(@Prov, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    RaiseLastOSError;
  try
    if not CryptCreateHash(Prov, CALG_SHA_256, 0, 0, @Hash) then
      RaiseLastOSError;
    try
      if (Length(Data)>0) and (not CryptHashData(Hash, PBYTE(Data), Length(Data), 0)) then
        RaiseLastOSError;
      L := 32;
      SetLength(Result, L);
      if not CryptGetHashParam(Hash, HP_HASHVAL, PBYTE(Result), L, 0) then
        RaiseLastOSError;
      SetLength(Result, L);
    finally
      CryptDestroyHash(Hash);
    end;
  finally
    CryptReleaseContext(Prov, 0);
  end;
end;

function HMAC_SHA256(const Key, Data: TBytes): TBytes;
const
  BLOCK = 64;
var
  K, K0, Ipad, Opad, Inner, InnerHash, Outer: TBytes;
  i: Integer;
begin
  if Length(Key) > BLOCK then
    K := SHA256_Bytes(Key)
  else
    K := Copy(Key, 0, Length(Key));

  SetLength(K0, BLOCK);
  if Length(K)>0 then Move(K[0], K0[0], Length(K));
  SetLength(Ipad, BLOCK);
  SetLength(Opad, BLOCK);
  for i := 0 to BLOCK-1 do
  begin
    Ipad[i] := K0[i] xor $36;
    Opad[i] := K0[i] xor $5C;
  end;

  Inner     := Concat2(Ipad, Data);
  InnerHash := SHA256_Bytes(Inner);
  Outer     := Concat2(Opad, InnerHash);
  Result    := SHA256_Bytes(Outer);

  WipeBytes(K);
  WipeBytes(K0);
  WipeBytes(Ipad);
  WipeBytes(Opad);
  WipeBytes(Inner);
  WipeBytes(InnerHash);
  WipeBytes(Outer);
end;

{ MAC klíč = SHA256( UTF-16LE(Password) || Salt || 'MAC' ) }
function DeriveMacKey(const Password: string; const Salt: TBytes): TBytes;
var
  pw, labelMac, mix: TBytes;
begin
  pw       := TEncoding.Unicode.GetBytes(Password);
  labelMac := TEncoding.ASCII.GetBytes('MAC');
  mix      := Concat3(pw, Salt, labelMac);
  Result   := SHA256_Bytes(mix);

  WipeBytes(pw);
  WipeBytes(labelMac);
  WipeBytes(mix);
end;

{ AES-256 klíč přes SHA256(Password||Salt) → CryptDeriveKey(AES-256) }
procedure DeriveAes256Key(const Password: string; const Salt: TBytes;
  out Prov: HCRYPTPROV; out Key: HCRYPTKEY);
var
  Hash: HCRYPTHASH;
begin
  if not CryptAcquireContext(@Prov, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
    RaiseLastOSError;

  if not CryptCreateHash(Prov, CALG_SHA_256, 0, 0, @Hash) then
  begin
    CryptReleaseContext(Prov, 0);
    RaiseLastOSError;
  end;

  try
    if (Length(Password) > 0) and
       (not CryptHashData(Hash, @Password[1], Length(Password)*SizeOf(Char), 0)) then
      RaiseLastOSError;

    if (Length(Salt) > 0) and
       (not CryptHashData(Hash, PBYTE(Salt), Length(Salt), 0)) then
      RaiseLastOSError;

    if not CryptDeriveKey(Prov, CALG_AES_256, Hash, CRYPT_EXPORTABLE, @Key) then
      RaiseLastOSError;
  finally
    CryptDestroyHash(Hash);
  end;
end;

{ ================== Save (.sec) ================== }

procedure SaveEncryptedConnectStringToDat_HMAC(
  const ConnStr, Password, AppName, FileName: string);
const
  MAGIC: array[0..3] of AnsiChar = ('A','C','S','F');
  VERSION: Byte = 2;
  SALT_LEN = 16;
  IV_LEN   = 16;
var
  Prov: HCRYPTPROV;
  Key: HCRYPTKEY;
  Salt, IV, Plain, Cipher, MacKey, Mix, Hmac: TBytes;
  BufLen, BufCap: DWORD;
  Mode: DWORD;
  MS: TMemoryStream;
  bSaltLen, bIVLen: Byte;
  dwCipher: DWORD;
  FullPath: string;
begin
  if ConnStr = '' then
    raise Exception.Create('ConnectString je prázdný.');

  FullPath := GetConnFilePath(AppName, FileName);

  // random salt/IV
  Salt := GenerateRandomBytes(SALT_LEN);
  IV   := GenerateRandomBytes(IV_LEN);

  // derive key + set CBC + IV
  DeriveAes256Key(Password, Salt, Prov, Key);
  try
    Mode := CRYPT_MODE_CBC;
    if not CryptSetKeyParam(Key, KP_MODE, @Mode, 0) then RaiseLastOSError;
    if not CryptSetKeyParam(Key, KP_IV, PBYTE(IV), 0) then RaiseLastOSError;

    // encrypt
    Plain := TEncoding.UTF8.GetBytes(ConnStr);
    Cipher := Copy(Plain, 0, Length(Plain));
    BufLen := Length(Cipher);
    BufCap := BufLen + 16; // prostor pro PKCS7
    SetLength(Cipher, BufCap);

    if not CryptEncrypt(Key, 0, True, 0, PBYTE(Cipher), BufLen, BufCap) then
      RaiseLastOSError;

    SetLength(Cipher, BufLen);
  finally
    CryptDestroyKey(Key);
    CryptReleaseContext(Prov, 0);
    // plaintext pryč
    WipeBytes(Plain);
  end;

  // HMAC over (Salt||IV||Cipher)
  Mix  := Concat3(Salt, IV, Cipher);
  MacKey := DeriveMacKey(Password, Salt);
  Hmac := HMAC_SHA256(MacKey, Mix);

  // write file
  MS := TMemoryStream.Create;
  try
    bSaltLen := Length(Salt);
    bIVLen   := Length(IV);
    dwCipher := Length(Cipher);

    MS.WriteBuffer(MAGIC, SizeOf(MAGIC));
    MS.WriteBuffer(VERSION, SizeOf(VERSION));
    MS.WriteBuffer(bSaltLen, SizeOf(bSaltLen));
    MS.WriteBuffer(bIVLen, SizeOf(bIVLen));
    MS.WriteBuffer(dwCipher, SizeOf(dwCipher));

    if bSaltLen>0 then MS.WriteBuffer(Salt[0], bSaltLen);
    if bIVLen>0   then MS.WriteBuffer(IV[0],   bIVLen);
    if dwCipher>0 then MS.WriteBuffer(Cipher[0], dwCipher);
    if Length(Hmac)<>32 then raise Exception.Create('HMAC size error');
    MS.WriteBuffer(Hmac[0], 32);

    ForceDirectories(ExtractFilePath(FullPath));
    MS.SaveToFile(FullPath);
  finally
    MS.Free;
    // wipe citlivých bufferů
    WipeBytes(Salt);
    WipeBytes(IV);
    WipeBytes(Cipher);    // ciphertext není tajemství, ale uklidíme RAM
    WipeBytes(Mix);
    WipeBytes(MacKey);
    WipeBytes(Hmac);
  end;
end;

{ ================== Load (.sec) ================== }

function LoadEncryptedConnectStringFromDat_HMAC(
  const Password, AppName, FileName: string): string;
const
  MAGIC: array[0..3] of AnsiChar = ('A','C','S','F');
var
  Prov: HCRYPTPROV;
  Key: HCRYPTKEY;
  MS: TMemoryStream;
  MagicRead: array[0..3] of AnsiChar;
  Version: Byte;
  bSaltLen, bIVLen: Byte;
  dwCipher: DWORD;
  Salt, IV, Cipher, HmacStored, MacKey, Mix, HmacCalc, OutBytes: TBytes;
  BufLen: DWORD;
  Mode: DWORD;
  FullPath: string;
begin
  Result := '';
  FullPath := GetConnFilePath(AppName, FileName);
  if not TFile.Exists(FullPath) then
    raise Exception.Create('Soubor nenalezen: ' + FullPath);

  MS := TMemoryStream.Create;
  try
    MS.LoadFromFile(FullPath);

    if MS.Read(MagicRead, SizeOf(MagicRead)) <> SizeOf(MagicRead) then
      raise Exception.Create('Poškozený soubor (MAGIC).');
    if not CompareMem(@MagicRead[0], @MAGIC[0], SizeOf(MAGIC)) then
      raise Exception.Create('Neznámý formát souboru.');

    if MS.Read(Version, SizeOf(Version)) <> SizeOf(Version) then
      raise Exception.Create('Poškozený soubor (verze).');
    if Version <> 2 then
      raise Exception.Create('Nepodporovaná verze souboru.');

    if (MS.Read(bSaltLen, SizeOf(bSaltLen)) <> SizeOf(bSaltLen)) or
       (MS.Read(bIVLen,   SizeOf(bIVLen))   <> SizeOf(bIVLen)) or
       (MS.Read(dwCipher, SizeOf(dwCipher)) <> SizeOf(dwCipher)) then
      raise Exception.Create('Poškozený soubor (hlavička).');

    if (bSaltLen=0) or (bIVLen=0) or (dwCipher=0) then
      raise Exception.Create('Neplatné délky (Salt/IV/Cipher).');

    SetLength(Salt, bSaltLen);
    SetLength(IV, bIVLen);
    SetLength(Cipher, dwCipher);
    SetLength(HmacStored, 32);

    if (MS.Read(Salt[0], bSaltLen) <> bSaltLen) or
       (MS.Read(IV[0],   bIVLen)   <> bIVLen) or
       (MS.Read(Cipher[0], dwCipher) <> Integer(dwCipher)) or
       (MS.Read(HmacStored[0], 32) <> 32) then
      raise Exception.Create('Poškozený soubor (data).');
  finally
    MS.Free;
  end;

  // HMAC ověření
  Mix := Concat3(Salt, IV, Cipher);
  MacKey := DeriveMacKey(Password, Salt);
  HmacCalc := HMAC_SHA256(MacKey, Mix);
  if (Length(HmacCalc)<>32) or (not CompareMem(@HmacCalc[0], @HmacStored[0], 32)) then
    raise Exception.Create('Autentizace selhala: neplatný HMAC (špatné heslo/změněná data).');

  // Dešifrovat
  DeriveAes256Key(Password, Salt, Prov, Key);
  try
    Mode := CRYPT_MODE_CBC;
    if not CryptSetKeyParam(Key, KP_MODE, @Mode, 0) then RaiseLastOSError;
    if not CryptSetKeyParam(Key, KP_IV, PBYTE(IV), 0) then RaiseLastOSError;

    BufLen := Length(Cipher);
    if not CryptDecrypt(Key, 0, True, 0, PBYTE(Cipher), BufLen) then
      RaiseLastOSError;

    SetLength(Cipher, BufLen);
    OutBytes := Copy(Cipher, 0, Length(Cipher));
    Result := TEncoding.UTF8.GetString(OutBytes);
  finally
    CryptDestroyKey(Key);
    CryptReleaseContext(Prov, 0);
    // wipe
    WipeBytes(OutBytes);
    WipeBytes(Cipher);
    WipeBytes(Salt);
    WipeBytes(IV);
    WipeBytes(Mix);
    WipeBytes(MacKey);
    WipeBytes(HmacCalc);
    WipeBytes(HmacStored);
  end;
end;

{ ================== Save (.sec) ================== s *.sec na síti/USB (UNC/SMB - s transportn9m heslem}

procedure SaveEncryptedConnectStringToFile_HMAC(
  const ConnStr, Password, FullPath: string);
const
  MAGIC: array[0..3] of AnsiChar = ('A','C','S','F');
  VERSION: Byte = 2;
  SALT_LEN = 16;
  IV_LEN   = 16;
var
  Prov: HCRYPTPROV;
  Key: HCRYPTKEY;
  Salt, IV, Plain, Cipher, MacKey, Mix, Hmac: TBytes;
  BufLen, BufCap: DWORD;
  Mode: DWORD;
  MS: TMemoryStream;
  bSaltLen, bIVLen: Byte;
  dwCipher: DWORD;
begin
  if ConnStr = '' then
    raise Exception.Create('ConnectString je prázdný.');

  // random salt/IV
  Salt := GenerateRandomBytes(SALT_LEN);
  IV   := GenerateRandomBytes(IV_LEN);

  // derive key + set CBC + IV
  DeriveAes256Key(Password, Salt, Prov, Key);
  try
    Mode := CRYPT_MODE_CBC;
    if not CryptSetKeyParam(Key, KP_MODE, @Mode, 0) then RaiseLastOSError;
    if not CryptSetKeyParam(Key, KP_IV, PBYTE(IV), 0) then RaiseLastOSError;

    // encrypt
    Plain := TEncoding.UTF8.GetBytes(ConnStr);
    Cipher := Copy(Plain, 0, Length(Plain));
    BufLen := Length(Cipher);
    BufCap := BufLen + 16;
    SetLength(Cipher, BufCap);

    if not CryptEncrypt(Key, 0, True, 0, PBYTE(Cipher), BufLen, BufCap) then
      RaiseLastOSError;

    SetLength(Cipher, BufLen);
  finally
    CryptDestroyKey(Key);
    CryptReleaseContext(Prov, 0);
    WipeBytes(Plain);
  end;

  // HMAC over (Salt||IV||Cipher)
  Mix    := Concat3(Salt, IV, Cipher);
  MacKey := DeriveMacKey(Password, Salt);
  Hmac   := HMAC_SHA256(MacKey, Mix);

  // write
  MS := TMemoryStream.Create;
  try
    bSaltLen := Length(Salt);
    bIVLen   := Length(IV);
    dwCipher := Length(Cipher);

    MS.WriteBuffer(MAGIC, SizeOf(MAGIC));
    MS.WriteBuffer(VERSION, SizeOf(VERSION));
    MS.WriteBuffer(bSaltLen, SizeOf(bSaltLen));
    MS.WriteBuffer(bIVLen, SizeOf(bIVLen));
    MS.WriteBuffer(dwCipher, SizeOf(dwCipher));

    if bSaltLen>0 then MS.WriteBuffer(Salt[0], bSaltLen);
    if bIVLen>0   then MS.WriteBuffer(IV[0],   bIVLen);
    if dwCipher>0 then MS.WriteBuffer(Cipher[0], dwCipher);
    if Length(Hmac)<>32 then raise Exception.Create('HMAC size error');
    MS.WriteBuffer(Hmac[0], 32);

    ForceDirectories(ExtractFilePath(FullPath));
    MS.SaveToFile(FullPath);
  finally
    MS.Free;
    WipeBytes(Salt); WipeBytes(IV); WipeBytes(Cipher);
    WipeBytes(Mix);  WipeBytes(MacKey); WipeBytes(Hmac);
  end;
end;

{ ================== Load (.sec) ================== s *.sec na síti/USB (UNC/SMB - s transportn9m heslem}

function LoadEncryptedConnectStringFromFile_HMAC(
  const Password, FullPath: string): string;
const
  MAGIC: array[0..3] of AnsiChar = ('A','C','S','F');
var
  Prov: HCRYPTPROV;
  Key: HCRYPTKEY;
  MS: TMemoryStream;
  MagicRead: array[0..3] of AnsiChar;
  Version: Byte;
  bSaltLen, bIVLen: Byte;
  dwCipher: DWORD;
  Salt, IV, Cipher, HmacStored, MacKey, Mix, HmacCalc, OutBytes: TBytes;
  BufLen: DWORD;
  Mode: DWORD;
begin
  if not TFile.Exists(FullPath) then
    raise Exception.Create('Soubor nenalezen: ' + FullPath);

  MS := TMemoryStream.Create;
  try
    MS.LoadFromFile(FullPath);

    if MS.Read(MagicRead, SizeOf(MagicRead)) <> SizeOf(MagicRead) then
      raise Exception.Create('Poškozený soubor (MAGIC).');
    if not CompareMem(@MagicRead[0], @MAGIC[0], SizeOf(MAGIC)) then
      raise Exception.Create('Neznámý formát souboru.');

    if MS.Read(Version, SizeOf(Version)) <> SizeOf(Version) then
      raise Exception.Create('Poškozený soubor (verze).');
    if Version <> 2 then
      raise Exception.Create('Nepodporovaná verze souboru.');

    if (MS.Read(bSaltLen, SizeOf(bSaltLen)) <> SizeOf(bSaltLen)) or
       (MS.Read(bIVLen,   SizeOf(bIVLen))   <> SizeOf(bIVLen)) or
       (MS.Read(dwCipher, SizeOf(dwCipher)) <> SizeOf(dwCipher)) then
      raise Exception.Create('Poškozený soubor (hlavička).');

    if (bSaltLen=0) or (bIVLen=0) or (dwCipher=0) then
      raise Exception.Create('Neplatné délky (Salt/IV/Cipher).');

    SetLength(Salt, bSaltLen);
    SetLength(IV, bIVLen);
    SetLength(Cipher, dwCipher);
    SetLength(HmacStored, 32);

    if (MS.Read(Salt[0], bSaltLen) <> bSaltLen) or
       (MS.Read(IV[0],   bIVLen)   <> bIVLen) or
       (MS.Read(Cipher[0], dwCipher) <> Integer(dwCipher)) or
       (MS.Read(HmacStored[0], 32) <> 32) then
      raise Exception.Create('Poškozený soubor (data).');
  finally
    MS.Free;
  end;

  // HMAC ověření
  Mix := Concat3(Salt, IV, Cipher);
  MacKey := DeriveMacKey(Password, Salt);
  HmacCalc := HMAC_SHA256(MacKey, Mix);
  if (Length(HmacCalc)<>32) or (not CompareMem(@HmacCalc[0], @HmacStored[0], 32)) then
    raise Exception.Create('Autentizace selhala: neplatný HMAC.');

  // decrypt
  DeriveAes256Key(Password, Salt, Prov, Key);
  try
    Mode := CRYPT_MODE_CBC;
    if not CryptSetKeyParam(Key, KP_MODE, @Mode, 0) then RaiseLastOSError;
    if not CryptSetKeyParam(Key, KP_IV, PBYTE(IV), 0) then RaiseLastOSError;

    BufLen := Length(Cipher);
    if not CryptDecrypt(Key, 0, True, 0, PBYTE(Cipher), BufLen) then
      RaiseLastOSError;

    SetLength(Cipher, BufLen);
    OutBytes := Copy(Cipher, 0, Length(Cipher));
    Result := TEncoding.UTF8.GetString(OutBytes);
  finally
    CryptDestroyKey(Key);
    CryptReleaseContext(Prov, 0);
    WipeBytes(OutBytes);
    WipeBytes(Cipher); WipeBytes(Salt); WipeBytes(IV);
    WipeBytes(Mix); WipeBytes(MacKey); WipeBytes(HmacCalc); WipeBytes(HmacStored);
  end;
end;




// Uloží šifrovaný ConnectString do Base64 textu (pro DB)
function EncryptConnectStringToBase64_HMAC(const ConnStr, Password: string): string;
const
  MAGIC: array[0..3] of AnsiChar = ('A','C','S','F');
  VERSION: Byte = 2;
  SALT_LEN = 16;
  IV_LEN   = 16;
var
  Prov: HCRYPTPROV;
  Key: HCRYPTKEY;
  Salt, IV, Plain, Cipher, MacKey, Mix, Hmac, Container: TBytes;
  BufLen, BufCap: DWORD;
  Mode: DWORD;
  bSaltLen, bIVLen: Byte;
  dwCipher: DWORD;
  MS: TMemoryStream;
begin
  if ConnStr = '' then
    raise Exception.Create('Connect string je prázdný.');

  // 1) Salt + IV
  Salt := GenerateRandomBytes(SALT_LEN);
  IV   := GenerateRandomBytes(IV_LEN);

  // 2) Derivace a nastavení AES-256/CBC + IV
  DeriveAes256Key(Password, Salt, Prov, Key);
  try
    Mode := CRYPT_MODE_CBC;
    if not CryptSetKeyParam(Key, KP_MODE, @Mode, 0) then RaiseLastOSError;
    if not CryptSetKeyParam(Key, KP_IV, PBYTE(IV), 0) then RaiseLastOSError;

    // 3) Šifrování
    Plain  := TEncoding.UTF8.GetBytes(ConnStr);
    Cipher := Copy(Plain, 0, Length(Plain));
    BufLen := Length(Cipher);
    BufCap := BufLen + 16; // rezerva na padding
    SetLength(Cipher, BufCap);

    if not CryptEncrypt(Key, 0, True, 0, PBYTE(Cipher), BufLen, BufCap) then
      RaiseLastOSError;

    SetLength(Cipher, BufLen);
  finally
    CryptDestroyKey(Key);
    CryptReleaseContext(Prov, 0);
    WipeBytes(Plain);
  end;

  // 4) HMAC(Salt || IV || Cipher) s macKey z hesla + salt
  MacKey := DeriveMacKey(Password, Salt);
  Mix    := Concat3(Salt, IV, Cipher);
  Hmac   := HMAC_SHA256(MacKey, Mix); // 32 B

  // 5) Zabalení do kontejneru (stejné jako .sec)
  bSaltLen := Length(Salt);
  bIVLen   := Length(IV);
  dwCipher := Length(Cipher);

  MS := TMemoryStream.Create;
  try
    MS.WriteBuffer(MAGIC, SizeOf(MAGIC));
    MS.WriteBuffer(VERSION, SizeOf(VERSION));
    MS.WriteBuffer(bSaltLen, SizeOf(bSaltLen));
    MS.WriteBuffer(bIVLen, SizeOf(bIVLen));
    MS.WriteBuffer(dwCipher, SizeOf(dwCipher));
    if bSaltLen>0 then MS.WriteBuffer(Salt[0], bSaltLen);
    if bIVLen>0   then MS.WriteBuffer(IV[0],   bIVLen);
    if dwCipher>0 then MS.WriteBuffer(Cipher[0], dwCipher);
    if Length(Hmac)<>32 then raise Exception.Create('HMAC size error');
    MS.WriteBuffer(Hmac[0], 32);

    SetLength(Container, MS.Size);
    MS.Position := 0;
    if MS.Size>0 then
      MS.ReadBuffer(Container[0], MS.Size);
  finally
    MS.Free;
  end;

  // 6) Base64 výstup
  Result := TNetEncoding.Base64.EncodeBytesToString(Container);

  // wipe
  WipeBytes(Salt); WipeBytes(IV); WipeBytes(MacKey); WipeBytes(Mix);
  WipeBytes(Hmac); WipeBytes(Cipher); WipeBytes(Container);
end;

// Načte (dešifruje) ConnectString z Base64 textu
function DecryptConnectStringFromBase64_HMAC(const Password, Base64Blob: string): string;
const
  MAGIC: array[0..3] of AnsiChar = ('A','C','S','F');
var
  Data: TBytes;
  p: Integer;
  MagicRead: array[0..3] of AnsiChar;
  Version: Byte;
  bSaltLen, bIVLen: Byte;
  dwCipher: DWORD;
  Salt, IV, Cipher, HmacStored, MacKey, Mix, HmacCalc, OutBytes: TBytes;
  Prov: HCRYPTPROV;
  Key: HCRYPTKEY;
  Mode: DWORD;
  BufLen: DWORD;
begin
  if Base64Blob = '' then
    raise Exception.Create('Kontejner je prázdný.');

  Data := TNetEncoding.Base64.DecodeStringToBytes(Base64Blob);
  p := 0;

  if Length(Data) < 4+1+1+1+4+32 then
    raise Exception.Create('Poškozený kontejner (příliš krátký).');

  // MAGIC
  Move(Data[p], MagicRead[0], 4); Inc(p, 4);
  if not CompareMem(@MagicRead[0], @MAGIC[0], 4) then
    raise Exception.Create('Neznámý formát (MAGIC).');

  // Verze
  Version := Data[p]; Inc(p, 1);
  if Version <> 2 then
    raise Exception.Create('Nepodporovaná verze souboru (očekává se 2).');

  // Délky
  bSaltLen := Data[p]; Inc(p, 1);
  bIVLen   := Data[p]; Inc(p, 1);
  Move(Data[p], dwCipher, 4); Inc(p, 4);

  if (bSaltLen=0) or (bIVLen=0) or (dwCipher=0) then
    raise Exception.Create('Neplatné délky (Salt/IV/Cipher).');

  if Cardinal(p) + bSaltLen + bIVLen + dwCipher + 32 > Cardinal(Length(Data)) then
    raise Exception.Create('Poškozený kontejner (rozsahy).');

  // Sekce
  SetLength(Salt, bSaltLen);
  SetLength(IV, bIVLen);
  SetLength(Cipher, dwCipher);
  SetLength(HmacStored, 32);

  if bSaltLen>0 then begin Move(Data[p], Salt[0], bSaltLen); Inc(p, bSaltLen); end;
  if bIVLen>0   then begin Move(Data[p], IV[0], bIVLen);   Inc(p, bIVLen);   end;
  if dwCipher>0 then begin Move(Data[p], Cipher[0], dwCipher); Inc(p, dwCipher); end;
  Move(Data[p], HmacStored[0], 32); Inc(p, 32);

  // HMAC ověření (Salt||IV||Cipher)
  MacKey := DeriveMacKey(Password, Salt);
  Mix := Concat3(Salt, IV, Cipher);
  HmacCalc := HMAC_SHA256(MacKey, Mix);
  if (Length(HmacCalc)<>32) or (not CompareMem(@HmacCalc[0], @HmacStored[0], 32)) then
    raise Exception.Create('Autentizace selhala: neplatný HMAC nebo heslo.');

  // Decrypt
  DeriveAes256Key(Password, Salt, Prov, Key);
  try
    Mode := CRYPT_MODE_CBC;
    if not CryptSetKeyParam(Key, KP_MODE, @Mode, 0) then RaiseLastOSError;
    if not CryptSetKeyParam(Key, KP_IV, PBYTE(IV), 0) then RaiseLastOSError;

    BufLen := Length(Cipher);
    if not CryptDecrypt(Key, 0, True, 0, PBYTE(Cipher), BufLen) then
      RaiseLastOSError;

    SetLength(Cipher, BufLen);
    OutBytes := Copy(Cipher, 0, Length(Cipher));
    Result := TEncoding.UTF8.GetString(OutBytes);
  finally
    CryptDestroyKey(Key);
    CryptReleaseContext(Prov, 0);
    WipeBytes(OutBytes);
  end;

  // wipe
  WipeBytes(Salt); WipeBytes(IV); WipeBytes(Cipher);
  WipeBytes(HmacStored); WipeBytes(MacKey); WipeBytes(Mix); WipeBytes(HmacCalc);
  WipeBytes(Data);
end;

// Nevyhazující varianty (vrací False a naplní Err zprávu)
function TryEncryptConnectStringToBase64_HMAC(
  const ConnStr, Password: string; out Base64Blob, Err: string): Boolean;
begin
  Result := False;
  Base64Blob := '';
  Err := '';
  try
    Base64Blob := EncryptConnectStringToBase64_HMAC(ConnStr, Password);
    Result := True;
  except
    on E: Exception do Err := E.Message;
  end;
end;

// Nevyhazující varianty (vrací False a naplní Err zprávu)
function TryDecryptConnectStringFromBase64_HMAC(
  const Password, Base64Blob: string; out ConnStr, Err: string): Boolean;
begin
  Result := False;
  ConnStr := '';
  Err := '';
  try
    ConnStr := DecryptConnectStringFromBase64_HMAC(Password, Base64Blob);
    Result := True;
  except
    on E: Exception do Err := E.Message;
  end;
end;


end.




