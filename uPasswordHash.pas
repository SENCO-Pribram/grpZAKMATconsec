unit uPasswordHash;

interface

uses
  System.SysUtils, System.NetEncoding, Windows;

type
  TStoredPwd = record
    Alg: string;     // např. 'pbkdf2-sha256'
    Iter: Integer;   // počet iterací PBKDF2
    SaltB64: string; // Base64(salt)
    HashB64: string; // Base64(odvozený klíč)
  end;

// vytvoří hash hesla (registrace/změna hesla)
function HashPassword(const Password: string; Iter: Integer = 200000): TStoredPwd;

// ověří heslo proti uloženému hashi
function VerifyPassword(const Password: string; const Stored: TStoredPwd): Boolean;

implementation

{ ===== WinAPI CryptoAPI deklarace ===== }

const
  PROV_RSA_AES        = 24;
  CALG_SHA_256        = $0000800C;
  CRYPT_VERIFYCONTEXT = $F0000000;
  HP_HASHVAL          = $0002;

type
  BYTE  = System.Byte;
  PBYTE = ^BYTE;

  HCRYPTPROV  = ULONG_PTR;  PHCRYPTPROV = ^HCRYPTPROV;
  HCRYPTHASH  = ULONG_PTR;  PHCRYPTHASH = ^HCRYPTHASH;

function CryptAcquireContext(phProv: PHCRYPTPROV; pszContainer, pszProvider: LPCWSTR;
  dwProvType, dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll' name 'CryptAcquireContextW';
function CryptCreateHash(hProv: HCRYPTPROV; Algid: DWORD; hKey: ULONG_PTR;
  dwFlags: DWORD; phHash: PHCRYPTHASH): BOOL; stdcall; external 'advapi32.dll';

function CryptHashData(hHash: HCRYPTHASH; pbData: PBYTE; dwDataLen, dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';
function CryptGetHashParam(hHash: HCRYPTHASH; dwParam: DWORD; pbData: PBYTE;
  var pdwDataLen: DWORD; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';

function CryptDestroyHash(hHash: HCRYPTHASH): BOOL; stdcall; external 'advapi32.dll';
function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall; external 'advapi32.dll';

function CryptGenRandom(hProv: HCRYPTPROV; dwLen: DWORD; pbBuffer: PBYTE): BOOL; stdcall; external 'advapi32.dll';
{ ===== Utility ===== }

procedure WipeBytes(var B: TBytes); inline;
begin
  if Length(B) > 0 then
    FillChar(B[0], Length(B), 0);
  SetLength(B, 0);
end;

function BytesToB64(const B: TBytes): string;
begin
  Result := TNetEncoding.Base64.EncodeBytesToString(B);
end;

function B64ToBytes(const S: string): TBytes;
begin
  Result := TNetEncoding.Base64.DecodeStringToBytes(S);
end;

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

{ ===== SHA-256 / HMAC-SHA256 ===== }

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
      if (Length(Data) > 0) and (not CryptHashData(Hash, PBYTE(Data), Length(Data), 0)) then
        RaiseLastOSError;
      L := 32;
      SetLength(Result, L);
      if not CryptGetHashParam(Hash, HP_HASHVAL, PBYTE(Result), L, 0) then
        RaiseLastOSError;
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
  if Length(K) > 0 then Move(K[0], K0[0], Length(K));
  SetLength(Ipad, BLOCK);
  SetLength(Opad, BLOCK);
  for i := 0 to BLOCK-1 do
  begin
    Ipad[i] := K0[i] xor $36;
    Opad[i] := K0[i] xor $5C;
  end;

  Inner     := Ipad + Data; // Delphi XE+ umí operator + na TBytes
  InnerHash := SHA256_Bytes(Inner);
  Outer     := Opad + InnerHash;
  Result    := SHA256_Bytes(Outer);

  WipeBytes(K); WipeBytes(K0); WipeBytes(Ipad); WipeBytes(Opad);
  WipeBytes(Inner); WipeBytes(InnerHash); WipeBytes(Outer);
end;

{ ===== PBKDF2-HMAC-SHA256 ===== }

function Swap32(x: DWORD): DWORD; inline;
begin
  Result := ((x and $000000FF) shl 24) or
            ((x and $0000FF00) shl  8) or
            ((x and $00FF0000) shr  8) or
            ((x and $FF000000) shr 24);
end;

function PBKDF2_HMAC_SHA256(const Password: string; const Salt: TBytes;
  Iterations, DKLen: Integer): TBytes;
var
  PW: TBytes;
  i, j, blocks, offset: Integer;
  U, TBlock, SaltCounter: TBytes;
  counterBE: DWORD;
begin
  if (Iterations <= 0) or (DKLen <= 0) then
    raise Exception.Create('PBKDF2: neplatné parametry.');

  PW := TEncoding.UTF8.GetBytes(Password);
  try
    blocks := (DKLen + 31) div 32;
    SetLength(Result, blocks * 32);
    offset := 0;

    for i := 1 to blocks do
    begin
      SetLength(SaltCounter, Length(Salt)+4);
      if Length(Salt) > 0 then Move(Salt[0], SaltCounter[0], Length(Salt));
      counterBE := Swap32(DWORD(i));
      Move(counterBE, SaltCounter[Length(Salt)], 4);

      U := HMAC_SHA256(PW, SaltCounter);
      TBlock := Copy(U, 0, Length(U));

      for j := 2 to Iterations do
      begin
        U := HMAC_SHA256(PW, U);
        PCardinal(@TBlock[0])^  := PCardinal(@TBlock[0])^  xor PCardinal(@U[0])^;
        PCardinal(@TBlock[4])^  := PCardinal(@TBlock[4])^  xor PCardinal(@U[4])^;
        PCardinal(@TBlock[8])^  := PCardinal(@TBlock[8])^  xor PCardinal(@U[8])^;
        PCardinal(@TBlock[12])^ := PCardinal(@TBlock[12])^ xor PCardinal(@U[12])^;
        PCardinal(@TBlock[16])^ := PCardinal(@TBlock[16])^ xor PCardinal(@U[16])^;
        PCardinal(@TBlock[20])^ := PCardinal(@TBlock[20])^ xor PCardinal(@U[20])^;
        PCardinal(@TBlock[24])^ := PCardinal(@TBlock[24])^ xor PCardinal(@U[24])^;
        PCardinal(@TBlock[28])^ := PCardinal(@TBlock[28])^ xor PCardinal(@U[28])^;
      end;

      Move(TBlock[0], Result[offset], 32);
      Inc(offset, 32);

      WipeBytes(U);
      WipeBytes(TBlock);
      WipeBytes(SaltCounter);
    end;

    SetLength(Result, DKLen);
  finally
    WipeBytes(PW);
  end;

end;

{ ===== Public API ===== }

function HashPassword(const Password: string; Iter: Integer): TStoredPwd;
var
  Salt, DK: TBytes;
begin
  Result.Alg := 'pbkdf2-sha256';
  Result.Iter := Iter;
  Salt := GenerateRandomBytes(16);
  DK := PBKDF2_HMAC_SHA256(Password, Salt, Iter, 32);
  Result.SaltB64 := BytesToB64(Salt);
  Result.HashB64 := BytesToB64(DK);
end;

function VerifyPassword(const Password: string; const Stored: TStoredPwd): Boolean;
var
  Salt, DK, DK2: TBytes;
  i: Integer;
begin
  if Stored.Alg <> 'pbkdf2-sha256' then
    raise Exception.Create('Nepodporovaný algoritmus hesla');

  Salt := B64ToBytes(Stored.SaltB64);
  DK   := PBKDF2_HMAC_SHA256(Password, Salt, Stored.Iter, 32);
  DK2  := B64ToBytes(Stored.HashB64);

  Result := (Length(DK) = Length(DK2));
  if Result then
    for i := 0 to High(DK) do
      Result := Result and (DK[i] = DK2[i]);

  WipeBytes(DK);
  WipeBytes(DK2);
end;

end.
