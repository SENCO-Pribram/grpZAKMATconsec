unit uDPAPIHelper;

interface

uses
  System.SysUtils, System.Classes, System.IOUtils, Windows;

{ Uloží tajemství (string) do %APPDATA%\AppName\FileName jako DPAPI-chráněný blob.
  UserScope=True  → vázané na přihlášeného uživatele (doporučeno).
  UserScope=False → vázané na počítač (LOCAL_MACHINE).
  Entropy je volitelná „dodatečná sůl“ – musí být stejná pro Save/Load. }
procedure DPAPI_SaveSecretToFile(const Secret, AppName, FileName: string;
  const UserScope: Boolean = True; const Entropy: string = '');

{ Načte a dešifruje tajemství uložené pomocí DPAPI_SaveSecretToFile. }
function DPAPI_LoadSecretFromFile(const AppName, FileName: string;
  const UserScope: Boolean = True; const Entropy: string = ''): string;

{ Helper pro cestu do %APPDATA%\AppName\FileName }
function GetAppDataFilePath(const AppName, FileName: string): string;

implementation

type
  // Windows DPAPI datový blob
  DATA_BLOB = record
    cbData: DWORD;
    pbData: PBYTE;
  end;
  PDATA_BLOB = ^DATA_BLOB;

  // Delphi nemá PPWSTR; pro nás stačí ukazatel na PWideChar
  PPWideChar = ^PWideChar;

function CryptProtectData(pDataIn: PDATA_BLOB; szDataDescr: LPCWSTR;
  pOptionalEntropy: PDATA_BLOB; pvReserved: Pointer; pPromptStruct: Pointer;
  dwFlags: DWORD; pDataOut: PDATA_BLOB): BOOL; stdcall; external 'crypt32.dll';

function CryptUnprotectData(pDataIn: PDATA_BLOB; ppszDataDescr: PPWideChar;
  pOptionalEntropy: PDATA_BLOB; pvReserved: Pointer; pPromptStruct: Pointer;
  dwFlags: DWORD; pDataOut: PDATA_BLOB): BOOL; stdcall; external 'crypt32.dll';

const
  CRYPTPROTECT_UI_FORBIDDEN  = $00000001;
  CRYPTPROTECT_LOCAL_MACHINE = $00000004;

{ ===== Dynamické načtení bezpečného „zeroize“ ===== }

type
  TRtlSecureZeroMemory = function(ptr: Pointer; cnt: SIZE_T): Pointer; stdcall;

var
  _RtlSecureZeroMemory: TRtlSecureZeroMemory = nil;

procedure SecureZero(p: Pointer; len: SIZE_T); inline;
begin
  if (p = nil) or (len = 0) then Exit;
  if Assigned(_RtlSecureZeroMemory) then
    _RtlSecureZeroMemory(p, len)
  else
    FillChar(p^, len, 0); // fallback – pro Delphi je to volání RTL, nebývá odoptimalizováno
end;

procedure InitSecureZero;
var
  h: HMODULE;
begin
  // nejprve zkuste ntdll.dll (obvykle exportuje RtlSecureZeroMemory)
  h := GetModuleHandle('ntdll.dll');
  if h <> 0 then
    @_RtlSecureZeroMemory := GetProcAddress(h, 'RtlSecureZeroMemory');

  // záloha: některé systémy jej exportují i v kernel32.dll
  if not Assigned(_RtlSecureZeroMemory) then
  begin
    h := GetModuleHandle('kernel32.dll');
    if h <> 0 then
      @_RtlSecureZeroMemory := GetProcAddress(h, 'RtlSecureZeroMemory');
  end;
end;

{ ===== Interní utility – převody a mazání ===== }

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

function BytesOfUTF8(const S: string): TBytes; inline;
begin
  Result := TEncoding.UTF8.GetBytes(S);
end;

function UTF8OfBytes(const B: TBytes): string; inline;
begin
  Result := TEncoding.UTF8.GetString(B);
end;

{ ===== Cesty ===== }

function GetAppDataFilePath(const AppName, FileName: string): string;
var
  base, dir: string;
begin
  base := GetEnvironmentVariable('APPDATA'); // C:\Users\...\AppData\Roaming
  if base = '' then
    base := TPath.GetHomePath; // fallback
  dir := TPath.Combine(base, AppName);
  ForceDirectories(dir);
  Result := TPath.Combine(dir, FileName);
end;

{ ===== Vnitřní DPAPI převody (string <-> blob) s vynulováním paměti ===== }

function ProtectStringToBlob(const Secret: string; const UserScope: Boolean;
  const Entropy: string): TBytes;
var
  InBlob, OutBlob, EntBlob: DATA_BLOB;
  Flags: DWORD;
  InBytes, EntBytes: TBytes;
begin
  Result := nil;

  InBytes  := BytesOfUTF8(Secret);
  EntBytes := BytesOfUTF8(Entropy);

  ZeroMemory(@InBlob, SizeOf(InBlob));
  ZeroMemory(@OutBlob, SizeOf(OutBlob));
  ZeroMemory(@EntBlob, SizeOf(EntBlob));

  if Length(InBytes) > 0 then
  begin
    InBlob.cbData := Length(InBytes);
    InBlob.pbData := PBYTE(InBytes);
  end;

  if Length(EntBytes) > 0 then
  begin
    EntBlob.cbData := Length(EntBytes);
    EntBlob.pbData := PBYTE(EntBytes);
  end;

  Flags := CRYPTPROTECT_UI_FORBIDDEN;
  if not UserScope then
    Flags := Flags or CRYPTPROTECT_LOCAL_MACHINE;

  if not CryptProtectData(@InBlob, nil, @EntBlob, nil, nil, Flags, @OutBlob) then
    RaiseLastOSError;

  try
    SetLength(Result, OutBlob.cbData);
    if OutBlob.cbData > 0 then
      Move(OutBlob.pbData^, Result[0], OutBlob.cbData);
  finally
    if OutBlob.pbData <> nil then
      LocalFree(HLOCAL(OutBlob.pbData));
    WipeBytes(InBytes);
    WipeBytes(EntBytes);
  end;
end;

function UnprotectBlobToString(const Blob: TBytes; const UserScope: Boolean;
  const Entropy: string): string;
var
  InBlob, OutBlob, EntBlob: DATA_BLOB;
  Flags: DWORD;
  EntBytes, OutBytes: TBytes;
begin
  Result := '';
  if Length(Blob) = 0 then Exit;

  EntBytes := BytesOfUTF8(Entropy);

  ZeroMemory(@InBlob, SizeOf(InBlob));
  ZeroMemory(@OutBlob, SizeOf(OutBlob));
  ZeroMemory(@EntBlob, SizeOf(EntBlob));

  InBlob.cbData := Length(Blob);
  InBlob.pbData := PBYTE(Blob);

  if Length(EntBytes) > 0 then
  begin
    EntBlob.cbData := Length(EntBytes);
    EntBlob.pbData := PBYTE(EntBytes);
  end;

  Flags := CRYPTPROTECT_UI_FORBIDDEN;
  if not UserScope then
    Flags := Flags or CRYPTPROTECT_LOCAL_MACHINE;

  if not CryptUnprotectData(@InBlob, nil, @EntBlob, nil, nil, Flags, @OutBlob) then
    RaiseLastOSError;

  try
    SetLength(OutBytes, OutBlob.cbData);
    if OutBlob.cbData > 0 then
      Move(OutBlob.pbData^, OutBytes[0], OutBlob.cbData);
    Result := UTF8OfBytes(OutBytes);
    WipeBytes(OutBytes);
  finally
    if OutBlob.pbData <> nil then
      LocalFree(HLOCAL(OutBlob.pbData));
    WipeBytes(EntBytes);
  end;
end;

{ ===== Veřejné API – se soubory ===== }

procedure DPAPI_SaveSecretToFile(const Secret, AppName, FileName: string;
  const UserScope: Boolean; const Entropy: string);
var
  blob: TBytes;
  path: string;
begin
  path := GetAppDataFilePath(AppName, FileName);
  blob := ProtectStringToBlob(Secret, UserScope, Entropy);
  try
    ForceDirectories(ExtractFilePath(path)); // kdyby FileName obsahovalo podsložky
    TFile.WriteAllBytes(path, blob);
  finally
    WipeBytes(blob);
  end;
end;

function DPAPI_LoadSecretFromFile(const AppName, FileName: string;
  const UserScope: Boolean; const Entropy: string): string;
var
  blob: TBytes;
  path: string;
begin
  path := GetAppDataFilePath(AppName, FileName);
  if not TFile.Exists(path) then
    raise Exception.Create('DPAPI tajemství nenalezeno: ' + path);

  blob := TFile.ReadAllBytes(path);
  try
    Result := UnprotectBlobToString(blob, UserScope, Entropy);
  finally
    WipeBytes(blob);
  end;
end;

initialization
  InitSecureZero;

finalization
  _RtlSecureZeroMemory := nil;

end.
