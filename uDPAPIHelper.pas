 {
 - Účel: bezpečně uložit a načíst master heslo k .sec lokálně (per-user / per-machine).
 - Technika: Windows DPAPI (CryptProtectData, CryptUnprotectData), %APPDATA%\AppName\….
 - API:
     - DPAPI_SaveSecretToFile(Secret, AppName, FileName; UserScope; Entropy)
     - DPAPI_LoadSecretFromFile(AppName, FileName; UserScope; Entropy): string
     - GetAppDataFilePath(AppName, FileName)
 - Použití: „trezor“ pro master heslo (aby uživatel nemusel nic zadávat při běhu).
 - Pozn.: Neřeší user login hesla, jen bezpečný storage lokálních tajemství.
}

unit uDPAPIHelper;

interface

uses
  System.SysUtils, System.Classes, System.IOUtils, Windows, System.NetEncoding;

{ Uloží tajemství (string) do %APPDATA%\AppName\FileName jako DPAPI-chráněný blob.
  UserScope=True  → vázané na přihlášeného uživatele (doporučeno).
  UserScope=False → vázané na počítač (LOCAL_MACHINE).
  Entropy je volitelná „dodatečná sůl“ – musí být stejná pro Save/Load. }
procedure DPAPI_SaveSecretToFile(const Secret,
                                       AppName,
                                       FileName: string;
                                 const UserScope: Boolean = True;
                                 const Entropy: string = '');

{ Načte a dešifruje tajemství uložené pomocí DPAPI_SaveSecretToFile. }
function DPAPI_LoadSecretFromFile(const AppName,
                                        FileName: string;
                                  const UserScope: Boolean = True;
                                  const Entropy: string = ''): string;

{ Načte a dešifruje tajemství uložené pomocí DPAPI_SaveSecretToFile. }
{Hodí se tam, kde nechceš přerušit běh (např. UI), ale jen zobrazit chybu:}
function TryDPAPI_LoadSecretFromFile(const AppName,
                                           FileName: string;
                                     const UserScope: Boolean;
                                     const Entropy: string;
                                     out   Secret: string;
                                     out   ErrMsg: string): Boolean;


{ Uloží tajemství (string) do %APPDATA%\AppName\FileName jako DPAPI-chráněný blob.
  UserScope=True  → vázané na přihlášeného uživatele (doporučeno).
  UserScope=False → vázané na počítač (LOCAL_MACHINE).
  Entropy je volitelná „dodatečná sůl“ – musí být stejná pro Save/Load. }
{ ukládání s description  SID, DOMAIN, UZIVATEL}
procedure DPAPI_SaveSecretToFile_WithDescr(const Secret,
                                                 AppName,
                                                 FileName,
                                                 Description: string;
                                           const UserScope: Boolean = True;
                                           const Entropy: string = '');


{ Načte a dešifruje tajemství uložené pomocí DPAPI_SaveSecretToFile. }
{ čtení s návratem description  SID, DOMAIN, UZIVATEL}
function DPAPI_LoadSecretFromFile_WithDescr(const AppName,
                                                  FileName: string;
                                            const UserScope: Boolean;
                                            const Entropy: string;
                                            out   Description: string): string;


{ Uloží tajemství (string) do DB
  UserScope=True  → vázané na přihlášeného uživatele (doporučeno).
  UserScope=False → vázané na počítač (LOCAL_MACHINE).
  Entropy je volitelná „dodatečná sůl“ – musí být stejná pro Save/Load. }
{ ukládání do DB s description  SID, DOMAIN, UZIVATEL}
function DPAPI_ProtectStringToBase64_WithDescr(const Secret,
                                                     Description: string;
                                               const UserScope: Boolean = True;
                                               const Entropy: string = ''): string;

{ Načte a dešifruje tajemství uložené pomocí DPAPI_ProtectStringToBase64_WithDescr. }
{ čtení z DB s návratem description  SID, DOMAIN, UZIVATEL}
function DPAPI_UnprotectBase64ToString_WithDescr(const Base64Blob: string;
                                                 out   Description: string;
                                                 const UserScope: Boolean = True;
                                                 const Entropy: string = '' ): string;


{ Try varianta
  Uloží tajemství (string) do DB
  UserScope=True  → vázané na přihlášeného uživatele (doporučeno).
  UserScope=False → vázané na počítač (LOCAL_MACHINE).
  Entropy je volitelná „dodatečná sůl“ – musí být stejná pro Save/Load. }
{ ukládání do DB s description  SID, DOMAIN, UZIVATEL}
function TryDPAPI_ProtectStringToBase64_WithDescr(const Secret,
                                                        Description: string;
                                                  const UserScope: Boolean;
                                                  const Entropy: string;
                                                  out   Base64Blob,
                                                        Err: string): Boolean;
{ Try varianta
   Načte a dešifruje tajemství uložené pomocí DPAPI_ProtectStringToBase64_WithDescr. }
{ čtení z DB s návratem description  SID, DOMAIN, UZIVATEL}
function TryDPAPI_UnprotectBase64ToString_WithDescr(const Base64Blob: string;
                                                    const UserScope: Boolean;
                                                    const Entropy: string;
                                                    out   Secret,
                                                          Description,
                                                          Err: string): Boolean;


{ Helper pro cestu do %APPDATA%\AppName\FileName }
function GetAppDataFilePath(const AppName, FileName: string): string;

{ helper: získá SID jako string   }
function GetCurrentUserSidString: string;

{ Primární: GetUserNameExW(NameSamCompatible) -> "DOMAIN\User"  }
function GetCurrentUserDomainSlashName: string;

{ --- Funkce: DOMAIN a User zvlášť (bez výjimek, vrací True/False) ---}
function GetCurrentUserDomainAndName(out Domain, User: string): Boolean;

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

//function GetAppDataFilePath(const AppName, FileName: string): string;
//var
//  base, dir: string;
//begin
//  base := GetEnvironmentVariable('APPDATA'); // C:\Users\...\AppData\Roaming
//  if base = '' then
//    base := TPath.GetHomePath; // fallback
//  dir := TPath.Combine(base, AppName);
//  ForceDirectories(dir);
//  Result := TPath.Combine(dir, FileName);
//end;

function GetAppDataFilePath(const AppName, FileName: string): string;
var
  base, dir: string;
begin
  Result := ''; // výchozí hodnota

  base := GetEnvironmentVariable('APPDATA'); // typicky C:\Users\...\AppData\Roaming
  if base = '' then
    base := TPath.GetHomePath; // fallback

  dir := TPath.Combine(base, AppName);

  try
    if not ForceDirectories(dir) then
      Exit; // nepodařilo se vytvořit složku -> vrátí ''
  except
    Exit; // zachycená výjimka -> vrátí ''
  end;

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

procedure DPAPI_SaveSecretToFile(const Secret,
                                       AppName,
                                       FileName: string;
                                 const UserScope: Boolean = True;
                                 const Entropy: string = '');
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

//function DPAPI_LoadSecretFromFile(const AppName, FileName: string;
//  const UserScope: Boolean; const Entropy: string): string;
//var
//  blob: TBytes;
//  path: string;
//begin
//  path := GetAppDataFilePath(AppName, FileName);
//  if not TFile.Exists(path) then
//    raise Exception.Create('DPAPI tajemství nenalezeno: ' + path);
//
//  blob := TFile.ReadAllBytes(path);
//  try
//    Result := UnprotectBlobToString(blob, UserScope, Entropy);
//  finally
//    WipeBytes(blob);
//  end;
//end;

function DPAPI_LoadSecretFromFile(const AppName,
                                        FileName: string;
                                  const UserScope: Boolean = True;
                                  const Entropy: string = ''): string;
var
  blob: TBytes;
  path: string;
begin
  Result := '';
  path := GetAppDataFilePath(AppName, FileName);

  // 1) Neplatná/nezískaná cesta
  if path = '' then
    raise Exception.CreateFmt('Nelze určit cestu k MasterKey (AppName="%s", FileName="%s").', [AppName, FileName]);

  // 2) Soubor neexistuje
  if not TFile.Exists(path) then
    raise Exception.Create('MasterKey nenalezen v: ' + path);

  // 3) Načtení souboru
  try
    blob := TFile.ReadAllBytes(path);
  except
    on E: Exception do
      raise Exception.CreateFmt('Chyba při čtení MasterKey souboru "%s": %s', [path, E.Message]);
  end;

  // 4) DPAPI rozšifrování
  try
    Result := UnprotectBlobToString(blob, UserScope, Entropy);
  except
    on E: Exception do
      raise Exception.CreateFmt('DPAPI dešifrování selhalo pro "%s": %s', [path, E.Message]);
  end;

  // 5) Wipe buffer
  WipeBytes(blob);
end;


function TryDPAPI_LoadSecretFromFile(const AppName,
                                           FileName: string;
                                     const UserScope: Boolean;
                                     const Entropy: string;
                                     out   Secret: string;
                                     out   ErrMsg: string): Boolean;
var
  blob: TBytes;
  path: string;
begin
  Result := False;
  Secret := '';
  ErrMsg := '';
  path := GetAppDataFilePath(AppName, FileName);

  if path = '' then
  begin
    ErrMsg := Format('Nelze určit cestu k MasterKey (AppName="%s", FileName="%s").', [AppName, FileName]);
    Exit;
  end;

  if not TFile.Exists(path) then
  begin
    ErrMsg := 'MasterKey nenalezen v: ' + path;
    Exit;
  end;

  try
    blob := TFile.ReadAllBytes(path);
    try
      Secret := UnprotectBlobToString(blob, UserScope, Entropy);
      Result := True;
    finally
      WipeBytes(blob);
    end;
  except
    on E: Exception do
      ErrMsg := Format('Načtení/DPAPI selhalo pro "%s": %s', [path, E.Message]);
  end;
end;






// ukládání do souboru s description
procedure DPAPI_SaveSecretToFile_WithDescr(const Secret,
                                                 AppName,
                                                 FileName,
                                                 Description: string;
                                           const UserScope: Boolean = True;
                                           const Entropy: string = '');
var
  path: string;
  InBlob, OutBlob, EntBlob: DATA_BLOB;
  InBytes, EntBytes: TBytes;
  Flags: DWORD;
begin
  // 1) Cílová cesta
  path := GetAppDataFilePath(AppName, FileName);
  if path = '' then
    raise Exception.CreateFmt('Nelze určit cílovou cestu (AppName="%s", FileName="%s").', [AppName, FileName]);
  ForceDirectories(ExtractFilePath(path));

  // 2) Připrav vstupy
  InBytes  := TEncoding.UTF8.GetBytes(Secret);
  EntBytes := TEncoding.UTF8.GetBytes(Entropy);

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

  // 3) DPAPI volání
  Flags := CRYPTPROTECT_UI_FORBIDDEN;
  if not UserScope then
    Flags := Flags or CRYPTPROTECT_LOCAL_MACHINE;

  // Pozn.: Description je WideChar řetězec – NENÍ tajný, jen metainformace.
  if not CryptProtectData(@InBlob, PWideChar(Description), @EntBlob, nil, nil, Flags, @OutBlob) then
    RaiseLastOSError;

  try
    // 4) Zápis na disk
    if OutBlob.cbData > 0 then
    begin
      var bytes: TBytes;
      SetLength(bytes, OutBlob.cbData);
      Move(OutBlob.pbData^, bytes[0], OutBlob.cbData);
      TFile.WriteAllBytes(path, bytes);
      // wipe dočasného bufferu s blobem (není nutné, ale konzistentní)
      if Length(bytes) > 0 then FillChar(bytes[0], Length(bytes), 0);
    end
    else
      TFile.WriteAllBytes(path, nil);
  finally
    // 5) Uvolnění paměti alokované DPAPI
    if OutBlob.pbData <> nil then
      LocalFree(HLOCAL(OutBlob.pbData));
    // 6) Wipe vstupů v RAM
    if Length(InBytes) > 0 then FillChar(InBytes[0], Length(InBytes), 0);
    if Length(EntBytes) > 0 then FillChar(EntBytes[0], Length(EntBytes), 0);
  end;
end;






// čtení ze souboru s návratem description
function DPAPI_LoadSecretFromFile_WithDescr(const AppName,
                                                  FileName: string;
                                            const UserScope: Boolean;
                                            const Entropy: string;
                                            out   Description: string): string;
var
  path: string;
  blob, entBytes, outBytes: TBytes;
  InBlob, OutBlob, EntBlob: DATA_BLOB;
  Flags: DWORD;
  DescPW: PWideChar; // DPAPI vrátí ukazatel na description (alokuje OS)
begin
  Result := '';
  Description := '';

  // 1) Najdi soubor
  path := GetAppDataFilePath(AppName, FileName);
  if path = '' then
    raise Exception.CreateFmt('Nelze určit cestu k MasterKey (AppName="%s", FileName="%s").', [AppName, FileName]);
  if not TFile.Exists(path) then
    raise Exception.Create('MasterKey nenalezen v: ' + path);

  // 2) Načti blob
  blob := TFile.ReadAllBytes(path);

  // 3) Připrav DATA_BLOBy
  ZeroMemory(@InBlob, SizeOf(InBlob));
  ZeroMemory(@OutBlob, SizeOf(OutBlob));
  ZeroMemory(@EntBlob, SizeOf(EntBlob));

  if Length(blob) > 0 then
  begin
    InBlob.cbData := Length(blob);
    InBlob.pbData := PBYTE(blob);
  end;

  entBytes := TEncoding.UTF8.GetBytes(Entropy);
  if Length(entBytes) > 0 then
  begin
    EntBlob.cbData := Length(entBytes);
    EntBlob.pbData := PBYTE(entBytes);
  end;

  // 4) Flagy DPAPI
  Flags := CRYPTPROTECT_UI_FORBIDDEN;
  if not UserScope then
    Flags := Flags or CRYPTPROTECT_LOCAL_MACHINE;

  // 5) Decrypt + ziskání description
  DescPW := nil;
  if not CryptUnprotectData(@InBlob, @DescPW, @EntBlob, nil, nil, Flags, @OutBlob) then
    RaiseLastOSError;

  try
    // description (není tajné, ale uvolňuje se přes LocalFree)
    if DescPW <> nil then
      Description := DescPW;

    // převod výstupních bajtů na string (UTF-8)
    SetLength(outBytes, OutBlob.cbData);
    if OutBlob.cbData > 0 then
      Move(OutBlob.pbData^, outBytes[0], OutBlob.cbData);
    Result := TEncoding.UTF8.GetString(outBytes);
    // volitelné wipe plaintextu v RAM
    if Length(outBytes) > 0 then
      FillChar(outBytes[0], Length(outBytes), 0);
  finally
    // uvolnění OS alokací
    if DescPW <> nil then
      LocalFree(HLOCAL(DescPW));
    if OutBlob.pbData <> nil then
      LocalFree(HLOCAL(OutBlob.pbData));
    // wipe inputů
    if Length(entBytes) > 0 then
      FillChar(entBytes[0], Length(entBytes), 0);
    if Length(blob) > 0 then
      FillChar(blob[0], Length(blob), 0);
  end;
end;



// ukládání do DB s description
function DPAPI_ProtectStringToBase64_WithDescr(const Secret,
                                                     Description: string;
                                               const UserScope: Boolean = True;
                                               const Entropy: string = ''): string;
var
  InBlob, OutBlob, EntBlob: DATA_BLOB;
  InBytes, EntBytes, OutBytes: TBytes;
  Flags: DWORD;
begin
  Result := '';

  // připrav vstupní data
  InBytes  := TEncoding.UTF8.GetBytes(Secret);
  EntBytes := TEncoding.UTF8.GetBytes(Entropy);

  ZeroMemory(@InBlob, SizeOf(InBlob));
  ZeroMemory(@OutBlob, SizeOf(OutBlob));
  ZeroMemory(@EntBlob, SizeOf(EntBlob));

  if Length(InBytes) > 0 then begin
    InBlob.cbData := Length(InBytes);
    InBlob.pbData := PBYTE(InBytes);
  end;

  if Length(EntBytes) > 0 then begin
    EntBlob.cbData := Length(EntBytes);
    EntBlob.pbData := PBYTE(EntBytes);
  end;

  Flags := CRYPTPROTECT_UI_FORBIDDEN;
  if not UserScope then
    Flags := Flags or CRYPTPROTECT_LOCAL_MACHINE;

  if not CryptProtectData(@InBlob, PWideChar(Description), @EntBlob, nil, nil, Flags, @OutBlob) then
    RaiseLastOSError;
  try
    // vytvoř Base64 z DPAPI blobu
    SetLength(OutBytes, OutBlob.cbData);
    if OutBlob.cbData > 0 then
      Move(OutBlob.pbData^, OutBytes[0], OutBlob.cbData);
    Result := TNetEncoding.Base64.EncodeBytesToString(OutBytes);
    // wipe dočasného bufferu
    if Length(OutBytes) > 0 then FillChar(OutBytes[0], Length(OutBytes), 0);
  finally
    if OutBlob.pbData <> nil then
      LocalFree(HLOCAL(OutBlob.pbData));
    if Length(InBytes) > 0 then FillChar(InBytes[0], Length(InBytes), 0);
    if Length(EntBytes) > 0 then FillChar(EntBytes[0], Length(EntBytes), 0);
  end;
end;

// čtení z DB s description
function DPAPI_UnprotectBase64ToString_WithDescr(const Base64Blob: string;
                                                 out   Description: string;
                                                 const UserScope: Boolean = True;
                                                 const Entropy: string = '' ): string;
var
  InBlob, OutBlob, EntBlob: DATA_BLOB;
  BlobBytes, EntBytes, OutBytes: TBytes;
  Flags: DWORD;
  DescPW: PWideChar;
begin
  Result := '';
  Description := '';

  if Base64Blob = '' then
    raise Exception.Create('DPAPI: prázdný Base64 blob.');

  BlobBytes := TNetEncoding.Base64.DecodeStringToBytes(Base64Blob);
  EntBytes  := TEncoding.UTF8.GetBytes(Entropy);

  ZeroMemory(@InBlob, SizeOf(InBlob));
  ZeroMemory(@OutBlob, SizeOf(OutBlob));
  ZeroMemory(@EntBlob, SizeOf(EntBlob));

  if Length(BlobBytes) > 0 then begin
    InBlob.cbData := Length(BlobBytes);
    InBlob.pbData := PBYTE(BlobBytes);
  end;

  if Length(EntBytes) > 0 then begin
    EntBlob.cbData := Length(EntBytes);
    EntBlob.pbData := PBYTE(EntBytes);
  end;

  Flags := CRYPTPROTECT_UI_FORBIDDEN;
  if not UserScope then
    Flags := Flags or CRYPTPROTECT_LOCAL_MACHINE;

  DescPW := nil;
  if not CryptUnprotectData(@InBlob, @DescPW, @EntBlob, nil, nil, Flags, @OutBlob) then
    RaiseLastOSError;
  try
    if DescPW <> nil then
      Description := DescPW;

    SetLength(OutBytes, OutBlob.cbData);
    if OutBlob.pbData <> nil then
      Move(OutBlob.pbData^, OutBytes[0], OutBlob.cbData);

    Result := TEncoding.UTF8.GetString(OutBytes);
    if Length(OutBytes) > 0 then FillChar(OutBytes[0], Length(OutBytes), 0);
  finally
    if DescPW <> nil then LocalFree(HLOCAL(DescPW));
    if OutBlob.pbData <> nil then LocalFree(HLOCAL(OutBlob.pbData));
    if Length(BlobBytes) > 0 then FillChar(BlobBytes[0], Length(BlobBytes), 0);
    if Length(EntBytes) > 0 then FillChar(EntBytes[0], Length(EntBytes), 0);
  end;
end;

// Try-varianta (nezvedá výjimky)
// ukládání do DB s description
function TryDPAPI_ProtectStringToBase64_WithDescr(const Secret,
                                                        Description: string;
                                                  const UserScope: Boolean;
                                                  const Entropy: string;
                                                  out   Base64Blob,
                                                        Err: string): Boolean;
begin
  Result := False;
  Base64Blob := '';
  Err := '';
  try
    Base64Blob := DPAPI_ProtectStringToBase64_WithDescr(Secret, Description, UserScope, Entropy);
    Result := True;
  except
    on E: Exception do Err := E.Message;
  end;
end;

// Try-varianta (nezvedá výjimky)
// čtení z DB s description
function TryDPAPI_UnprotectBase64ToString_WithDescr(const Base64Blob: string;
                                                    const UserScope: Boolean;
                                                    const Entropy: string;
                                                    out   Secret,
                                                          Description,
                                                          Err: string): Boolean;
begin
  Result := False;
  Secret := '';
  Description := '';
  Err := '';
  try
    Secret := DPAPI_UnprotectBase64ToString_WithDescr(Base64Blob, Description, UserScope, Entropy);
    Result := True;
  except
    on E: Exception do Err := E.Message;
  end;
end;









// ====== Minimalní deklarace pro čtení SID aktuálního uživatele ======
type
  PSID = Pointer;

  SID_AND_ATTRIBUTES = record
    Sid: PSID;
    Attributes: DWORD;
  end;

  PTOKEN_USER = ^TOKEN_USER;
  TOKEN_USER = record
    User: SID_AND_ATTRIBUTES;
  end;

// Starší Delphi nemusí mít enum; stačí konstanta
const
  TokenUser = 1; // TOKEN_INFORMATION_CLASS hodnoty: 1 = TokenUser

function OpenProcessToken(ProcessHandle: THandle; DesiredAccess: DWORD;
  var TokenHandle: THandle): BOOL; stdcall; external 'advapi32.dll';

function GetTokenInformation(TokenHandle: THandle; TokenInformationClass: DWORD;
  TokenInformation: Pointer; TokenInformationLength: DWORD;
  var ReturnLength: DWORD): BOOL; stdcall; external 'advapi32.dll';

function ConvertSidToStringSidW(Sid: PSID; var StringSid: LPWSTR): BOOL; stdcall;
  external 'advapi32.dll';

// CloseHandle/GetCurrentProcess jsou v kernel32 (už bývá v unitě Windows)

// helper: získá SID jako string
function GetCurrentUserSidString: string;
var
  hTok: THandle;
  need: DWORD;
  pUser: PTOKEN_USER;
  sidStr: LPWSTR;
begin
  Result := '';
  hTok := 0;
  if not OpenProcessToken(GetCurrentProcess, TOKEN_QUERY, hTok) then
    RaiseLastOSError;
  try
    need := 0;
    // 1. zjištění potřebné délky
    GetTokenInformation(hTok, TokenUser, nil, 0, need);
    if need = 0 then
      RaiseLastOSError;

    GetMem(pUser, need);
    try
      if not GetTokenInformation(hTok, TokenUser, pUser, need, need) then
        RaiseLastOSError;

      sidStr := nil;
      if not ConvertSidToStringSidW(pUser.User.Sid, sidStr) then
        RaiseLastOSError;
      try
        Result := sidStr; // WideChar -> UnicodeString
      finally
        if sidStr <> nil then
          LocalFree(HLOCAL(sidStr));
      end;
    finally
      FreeMem(pUser);
    end;
  finally
    if hTok <> 0 then
      CloseHandle(hTok);
  end;
end;



// --- Deklarace (pokud je ještě nemáš v unitě) ---
type
  EXTENDED_NAME_FORMAT = ULONG;

const
  NameSamCompatible: EXTENDED_NAME_FORMAT = 2; // "DOMAIN\UserName"
  ERROR_MORE_DATA = 234;

function GetUserNameExW(NameFormat: EXTENDED_NAME_FORMAT; lpNameBuffer: LPWSTR; var nSize: ULONG): BOOL; stdcall;
  external 'secur32.dll';

function LookupAccountSidW(lpSystemName: LPCWSTR; Sid: Pointer; Name: LPWSTR; var cchName: DWORD;
  ReferencedDomainName: LPWSTR; var cchReferencedDomainName: DWORD; var peUse: DWORD): BOOL; stdcall;
  external 'advapi32.dll';

// (musíš mít také deklarace OpenProcessToken, GetTokenInformation, TOKEN_USER/PSID atd. – jak jsme přidávali dřív)


// --- Funkce: DOMAIN a User zvlášť (bez výjimek, vrací True/False) ---
function GetCurrentUserDomainAndName(out Domain, User: string): Boolean;
var
  size: ULONG;
  buf: PWideChar;
  s, dom, usr: string;
  p: Integer;

  // fallback proměnné
  hTok: THandle;
  need: DWORD;
  pUser: PTOKEN_USER;
  nameLen, domLen, useVal: DWORD;
  nameBuf, domBuf: PWideChar;
begin
  Result := False;
  Domain := '';
  User := '';

  // 1) Primární: GetUserNameExW(NameSamCompatible) -> "DOMAIN\User"
  size := 0;
  GetUserNameExW(NameSamCompatible, nil, size);
  if (size > 0) and (GetLastError = ERROR_MORE_DATA) then
  begin
    GetMem(buf, size * SizeOf(WideChar));
    try
      if GetUserNameExW(NameSamCompatible, buf, size) then
      begin
        s := buf; // UnicodeString
        // rozdělit na DOMAIN a user
        p := Pos('\', s);
        if p > 0 then
        begin
          dom := Copy(s, 1, p-1);
          usr := Copy(s, p+1, MaxInt);
        end
        else
        begin
          // žádná doména – může být lokální účet
          dom := '';
          usr := s;
        end;
        Domain := dom;
        User := usr;
        Exit(True);
      end;
    finally
      FreeMem(buf);
    end;
  end;

  // 2) Fallback: přes SID -> LookupAccountSidW
  hTok := 0;
  if not OpenProcessToken(GetCurrentProcess, TOKEN_QUERY, hTok) then
    Exit(False);
  try
    need := 0;
    GetTokenInformation(hTok, TokenUser, nil, 0, need);
    if need = 0 then
      Exit(False);

    GetMem(pUser, need);
    try
      if not GetTokenInformation(hTok, TokenUser, pUser, need, need) then
        Exit(False);

      nameLen := 0;
      domLen := 0;
      useVal := 0;
      LookupAccountSidW(nil, pUser.User.Sid, nil, nameLen, nil, domLen, useVal);
      if (GetLastError <> ERROR_INSUFFICIENT_BUFFER) or (nameLen = 0) or (domLen = 0) then
        Exit(False);

      GetMem(nameBuf, nameLen * SizeOf(WideChar));
      GetMem(domBuf, domLen * SizeOf(WideChar));
      try
        if LookupAccountSidW(nil, pUser.User.Sid, nameBuf, nameLen, domBuf, domLen, useVal) then
        begin
          if (domBuf <> nil) and (domBuf^ <> #0) then
            Domain := domBuf
          else
            Domain := ''; // lokální účet bez domény

          if (nameBuf <> nil) and (nameBuf^ <> #0) then
            User := nameBuf
          else
            User := '';

          Result := (User <> '');
        end;
      finally
        if nameBuf <> nil then FreeMem(nameBuf);
        if domBuf  <> nil then FreeMem(domBuf);
      end;
    finally
      FreeMem(pUser);
    end;
  finally
    if hTok <> 0 then CloseHandle(hTok);
  end;
end;

// --- Pohodlné obaly (volitelné) ---
function GetCurrentUserDomain: string;
var
  d, u: string;
begin
  if GetCurrentUserDomainAndName(d, u) then
    Result := d
  else
    Result := '';
end;

function GetCurrentUserNameOnly: string;
var
  d, u: string;
begin
  if GetCurrentUserDomainAndName(d, u) then
    Result := u
  else
    Result := '';
end;

function GetCurrentUserDomainSlashName: string;
var
  d, u: string;
begin
  if GetCurrentUserDomainAndName(d, u) then
  begin
    if d <> '' then
      Result := d + '\' + u
    else
      Result := u;
  end
  else
    Result := '';
end;



initialization
  InitSecureZero;

finalization
  _RtlSecureZeroMemory := nil;

end.
