program grpZAKMATconsec;

uses
  Vcl.Forms,
  Unit1 in 'Unit1.pas' {Form1},
  uConnStorage in 'uConnStorage.pas',
  uCryptoHelper_AES in 'uCryptoHelper_AES.pas',
  uDPAPIHelper in 'uDPAPIHelper.pas',
  uPasswordHash in 'uPasswordHash.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
