rule EICAR_Test_File
{
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar
}

rule Suspicious_PowerShell
{
    strings:
        $ps = "powershell.exe"

    condition:
        $ps
}
