# Copilot Context - scan_network

## Scop proiect

`scan_network` este un utilitar CLI pentru scanarea retelei locale si monitorizarea dispozitivelor cunoscute dupa adresa MAC.

Proiectul original contine scriptul Linux/Bash `scan_retea.sh`. In acest workspace a fost adaugata o varianta Windows/PowerShell: `scan_retea.ps1`.

## Structura curenta

- `scan_retea.sh` - scriptul original Bash pentru Linux.
- `scan_retea.ps1` - port Windows PowerShell, dezvoltat local.
- `.gitignore` - exclude fisiere generate la rulare: configuratii locale, istoric, loguri si backup-uri.
- `LICENSE` - licenta proiectului.

Fisiere generate la rulare, ignorate de Git:

- `retea_config.windows.json`
- `retea_history.windows.jsonl`
- `status_retea_windows.log`
- backup-uri/corrupt copies pentru config

## Rulare Windows

Din directorul proiectului:

```powershell
cd H:\_scan_network\scan_network
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1
```

Comenzi directe:

```powershell
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1 -Scan
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1 -Interactive
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1 -Config
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1 -History
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1 -FlushArp
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1 -Repair
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1 -InstallNmap
```

Optional, se poate forta subnetul:

```powershell
powershell -ExecutionPolicy Bypass -File .\scan_retea.ps1 -Scan -Subnet 192.168.1.0/24
```

## Varianta Windows

`scan_retea.ps1` pastreaza ideea scriptului Bash, dar foloseste API-uri si formate native Windows:

- configuratia este JSON: `retea_config.windows.json`;
- istoricul este JSON Lines: `retea_history.windows.jsonl`;
- logul este separat: `status_retea_windows.log`;
- detecteaza subnetul implicit din `Get-NetIPConfiguration`;
- foloseste Nmap daca exista;
- daca Nmap lipseste, foloseste fallback rapid cu ping sweep + ARP;
- poate instala Nmap cu acordul utilizatorului.

## Nmap

Nmap este recomandat pentru rezultate mai bune:

- detectie MAC/vendor mai buna;
- descoperire mai buna a hosturilor active;
- verificare mai buna a porturilor comune pentru PC/server.

Scriptul nu instaleaza Nmap automat. Fluxul corect:

1. Detecteaza ca Nmap lipseste.
2. Explica beneficiul.
3. Cere confirmare explicita `y/N`.
4. Ruleaza instalarea prin unul dintre:
   - `winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements`
   - `choco install nmap -y`
   - `scoop install nmap`
5. Reincarca `PATH` in procesul curent cu `Update-ProcessPath`.
6. Verifica din nou daca `nmap` este disponibil.

Important: `Update-ProcessPath` reincarca `Path` din variabilele Windows `Machine` si `User`, pastreaza PATH-ul curent si adauga explicit directoarele standard `C:\Program Files\Nmap` si `C:\Program Files (x86)\Nmap` daca exista `nmap.exe`.

## Meniu Windows

Cand este rulat fara parametri, scriptul afiseaza meniul:

- `1` - scanare rapida;
- `2` - scanare interactiva;
- `3` - afisare configuratie;
- `4` - afisare istoric;
- `5` - editare configuratie manuala;
- `6` - curatare cache ARP;
- `7` - reimprospatare status calculatoare;
- `8` - verificare si reparare configuratie;
- `9` - instalare Nmap, afisata doar daca Nmap lipseste;
- `0` - iesire.

Bug reparat: iesirea din aplicatie foloseste `break MainMenu`, deoarece `break` simplu intr-un `switch` PowerShell poate iesi doar din `switch`, nu din bucla meniului.

## Decizii importante de implementare

- Nu se modifica automat sistemul fara acordul utilizatorului.
- Fallback-ul fara Nmap trebuie sa ramana utilizabil, dar Nmap este calea recomandata.
- Configuratia Windows este separata de configuratia Bash ca sa nu corupa formatul original.
- `Import-LegacyConfig` poate importa `retea_config.conf` daca exista, normalizand adresele MAC.
- Adresele MAC sunt normalizate in format `AA:BB:CC:DD:EE:FF`.
- Istoricul Windows este JSONL valid, nu un JSON array modificat incremental.
- Fisierele runtime nu trebuie comise in Git.

## Verificari facute local

Sintaxa PowerShell:

```powershell
$tokens=$null
$errors=$null
[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\scan_retea.ps1), [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) { $errors | Format-List *; exit 1 } else { 'PowerShell syntax OK' }
```

Comenzi testate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scan_retea.ps1 -Config -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File .\scan_retea.ps1 -Repair -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File .\scan_retea.ps1 -History -NoColor
powershell -NoProfile -ExecutionPolicy Bypass -File .\scan_retea.ps1 -Scan -NoColor
```

Pe masina curenta Nmap nu era instalat, deci `-Scan` a folosit fallback ping + ARP.

## Directii urmatoare

Idei bune pentru urmatoarele iteratii:

- imbunatatire clasificare PC vs IoT;
- gestionare mai buna a duplicatelor ARP;
- optiune de redenumire/stergere dispozitive din configuratie;
- export raport CSV/HTML;
- afisare vendor MAC prin baza locala OUI sau API optional;
- detectie mai buna a hostname-urilor fara blocaje lente;
- teste Pester pentru functiile pure: MAC normalize, CIDR, config load/save, PATH reload;
- README actualizat cu instructiuni Windows.
