# DeltaFlare
## Description
#### This repository content a matrix with the references on legit software abused by Threat Actors for hunt by reuse TTPs methods.
## Objectives
#### This matrix has for objectives for to help to attribution to a Threat Actor that abuse again a legit software for theirs operations or for hunting the activities on the public sandboxes in checking new submissions. This content also references on articles and analysis for check the cases.
## Case study (Positive case)
#### We take the case for SideWinder group that use ``` EFS REKEY wizard ```, the wizard for the management of EFS solution of Microsoft that vulnerable to side-loading method.

<a href="https://app.any.run/submissions/#filehash:fa86b5bc5343ca92c235304b8dcbcf4188c6be7d4621c625564bebd5326ed850">Anyrun link</a>

<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/Anyrun-Sidewinder.png"></img></p>

#### We can see a lot of samples with the same TTPs in using RTF files that use the vulnerability ```CVE-2017-11882``` for execute arbitrary code in the computer, this drops the files and executes the main program. Like that on the same folder, this load the malicious dll by first steps to check path on system.

<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/Anyrun-Sidewinder-DLL.png"></img></p>

#### The following code in PowerShell allows to parse the references in searching with the hash.

```c#
$matrix = (gc .\DeltaFlare.json)|convertfrom-Json
$result = $matrix.data|?{$_.Hash -eq "fa86b5bc5343ca92c235304b8dcbcf4188c6be7d4621c625564bebd5326ed850"} # results that equal to the hash
$result
```

#### This returns the following results to the console.

```
Date         : 2019-08-08
Hash         : fa86b5bc5343ca92c235304b8dcbcf4188c6be7d4621c625564bebd5326ed850
PDB          : rekeywiz.pdb
Software     : EFS REKEY wizard
Filename     : rekeywiz.exe
Malware      : GdSda
Threat_Actor : SideWinder
References   : {@{Title=The SideWinder campaign continue; URL=https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/11-10-2019/Analysis.md}, @{Title=SideWinder same targets, same TTPs, time to counter-attack !;URL=https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/25-12-19/analysis.md}}
```

#### With the references and the analysis of the TTPs and malwares, we can confirm attribution of the case to SideWinder group.

<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/Anyrun-Sidewinder-confirm.png"></img></p>

## case study (Wrong positive)

#### On the following case, this an example of a false positive, like here with a Recuva that parse the repository of Google Update executable (9c36a08d9e7932ff4da7b5f24e6b42c92f28685b8abe964c870e8d7670fd531a). This appears as used, it is, therefore, a false positive which appears in the list of results.

<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/Anyrun-Recuva.png"></img></p>

## Important note
#### Some Threat Actors like Chinese and Vietnamese reuse the vulnerable software used by the enemy for the future operations, check the references and date for help on the attribution of the good Threat Actors.

#### By the example, here, we can see that the vulnerable software ```Microsoft Office Word 2007 (6c959cfb001fbb900958441dfd8b262fb33e052342948bab338775d3e83ef7f7)``` is as first used APT32 and reused by Mustang Panda group.

```
Date         : 2020-07-12
Hash         : 6c959cfb001fbb900958441dfd8b262fb33e052342948bab338775d3e83ef7f7
PDB          : t:\word\x86\ship\0\winword.pdb
Software     : Microsoft Office Word 2007
Filename     : WinWord.exe
Malware      : RedDelta PlugX
Threat_Actor : Mustang Panda
References   : {@{Title=Mustang Panda group focuses catholic groups in Honk Kong; URL=https://twitter.com/Arkbird_SOLG/status/1283000270151208960}}

Date         : 2019-01-12
Hash         : 6c959cfb001fbb900958441dfd8b262fb33e052342948bab338775d3e83ef7f7
PDB          : t:\word\x86\ship\0\winword.pdb
Software     : Microsoft Office Word 2007
Filename     : WinWord.exe
Malware      : KerrDown
Threat_Actor : APT32
References   : {@{Title=Tracking OceanLotusâ€™ new Downloader, KerrDown; URL=https://unit42.paloaltonetworks.com/tracking-oceanlotus-new-downloader-kerrdown/}, @{Title=Suspected new trend of OceanLotus organization: pretending to be candidates for spear email attacks; URL=https://www.secrss.com/articles/7808}}
```

## Hunting
#### This can help to hunt the Threat Actor reuse the vulnerable software.
### By the Threat Actor

#### Like seeing previously, we can interact for get the results the hashs that match with the Threat Actors to hunt.

```c#
$matrix = (gc .\DeltaFlare.json)|convertfrom-Json
$result = $matrix.data|?{$_.Threat_Actor -eq "APT32"} # results that equal to the APT32
$result
```
#### This returns an object this can give hashs and references.

### By the Hash

#### Like seeing previously, Anyrun allows to hunt by hash on the dropped/used hash, we can submit on this field for hunting (in red). This also possible in Hybrid Analysis with ``` context``` argument.

<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/Anyrun-Hash.png"></img></p>

## By the PDB path

#### You can also hunt new legit software abused in sandbox in hunting by PDB path, lot of time legit software don't hide it theirs PDB paths. The public sandbox can be queried by context, advanced string search, by cache method in using Google or others web search engines by google dorks.

#### The PDB sections have been added in the references for hunting new abuse on legitimate software, that can more valuable to your investigative research on the Threat Actor (here for the legitimate office word software).

```
Date         : 2020-07-12
Hash         : 6c959cfb001fbb900958441dfd8b262fb33e052342948bab338775d3e83ef7f7
PDB          : t:\word\x86\ship\0\winword.pdb
Software     : Microsoft Office Word 2007
Filename     : WinWord.exe
Malware      : RedDelta PlugX
Threat_Actor : Mustang Panda
References   : {@{Title=Mustang Panda group focuses catholic groups in Honk Kong; URL=https://twitter.com/Arkbird_SOLG/status/1283000270151208960}}
```
