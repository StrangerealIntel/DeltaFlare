# DeltaFlare
## Description
#### This repository content a matrix with the references on legit software abused by Threat Actors for hunt by reuse TTPs methods.
## Objectives
#### This matrix has for objectives for to help to attribution to a Threat Actor that abuse again a legit software for theirs operations or for hunting the activities on the public sandboxes in checking new submissions. This content also references on articles and analysis for check the cases.
## Release notes 

```
Release date : 28-Jun-2021
Build        : 1.0.3
Description  : 
                - Add new references
                - Update the existant data or add on the new data with anyrun links for the TTPs
                - New tracker for the SID (CSV/JSON output) [Thanks to @BushidoToken for help]              
==============================
Release date : 27-Mar-2021
Build        : 1.0.2
Description  : 
                - Add new references
==============================
Release date : 06-Jan-2021
Build        : 1.0.1
Description  :
                 - Add new references
                 - New confidence feature for ensure that the good affectation
```
## Outputs

<ul>
<li>CSV</li>
<h4>The CSV output can be downloaded and used by a third-party software or can be consulted in the github page for search by keywords.</h4>
<img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/QueryGithub.png"></img>
<li>JSON</li>
<h4>The JSON output can be used by a third-party software for the survey tasks in proactive hunting or search by keywords.</h4>
</ul>

<h4> Note : On the CSV output, the separator for the sections is "," and for the references and links is ";". This allows to be parsed by github for the search keywords and list the references in one line (Github limits the number of lines that can parse in the dynamic page).</h4>

## Case study (Positive case)
#### We take the case for SideWinder group that use ``` EFS REKEY wizard ```, the wizard for the management of EFS solution of Microsoft that vulnerable to side-loading method.

<a href="https://app.any.run/submissions/#filehash:fa86b5bc5343ca92c235304b8dcbcf4188c6be7d4621c625564bebd5326ed850">Anyrun link</a>

<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/Anyrun-Sidewinder.png"></img></p>

#### We can see a lot of samples with the same TTPs in using RTF files that use the vulnerability ```CVE-2017-11882``` for execute arbitrary code in the computer, this drops the files and executes the main program. Like that on the same folder, this load the malicious dll by first steps to check path on system.

<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/Anyrun-Sidewinder-DLL.png"></img></p>

#### The following code in PowerShell allows to parse the references in searching with the hash.

```c#
$matrix = (gc .\DeltaFlare.json)|convertfrom-Json
$matrix.data|?{$_.Hash -eq "fa86b5bc5343ca92c235304b8dcbcf4188c6be7d4621c625564bebd5326ed850"} # results that equal to the hash
```

#### This returns the following results to the console.

```
Date         : 2019-08-08
Hash         : fa86b5bc5343ca92c235304b8dcbcf4188c6be7d4621c625564bebd5326ed850
Confidence   : 80
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
Confidence   : 100
PDB          : t:\word\x86\ship\0\winword.pdb
Software     : Microsoft Office Word 2007
Filename     : WinWord.exe
Malware      : RedDelta PlugX
Threat_Actor : Mustang Panda
References   : {@{Title=Mustang Panda group focuses catholic groups in Honk Kong; URL=https://twitter.com/Arkbird_SOLG/status/1283000270151208960}}

Date         : 2019-01-12
Hash         : 6c959cfb001fbb900958441dfd8b262fb33e052342948bab338775d3e83ef7f7
Confidence   : 100
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
$matrix.data|?{$_.Threat_Actor -eq "APT32"} # results that equal to the APT32
```
#### This returns an object this can give hashs and references.

### By the Hash

#### Like seeing previously, Anyrun allows to hunt by hash on the dropped/used hash, we can submit on this field for hunting (in red). This also possible in Hybrid Analysis with ``` context``` argument.

<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/DeltaFlare/main/Pictures/Anyrun-Hash.png"></img></p>

### By the PDB path

#### You can also hunt new legit software abused in sandbox in hunting by PDB path, lot of time legit software don't hide it theirs PDB paths. The public sandbox can be queried by context, advanced string search, by cache method in using Google or others web search engines by google dorks.

#### The PDB sections have been added in the references for hunting new abuse on legitimate software, that can more valuable to your investigative research on the Threat Actor (here for the legitimate office word software).

```
Date         : 2020-07-12
Hash         : 6c959cfb001fbb900958441dfd8b262fb33e052342948bab338775d3e83ef7f7
Confidence   : 100
PDB          : t:\word\x86\ship\0\winword.pdb
Software     : Microsoft Office Word 2007
Filename     : WinWord.exe
Malware      : RedDelta PlugX
Threat_Actor : Mustang Panda
References   : {@{Title=Mustang Panda group focuses catholic groups in Honk Kong; URL=https://twitter.com/Arkbird_SOLG/status/1283000270151208960}}
```

### By SID (Suricata ID)
#### Like the others sections, you can search by the malwares and hunt the adversaries by the Suricata ID (here for APT28).
```
Date         : 2019-08-10
SID          : 10004298
Confidence   : 60
Description  : MALWARE [PTsecurity] Trojan/Sednit SSL certificate
Malware      : Seduploader
Organization : APT28
References   : {@{Title=-; URL=-}}
Resources    : {@{URL=https://app.any.run/tasks/9abe2703-3750-4728-a932-129177b2a72a/}, @{URL=https://app.any.run/tasks/d6a8d1db-52c8-4371-b6d3-bf740408bb10/}}

Date         : 2021-06-07
SID          : 2033096
Confidence   : 70
Description  : ET TROJAN APT28/SkinnyBoy Checkin
Malware      : Skinnyboy
Organization : APT28
References   : {@{Title=-; URL=-}}
Resources    : {@{URL=https://app.any.run/tasks/780d4c5d-c34e-42c8-9ee7-0b2f6664d207/}}

Date         : 2021-06-07
SID          : 2033097
Confidence   : 70
Description  : ET TROJAN APT28/SkinnyBoy Payload Request
Malware      : Skinnyboy
Organization : APT28
References   : {@{Title=-; URL=-}}
Resources    : {@{URL=https://app.any.run/tasks/780d4c5d-c34e-42c8-9ee7-0b2f6664d207/}}
```
