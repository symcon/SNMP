# SMNP Anzeige
Die SMNP Anzeige zeigt die OIDs an. Die OIDs können als Variable erstellt und beschreiben werden. 

### Inhaltsverzeichnis

1. [Funktionsumfang](#1-funktionsumfang)
2. [Voraussetzungen](#2-voraussetzungen)
3. [Software-Installation](#3-software-installation)
4. [Einrichten der Instanzen in IP-Symcon](#4-einrichten-der-instanzen-in-ip-symcon)
5. [Statusvariablen und Profile](#5-statusvariablen-und-profile)
6. [WebFront](#6-webfront)
7. [PHP-Befehlsreferenz](#7-php-befehlsreferenz)

### 1. Funktionsumfang

* Anzeige von SNMP OIDs
* Erstellung einzelner OIDs als Variable
* Schreiben von Werten auf die OIDs 

### 2. Voraussetzungen

- IP-Symcon ab Version 6.0

### 3. Software-Installation

* Über den Module Store das 'SMNP Anzeige'-Modul installieren.
* Alternativ über das Module Control folgende URL hinzufügen

### 4. Einrichten der Instanzen in IP-Symcon

 Unter 'Instanz hinzufügen' kann das 'SMNP Anzeige'-Modul mithilfe des Schnellfilters gefunden werden.  
	- Weitere Informationen zum Hinzufügen von Instanzen in der [Dokumentation der Instanzen](https://www.symcon.de/service/dokumentation/konzepte/instanzen/#Instanz_hinzufügen)

__Konfigurationsseite__:

Name                                       | Beschreibung
------------------------------------------ | ------------------
Host                                       | Adresse des Host
Version                                    | Auswahl zwischen den Versionen SNMPv1, SNMPv2, SNMPv3
Starte bei                                 | OID bei dem der Walk starten soll
Benutzer                                   | Benutzername
Community                                  | Für SNMPv1, SNMPv2 nötig
Authentifizierung aktivieren               | Aktiviert die Möglichkeit der Authentifizierung 
Authentifizierungspasswort                 | Passwort für die Authentifizierung
Autentifizierungsart                       | Auswahl der Autentifizierungsart: MD5, SHA1, SHA224, SHA256, SHA384, SHA512
Verschlüsselung aktivieren                 | Aktiviert die Verschlüsselung
Verschlüsselungspasswort                   | Passwort für die Verschlüsselung
Verschlüsselungsart                        | Auswahl für die Verschlüsselungsart: DES, AES128, 3DES, AES192, AES256, AES192blue, AES256blue
Zeige nur bekannte OIDs aus den OIDLibs an | Bei Aktivierung werdern nur OIDs an, welche in den OIDLibs vorhanden sind
OIDLibs                                    | Liste von Dateien, welche die OIDs mit Beschreibung und Namen versieht. [MIB-Dateien zu OIDLibs](https://www.paessler.com/tools/mibimporter)
Aktualisierungsintervall                   | Intervall, in welchem zeitlichen Abstand die Werte aktualisiert werden


Name                        | Beschreibung
--------------------------- | ------
Walk starten / Walk stoppen | Button um den Walk zu starten und zu stoppen 
OID                         | Anzeige der OID 
Name                        | Name, welcher durch die OIDLib gegeben wurde
Beschreibung                | Beschreibung , welche durch die OIDLib gegeben wurde
Wert                        | Wert der OID, welcher zum Zeitpunkt des Walks 
Aktiv?                      | Erstellt eine Variable
Schreibbar?                 | Schreibt den Wert zum SNMP-Server 

### 5. PHP-Befehlsreferenz

`boolean SNMP_UpdateValues(int $InstanzID);`
Updated die Variablenwerte, welche unterhalb der Instanz liegen. 

Beispiel:
`SNMP_BeispielFunktion(12345);`