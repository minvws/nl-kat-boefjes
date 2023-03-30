# Boefje nessus

Nessus is an open-source network vulnerability scanner that uses the Common Vulnerabilities and Exposures architecture for easy cross-linking between compliant security tools. KAT currently uses Nessus to import the nessus scans into Octopoes.

### Input OOIs

Boefje Nessus expects the ipAdress of your Nessus scanner.

### Output OOIs

Nessus currently outputs the following OOIs:

|OOI type|Description|
|---|---|
|CveFindingType|Known vulnerability of software behind IpPort|
|NessusFindingType|Known vulnerability of software behind IpPort|

