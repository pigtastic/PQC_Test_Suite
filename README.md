# PQC_Test_Suite
## Voraussetzungen 
https://github.com/open-quantum-safe/liboqs-python

### Installation

> pip3 install loguru

### Im Vordergrund ausführen

> python3 kem-test-suite.py


#### Im Hintergrund ausführen

> nohub python3 kem-test-suite.py  &

##### Ausgabe des Fortschritts

Für das gesamte logfile
> cat nohup.out

Nur die letzten 16 Zeilen
> tail -n 16 nohup.out


