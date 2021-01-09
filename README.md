# PQC_Test_Suite
## Voraussetzung 
> https://github.com/open-quantum-safe/liboqs-python

### Installation

> pip3 install loguru

### Im Vordergrund ausführen

> python3 kem-test-suite.py


#### Im Hintergrund ausführen

> nohub python3 kem-test-suite.py  &

##### Ausgabe des Fortschritts

Für das gesamte logfile
> cat nohup.out

Nur die letzten 22 Zeilen
> tail -n 22 nohup.out


