SCION
=====

Python implementation of [SCION](http://www.netsec.ethz.ch/research/SCION), a future Internet architecture.

* [doc](https://github.com/netsec-ethz/scion/tree/master/doc) contains documentation and material to present SCION
* [infrastructure](https://github.com/netsec-ethz/scion/tree/master/infrastructure)
* [lib](https://github.com/netsec-ethz/scion/tree/master/lib) contains the most relevant SCION libraries
* [topology](https://github.com/netsec-ethz/scion/tree/servers/topology) contains the scripts to generate the SCION configuration and topology files, as well as the certificates and ROT files

Necessary steps in order to run SCION:

0. Install required packages with dependencies:

    sudo apt-get install python3 python3-pip
    sudo pip3 install bitstring python-pytun pydblite

1. Compile the crypto library:

	./scion.sh init

2. Create the topology and configuration files (according to “topology/ADRelationships” and “topology/ADToISD"):

	./scion.sh topology

3. Configure the loopback interface accordingly:

 	./scion.sh setup

4. Run the infrastructure

	./scion.sh run

5. Stop the infrastructure

	./scion.sh stop

6. Flush all IP addresses assigned to the loopback interface

	./scion.sh clean

In order to run the unit tests:

0. cd test/

1. PYTHONPATH=../ python3 *_test.py (arguments)
