#!/bin/bash

rm -r ${SC}/logs/*
sudo rm /run/shm/dispatcher/default.sock
sudo rm -r /run/shm/dispatcher/lwip/
docker rm docker_border_1 docker_dispatcher_1 docker_sciond_1 docker_path_py_1 docker_beacon_1 docker_cert_1
sudo chown -R ${LOGNAME}:${LOGNAME} /run/shm/dispatcher/
sudo chown -R ${LOGNAME}:${LOGNAME} /run/shm/sciond/
