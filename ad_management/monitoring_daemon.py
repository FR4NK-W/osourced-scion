#!/usr/bin/env python3
# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`monitoring_daemon` --- Ad management tool daemon
======================================================
"""
# Stdlib
import base64
import hashlib
import json
import logging
import os
import sys
import threading
import time
from subprocess import Popen

# External packages
from kazoo.client import KazooClient
from kazoo.exceptions import NoNodeError

# SCION
from ad_management.common import (
    get_supervisor_server,
    is_success,
    LOGS_DIR,
    MONITORING_DAEMON_PORT,
    response_failure,
    response_success,
    UPDATE_DIR_PATH,
    UPDATE_SCRIPT_PATH,
)
from ad_management.secure_rpc_server import XMLRPCServerTLS
from lib.defines import PROJECT_ROOT
from lib.log import init_logging
from topology.generator import ConfigGenerator


class MonitoringDaemon(object):
    """
    Daemon which is launched on every AD node.

    It serves as a RPC server for the web panel and as a client to
    Supervisor and Zookeeper, proxying corresponding commands to them.
    It also runs updater and generates software packages.

    :ivar addr:
    :type addr:
    :ivar rpc_server:
    :type rpc_server:
    """

    def __init__(self, addr):
        """
        Initialize an instance of the class MonitoringDaemon.

        :param addr:
        :type addr:
        """
        super().__init__()
        self.addr = addr
        self.rpc_server = XMLRPCServerTLS((self.addr, MONITORING_DAEMON_PORT))
        self.rpc_server.register_introspection_functions()
        # Register functions
        to_register = [self.get_topology, self.get_process_info,
                       self.control_process, self.get_ad_info,
                       self.send_update, self.update_topology,
                       self.get_master_id]
        for func in to_register:
            self.rpc_server.register_function(func)
        logging.info("Monitoring daemon started")
        self.rpc_server.serve_forever()

    def get_full_ad_name(self, isd_id, ad_id):
        """
        Return the full AD name.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :returns: the full AD name.
        :rtype: string
        """
        return 'ad{}-{}'.format(isd_id, ad_id)

    def get_topo_path(self, isd_id, ad_id):
        gen = ConfigGenerator()
        topo_path = gen.path_dict(isd_id, ad_id)['topo_file_abs']
        return topo_path

    def restart_supervisor_async(self):
        """
        Restart Supervisor after some delay, so the initial RPC call has time
        to finish.
        """
        def _restart_supervisor_wait():
            time.sleep(0.1)
            server = get_supervisor_server()
            server.supervisor.restart()

        threading.Thread(target=_restart_supervisor_wait,
                         name="Restart supervisor daemon",
                         daemon=True).start()

    def update_topology(self, isd_id, ad_id, topology):
        # TODO check security!
        topo_path = self.get_topo_path(isd_id, ad_id)
        if not os.path.isfile(topo_path):
            return response_failure('No AD topology found')
        with open(topo_path, 'w') as topo_fh:
            json.dump(topology, topo_fh, sort_keys=True, indent=4)
            logging.info('Topology file written')
        generator = ConfigGenerator()
        generator.write_derivatives(topology)
        self.restart_supervisor_async()
        return response_success('Topology file is successfully updated')

    def get_topology(self, isd_id, ad_id):
        """
        Read topology file of the given AD.
        Registered function.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :returns:
        :rtype:
        """
        isd_id, ad_id = str(isd_id), str(ad_id)
        logging.info('get_topology call')
        topo_path = self.get_topo_path(isd_id, ad_id)
        if os.path.isfile(topo_path):
            return response_success(open(topo_path, 'r').read())
        else:
            return response_failure('No topology file found')

    def get_ad_info(self, isd_id, ad_id):
        """
        Get status of all processes for the given AD.
        Registered function.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :returns:
        :rtype:
        """
        logging.info('get_ad_info call')
        ad_name = self.get_full_ad_name(isd_id, ad_id)
        server = get_supervisor_server()
        all_process_info = server.supervisor.getAllProcessInfo()
        ad_process_info = list(filter(lambda x: x['group'] == ad_name,
                                      all_process_info))
        return response_success(list(ad_process_info))

    def get_process_info(self, full_process_name):
        """
        Get process information (status, running time, etc.).
        Registered function.

        :param full_process_name:
        :type full_process_name:
        :returns:
        :rtype:
        """
        logging.info('get_process_info call')
        server = get_supervisor_server()
        info = server.supervisor.getProcessInfo(full_process_name)
        return response_success(info)

    def get_process_state(self, full_process_name):
        """
        Return process state (RUNNING, STARTING, etc.).

        :param full_process_name:
        :type full_process_name:
        :returns:
        :rtype:
        """
        info_response = self.get_process_info(full_process_name)
        if is_success(info_response):
            info = info_response[1]
            return info['statename']
        else:
            return None

    def start_process(self, process_name):
        """
        Start a process.

        :param process_name:
        :type process_name:
        :returns:
        :rtype:
        """
        if self.get_process_state(process_name) in ['RUNNING', 'STARTING']:
            return True
        server = get_supervisor_server()
        return server.supervisor.startProcess(process_name)

    def stop_process(self, process_name):
        """
        Stop a process.

        :param process_name:
        :type process_name:
        :returns:
        :rtype:
        """
        if self.get_process_state(process_name) not in ['RUNNING', 'STARTING']:
            return True
        server = get_supervisor_server()
        return server.supervisor.stopProcess(process_name)

    def control_process(self, isd_id, ad_id, process_name, command):
        """
        Send the command to the given process of the specified AD.
        Registered function.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param process_name:
        :type process_name:
        :param command:
        :type command:
        :returns:
        :rtype:
        """
        ad_name = self.get_full_ad_name(isd_id, ad_id)
        full_process_name = '{}:{}'.format(ad_name, process_name)
        if command == 'START':
            res = self.start_process(full_process_name)
        elif command == 'STOP':
            res = self.stop_process(full_process_name)
        elif command == 'RESTART':
            self.stop_process(full_process_name)
            res = self.start_process(full_process_name)
        else:
            return response_failure('Invalid command')
        return response_success(res)

    def run_updater(self, archive, path):
        """
        Launch the updater in a new process.

        :param archive:
        :type archive:
        :param path:
        :type path:
        """
        updater_log = open(os.path.join(LOGS_DIR, 'updater.log'), 'a')
        Popen([sys.executable, UPDATE_SCRIPT_PATH, archive, path],
              stdout=updater_log, stderr=updater_log)

    def send_update(self, isd_id, ad_id, data_dict):
        """
        Verify and extract the received update archive.
        Registered function.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param data_dict:
        :type data_dict:
        :returns:
        :rtype:
        """
        # Verify the hash value
        base64_data = data_dict['data']
        received_digest = data_dict['digest']
        raw_data = base64.b64decode(base64_data)
        if hashlib.sha1(raw_data).hexdigest() != received_digest:
            return response_failure('Hash value does not match')

        if not os.path.exists(UPDATE_DIR_PATH):
            os.makedirs(UPDATE_DIR_PATH)
        assert os.path.isdir(UPDATE_DIR_PATH)
        archive_name = os.path.basename(data_dict['name'])
        out_file_path = os.path.join(UPDATE_DIR_PATH, archive_name)
        with open(out_file_path, 'wb') as out_file_fh:
            out_file_fh.write(raw_data)
        self.run_updater(out_file_path, PROJECT_ROOT)
        return response_success()

    def get_master_id(self, isd_id, ad_id, server_type):
        """
        Registered function.

        Get the id of the current master process for a given server type.
        """
        if server_type not in ['bs', 'cs', 'ps']:
            return response_failure('Invalid server type')
        kc = KazooClient(hosts="localhost:2181")
        lock_path = '/ISD{}-AD{}/{}/lock'.format(isd_id, ad_id, server_type)
        get_id = lambda name: name.split('__')[-1]
        try:
            kc.start()
            contenders = kc.get_children(lock_path)
            if not contenders:
                return response_failure('No lock contenders found')

            lock_holder_file = sorted(contenders, key=get_id)[0]
            lock_holder_path = os.path.join(lock_path, lock_holder_file)
            lock_contents = kc.get(lock_holder_path)
            server_id, _, _ = lock_contents[0].split(b"\x00")
            server_id = str(server_id, 'utf-8')
            return response_success(server_id)
        except NoNodeError:
            return response_failure('No lock data found')
        finally:
            kc.stop()


if __name__ == "__main__":
    init_logging()
    MonitoringDaemon(sys.argv[1])
