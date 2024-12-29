from agent.Agent import Agent
from agent.pqfl.SA_ServiceAgent import SA_ServiceAgent as ServiceAgent
from agent.pqfl.SA_ClientAgent import SA_ClientAgent as ClientAgent
from message.Message import Message

import dill
import time
import logging

import math
import libnum
import numpy as np
import pandas as pd
import random
import time
from pympler import asizeof

# pycryptodomex library functions
from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS

# other user-level crypto functions
import hashlib
from util import param
from util import util
from util.crypto import ecchash
from util.crypto.secretsharing import secret_int_to_points, points_to_secret_int
from util import pqfl_utils

# The PPFL_TemplateClientAgent class inherits from the base Agent class.
class SA_NodeAgent(Agent):
    
    def __str__(self):
        return "[client]"

    # Default param:
    # num of iterations = 4
    # key length = 32 bytes
    def __init__(self, id, name, type,
                 iterations=4, 
                 num_clients=128,
                 num_nodes=3,
                 debug_mode=0,
                 users=[],
                 random_state=None,
                 precomputed=False):

        # Base class init
        super().__init__(id, name, type, random_state)

        # Set logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        if debug_mode:
            logging.basicConfig()
            
        self.id = id
        
        """Set parameters."""
        self.num_clients = num_clients
        self.vector_len = param.vector_len
        self.vector_dtype = param.vector_type
        self.prime = ecchash.n
        self.cipher_stored = None   # Store cipher from server across steps
        self.precomputed = precomputed
        
        self.client_pks = {}
        self.client_sks = {} # shared keys
        self.client_masks = {}
        self.server_pk = {}
        
        
        
        self.elapsed_time = {'node_precomputed_time': pd.Timedelta(0),
                             'node_setup_time': pd.Timedelta(0),
                             'node_aggregate_time': pd.Timedelta(0)}


        self.message_size = {'node_setup_msg': 0,
                             'node_aggregate_msg': 0}
        
        dt_protocol_start = pd.Timestamp('now')
        sign_pk, sign_sk = pqfl_utils.generate_dili_keypair()
        
        self.sign_pk = sign_pk
        self.sign_sk = sign_sk
        
        
        ex_pk, ex_sk = pqfl_utils.gen_pk("Kyber")
        self.ex_pk = ex_pk
        self.ex_sk = ex_sk
        
        self.recordTime(dt_protocol_start, 'node_setup_time')
        
        if self.precomputed:
            dt_protocol_start = pd.Timestamp('now')
            pqfl_utils.crypto_precompute(self.sign_sk, 100)
            self.recordTime(dt_protocol_start, 'node_precomputed_time')
        
        # Iteration counter
        self.no_of_iterations = iterations
        self.current_iteration = 1
        self.current_round = 0

        # State flag
        self.setup_server_done = False
        self.setup_client_done = False
        self.setup_complete = False
        
        self.clientAgentID = users
        self.online_users = []
        self.client_msg_count = 0


    # Simulation lifecycle messages.
    def kernelStarting(self, startTime):

        # Initialize custom state properties into which we will later accumulate results.
        # To avoid redundancy, we allow only the first client to handle initialization.
        if self.id == self.num_clients:
            self.kernel.custom_state['node_precomputed_time'] = pd.Timedelta(0)
            self.kernel.custom_state['node_setup_time'] = pd.Timedelta(0)
            self.kernel.custom_state['node_aggregate_time'] = pd.Timedelta(0)
            self.kernel.custom_state['node_setup_msg'] = 0
            self.kernel.custom_state['node_aggregate_msg'] = 0
        
        

        # Find the PPFL service agent, so messages can be directed there.
        # self.clientAgentID = self.kernel.findAgentByType(ClientAgent)
        self.serviceAgentID = self.kernel.findAgentByType(ServiceAgent)

        self.setComputationDelay(0)

        # Request a wake-up call as in the base Agent.  Noise is kept small because
        # the overall protocol duration is so short right now.  (up to one microsecond)
        super().kernelStarting(startTime +
                               pd.Timedelta(self.random_state.randint(low=0, high=1000), unit='ns'))

    def kernelStopping(self):

        # Accumulate into the Kernel's "custom state" this client's elapsed times per category.
        # Note that times which should be reported in the mean per iteration are already so computed.
        # These will be output to the config (experiment) file at the end of the simulation.

        self.kernel.custom_state['node_precomputed_time'] += (
            self.elapsed_time['node_precomputed_time'] / self.no_of_iterations)
        self.kernel.custom_state['node_setup_time'] += (
            self.elapsed_time['node_setup_time'] / self.no_of_iterations)
        
        self.kernel.custom_state['node_aggregate_time'] += (
            self.elapsed_time['node_aggregate_time'] / self.no_of_iterations)

        # self.kernel.custom_state['setup'] += self.message_size['PUBKEY']
        self.kernel.custom_state['node_setup_msg'] += self.message_size['node_setup_msg']
        
        self.kernel.custom_state['node_aggregate_msg'] += self.message_size['node_aggregate_msg']
        
        
        super().kernelStopping()

    # Simulation participation messages.
    def wakeup(self, currentTime):
        super().wakeup(currentTime)
        dt_wake_start = pd.Timestamp('now')
        if self.current_round == 0:
            self.sendKeys(currentTime)
        elif self.current_round == 2:
            self.sendMaskingSum(currentTime)
        elif self.current_round > 2:
            self.sendVectors(currentTime)

    def receiveMessage(self, currentTime, msg):
        
        super().receiveMessage(currentTime, msg)
        dt_protocol_start = pd.Timestamp('now')

        # if msg.body['msg'] == "SERVER_PK":
        #     # server_id = msg.body['id']
        #     # server_pk = msg.body['server_pk']
        #     # self.server_pk[server_id] = server_pk
        #     # self.recordTime(dt_protocol_start, 'node_setup_time')
        #     self.setup_server_done = True
        #     if self.setup_server_done and self.setup_client_done:
        #         self.setup_complete = True
        #         self.computeMasking(currentTime)
        #         self.current_round = 1
        #         print("node {}: setup_complete".format(self.id))
        
        if msg.body['msg'] == "CLIENT_PK":
            client_id = msg.body['id']
            client_pk = msg.body['client_pk']
            self.client_pks[client_id] = client_pk
            client_sk = msg.body['client_sk']
            
            dt_protocol_start = pd.Timestamp('now')
            k = pqfl_utils.kyber_decaps(self.ex_sk, client_sk)
            self.client_sks[client_id] = k
            self.recordTime(dt_protocol_start, 'node_setup_time')
            if len(self.client_pks) == self.num_clients and len(self.client_sks) == self.num_clients:
            #     self.setup_client_done = True
            # if self.setup_server_done and self.setup_client_done:
                self.setup_complete = True
                self.computeMasking(currentTime)
                self.current_round = 1
                print("node {}: setup_complete".format(self.id))
        
        elif msg.body['msg'] == "CLIENT_ITER_NUM":
            client_id = msg.body['id']
            client_t = msg.body['iteration_num']
            client_sign = msg.body['signature']
            client_pk = self.client_pks[client_id]
            
            dt_protocol_start = pd.Timestamp('now')
            self.client_msg_count += 1
            if client_t == self.current_iteration:
                ver, dt_protocol_start = pqfl_utils.signature_verify(client_sign, client_t.to_bytes(2, 'big'), client_pk)
                self.recordTime(dt_protocol_start, 'node_aggregate_time')
                if ver:
                    self.online_users.append(client_id)
                else:
                    print("node: signature verify fail")
            # self.recordTime(dt_protocol_start, 'node_aggregate_time')
            if len(self.online_users) == self.num_clients:
                # self.sendMaskingSum(currentTime)
                print("node {}: CLIENT_ITER_NUM done".format(self.id))
                self.current_round = 2
                self.setWakeup(currentTime + pd.Timedelta('3s'))
            
            
        
        

    ###################################
    # Round logics
    ###################################
    def computeMasking(self, currentTime, iterations=1):
        dt_protocol_start = pd.Timestamp('now')
        if self.precomputed:
            for iter_num in range(1, iterations+1):
                self.client_masks[iter_num] = {}
                for client_id in self.clientAgentID:
                    x_a = self.client_sks[client_id]
                    x_a_prf = pqfl_utils.gen_at(x_a, iter_num, self.vector_len)
                    self.client_masks[iter_num][client_id] = x_a_prf
            
            self.recordTime(dt_protocol_start, 'node_precomputed_time')
        
        
    def sendKeys(self, currentTime):
        msg_size1 = asizeof.asizeof(self.sign_pk) + asizeof.asizeof(self.ex_pk)
        msg_size2 = asizeof.asizeof(self.sign_pk)
        for id in self.clientAgentID:
            self.sendMessage(id,
                             Message({"msg": "NODE_PK",
                                      "id": self.id,
                                      "node_sign_pk" : self.sign_pk,
                                      "node_ex_pk": self.ex_pk
                                      }),
                             tag="node_setup_comm",
                             msg_size=msg_size1)
            
            self.recordBandwidth(self.sign_pk, 'node_setup_msg')
            self.recordBandwidth(self.ex_pk, 'node_setup_msg')
        
        self.sendMessage(self.serviceAgentID, Message({"msg": "NODE_PK", "id": self.id, "node_pk" : self.sign_pk}), tag="node_setup_comm", msg_size=msg_size2)
        self.recordBandwidth(self.sign_pk, 'node_setup_msg')
    
    def sendMaskingSum(self, currentTime):
        print("sendMaskingSum")
        dt_protocol_start = pd.Timestamp('now')
        a_t = np.zeros(self.vector_len)
        if self.precomputed:
            for client_id in self.online_users:
                a_t = a_t + self.client_masks[self.current_iteration][client_id]
        else:
            for client_id in self.online_users:
                x_a = self.client_sks[client_id]
                x_a_prf = pqfl_utils.gen_at(x_a, self.current_iteration, self.vector_len)
                a_t = a_t + x_a_prf
        a_t = a_t.astype(self.vector_dtype)
        m = a_t
        m = np.insert(m, 0, self.current_iteration)
        m = np.insert(m, 1, len(self.online_users))
        # msg_vec = np.array2string(m, separator=', ', threshold=np.inf)
        sign = pqfl_utils.signature_calc(m.tobytes(), self.sign_sk)
        self.recordTime(dt_protocol_start, 'node_aggregate_time')
        self.sendMessage(self.serviceAgentID, Message({"msg": "NODE_MASK_SUM", "id": self.id, "node_mask_sum" : m, "signature": sign}), tag="node_aggregate_comm", msg_size=asizeof.asizeof(m)+asizeof.asizeof(sign))
        
        self.recordBandwidth(m, 'node_aggregate_msg')
        self.recordBandwidth(sign, 'node_aggregate_msg')
        # print(f"asizeof.asizeof(m) = {asizeof.asizeof(m)}")
        # print(f"asizeof.asizeof(sign) = {asizeof.asizeof(sign)}")
        
        self.current_round += 1
        self.setWakeup(currentTime + pd.Timedelta('3s'))
        
        
    def sendVectors(self, currentTime):

        dt_protocol_start = pd.Timestamp('now')
        self.current_iteration += 1
        if self.current_iteration > self.no_of_iterations:
            return
        return


# ======================== UTIL ========================
    
    def recordTime(self, startTime, categoryName):
        dt_protocol_end = pd.Timestamp('now')
        self.elapsed_time[categoryName] += dt_protocol_end - startTime
    
    def agent_print(*args, **kwargs):
        """
        Custom print function that adds a [Server] header before printing.

        Args:
            *args: Any positional arguments that the built-in print function accepts.
            **kwargs: Any keyword arguments that the built-in print function accepts.
        """
        print(*args, **kwargs)

    def recordBandwidth(self, msgobj, categoryName):
        self.message_size[categoryName] += asizeof.asizeof(msgobj)