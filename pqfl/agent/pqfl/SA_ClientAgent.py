from agent.Agent import Agent
from agent.pqfl.SA_ServiceAgent import SA_ServiceAgent as ServiceAgent
# from agent.pqfl.SA_NodeAgent import SA_NodeAgent as NodeAgent
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
class SA_ClientAgent(Agent):
    
    def __str__(self):
        return "[client]"

    # Default param:
    # num of iterations = 4
    # key length = 32 bytes
    # neighbors ~ 2 * log(num per iter) 
    def __init__(self, id, name, type,
                 iterations=4, 
                 num_clients=128,
                 num_nodes=3,
                 debug_mode=0,
                 random_state=None,
                 precomputed=False):

        # Base class init
        super().__init__(id, name, type, random_state)

        # Set logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        if debug_mode:
            logging.basicConfig()
        
        
        """Set parameters."""
        self.num_clients = num_clients
        self.num_nodes = num_nodes
        self.vector_len = param.vector_len
        self.vector_dtype = param.vector_type
        self.prime = ecchash.n
        self.neighbors_list = set() # neighbors
        self.cipher_stored = None   # Store cipher from server across steps
        self.precomputed = precomputed
        
        self.node_pks = {}
        self.node_sks = {}
        self.node_masks = {}
        self.server_pk = {}
        
        
        
        # Accumulate this client's run time information by step.
        self.elapsed_time = {'client_precomputed_time': pd.Timedelta(0),
                             'client_setup_time': pd.Timedelta(0),
                             'client_aggregate_time': pd.Timedelta(0)}


        self.message_size = {'client_setup_msg' : 0,
                             'client_aggregate_msg' : 0}
        
        
        dt_protocol_start = pd.Timestamp('now')
        sign_pk, sign_sk = pqfl_utils.generate_dili_keypair()
        self.recordTime(dt_protocol_start, 'client_setup_time')
        
        self.sign_pk = sign_pk
        self.sign_sk = sign_sk
        
        dt_protocol_start = pd.Timestamp('now')
        ex_pk, ex_sk = pqfl_utils.gen_pk("Kyber")
        self.recordTime(dt_protocol_start, 'client_setup_time')
        self.ex_pk = ex_pk
        self.ex_sk = ex_sk
        
        
        if self.precomputed:
            dt_protocol_start = pd.Timestamp('now')
            pqfl_utils.crypto_precompute(self.sign_sk, 100)
            self.recordTime(dt_protocol_start, 'client_precomputed_time')
        
        # Iteration counter
        self.no_of_iterations = iterations
        self.current_iteration = 1
        self.current_base = 0
        self.current_round = 0

        # State flag
        self.setup_server_done = False
        self.setup_node_done = False
        self.setup_complete = False


    # Simulation lifecycle messages.
    def kernelStarting(self, startTime):

        # Initialize custom state properties into which we will later accumulate results.
        # To avoid redundancy, we allow only the first client to handle initialization.
        if self.id == 0:
            self.kernel.custom_state['client_precomputed_time'] = pd.Timedelta(0)
            self.kernel.custom_state['client_setup_time'] = pd.Timedelta(0)
            self.kernel.custom_state['client_aggregate_time'] = pd.Timedelta(0)
            self.kernel.custom_state['client_setup_msg'] = 0
            self.kernel.custom_state['client_aggregate_msg'] = 0


        # Find the PPFL service agent, so messages can be directed there.
        # self.nodeAgentID = self.kernel.findAgentByType(NodeAgent)
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

        self.kernel.custom_state['client_precomputed_time'] += (
            self.elapsed_time['client_precomputed_time'] / self.no_of_iterations)
        self.kernel.custom_state['client_setup_time'] += (
            self.elapsed_time['client_setup_time'] / self.no_of_iterations)
        self.kernel.custom_state['client_aggregate_time'] += (
            self.elapsed_time['client_aggregate_time'] / self.no_of_iterations)

        # self.kernel.custom_state['setup'] += self.message_size['PUBKEY']
        self.kernel.custom_state['client_setup_msg'] += self.message_size['client_setup_msg']
        self.kernel.custom_state['client_aggregate_msg'] += self.message_size['client_aggregate_msg']
        
        super().kernelStopping()

    # Simulation participation messages.
    def wakeup(self, currentTime):
        super().wakeup(currentTime)
        dt_wake_start = pd.Timestamp('now')
        if self.current_round == 1:
            self.sendMaskedVectors(currentTime)
        if self.current_round > 1:
            self.sendVectors(currentTime)

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)
        dt_protocol_start = pd.Timestamp('now')

        if msg.body['msg'] == "SERVER_PK":
            server_id = msg.body['id']
            server_pk = msg.body['server_pk']
            self.server_pk[server_id] = server_pk
            # self.recordTime(dt_protocol_start, 'client_setup_time')
            self.sendMessage(self.serviceAgentID, Message({"msg": "CLIENT_PK", "id": self.id, "client_pk" : self.sign_pk}), tag="client_setup_comm", msg_size=asizeof.asizeof(self.sign_pk))
            self.recordBandwidth(self.sign_pk, 'client_setup_msg')
            self.setup_server_done = True
            if self.setup_server_done and self.setup_node_done:
                self.setup_complete = True
                self.computeMasking(currentTime)
                self.current_round = 1
                print("client {}: setup_complete".format(self.id))
                # self.sendMaskedVectors(currentTime)
                self.setWakeup(currentTime + pd.Timedelta('20s'))
        
        elif msg.body['msg'] == "NODE_PK":
            node_id = msg.body['id']
            node_pk = msg.body['node_sign_pk']
            node_ex_pk = msg.body['node_ex_pk']
            self.node_pks[node_id] = node_pk
            dt_protocol_start = pd.Timestamp('now')
            c, k = pqfl_utils.kyber_encaps(node_ex_pk)
            self.node_sks[node_id] = k
            self.recordTime(dt_protocol_start, 'client_setup_time')
            self.sendMessage(node_id,
                             Message({"msg": "CLIENT_PK",
                                      "id": self.id,
                                      "client_pk" : self.sign_pk,
                                      "client_sk": c
                                      }),
                             tag="client_setup_comm",
                             msg_size=asizeof.asizeof(self.sign_pk)+asizeof.asizeof(c))
            self.recordBandwidth(self.sign_pk, 'client_setup_msg')
            self.recordBandwidth(c, 'client_setup_msg')
            if len(self.node_pks) == self.num_nodes and len(self.node_sks) == self.num_nodes:
                self.setup_node_done = True
            if self.setup_server_done and self.setup_node_done:
                self.setup_complete = True
                self.computeMasking(currentTime)
                self.current_round = 1
                print("client {}: setup_complete".format(self.id))
                # self.sendMaskedVectors(currentTime)
                self.setWakeup(currentTime + pd.Timedelta('20s'))
        
        elif msg.body['msg'] == "SERVER_AGG_VECTOR":
            server_id = msg.body['id']
            agg_vector = msg.body['server_agg_vector']
            server_sign = msg.body['signature']
            server_pk = self.server_pk[server_id]
            # msg_vec = np.array2string(agg_vector, separator=', ', threshold=np.inf)
            ver, _ = pqfl_utils.signature_verify(server_sign, agg_vector.tobytes(), server_pk)
            if ver:
                self.current_round += 1
            else: 
                print("client {}: SERVER_AGG_VECTOR sign verify fail".format(self.id))
            
            # self.recordTime(dt_protocol_start, 'client_aggregate_time')
        

    ###################################
    # Round logics
    ###################################
    def computeMasking(self, currentTime, iterations=1):
        dt_protocol_start = pd.Timestamp('now')
        if self.precomputed:
            for iter_num in range(1, iterations+1):
                self.node_masks[iter_num] = {}
                for node_id in self.node_sks:
                    x_a = self.node_sks[node_id]
                    x_a_prf = pqfl_utils.gen_at(x_a, iter_num, self.vector_len)
                    self.node_masks[iter_num][node_id] = x_a_prf
            
            self.recordTime(dt_protocol_start, 'client_precomputed_time')
    
    def sendMaskedVectors(self, currentTime):
        # print("sendMaskedVectors")
        vec = np.ones(self.vector_len, dtype=self.vector_dtype)
        
        dt_protocol_start = pd.Timestamp('now')
        
        a_t = np.zeros(self.vector_len)
        if self.precomputed:
            for node_id in self.node_masks[self.current_iteration]:
                # node_masks_keys = self.node_masks.keys()
                # print(f"Keys of self.node_masks: {node_masks_keys}")
                # print(self.node_masks[self.current_iteration])
                a_t = a_t + self.node_masks[self.current_iteration][node_id]
        else:
            for node_id in self.node_sks:
                x_a = self.node_sks[node_id]
                x_a_prf = pqfl_utils.gen_at(x_a, self.current_iteration, self.vector_len)
                a_t = a_t + x_a_prf
        a_t = a_t.astype(self.vector_dtype)
        y_t = vec + a_t
        
        y_t = y_t.astype(self.vector_dtype)
        m = np.insert(y_t, 0, self.current_iteration)
        # msg_vec = np.array2string(m, separator=', ', threshold=np.inf)
        sign = pqfl_utils.signature_calc(m.tobytes(), self.sign_sk)
        self.recordTime(dt_protocol_start, 'client_aggregate_time')
        self.sendMessage(self.serviceAgentID, Message({"msg": "CLIENT_MASK_VEC", "id": self.id, "client_mask_vec" : m, "signature": sign}), tag="client_aggregate_comm", msg_size=asizeof.asizeof(m)+asizeof.asizeof(sign))
        
        self.recordBandwidth(m, 'client_aggregate_msg')
        self.recordBandwidth(sign, 'client_aggregate_msg')
        # print(f"cnasizeof.asizeof(m) = {asizeof.asizeof(m)}")
        # print(f"len(m) = {len(m)}")
        # print(f"cnasizeof.asizeof(sign) = {asizeof.asizeof(sign)}")
        
        
        dt_protocol_start = pd.Timestamp('now')
        # m = np.array([self.current_iteration])
        m = self.current_iteration
        # msg_vec = np.array2string(m, separator=', ', threshold=np.inf)
        # msg_vec = str(self.current_iteration)
        sign = pqfl_utils.signature_calc(m.to_bytes(2, 'big'), self.sign_sk)
        self.recordTime(dt_protocol_start, 'client_aggregate_time')
        msg_size = asizeof.asizeof(m)+asizeof.asizeof(sign)
        
        i = 0
        for node_id in self.node_sks:
            i = node_id
            self.sendMessage(node_id, Message({"msg": "CLIENT_ITER_NUM", "id": self.id, "iteration_num" : m, "signature": sign}), tag="client_aggregate_comm", msg_size=msg_size)
            break
        self.recordBandwidth(m, 'client_aggregate_msg')
        self.recordBandwidth(sign, 'client_aggregate_msg')
            
        # print(f"casizeof.asizeof(m) = {asizeof.asizeof(m)}")
        # print(f"casizeof.asizeof(sign) = {asizeof.asizeof(sign)}")
        
        
        for node_id in self.node_sks:
            if node_id == i:
                continue
            self.sendMessage(node_id, Message({"msg": "CLIENT_ITER_NUM", "id": self.id, "iteration_num" : m, "signature": sign}), tag="client_aggregate_comm1", msg_size=msg_size)
        
        self.current_round += 1
        
    
        
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