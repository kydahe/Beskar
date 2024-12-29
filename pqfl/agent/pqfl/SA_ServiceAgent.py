from agent.Agent import Agent
from message.Message import Message

import multiprocessing
import dill
import json
import time
import logging

import math
import numpy as np
import pandas as pd
import random

from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS

from util import param
from util import util
from util.crypto import ecchash
from util.crypto.secretsharing import secret_int_to_points, points_to_secret_int
from pympler import asizeof
from util import pqfl_utils


from ctypes import cdll, c_long, POINTER

def parallel_mult(vec, coeff):
    """Scalar multiplication for EC points in parallel."""
    points = vec.apply(lambda row: ECC.EccPoint(row[0],row[1]),axis=1)
    points = points * coeff
    points = pd.DataFrame([(p.x,p.y) for p in points])
    points = points.applymap(lambda x: int(x))

    return points

WEIGHTLISTSIZE = 16000

# PPFL_ServiceAgent class inherits from the base Agent class.
class SA_ServiceAgent(Agent):

    def __str__(self):
        return "[server]"
    
    def __init__(self, id, name, type,
                 random_state=None,
                 msg_fwd_delay=1000000,
                 round_time=pd.Timedelta("10s"),
                 iterations=4,\
                 num_clients=10,
                 num_nodes=3,
                 parallel_mode=1,
                 debug_mode=0,
                 users=[],
                 nodes=[],
                 precomputed=False):

        # Base class init. 
        super().__init__(id, name, type, random_state)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        if debug_mode:
            logging.basicConfig()
        
        self.id = id

        # System parameters.
        self.msg_fwd_delay = msg_fwd_delay  # time to forward a peer-to-peer client relay message
        self.round_time = round_time        # default waiting time per round
        self.no_of_iterations = iterations  # number of iterations 
        self.parallel_mode = parallel_mode  # parallel
        
        # Input parameters.
        self.num_clients = num_clients      # number of users per training round
        self.users = users                  # the list of user IDs
        self.vector_len = param.vector_len
        self.vector_dtype = param.vector_type
        self.vec_sum_partial = np.zeros(self.vector_len, dtype=self.vector_dtype)
        self.final_sum = np.zeros(self.vector_len, dtype=self.vector_dtype)
        
        self.num_nodes = num_nodes 
        
        self.precomputed = precomputed
        
        # Security parameeters.
        self.prime = ecchash.n
        self.committee_threshold = 0
        
        self.nodes = nodes
        
        
        
        self.node_pks = {}
        self.client_pks = {}
        self.client_masks = []
        self.node_masks = []
        self.online_users = []
        self.user_from_node = []
        
            
        

        # Read keys.
        # self.server_key = util.read_key("pki_files/server_key.pem")
        # self.system_sk = util.read_sk("pki_files/system_pk.pem")

        # agent accumulation of elapsed times by category of tasks
        self.elapsed_time = {'server_precomputed_time': pd.Timedelta(0),
                             'server_setup_time': pd.Timedelta(0),
                             'server_aggregate_time': pd.Timedelta(0)}
        
        self.message_size = {'server_setup_msg': 0,
                             'server_aggregate_msg': 0,}
        
        
        
        dt_protocol_start = pd.Timestamp('now')
        sign_pk, sign_sk = pqfl_utils.generate_dili_keypair()
        self.recordTime(dt_protocol_start, 'server_setup_time')
        
        self.sign_pk = sign_pk
        self.sign_sk = sign_sk
        
        if self.precomputed:
            dt_protocol_start = pd.Timestamp('now')
            pqfl_utils.crypto_precompute(self.sign_sk, 100)
            self.recordTime(dt_protocol_start, 'server_precomputed_time')
        
        
        # Track the current iteration and round of the protocol.
        self.current_iteration = 1
        self.current_round = 0
        
        
        self.setup_client_done = False
        self.setup_node_done = False
        self.setup_complete = False
        
        
        self.agg_client_done = False
        self.agg_node_done = False
        self.agg_complete = False

        # Map the message processing functions
        self.aggProcessingMap = {
            0: self.setup,
            1: self.aggregate,
            2: self.report,
            # 2: self.forward_signatures,
            # 3: self.reconstruction,
        }

        self.namedict = {
            0: "setup",
            1: "aggregate",
            2: "report",
            # 2: "forward_signatures",
            # 3: "reconstruction",
        }
    
    # Simulation lifecycle messages.
    def kernelStarting(self, startTime):
        # self.kernel is set in Agent.kernelInitializing()

        # Initialize custom state properties into which we will accumulate results later.
        self.kernel.custom_state['server_precomputed_time'] = pd.Timedelta(0)
        self.kernel.custom_state['server_setup_time'] = pd.Timedelta(0)
        self.kernel.custom_state['server_aggregate_time'] = pd.Timedelta(0)
        
        self.kernel.custom_state['server_setup_msg'] = 0
        self.kernel.custom_state['server_aggregate_msg'] = 0

        # This agent should have negligible (or no) computation delay until otherwise specified.
        self.setComputationDelay(0)

        # Request a wake-up call as in the base Agent.
        super().kernelStarting(startTime)

    def kernelStopping(self):
        # Add the server time components to the custom state in the Kernel, for output to the config.
        # Note that times which should be reported in the mean per iteration are already so computed.
        self.kernel.custom_state['server_precomputed_time'] += (
            self.elapsed_time['server_precomputed_time'] / self.no_of_iterations)
        self.kernel.custom_state['server_setup_time'] += (
            self.elapsed_time['server_setup_time'] / self.no_of_iterations)
        self.kernel.custom_state['server_aggregate_time'] += (
            self.elapsed_time['server_aggregate_time'] / self.no_of_iterations)

        
        self.kernel.custom_state['server_setup_msg'] += self.message_size['server_setup_msg']
        self.kernel.custom_state['server_aggregate_msg'] += self.message_size['server_aggregate_msg']

        # Allow the base class to perform stopping activities.
        super().kernelStopping()


    def wakeup(self, currentTime):
        """
        The service agent wakes up at the end of each round.

        More specifically, it:
        1. Stores the received messages.
        2. When timing out occurs or 
           when it collects a sufficient number of messages
           from the clients it is waiting for, 
           initiates processing and replying to messages 

        Args:
        - currentTime: The (absolute) current time when the agent wakes up.
                       Note that currentTime is the 'start' of the function.
        """
        super().wakeup(currentTime)
        # self.agent_print(f"wakeup in iteration {self.current_iteration} at function {self.namedict[self.current_round]}; current time is {currentTime}")
        # print(f"wakeup in iteration {self.current_iteration} at function {self.namedict[self.current_round]}; current time is {currentTime}")

        # In the k-th iteration
        # print(self.current_round)
        self.aggProcessingMap[self.current_round](currentTime)

    
    def receiveMessage(self, currentTime, msg):
        """Collect messages from clients.
        
        Three types: 
        - VECTOR message meant for report step, 
        - SIGN message meant for crosscheck step,
        - SHARED_RESULT message meant for reconstruction step.
        """
        

        # Allow the base Agent to do whatever it needs to.
        super().receiveMessage(currentTime, msg)
        dt_protocol_start = pd.Timestamp('now')
        # print("receive {} {}".format(msg.body['msg'], msg.body['id']))

        # Collect masked vectors from clients
        if msg.body['msg'] == "CLIENT_PK":
            client_id = msg.body['id']
            client_pk = msg.body['client_pk']
            self.client_pks[client_id] = client_pk
            # self.recordTime(dt_protocol_start, 'server_setup_time')
            
            if len(self.client_pks) == self.num_clients:
                self.setup_client_done = True
            if self.setup_client_done and self.setup_node_done:
                self.setup_complete = True
                print("server: setup_complete")
                self.current_round = 1
            
        elif msg.body['msg'] == "NODE_PK":
            node_id = msg.body['id']
            node_pk = msg.body['node_pk']
            self.node_pks[node_id] = node_pk
            # self.recordTime(dt_protocol_start, 'server_setup_time')
            if len(self.node_pks) == self.num_nodes:
                self.setup_node_done = True
            if self.setup_client_done and self.setup_node_done:
                self.setup_complete = True
                print("server: setup_complete")
                self.current_round = 1
        
        elif msg.body['msg'] == "CLIENT_MASK_VEC":
            client_id = msg.body['id']
            client_mask_vec = msg.body['client_mask_vec']
            client_sign = msg.body['signature']
            client_pk = self.client_pks[client_id]
            # msg_vec = np.array2string(client_mask_vec, separator=', ', threshold=np.inf)
            dt_protocol_start = pd.Timestamp('now')
            if client_mask_vec[0] == self.current_iteration:
                ver, dt_protocol_start = pqfl_utils.signature_verify(client_sign, client_mask_vec.tobytes(), client_pk)
                self.recordTime(dt_protocol_start, 'server_aggregate_time')
                if ver:
                    self.online_users.append(client_id)
                    self.client_masks.append(client_mask_vec[1:])
                else:
                    print("server: signature verify fail.")
            # self.recordTime(dt_protocol_start, 'server_aggregate_time')
            if len(self.online_users) == self.num_clients:
                self.agg_client_done = True
            if self.agg_client_done and self.agg_node_done:
                # self.current_round = 2
                self.agg_complete = True
                print("agg_complete")
            
        elif msg.body['msg'] == "NODE_MASK_SUM":
            node_id = msg.body['id']
            node_mask_sum = msg.body['node_mask_sum']
            node_sign = msg.body['signature']
            node_pk = self.node_pks[node_id]
            # msg_vec = np.array2string(node_mask_sum, separator=', ', threshold=np.inf)
            dt_protocol_start = pd.Timestamp('now')
            if node_mask_sum[0] == self.current_iteration:
                ver, dt_protocol_start = pqfl_utils.signature_verify(node_sign, node_mask_sum.tobytes(), node_pk)
                self.recordTime(dt_protocol_start, 'server_aggregate_time')
                if ver:
                    self.user_from_node.append(node_mask_sum[1])
                    self.node_masks.append(node_mask_sum[2:])
                else:
                    print("server: signature verify fail.")
            # self.recordTime(dt_protocol_start, 'server_aggregate_time')
            if len(self.node_masks) == self.num_nodes:
                self.agg_node_done = True
            if self.agg_client_done and self.agg_node_done:
                # self.current_round = 2
                self.agg_complete = True
                print("server: agg_complete")
    
    # Processing and replying the messages.
    def setup(self, currentTime):
        print("setup")
        s_time = time.time()
        dt_protocol_start = pd.Timestamp('now')
        # first_id = 0
        # for id in self.users:
        #     first_id = id
        #     self.sendMessage(id,
        #                         Message({"msg": "SERVER_PK",
        #                                 "id": self.id,
        #                                 "server_pk" : self.sign_pk
        #                                 }),
        #                         tag="server_setup_comm",
        #                         msg_size=asizeof.asizeof(self.sign_pk))
        #     break
        # self.recordTime(dt_protocol_start, 'server_setup_time')
        for id in self.users:
            # if id == first_id:
            #     continue
            self.sendMessage(id,
                             Message({"msg": "SERVER_PK",
                                      "id": self.id,
                                      "server_pk" : self.sign_pk
                                      }),
                             tag="server_setup_comm",
                             msg_size=asizeof.asizeof(self.sign_pk))
            
        self.recordBandwidth(self.sign_pk, 'server_setup_msg')
        
        # for id in self.nodes:
        #     self.sendMessage(id,
        #                      Message({"msg": "SERVER_PK",
        #                               "id": self.id
        #                               }),
        #                      tag="server_setup_comm1",
        #                      msg_size=asizeof.asizeof(self.sign_pk))
            
        #     self.recordBandwidth(self.sign_pk, 'server_setup_msg')
        
        
        
        # self.current_round = 1
        self.setWakeup(currentTime + pd.Timedelta('3s'))

    def aggregate(self, currentTime):
        # print("aggregate")
        if self.agg_complete == False:
            self.setWakeup(currentTime + pd.Timedelta('10s'))
            return
        dt_protocol_start = pd.Timestamp('now')
        
        for user_count in self.user_from_node:
            if user_count != len(self.online_users):
                print("Online User In Assisting Node Not Matched.")
        
        w = self.calc_final_w(self.client_masks, self.node_masks)
        # self.recordTime(dt_protocol_start, 'server_aggregate_time')
        # msg_vec = np.array2string(w, separator=', ', threshold=np.inf)
        sign = pqfl_utils.signature_calc(w.tobytes(), self.sign_sk)
        
        # self.sendMessage(0, Message({"msg": "SERVER_AGG_VECTOR", "id": self.id, "server_agg_vector" : w, "signature": sign}), tag="server_aggregate_comm", msg_size=asizeof.asizeof(w)+asizeof.asizeof(sign))
        
        # self.recordTime(dt_protocol_start, 'server_aggregate_time')
        self.recordBandwidth(w, 'server_aggregate_msg')
        # self.recordBandwidth(sign, 'server_aggregate_msg')
        
        for client_id in self.online_users:
            # if client_id == 0:
            #     continue
            self.sendMessage(client_id, Message({"msg": "SERVER_AGG_VECTOR", "id": self.id, "server_agg_vector" : w, "signature": sign}), tag="server_aggregate_comm")
        
        self.current_round += 1
        self.setWakeup(currentTime + pd.Timedelta('3s'))
        
    def aggOfLists(self, aVector, NumOfAN, type):
        lib = cdll.LoadLibrary('/home/zhan4630/pq_fl_project/pqfl/aggregation.so')
        lib.add_one.argtypes = [POINTER(POINTER(c_long)), c_long, c_long]
        lib.add_one.restype = POINTER(c_long)

        rows = NumOfAN
        num_rows = len(aVector)
        num_cols = len(aVector[0])
        templist = [[0 for j in range(num_cols)] for i in range(num_rows)]

        for i in range(len(aVector)):
            for j in range(len(aVector[0])):
                if type == 0:
                    templist[i][j] = int(aVector[i][j],2)
                else:
                    templist[i][j] = aVector[i][j]

        arr_ptr = (POINTER(c_long) * rows)()
        for i in range(rows):
            arr_ptr[i] = (c_long * WEIGHTLISTSIZE)(*templist[i])

        dt_protocol_start = pd.Timestamp('now')
        new_arr_ptr = lib.add_one(arr_ptr, rows, WEIGHTLISTSIZE)
        self.recordTime(dt_protocol_start, 'server_aggregate_time')

        result = [new_arr_ptr[i] for i in range(16000)]

        return result

    def calc_final_w(self, user_updates, node_updates):
        # # sum up user vectors
        # u_stacks = np.stack(user_updates)
        # u_sum = np.sum(u_stacks, axis=0)
        
        # # sum up asnode vectors
        # n_stacks = np.stack(node_updates)
        # n_sum = np.sum(n_stacks, axis=0)
        # final_w = u_sum - n_sum
        
        
        a_t_A_list = []
        y_t_p_list = []
        FinalWeightList = []
        
        a_t_A = self.aggOfLists(node_updates, len(node_updates),1)
        y_t_p = self.aggOfLists(user_updates, len(user_updates),1)

        for y in a_t_A:
            binMaskedWeight = bin(y)[2:]
            if len(binMaskedWeight) > 32:
                binMaskedWeight = binMaskedWeight[-32:]
            a_t_A_list.append(binMaskedWeight)

        for y in y_t_p:
            binMaskedWeight = bin(y)[2:]
            if len(binMaskedWeight) > 32:
                binMaskedWeight = binMaskedWeight[-32:]
            y_t_p_list.append(binMaskedWeight)
        
        
        dt_protocol_start = pd.Timestamp('now')
        for i in range(0, WEIGHTLISTSIZE):
            FinalWeightValue = int(y_t_p_list[i], 2) - int(a_t_A_list[i], 2)
            if FinalWeightValue < 0:
                y_t_p_list[i] = "1" + y_t_p_list[i]
                FinalWeightValue = int(y_t_p_list[i], 2) - int(a_t_A_list[i], 2)

            FinalWeightList.append(FinalWeightValue)
        self.recordTime(dt_protocol_start, 'server_aggregate_time')
        print(len(FinalWeightList))
        final_w = np.array(FinalWeightList)
        return final_w
    
    def report(self, currentTime):
        dt_protocol_start = pd.Timestamp('now')
        self.current_iteration += 1
        if self.current_iteration > self.no_of_iterations:
            return
        return


# ======================== UTIL ========================

    def recordTime(self, startTime, categoryName):
        # Accumulate into time log.
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
