from opacus import PrivacyEngine
import torch
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm

import zmq
import json
import os
import sys

import time
import random
import base64
import numpy as np
import ast

import pandas as pd

import numpy as np
import ast
import threading
from Crypto.Cipher import AES
import ctypes
import os
import time
import string
import random

from pympler import asizeof


from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
parent_dir = os.path.dirname(parent_dir)
sys.path.insert(0, parent_dir)
sys.path.insert(0, parent_dir+"/dilithium_py")
original_cwd = os.getcwd()
os.chdir(parent_dir+"/dilithium_py")
from dilithium_py.dilithium import *
sys.path.insert(0, parent_dir+"/pyascon")
original_cwd = os.getcwd()
os.chdir(parent_dir+"/pyascon")
from ascon import *
sys.path.insert(0, parent_dir+"/kyber_py")
original_cwd = os.getcwd()
os.chdir(parent_dir+"/kyber_py")
from kyber_py.kyber import *




fips202_lib = ctypes.cdll.LoadLibrary('/home/zhan4630/pq_fl_project/dilithium/avx2/libpqcrystals_fips202_avx2.so')

# print("load libpqcrystals_fips202_avx2 successfully.")

lib = ctypes.cdll.LoadLibrary('/home/zhan4630/pq_fl_project/dilithium/avx2/libpqcrystals_dilithium2_avx2.so')

# print("load libpqcrystals_dilithium2_avx2 successfully.")

blake_lib = ctypes.cdll.LoadLibrary('/home/zhan4630/pq_fl_project/BLAKE3/c/libblake3.so')

# print(dir(lib))
# 声明函数原型
crypto_sign_keypair = lib.pqcrystals_dilithium2_avx2_keypair
# print("load crypto_sign_keypair successfully.")
crypto_sign_keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
crypto_sign_keypair.restype = ctypes.c_int

crypto_precompute = lib.pqcrystals_dilithium2_avx2_precomputing
crypto_precompute.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
# print("load crypto_precompute successfully.")

crypto_sign_precompute = lib.pqcrystals_dilithium2_avx2_sign_precomputing
# print("load sign_precomputing successfully.")
crypto_sign_precompute.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t),
                        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_ubyte)]
crypto_sign_precompute.restype = ctypes.c_int

crypto_sign = lib.pqcrystals_dilithium2_avx2
# print("load pqcrystals_dilithium2_avx2 successfully.")
crypto_sign.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t),
                        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_ubyte)]
crypto_sign.restype = ctypes.c_int

crypto_sign_verify = lib.pqcrystals_dilithium2_avx2_verify
# print("load pqcrystals_dilithium2_avx2_verify successfully.")
crypto_sign_verify.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_ubyte)]
crypto_sign_verify.restype = ctypes.c_int


# # BLAKE3_API void blake3_hasher_init(blake3_hasher *self);
# blake_hash_init = blake_lib.blake3_hasher_init
# class blake3_hasher(ctypes.Structure):
#     _fields_ = [
#         ("key", ctypes.c_uint32 * 8),
#         ("chunk", ctypes.c_byte * 1024),  # 这里的大小需要根据实际情况进行修改
#         ("cv_stack_len", ctypes.c_uint8),
#         ("cv_stack", ctypes.c_byte * ((32 + 1) * 64))  # 这里的大小需要根据实际情况进行修改
#     ]
# blake_hash_init.argtypes = [ctypes.POINTER(blake3_hasher)]
# blake_hash_init.restype = None

# # BLAKE3_API void blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len);
# blake_hash_update = blake_lib.blake3_hasher_update
# blake_hash_update.argtypes = [ctypes.POINTER(blake3_hasher), ctypes.c_void_p, ctypes.c_size_t]
# blake_hash_update.restype = None

# # BLAKE3_API void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len);
# blake_hash_finalize = blake_lib.blake3_hasher_finalize
# blake_hash_finalize.argtypes = [ctypes.POINTER(blake3_hasher), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
# blake_hash_finalize.restype = None

# print("pre load complete")




def int_to_bytes(num):
    return num.to_bytes(4, byteorder='big', signed=False)


def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big', signed=False)


def gen_dili_pk():
    pk, sk = Dilithium2.keygen()
    # print(len(sk))
    return pk, sk

def gen_kyber_pk():
    # pk, sk = Kyber1024._cpapke_keygen()
    pk, sk = Kyber1024.keygen()
    # print(len(sk))
    return pk, sk

def gen_pk(opt="Dili"):
    if opt == "Dili":
        return gen_dili_pk()
    else:
        return gen_kyber_pk()

def gen_r():
    random_number = random.randint(0, 4294967295)
    seed_msg = bytes("Message is {}".format(random_number).encode('UTF-8'))
    
    # seed_msg = bytes("{}".format(random_number).encode('UTF-8'))
    # cipher = AES.new(b"seed_msg", AES.MODE_CTR, use_aesni='True')
    # r = cipher.encrypt(seed_msg)
    
    variant="Ascon-Hash"
    hashlength = 32
    r = ascon_hash(seed_msg, variant, hashlength)
    
    # print(random_number)
    # print(r.hex())
    return r


def gen_at(x_a, t, length=16000):
    t_bytes = t.to_bytes(4, byteorder='big')
    a_t_bytes = ascon_mac(x_a[0:16], t_bytes, "Ascon-Prf", length)
    a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
    return a_t


def padding(msg, target_len):
    msg_len = len(msg)
    padding_len = (target_len - msg_len)
    padding = []
    padding.extend([padding_len for _ in range(padding_len)])
    return msg + bytes(padding)

def unpadding(msg):
    msg_len = len(msg)
    padding_len = int(msg[-1])
    return msg[0:msg_len - padding_len]

def kyber_enc(plaintext, pk, r):
    target_len = int(Kyber1024.n / 8)
    msg_padding = padding(plaintext, target_len)
    ciphertext = Kyber1024._cpapke_enc(pk, msg_padding, r)
    return ciphertext

def kyber_dec(ciphertext, sk):
    msg = Kyber1024._cpapke_dec(sk, ciphertext)
    # print(msg)
    plaintext = unpadding(msg)
    return plaintext

def dili_sign(msg, sk, i=0, N=50):
    sig, _, __ = Dilithium2.sign_precomputed_only(sk, msg, N, N*i)
    return sig

def dili_verify(msg, sig, pk):
    ver = Dilithium2.verify_precomputed(pk, msg, sig)
    if ver == False:
        print("verify result = {}".format(ver)) 
    return ver

def kyber_encaps(pk):
    c, key = Kyber1024.enc(pk)
    return c, key

def kyber_decaps(sk, c):
    key = Kyber1024.dec(c, sk)
    return key


def message_size(m):
    total_size = sum(sys.getsizeof(item) for item in m)
    total_size_kb = total_size / 1024
    print(f"Total length: {len(m)}, size: {total_size} bytes, or {total_size_kb} KB")


def get_gradients(model):
    gradients = {name: param.grad for name, param in model.named_parameters()}
    # for name, param in model.named_parameters():
    #     print(name)
    #     print(param.grad.clone())
    #     print(param.grad.clone().shape)
    #     break
    return gradients

def get_parameters(model):
    params = {name: param for name, param in model.named_parameters()}
    # for name, param in model.named_parameters():
    #     print(name)
    #     print(param.grad.clone())
    #     print(param.grad.clone().shape)
    #     break
    return params

def gradients_to_np_array(gradients):
    mid_gradients = {}
    flat_gradients = []
    for name, grad in gradients.items():
        grad = grad.cpu()
        flat_grad = torch.flatten(grad)
        grad_np = flat_grad.numpy()
        mid_gradients[name] = grad_np
    flat_gradients = np.concatenate([arr for arr in mid_gradients.values()])
    return flat_gradients, mid_gradients

def params_to_np_array(params):
    mid_params = {}
    flat_params = []
    for name, param in params.items():
        param = param.cpu()
        flat_param = torch.flatten(param)
        param_np = flat_param.detach().numpy()
        mid_params[name] = param_np
    flat_params = np.concatenate([arr for arr in mid_params.values()])
    return flat_params, mid_params

def get_shape(model, gradients):
    original_shapes = {}
    for name, param in model.named_parameters():
        original_shapes[name] = [param.grad.shape, len(gradients[name])]
    return original_shapes

def np_array_to_gradients(flat_gradients, original_shapes, device='cuda:0'):
    gradients = {}
    i = 0
    for name in original_shapes:
        original_shape = original_shapes[name][0]
        shape_len = original_shapes[name][1]
        grad_np = flat_gradients[i: i+shape_len]
        param_grad_flat = torch.from_numpy(grad_np)
        param_grad = param_grad_flat.reshape(original_shape)
        gradients[name] = param_grad.to(device)
        i = i+shape_len
    return gradients

def compare_tensor_dicts(dict1, dict2):
    # check keys
    if dict1.keys() != dict2.keys():
        return False
    # check values
    for key in dict1:
        if not torch.equal(dict1[key], dict2[key]):
            return False
    return True


def generate_dili_keypair():
    pk = (ctypes.c_ubyte * 1312)()  # Assuming CRYPTO_PUBLICKEYBYTES is 1312
    sk = (ctypes.c_ubyte * 2528)()  # Assuming CRYPTO_SECRETKEYBYTES is 2528
    crypto_sign_keypair(pk, sk)
    return pk, sk


def generate_vector():
    w_arr = [bytes_to_int(gen_r()[:4]) for _ in range(VEC_LEN)]
    w = np.array(w_arr)
    for user_id in user_ids:
        # w_arr = [bytes_to_int(gen_r()[:4]) for _ in range(VEC_LEN)]
        # w = np.array(w_arr)
        # print("{} generate_vector".format(user_id))
        node_info[user_id]['VECTOR'][str(iter_num)] = w

# def gen_at(x_a, t, length=16):
#     # start_time = time.time()
#     t_bytes = t.to_bytes(4, byteorder='big')
    
#     # a_t_bytes = ascon_mac(x_a[0:16], t_bytes, "Ascon-Prf", length)
#     # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
#     # print("bytes len {}".format(len(a_t_bytes)))
#     # print(len(a_t))
    
#     nonce = b'\x00'*8
#     cipher = AES.new(x_a[0:16], AES.MODE_CTR, nonce=nonce, use_aesni='True')
#     a_t_bytes = cipher.encrypt(t_bytes)*(math.ceil(VEC_LEN/4))
#     a_t = np.frombuffer(a_t_bytes[0:VEC_LEN], dtype=np.uint8)
#     # print("bytes len {}".format(len(a_t_bytes)))
#     # print(cipher.nonce)
    
#     # nonce_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00'
#     # chacha_algo = ChaCha20.new(key=x_a[0:32], nonce=nonce_bytes)
#     # data = t_bytes
#     # a_t_bytes = chacha_algo.encrypt(data) *4000
#     # a_t = np.frombuffer(a_t_bytes, dtype=np.uint8)
    
#     # print("gen_at time: {}".format(time.time()-start_time))
#     return a_t

sign_count = 0
base = 100

def signature_calc(msg, sk):
    # Blake3 pre-hashing for messages
    # if len(msg) > 1000:
    #     hasher = blake3_hasher()
    #     blake_hash_init(ctypes.byref(hasher))
    #     blake_hash_update(ctypes.byref(hasher), msg, len(msg))
    #     message_bytes1 = (ctypes.c_uint8 * 16)()
    #     blake_hash_finalize(ctypes.byref(hasher), message_bytes1, len(message_bytes1))
    #     message_bytes = bytes(message_bytes1)
    # else:
    #     message_bytes = msg
    
    global sign_count
    message_bytes = msg
    # Dilithium signing
    mlen = len(message_bytes)
    # message_bytes = message.encode('utf-8')
    m = (ctypes.c_ubyte * len(message_bytes)).from_buffer_copy(message_bytes)
    sm = (ctypes.c_ubyte * (2420 + mlen))()  # Assuming CRYPTO_BYTES is 2420
    smlen = ctypes.c_size_t()
    round_num = crypto_sign_precompute(sm, ctypes.byref(smlen), m, mlen, sk, sign_count)
    sign_count = (sign_count + 1) % base
    return bytes(sm[:smlen.value-mlen])

def signature_verify(sig, msg, pk):
    # Blake3 pre-hashing
    # if len(msg) > 1000:
    #     hasher = blake3_hasher()
    #     blake_hash_init(ctypes.byref(hasher))
    #     blake_hash_update(ctypes.byref(hasher), msg, len(msg))
    #     message_bytes = (ctypes.c_uint8 * 16)()
    #     blake_hash_finalize(ctypes.byref(hasher), message_bytes, len(message_bytes))
    #     message_bytes = bytes(message_bytes)
    # else:
    #     message_bytes = msg
    message_bytes = msg
    sig_ptr = ctypes.cast(sig, ctypes.POINTER(ctypes.c_ubyte))
    pk_ptr = ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte))
    mlen = len(message_bytes)
    # message_bytes = message.encode('utf-8')
    m = (ctypes.c_ubyte * len(message_bytes)).from_buffer_copy(message_bytes)
    
    dt_protocol_start = pd.Timestamp('now')
    result = crypto_sign_verify(sig_ptr, len(sig), m, mlen, pk)
    return result == 0, dt_protocol_start
