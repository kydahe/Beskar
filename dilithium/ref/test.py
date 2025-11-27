import ctypes
import os

fips202_lib = ctypes.CDLL('/home/zhan4630/pq_fl_project/dilithium/ref/libpqcrystals_dilithium2_ref.so')
lib = ctypes.CDLL('/home/zhan4630/pq_fl_project/dilithium/ref/libpqcrystals_dilithium2_ref.so')


# 声明函数原型
crypto_sign_keypair = lib.crypto_sign_keypair
crypto_sign_keypair.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
crypto_sign_keypair.restype = ctypes.c_int

crypto_sign = lib.crypto_sign
crypto_sign.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t),
                        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_ubyte)]
crypto_sign.restype = ctypes.c_int


def generate_keypair():
    pk = (ctypes.c_ubyte * 64)()  # Assuming CRYPTO_PUBLICKEYBYTES is 64
    sk = (ctypes.c_ubyte * 128)()  # Assuming CRYPTO_SECRETKEYBYTES is 128
    crypto_sign_keypair(pk, sk)
    return pk, sk

def sign_message(message, sk):
    mlen = len(message)
    sm = (ctypes.c_ubyte * (128 + mlen))()  # Assuming CRYPTO_BYTES is 128
    smlen = ctypes.c_size_t()
    crypto_sign(sm, ctypes.byref(smlen), message.encode('utf-8'), mlen, sk)
    return bytes(sm[:smlen.value])

# 生成密钥对
pk, sk = generate_keypair()

# 要签名的消息
message = "Hello, world!"

# 对消息进行签名
signature = sign_message(message, sk)

print("Public key:", pk)
print("Signature:", signature.hex())

