import json
import os
import random

from bitcoinx import PrivateKey, PublicKey, double_sha256, Signature, sha256, SigHash
from scryptlib import (
        compile_contract, build_contract_class, build_type_classes, Sig, create_dummy_input_context, get_preimage_from_input_context
        )


p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

if __name__ == '__main__':
    contract = 'p2group.scrypt' 

    #compiler_result = compile_contract(contract, debug=False)
    #desc = compiler_result.to_desc()

    # Load desc instead:
    with open('out/p2group_desc.json', 'r') as f:
        desc = json.load(f)

    type_classes = build_type_classes(desc)
    Point = type_classes['Point']

    n_keys = 3

    key_privs = []
    key_pubs = []
    key_pubs_bytes = b''.join([x.to_bytes(compressed=False) for x in key_pubs])
    key_pubs_points = []

    for i in range(n_keys):
        key_priv = PrivateKey.from_random()
        key_pub = key_priv.public_key
        key_privs.append(key_priv)
        key_pubs.append(key_pub)

        x, y = key_pub.to_point()
        key_pubs_points.append(Point({'x': x, 'y': y}))

    G = PrivateKey.from_int(1).public_key
    st = G.to_bytes(compressed=False) + key_pubs_bytes

    P2G = build_contract_class(desc)
    p2g = P2G(key_pubs_points, st)

    context = create_dummy_input_context()
    context.utxo.script_pubkey = p2g.locking_script
    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    tx_preimage = get_preimage_from_input_context(context, sighash_flag)

    # Choose which one of the key holders is going to prove knowledge.
    j = 1
    x = key_privs[j]
    PKj = key_pubs[j]

    a = PrivateKey.from_random() 
    Aj = a.public_key

    sub_out = []
    e_sum = 0
    for i in range(n_keys):
        if i == j:
            sub_out.append((Aj, None, None))
            continue
        e_int = random.randint(1, 2**128 - 1)
        ei = PrivateKey.from_int(e_int)
        ei_neg = PrivateKey.from_int((e_int * -1 + order) % p)

        zi = PrivateKey.from_random()
        A_1 = G.multiply(zi._secret)
        A_2 = key_pubs[i].multiply(ei_neg._secret)
        Ai = PublicKey.combine_keys([A_1, A_2])

        sub_out.append((Ai, ei.to_int(), zi.to_int()))

        e_sum += e_int

    o = int.from_bytes(
            sha256(
                tx_preimage + st + b''.join([out[0].to_bytes(compressed=False) for out in sub_out])
            ), byteorder='little') % 2**128
    e = (o - e_sum) % 2**128
    z = PrivateKey.from_int((a.to_int() + e * x.to_int()) % p).to_int()

    e_all = []
    z_all = []
    for i in range(n_keys):
        if i == j:
            e_all.append(e)
            z_all.append(z)
        else:
            _, ei, zi = sub_out[i]
            e_all.append(ei)
            z_all.append(zi)

    ### Proof verificiation in Python
    ser_as = b''
    sum_e_vals = 0
    for i in range(n_keys):
        ei_neg = PrivateKey.from_int((e_all[i] * -1 + order) % p)

        A_1 = G.multiply(PrivateKey.from_int(z_all[i])._secret)
        A_2 = key_pubs[i].multiply(ei_neg._secret)
        Ai = PublicKey.combine_keys([A_1, A_2])
        ser_as +=  Ai.to_bytes(compressed=False)

        sum_e_vals += e_all[i]

    print(ser_as.hex())
    o = int.from_bytes(sha256(tx_preimage + st + ser_as), byteorder='little') % 2**128
    # TODO: compare o values... should be the same?
    assert o == (sum_e_vals % 2**128)


    ### Contract evaluation


