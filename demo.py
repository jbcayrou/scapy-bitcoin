#!/usr/bin/env python

from bitcoin import *


#################################################################################
# A demo script which genearates basic sameple binary packages for each message #
#################################################################################
if __name__ == "__main__":

    # version
    pkt = BitcoinHdr() / BitcoinVersion(
        version=70001, user_agent=VarStrPktField(data="User_Agent"),
    )
    with open("samples/version.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # addr
    pkt = BitcoinHdr() / BitcoinAddr(
        count=2, addr_list=[AddrPktField(), AddrPktField()]
    )
    with open("samples/addr.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # inv
    pkt = BitcoinHdr() / BitcoinInv(
        inventory=[
            InventoryPktField(hash="randomHash"),
            InventoryPktField(hash="HashRandom"),
            InventoryPktField(hash="nothinghash"),
        ]
    )
    with open("samples/inv.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # getdata
    pkt = BitcoinHdr() / BitcoinGetdata(
        inventory=[InventoryPktField(hash="DataRandomHash"),]
    )
    with open("samples/getdata.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # notfound
    pkt = BitcoinHdr() / BitcoinNotfound(
        inventory=[
            InventoryPktField(hash="NotfoundRandomHash"),
            InventoryPktField(hash="NotfoundHashRandom"),
        ]
    )
    with open("samples/notfound.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # getblocks
    pkt = BitcoinHdr() / BitcoinGetblocks(
        version=70001, hashes=["xxx", "yyyy"], hash_stop="",
    )
    with open("samples/getblocks.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # getheaders
    pkt = BitcoinHdr() / BitcoinGetheaders(version=70001, hashes=[], hash_stop="")
    with open("samples/getheaders.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # tx
    pkt = BitcoinHdr() / BitcoinTx(
        version=70001,
        tx_in_count=4,
        tx_in=[TxInPktField(), TxInPktField(), TxInPktField(), TxInPktField()],
        tx_out_count=2,
        tx_out=[TxOutPktField(), TxOutPktField()],
    )
    with open("samples/tx.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # block
    pkt = BitcoinHdr() / BitcoinBlock(
        version=70001, bits=40, txns=[BitcoinTx(), BitcoinTx(), BitcoinTx()]
    )
    with open("samples/block.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # headers
    pkt = BitcoinHdr() / BitcoinHeaders(
        headers=[
            BlockHeaderPktField(),
            BlockHeaderPktField(),
            BlockHeaderPktField(),
            BlockHeaderPktField(),
            BlockHeaderPktField(),
            BlockHeaderPktField(),
        ]
    )
    with open("samples/headers.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # ping
    pkt = BitcoinHdr() / BitcoinPing()
    with open("samples/ping.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # pong
    pkt = BitcoinHdr() / BitcoinPong()
    with open("samples/pong.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # reject
    pkt = BitcoinHdr() / BitcoinReject(
        message=VarStrPktField(data="It's a message about reject"),
        reason=VarStrPktField(data="Reason of reject"),
    )
    with open("samples/reject.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # filterload
    pkt = BitcoinHdr() / BitcoinFilterload(filter=VarStrPktField(data="xxserrsfggt"))
    with open("samples/filterload.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # filteradd
    pkt = BitcoinHdr() / BitcoinFilteradd(filter=VarStrPktField(data="qwerty"))
    with open("samples/filteradd.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # merkleblock
    pkt = BitcoinHdr() / BitcoinMerkleblock(
        hashes=["hash1", "hash2", "hash"], flags=[1, 2, 3, 4]
    )
    with open("samples/merkleblock.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # feefilter
    pkt = BitcoinHdr() / BitcoinFeefilter(feerate=10)
    with open("samples/feefilter.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # sendcmpct
    pkt = BitcoinHdr() / BitcoinSendcmpct()
    with open("samples/sendcmpct.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # cmpctblock
    pkt = BitcoinHdr() / BitcoinCmpctblock(
        shortids=[12, 11, 77, 45],
        prefilled_txn=[PrefilledTxn(), PrefilledTxn(), PrefilledTxn()],
    )
    with open("samples/cmpctblock.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # getblocktxn
    pkt = BitcoinHdr() / BitcoinGetblocktxn(
        block_hash="blockhash", indexes=[15, 22, 225]
    )
    with open("samples/getblocktxn.bin", "wb") as myFile:
        myFile.write(raw(pkt))

    # blocktxn
    pkt = BitcoinHdr() / BitcoinBlocktxn(
        transactions=[BitcoinTx(), BitcoinTx(), BitcoinTx(), BitcoinTx()]
    )
    with open("samples/blocktxn.bin", "wb") as myFile:
        myFile.write(raw(pkt))
