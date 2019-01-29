// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

#include "arith_uint256.h"
#include "primitives/block.h"
#include "pow.h"
#include "tinyformat.h"
#include "uint256.h"

#include <vector>

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(VARINT(nFile));
        READWRITE(VARINT(nPos));
    }

    CDiskBlockPos() {
        SetNull();
    }

    CDiskBlockPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return !(a == b);
    }

    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    std::string ToString() const
    {
        return strprintf("CBlockDiskPos(nFile=%i, nPos=%i)", nFile, nPos);
    }

};

enum BlockStatus {
    //未使用
    //! Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    //解析时版本正常，哈希声明满足PoW，1 <= vtx count <= max，时间戳不在将来
    //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER       =    1,

    //找到所有父标题，难度匹配，时间戳> =中位数前一个检查点。 意味着所有的父母至少也是TREE。
    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    /**
     * 只有第一个tx是coinbase，2 <= coinbase输入脚本长度<= 100，
    交易有效，没有重复的txids，sigops，大小，merkle根。
    意味着所有父母至少是TREE，但不一定是TRANSACTIONS。
    当所有父块都有TRANSACTIONS时，CBlockIndex :: nChainTx将会被设置。
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
     */
    BLOCK_VALID_TRANSACTIONS =    3,

    // 输出不会超支输入，没有双重花费，coinbase输出正常，
    // 没有不成熟的硬币，BIP30。
    // 意味着所有的父母也至少在链中。
    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    // 脚本和签名确定。 意味着所有的父母也至少是脚本。
    //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    //! All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, //! full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, //! undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID       =   32, //! stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, //! descends from failed block
    BLOCK_FAILED_MASK        =   BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block. A blockindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class CBlockIndex
{
public:
    //! pointer to the hash of the block, if any. Memory is owned by this CBlockIndex
    const uint256* phashBlock;

    //! pointer to the index of the predecessor of this block
    CBlockIndex* pprev;

    //! pointer to the index of some further predecessor of this block
    CBlockIndex* pskip;

    //! height of the entry in the chain. The genesis block has height 0
    int nHeight;

    //! Which # file this block is stored in (blk?????.dat)
    int nFile;

    //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos;

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos;

    //! (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    arith_uint256 nChainWork;

    //! Number of transactions in this block.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx;////块的交易数量

    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero only if and only if transactions for this block and all its parents are available.
    //! Change to 64-bit type when necessary; won't happen before 2030
    //包括此块在内的链中的交易数量，当且仅当此块及其所有父项的交易可用时，才会设置此值
    /**
     * nChainTx只存储在内存中; 数据库中没有对应的条目。
     * 因此，nChainTx> 0是一个 VALID_TRANSACTIONS 链的简写。 注意，这个信息不能通过块状态枚举来获得。 也就是说，VALID_TRANSACTIONS 只意味着它的父母是 TREE，而 VALID_CHAIN 意味着父母也是 CHAIN。 因此，从某种意义上来说，表达式（nChainTx！= 0）是可以被称为 “VALID_nChainTx = 3.5”的状态的缩写 - 因为它比VALID_TRANSACTIONS更多但是小于VALID_CHAIN。
     */
    unsigned int nChainTx;

    //! Verification status of this block. See enum BlockStatus
    unsigned int nStatus;

    //! block header
    int nVersion;
    uint256 hashMerkleRoot;
    unsigned int nTime;
    unsigned int nBits;
    unsigned int nNonce;

    //! (memory only) Sequential id assigned to distinguish order in which blocks are received.
    uint32_t nSequenceId;

    void SetNull()
    {
        phashBlock = NULL;
        pprev = NULL;
        pskip = NULL;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainWork = arith_uint256();
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;
        nSequenceId = 0;

        nVersion       = 0;
        hashMerkleRoot = uint256();
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
    }

    CBlockIndex()
    {
        SetNull();
    }

    CBlockIndex(const CBlockHeader& block)
    {
        SetNull();

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
    }

    CDiskBlockPos GetBlockPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_DATA) {
            ret.nFile = nFile;
            ret.nPos  = nDataPos;
        }
        return ret;
    }

    CDiskBlockPos GetUndoPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_UNDO) {
            ret.nFile = nFile;
            ret.nPos  = nUndoPos;
        }
        return ret;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    enum { nMedianTimeSpan=11 };

    int64_t GetMedianTimePast() const
    {
        int64_t pmedian[nMedianTimeSpan];
        int64_t* pbegin = &pmedian[nMedianTimeSpan];
        int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    std::string ToString() const
    {
        return strprintf("CBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
            pprev, nHeight,
            hashMerkleRoot.ToString(),
            GetBlockHash().ToString());
    }

    //! Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }

    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(enum BlockStatus nUpTo)
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this block.
    CBlockIndex* GetAncestor(int height);
    const CBlockIndex* GetAncestor(int height) const;
};

/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;

    CDiskBlockIndex() {
        hashPrev = uint256();
    }

    explicit CDiskBlockIndex(const CBlockIndex* pindex) : CBlockIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBlockHash() : uint256());
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(VARINT(nVersion));

        READWRITE(VARINT(nHeight));
        READWRITE(VARINT(nStatus));
        READWRITE(VARINT(nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
            READWRITE(VARINT(nFile));
        if (nStatus & BLOCK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    uint256 GetBlockHash() const
    {
        CBlockHeader block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        return block.GetHash();
    }


    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s)",
            GetBlockHash().ToString(),
            hashPrev.ToString());
        return str;
    }
};

/**
 * CChain类是一个CBlockIndex的序列链。这个结构就很像我们经常说的区块链了。
 * 可以看到CBlockIndex基本上满足了区块的结构。通过这个类的结构可以看到这个类包括了区块头的信息，但没有交易信息，所以还不算是区块。
 * 但这个类记录了区块的存储文件地址，区块高度，区块哈希和父哈希及工作量证明和验证状态和交易数量。
 * 关于这块的内容可以看《精通比特币》的第七章。在CChain类中可以看到我们的对象chainActive。
 * 通过注释可以知道它表示当前已经连接的一个块链

 */
/** An in-memory indexed chain of blocks. */
class CChain {
private:
    std::vector<CBlockIndex*> vChain;

public:
    /** Returns the index entry for the genesis block of this chain, or NULL if none. */
    CBlockIndex *Genesis() const {
        return vChain.size() > 0 ? vChain[0] : NULL;
    }

    /** Returns the index entry for the tip of this chain, or NULL if none. */
    CBlockIndex *Tip() const {
        return vChain.size() > 0 ? vChain[vChain.size() - 1] : NULL;
    }

    /** Returns the index entry at a particular height in this chain, or NULL if no such height exists. */
    CBlockIndex *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return NULL;
        return vChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain &a, const CChain &b) {
        return a.vChain.size() == b.vChain.size() &&
               a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const {
        return (*this)[pindex->nHeight] == pindex;
    }

    /** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
    CBlockIndex *Next(const CBlockIndex *pindex) const {
        if (Contains(pindex))
            return (*this)[pindex->nHeight + 1];
        else
            return NULL;
    }

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const {
        return vChain.size() - 1;
    }

    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator GetLocator(const CBlockIndex *pindex = NULL) const;

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;
};

#endif // BITCOIN_CHAIN_H
