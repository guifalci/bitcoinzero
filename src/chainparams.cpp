// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/consensus.h"
#include "zerocoin_params.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "libzerocoin/bitcoin_bignum/bignum.h"
#include <assert.h>
#include <boost/assign/list_of.hpp>
#include "chainparamsseeds.h"
#include "arith_uint256.h"

static CBlock CreateGenesisBlock(const char *pszTimestamp, const CScript &genesisOutputScript, uint32_t nTime, uint32_t nNonce,
                   uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
                   std::vector<unsigned char> extraNonce)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0x1f0fffff << CBigNum(4).getvch() << std::vector < unsigned
    char >
    ((const unsigned char *) pszTimestamp, (const unsigned char *) pszTimestamp + strlen(pszTimestamp)) << extraNonce;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward, std::vector<unsigned char> extraNonce)
{
    const char *pszTimestamp = "Lets Swap Hexx";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward, extraNonce);
}

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        strNetworkID = "main";
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 150; // every block
        consensus.nPowTargetSpacing = 150; // 2.5 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
		consensus.nRuleChangeActivationThreshold = 1900; // 95% of 100
        consensus.nMinerConfirmationWindow = 2000; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1462060800; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1479168000; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1517744282; //
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517744282; // 

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1517744282; //
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517744282; // 

        // bznode params
        strSporkPubKey = "04ffde6668d0dff8ba92c67b1f751568e11608f23c8c0437eccd5a6ec713ae3638238478b816783593d552bc8b6a57147dd67596eb372b0cadc743d3835c43e9e3";
        strBznodePaymentsPubKey = "04ffde6668d0dff8ba92c67b1f751568e11608f23c8c0437eccd5a6ec713ae3638238478b816783593d552bc8b6a57147dd67596eb372b0cadc743d3835c43e9e3";

		pchMessageStart[0] = { 'h' };
		pchMessageStart[1] = { 'e' };
		pchMessageStart[2] = { 'x' };
		pchMessageStart[3] = { 'x' };
        nDefaultPort = 29101;
        nPruneAfterHeight = 100000;
        std::vector<unsigned char> extraNonce(4);
		extraNonce[0] = 0x82;
		extraNonce[1] = 0x3f;
		extraNonce[2] = 0x00;
		extraNonce[3] = 0x00;
        genesis = CreateGenesisBlock(1485785935, 2610, 0x1f0fffff, 2, 0 * COIN, extraNonce);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x322bad477efb4b33fa4b1f0b2861eaf543c61068da9898a95062fdb02ada486f"));
        assert(genesis.hashMerkleRoot == uint256S("0x31f49b23f8a1185f85a6a6972446e72a86d50ca0e3b3ffe217d0c2fea30473db"));
        vSeeds.push_back(CDNSSeedData("76.74.170.128", "76.74.170.128"));
        vSeeds.push_back(CDNSSeedData("5.79.119.106", "5.79.119.106"));
        base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 10);
        base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 210);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container < std::vector < unsigned char > > ();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container < std::vector < unsigned char > > ();
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData)
		{
		boost::assign::map_list_of
        (   0, uint256S("0x322bad477efb4b33fa4b1f0b2861eaf543c61068da9898a95062fdb02ada486f"))
        (   1, uint256S("0xedcce7a202f07ea4ea2ca1883b7d70c6f44fa53f5f88ba62abe8f94284a1d7b3"))
        ( 801, uint256S("0xb3a950b3d94c2d1298cacc9089c8e3ba90fb425306cfbf04cc39282ac6a794d2")) // chain revert to fix zerocoin
        (15001, uint256S("0xc84d91a83ec6fa779e607fa7403e8708318f321c8364c6686205f7e70900cb98"))	
        (30001, uint256S("0x223dca0c2a6fd028dc4df4b5b4309985502ee839bc7dcd968494368007866540"))
        (204045, uint256S("0x49cd241e4f6ca0bcd882b470d41484cd51a89b04c52c50dba0f4cd07befc2031"))
        (220974, uint256S("0xd85b2231760133f521aec73e240c7867b62f4981aecbf4d2f797813925ecdccb"))
        (222665, uint256S("0x348fda46a431cc2b66f94f9086df05491d8c645576de3d5ab783434fd9c47043"))
        (258199, uint256S("0x012a7e8ad93aca202d3833f843e79b7eabf124e2697b7b411d51c352589ee2e6"))
        (267697, uint256S("0x3f0726ac75b77902e94cd172fc997ed7979d8238e28133f5300d09c87ba3d479")),
        1526792483, // * UNIX timestamp of last checkpoint block
        204045,    // * total number of transactions between genesis and last checkpoint
                  //   (the tx=... number in the SetBestChain debug.log lines)
		576.0 // * estimated number of transactions per day after checkpoint
		};

        nCheckBugFixedAtBlock = ZC_CHECK_BUG_FIXED_AT_BLOCK;
        nSpendV15StartBlock = ZC_V1_5_STARTING_BLOCK;
        nSpendV2ID_1 = ZC_V2_SWITCH_ID_1;
        nSpendV2ID_10 = ZC_V2_SWITCH_ID_10;
        nSpendV2ID_25 = ZC_V2_SWITCH_ID_25;
        nSpendV2ID_50 = ZC_V2_SWITCH_ID_50;
        nSpendV2ID_100 = ZC_V2_SWITCH_ID_100;
        nModulusV2StartBlock = ZC_MODULUS_V2_START_BLOCK;
        nModulusV1MempoolStopBlock = ZC_MODULUS_V1_MEMPOOL_STOP_BLOCK;
        nModulusV1StopBlock = ZC_MODULUS_V1_STOP_BLOCK;

        nForkStartHeight = 321700;
        nForkHeightRange = 1;

	}
};

static CMainParams mainParams;

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams()
	{
        strNetworkID = "test";
    }
};

static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams()
	{
        strNetworkID = "regtest";
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
	{
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};

static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(const std::string &chain) {
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout) {
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
