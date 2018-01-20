// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

using namespace std;

#include "chainparamsseeds.h"

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "ZCL";
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 2;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 8033;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        /**
         * Build the genesis block. Note that the output of its generation
         * transaction cannot be spent since it did not originally exist in the
         * database (and is in any case of zero value).
         *
         * >>> from pyblake2 import blake2s
         * >>> 'Zclassic' + blake2s(b'No taxation without representation. BTC #437541 - 00000000000000000397f175a94dd3f530b957182eb2a9f7b79a44a94a5e0450').hexdigest()
         */
        const char* pszTimestamp = "Zclassic860413afe207aa173afee4fcfa9166dc745651c754a41ea8f155646f5aa828ac";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 4;
        genesis.nTime    = 1478403829;
        genesis.nBits    = 0x1f07ffff;
        genesis.nNonce   = uint256S("0x000000000000000000000000000000000000000000000000000000000000021d");
        genesis.nSolution = ParseHex("009aaa951ca873376788d3002918d956e371bdf03c1afcfd8eea17867b5480d2e59a2a4dd52ed0d091af0c0909aa66ce2da97266926a9ea69b9ccca389bc120d9c4dbbae727ab9d6dfd1cd847df0ef0cc9bc989f11bdd6522429c15957daa3c5a2612522ded69857c148c0638611a19287599b47683c714b5774d0fcb1341cf4fc3a546a2441a19f02a55c6f9775749e57783b2abd5b25d41753d2f60892bbb4c3173d7787dbf5e50267324db218a14dd65f71bb02cf2566d3201800f866701db8c221424b75c639de58e7e40705157ae7d10da708ec2b9e71b9bc1ad34854a7bdf58d93766b6e291d3b545fa1f785a1a9829eccd525d16856f4317f0449d5c3516736f1e564f17690f13d3c939ad5516f1db70194902c20afd939168037fa404ec962dfbe752f79ac87a2cc3fd07bcd94d1975b1849cc739c0bc144ae4e75eda1bbed5b5ef8f65966257ec7b1fc6bb600e12e1c65c8c13a505f35dd363e07b6238211a0e502e36db5a620310b544360dd9b4a6cedabc34eeb530139daad50d4a5b6eaf4d50be4ba10e970ce984fb705376a3b0b4bf3f3778600f14e739e04406106f707085ab87ca70598c032b6717a54a9fd8ef72fdd78fb41fa9d45ad685caf77e0fc42e8e644634c24bc972f3ab0e3f0345854eda624045feb6bc9d20b5b1fc6903ebc64026e51da598c0d8711c452131a8fd2bbe01403af20e5db88afcd53b6107f001dae78b548d6a1581baca15359de83e54e75d8fc6374ca1edec17a9f4b06931162f9952575c5c3fb5dfc70a0f793049e781926daaafd4f4d330cf7d5635af1541f0d29e709a37c088d6d2e7aa09d15dfb9c2ae6c1ce661e85e9d89772eb47cfea00c621b66faf8a48cfa970b898dbd77b14e7bf44b742c00f76d2435f949f027132adb1e974551488f988e9fe379a0f86538ee59e26637a3d50bf400c7f52aa9457d77c3eb426628bb17909b26a6820d0772d4c6f74472f635e4c6e72272ce01fc475df69e10371457c55e0fbdf3a392850b9924da9c9a55792325c4318562593f0df8d39559065be03a22b1b6c21206aa1958a0d33257d89b74dea42a11aabf8eddbfe6136ab649744b704eb3e3d473654b588927dd9f486c1cd02639cf656ccbf2c4869c2ed1f2ba4ec55e69a42d5af6b3605a0cdf987734727c6fc1c1489870fb300139328c4d12eb6f5e8309cc09f5f3c29ab0957374113931ec9a56e7579446f12faacda9bd50899a17bd0f78e89ed70a723fdadfb1f4bc3317c8caa32757901604fb79ae48e22251c3b1691125ec5a99fabdf62b015bc817e1c30c06565a7071510b014058a77856a150bf86ab0c565b8bbbed159e2fb862c6215752bf3f0563e2bbbf23b0dbfb2de21b366b7e4cda212d69502643ca1f13ce362eef7435d60530b9999027dd39cd01fd8e064f1ccf6b748a2739707c9f76a041f82d3e046a9c184d83396f1f15b5a11eddb2baff40fc7b410f0c43e36ac7d8ff0204219abe4610825191fbb2be15a508c839259bfd6a4c5204c779fad6c23bbd37f90709654a5b93c6f93b4c844be12cd6cd2200afbf600b2ae9b6c133d8cdb3a85312a6d9948213c656db4d076d2bacd10577d7624be0c684bd1e5464bb39006a524d971cd2223ae9e23dea12366355b3cc4c9f6b8104df6abd23029ac4179f718e3a51eba69e4ebeec511312c423e0755b53f72ac18ef1fb445d7ab83b0894435a4b1a9cd1b473792e0628fd40bef624b4fb6ba457494cd1137a4da9e44956143068af9db98135e6890ef589726f4f5fbd45a713a24736acf150b5fb7a4c3448465322dccd7f3458c49cf2d0ef6dd7dd2ed1f1147f4a00af28ae39a73c827a38309f59faf8970448436fbb14766a3247aac4d5c610db9a662b8cb5b3e2");

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602"));
        assert(genesis.hashMerkleRoot == uint256S("0x19612bcf00ea7611d315d7f43554fa983c6e8c30cba17e52c679e0e80abf7d42"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("zclassic.org", "dnsseed.zclassic.org")); // zclassic
        vSeeds.push_back(CDNSSeedData("indieonion.org", "dnsseed.indieonion.org")); // @IndieOnion
        vSeeds.push_back(CDNSSeedData("rotorproject.org", "dnsseed.rotorproject.org")); // @IndieOnion

        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock)
            ( 30000, uint256S("0x000000005c2ad200c3c7c8e627f67b306659efca1268c9bb014335fdadc0c392"))
            ( 160000, uint256S("0x000000065093005a1a46ee95d6d66c2b07008220ca64dd3b3a93bbd1945480c0")),
            1502742046,     // * UNIX timestamp of last checkpoint block
            392489,          // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1413            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
//          "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd", /* main-index: 0*/
//            "t3cL9AucCajm3HXDhb5jBnJK2vapVoXsop3", /* main-index: 1*/
//            "t3fqvkzrrNaMcamkQMwAyHRjfDdM2xQvDTR", /* main-index: 2*/
//            "t3TgZ9ZT2CTSK44AnUPi6qeNaHa2eC7pUyF", /* main-index: 3*/
//            "t3SpkcPQPfuRYHsP5vz3Pv86PgKo5m9KVmx", /* main-index: 4*/
//            "t3Xt4oQMRPagwbpQqkgAViQgtST4VoSWR6S", /* main-index: 5*/
//            "t3ayBkZ4w6kKXynwoHZFUSSgXRKtogTXNgb", /* main-index: 6*/
//            "t3adJBQuaa21u7NxbR8YMzp3km3TbSZ4MGB", /* main-index: 7*/
//            "t3K4aLYagSSBySdrfAGGeUd5H9z5Qvz88t2", /* main-index: 8*/
//            "t3RYnsc5nhEvKiva3ZPhfRSk7eyh1CrA6Rk", /* main-index: 9*/
//            "t3Ut4KUq2ZSMTPNE67pBU5LqYCi2q36KpXQ", /* main-index: 10*/
//            "t3ZnCNAvgu6CSyHm1vWtrx3aiN98dSAGpnD", /* main-index: 11*/
//            "t3fB9cB3eSYim64BS9xfwAHQUKLgQQroBDG", /* main-index: 12*/
//            "t3cwZfKNNj2vXMAHBQeewm6pXhKFdhk18kD", /* main-index: 13*/
//            "t3YcoujXfspWy7rbNUsGKxFEWZqNstGpeG4", /* main-index: 14*/
//            "t3bLvCLigc6rbNrUTS5NwkgyVrZcZumTRa4", /* main-index: 15*/
//            "t3VvHWa7r3oy67YtU4LZKGCWa2J6eGHvShi", /* main-index: 16*/
//            "t3eF9X6X2dSo7MCvTjfZEzwWrVzquxRLNeY", /* main-index: 17*/
//            "t3esCNwwmcyc8i9qQfyTbYhTqmYXZ9AwK3X", /* main-index: 18*/
//            "t3M4jN7hYE2e27yLsuQPPjuVek81WV3VbBj", /* main-index: 19*/
//            "t3gGWxdC67CYNoBbPjNvrrWLAWxPqZLxrVY", /* main-index: 20*/
//            "t3LTWeoxeWPbmdkUD3NWBquk4WkazhFBmvU", /* main-index: 21*/
//            "t3P5KKX97gXYFSaSjJPiruQEX84yF5z3Tjq", /* main-index: 22*/
//            "t3f3T3nCWsEpzmD35VK62JgQfFig74dV8C9", /* main-index: 23*/
//            "t3Rqonuzz7afkF7156ZA4vi4iimRSEn41hj", /* main-index: 24*/
//            "t3fJZ5jYsyxDtvNrWBeoMbvJaQCj4JJgbgX", /* main-index: 25*/
//            "t3Pnbg7XjP7FGPBUuz75H65aczphHgkpoJW", /* main-index: 26*/
//            "t3WeKQDxCijL5X7rwFem1MTL9ZwVJkUFhpF", /* main-index: 27*/
//            "t3Y9FNi26J7UtAUC4moaETLbMo8KS1Be6ME", /* main-index: 28*/
//            "t3aNRLLsL2y8xcjPheZZwFy3Pcv7CsTwBec", /* main-index: 29*/
//            "t3gQDEavk5VzAAHK8TrQu2BWDLxEiF1unBm", /* main-index: 30*/
//            "t3Rbykhx1TUFrgXrmBYrAJe2STxRKFL7G9r", /* main-index: 31*/
//            "t3aaW4aTdP7a8d1VTE1Bod2yhbeggHgMajR", /* main-index: 32*/
//            "t3YEiAa6uEjXwFL2v5ztU1fn3yKgzMQqNyo", /* main-index: 33*/
//            "t3g1yUUwt2PbmDvMDevTCPWUcbDatL2iQGP", /* main-index: 34*/
//            "t3dPWnep6YqGPuY1CecgbeZrY9iUwH8Yd4z", /* main-index: 35*/
//            "t3QRZXHDPh2hwU46iQs2776kRuuWfwFp4dV", /* main-index: 36*/
//            "t3enhACRxi1ZD7e8ePomVGKn7wp7N9fFJ3r", /* main-index: 37*/
//            "t3PkLgT71TnF112nSwBToXsD77yNbx2gJJY", /* main-index: 38*/
//            "t3LQtHUDoe7ZhhvddRv4vnaoNAhCr2f4oFN", /* main-index: 39*/
//            "t3fNcdBUbycvbCtsD2n9q3LuxG7jVPvFB8L", /* main-index: 40*/
//            "t3dKojUU2EMjs28nHV84TvkVEUDu1M1FaEx", /* main-index: 41*/
//            "t3aKH6NiWN1ofGd8c19rZiqgYpkJ3n679ME", /* main-index: 42*/
//            "t3MEXDF9Wsi63KwpPuQdD6by32Mw2bNTbEa", /* main-index: 43*/
//            "t3WDhPfik343yNmPTqtkZAoQZeqA83K7Y3f", /* main-index: 44*/
//            "t3PSn5TbMMAEw7Eu36DYctFezRzpX1hzf3M", /* main-index: 45*/
//            "t3R3Y5vnBLrEn8L6wFjPjBLnxSUQsKnmFpv", /* main-index: 46*/
//            "t3Pcm737EsVkGTbhsu2NekKtJeG92mvYyoN", /* main-index: 47*/
////            "t3PZ9PPcLzgL57XRSG5ND4WNBC9UTFb8DXv", /* main-index: 48*/
////            "t3L1WgcyQ95vtpSgjHfgANHyVYvffJZ9iGb", /* main-index: 49*/
////            "t3JtoXqsv3FuS7SznYCd5pZJGU9di15mdd7", /* main-index: 50*/
////            "t3hLJHrHs3ytDgExxr1mD8DYSrk1TowGV25", /* main-index: 51*/
////            "t3fmYHU2DnVaQgPhDs6TMFVmyC3qbWEWgXN", /* main-index: 52*/
////            "t3T4WmAp6nrLkJ24iPpGeCe1fSWTPv47ASG", /* main-index: 53*/
////            "t3fP6GrDM4QVwdjFhmCxGNbe7jXXXSDQ5dv", /* main-index: 54*/
};
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "ZCT";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.fPowAllowMinDifficultyBlocks = true;
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 18233;
        nPruneAfterHeight = 1000;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1516404575;
        genesis.nBits = 0x2007ffff;
        genesis.nNonce = uint256S("0x000000000000000000000000000000000000000000000000000000000000001b");
        genesis.nSolution = ParseHex("010a4ddefd0a679ddc32f029b23139695a426db6800e2811cd701563076799018c572034698ef2fefa1616c1064fc72b6ae5b444d8d235720dba3f4214e1de4d943a81885495daa5b7e5c948f9344722f8bbfe8304df83c0b45aef7d803115734a4c902354641d2732064d091233c6e06ceaa523b0d5d829cf8ebfde873c12206985a349dd569aed757a1bb27a6266e915a4462cd3c19376537b0eb305459189bd92764e36f7900d0b0d0699bad1e0e32a7913b9522f0ba712051d622b1f8e2c211191efaca6388332892ace0227effaa89010f54bb430d5d70ad6ef95ac48c6d7272c2ddc20f231ee71f640cf29a36a6363c6372cd12171b0ee86e01ba021a13b9775d39d3136a149f11ebe0e4a70f06c2dee6c0c7b5c5c57ca96447d7a54e7b1d49ada834e1d28c9ce21692a03f40c935c4e7b0a75913294518022721fbe92615cf5d3a3b318f5aa434d61d151c1a003fe53d58354eb45e523408d1f3de01071401a76e00af72705c7c88d82fc8041c08129c8c4fad4f09e8716398b96cfc7878bab433469cf7395b9e5108ff1f53d5c2a1ac9cf8cf76696b45b4f7b0723bc323e23a512cb02857f09d07dfc5b628faaab58df080c1d22c91cfddca12f081e2086b406db7d7b36aa456bd8470c18dbe662236e1cc7e2de828fb5290891a176b6870f425d522e32f1f453d02ab66292bded3e70febabc550762fbdc1002a9a61aa5315539adcf67ab4efd60f424c12ecd9615194dabb905bc193459b20311926dac1ffd7a96b4966aaec8b7779af1ffb84638fd77919b2a3795ffcd90d121c3b462ce92bac5da3071180b5a0cb6e1fdcae6bb61ce6b737138a209d23c83d207721df98a4aee935e85e0fd244ad0aecd6331077b2c8013f025b5e8d9ec410dffe74bc5531d4284c85ca7bf1c76f5da1d5ce0139662c277706b43dad4b37e6537013e300c4ff37ef9e02110329f334aaddaf8bd07171f6fdf99fa4c6928efdd13f625ead13a2e94f1c4d021a584cb84eb58735fd6876b0eeebfdef60f5cbc913290676abca5aabf667f75f8f5b210b5e6ad3e8fde068a07550d880c897cbbb0b7baa9429998c6adecb30bbc613a77dd82fdcfcef607b75bc31f234a3a05b20ad1b11527cec9f2872b02221257fc9d045d5a200a0f1417412d9e9c1df998338c0e570e7524de79aeaf01a8dfe320dbc2ad913e42abd15ab8bb19ac9cb35c11345a8df7863a8bfecd01d0ef9ad761fbf5d0aeed13d933f4fc5ea7fde65f2184707a6255a556349aad4ace2bd9e076e743f09b56128adfd3272b265b715904f8c39fbdf33883adc8136def5ca2ca847fdd9fc460ff7cee4125c005acf0c70f1342bb43ce05ffe6d5068a4ca0d8479bf56652a06be15e62f9865ab6d70a07efbb71a2258197f7d8211ceb1fba6d119b1aab550323b2fe1263c3db467d94dfabb8595a02909cbbe408d03e846298be2d743b739a237caa490d956ead7f178b4c53288f61eda2a189a5a2cea2f29fb41e0d4a235077098a5fa3b1bd51866b97f69c1252f69ada320a6a170711f5c671b51a613d273711898cda4e18af6f485ffc336db419a17e37a01063b9d1f3629288cd1a6a42671550766490dea4178934e01df6c6f7cbd631292ac720f58043d1ae939852d929a1b8cab1c3b10acf5b972c1b4f1decb0c29da82d6c98eada9487d823fbcfd39255bfbeb5d2f2d6c51aa591e79ef19b0f47468c03b617b5a3a2fc480e60715d223f23947d31492fce6e70ba0099e239074ab17ab07614aa3dfc6e14db2906af66866ff2963555f0fb37534f9ebc7ee819c2e4f693f3d757f54f742872c9cb897b77d81fd1276902e9bf5489879d72c33e04d671050818b4a6af2f7ff28cfd536dcb7aa855cdb9bf0705cfc7900c7d");
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x070fb9e93f924b7b8ec5864bb157950979d75716389487bb22647c32a87b5948"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("rotorproject.org", "test-dnsseed.rotorproject.org")); // Zclassic

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (Checkpoints::CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = {
        /*
            "t2UNzUUx8mWBCRYPRezvA363EYXyEpHokyi", "t2N9PH9Wk9xjqYg9iin1Ua3aekJqfAtE543", "t2NGQjYMQhFndDHguvUw4wZdNdsssA6K7x2", "t27ktmq1kbeCWiQ5TZ7w5npSzcdbBmTB7v6",
            "t2GcBttAKD2WTHka8HyGc2dfvVTKYZUfHmJ", "t2Q3vxWaD9LrdqUE8Xd9Ddjpr9pUQ2aGotK", "t2TTfWDsYu998fHWzVP9Gns4fgxXXRi1Wzu", "t2KS6R4MMWdSBMjLCiw2iMyhWGRQPmyRqDn",
            "t2Q2ELrgotWv3Eec6LEtMMiiQ8dtW38u8Tj", "t2AEgJA88vTWAKqxJDFUEJWyHUtQAZi5G1D", "t2HCSdmpq1TQKksuwPQevwAzPTgfJ2rkMbG", "t2HQCPFAUQaUdJWHPhg5pPBxit7inaJzubE",
            "t2Fzqvq8Y9e6Mn3JNPb982aYsLmq4b5HmhH", "t2HEz7YZQqDUgC5h4y2WSD3mWneqJNVRjjJ", "t2GCR1SCk687Eeo5NEZ23MLsms7JjVWBgfG", "t2KyiPR9Lztq2w1w747X6W4nkUMAGL8M9KN",
            "t2UxymadyxSyVihmbq7S1yxw5dCBqJ1S4jT", "t2AVeMy7fdmTcJhckqiKRG8B7F1vccEhSqU", "t26m7LwihQzD2sH7ZVhYpPJM5j7kzwbfKW9", "t2DgwUNTe7NxuyPU6fxsB5xJXap3E4yWXrN",
            "t2U6funcXA11fC9SZehyvUL3rk3Vhuh7fzS", "t284JhyS8LGM72Tx1porSqwrcq3CejthP1p", "t29egu8QcpzKeLoPLqWS6QVMnUUPQdF6eNm", "t29LqD9p9D3B26euBwFi6mfcWu8HPA38VNs",
            "t28GsAMCxAyLy85XaasddDzaYFTtfewr86y", "t2GV44QyaikQPLUfm6oTfZnw71LLjnR7gDG", "t2U2QzNLQ1jtAu4L6xxVnRXLBsQpQvGRR2g", "t2QKGr5PNan7nrwDgseyHMN9NFeeuUjCh8b",
            "t2AfS8u6HwBeJpKpbuxztvRjupKQDXqnrwa", "t2CTRQUViQd3CWMhnKhFnUHqDLUyTxmWhJs", "t2CbM9EqszNURqh1UXZBXYhwp1R4GwEhWRE", "t2LM7uYiAsKDU42GNSnMwDxbZ8s1DowQzYH",
            "t2AgvT35LHR378AE3ouz6xKMhkTLHLJC6nD", "t285EAQXUVyi4NMddJv2QqTrnv45GRMbP8e", "t2EpMRCD5b8f2DCQ37npNULcpZhkjC8muqA", "t2BCmWXrRPiCeQTpizSWKKRPM5X6PS7umDY",
            "t2DN7X6wDFn5hYKBiBmn3Z98st419yaTVTH", "t2QJj8HeCwQ6mHwqekxxDLZntYpZTHNU62t", "t2QdHBR1Yciqn4j8gpS8DcQZZtYetKvfNj3", "t2E5cpLA1ey5VNxFNcuopeQMq2rH2NHiPdu",
            "t2EVRGtzjFAyz8CF8ndvLuiJu7qZUfDa93H", "t2KoQDk3BSFadBkuaWdLwchFuQamzw9RE4L", "t2FnR3yhTmuiejEJeu6qpidWTghRd1HpjLt", "t2BAuBAAospDc9d1u5nNGEi6x4NRJBD2PQ2",
            "t2RtKrLCGcyPkm4a4APg1YY9Wu2m4R2PgrB", "t28aUbSteZzBq2pFgj1K1XNZRZP5mMMyakV", "t2Urdy1ERfkvsFuy6Z4BkhvYGzWdmivfAFR", "t2ADinR4JrvCMd4Q1XGALPajzFrirqvhED6",
        */
        };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nMaxTipAge = 24 * 60 * 60;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;
        genesis.nTime = 1482971059;
        genesis.nBits = 0x200f0f0f;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000009");
        genesis.nSolution = ParseHex("05ffd6ad016271ade20cfce093959c3addb2079629f9f123c52ef920caa316531af5af3f");
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18033;
        assert(consensus.hashGenesisBlock == uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (Checkpoints::CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a")),
            0,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        //vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
    vFoundersRewardAddress = { };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.IsValid());
    assert(address.IsScript());
    CScriptID scriptID = get<CScriptID>(address.Get()); // Get() returns a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}
