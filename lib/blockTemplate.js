var bignum = require('bignum');
var crypto = require('crypto');
var SHA3 = require('sha3');
var options =require(options);

var merkle = require('./merkleTree.js');
var transactions = require('./transactions.js');
var util = require('./util.js');

/**
 * The BlockTemplate class holds a single job.
 * and provides several methods to validate and submit it to the daemon coin
**/
var BlockTemplate = module.exports = function BlockTemplate(
    jobId,
    rpcData,
    extraNoncePlaceholder,
    recipients,
    poolAddress,
    poolHex,
    coin
) {
    //epoch length
    const EPOCH_LENGTH = 7500;

    //private members
    var submits = [];

    //public members
    this.rpcData = rpcData;
    this.jobId = jobId;

    // get target info
    this.target = bignum(rpcData.target, 16);
    this.target_hex = rpcData.target;

    this.difficulty = parseFloat((diff1 / this.target.toNumber()).toFixed(9));
    console.log("In BlockTemplate difficulty is "+this.difficulty);

    //nTime
    var nTime = util.packUInt32BE(rpcData.curtime).toString('hex');

    let blockReward;
    // generate the fees and coinbase tx
    if(options.coin.algorithm === 'kawpow') {
        blockReward = this.rpcData.coinbasevalue;
    }else {
        blockReward = {
            'total': (this.rpcData.miner) * (coin.subsidyMultipleOfSatoshi || 100000000)
        };
    }

    var masternodeReward;
    var masternodePayee;
    var masternodePayment;
    var zelnodeBasicAddress;
    var zelnodeBasicAmount;
    var zelnodeSuperAddress;
    var zelnodeSuperAmount;
    var zelnodeBamfAddress;
    var zelnodeBamfAmount;

    if (coin.payFoundersReward === true) {
        if (!this.rpcData.founders || this.rpcData.founders.length <= 0) {
            console.log('Error, founders reward missing for block template!');
        } else if (coin.payAllFounders){
            // SafeCash / Genx
            if (!rpcData.masternode_payments_started)
            {
                // Pre masternodes
                blockReward = {
                    "miner": (this.rpcData.miner),
                    "infrastructure": (this.rpcData.infrastructure),
                    "giveaways": (this.rpcData.giveaways),
                    "founderSplit": (this.rpcData.loki),
                    "total": (this.rpcData.miner + this.rpcData.founderstotal + this.rpcData.infrastructure + this.rpcData.giveaways)
                };
                //console.log(`SafeCash: ${this.rpcData.miner}`);
            }
            else
            {
                // console.log(this.rpcData);
                // Masternodes active
                blockReward = {
                    "miner": (this.rpcData.miner),
                    "infrastructure": (this.rpcData.infrastructure),
                    "giveaways": (this.rpcData.giveaways),
                    "founderamount": (this.rpcData.founderamount),
                    "total": (this.rpcData.coinbasevalue)
                };
            }
        } else {
            blockReward = {
                "total": (this.rpcData.miner + this.rpcData.founders + (this.rpcData.treasury || 0) + this.rpcData.securenodes + this.rpcData.supernodes) * 100000000
            };
        }
    }

    //Vidulum VRS Support
    if(coin.VRSEnabled === true) {
        //VRS Activation is Live
        if(this.rpcData.height >= coin.VRSBlock){
            if (!this.rpcData.vrsReward || this.rpcData.vrsReward.length <= 0) {
                console.log('Error, vidulum reward system payout missing for block template!');
            }
            else {
                blockReward = {
                    "total": (this.rpcData.miner * 100000000) + this.rpcData.vrsReward + this.rpcData.payee_amount
                };
            }
        }
        else{ //VRS Ready but not yet activated by chain
            blockReward = {
                "total": (this.rpcData.miner * 100000000) + this.rpcData.payee_amount
            };
        }
    }

    masternodeReward = rpcData.payee_amount;
    masternodePayee = rpcData.payee;
    masternodePayment = rpcData.masternode_payments;
    zelnodeBasicAddress = coin.payZelNodes ? rpcData.basic_zelnode_address : null;
    zelnodeBasicAmount = coin.payZelNodes ? (rpcData.basic_zelnode_payout || 0) : 0;
    zelnodeSuperAddress = coin.payZelNodes ? rpcData.super_zelnode_address : null;
    zelnodeSuperAmount = coin.payZelNodes ? (rpcData.super_zelnode_payout || 0) : 0;
    zelnodeBamfAddress = coin.payZelNodes ? rpcData.bamf_zelnode_address : null;
    zelnodeBamfAmount = coin.payZelNodes ? (rpcData.bamf_zelnode_payout || 0): 0;

    var fees = [];
    rpcData.transactions.forEach(function(value) {
        fees.push(value);
    });
    this.rewardFees = transactions.getFees(fees);
    rpcData.rewardFees = this.rewardFees;


    if (typeof this.genTx === 'undefined') {
        switch (options.coin.algorithm) {
            default:
                this.genTx = transactions.createGeneration(
                    rpcData,
                    blockReward,
                    this.rewardFees,
                    recipients,
                    poolAddress,
                    poolHex,
                    coin,
                    masternodeReward,
                    masternodePayee,
                    masternodePayment,
                    zelnodeBasicAddress,
                    zelnodeBasicAmount,
                    zelnodeSuperAddress,
                    zelnodeSuperAmount,
                    zelnodeBamfAddress,
                    zelnodeBamfAmount
                ).toString('hex');
                this.genTxHash = transactions.txHash();
                break;
            case 'kawpow':
                this.genTx = transactions.createGeneration(rpcData, blockReward, this.rewardFees, recipients, poolAddress,poolHex, coin).toString('hex');
                this.genTxHash = transactions.txHash();
                break;
        }

        /*
        console.log('this.genTxHash: ' + transactions.txHash());
        console.log('this.merkleRoot: ' + merkle.getRoot(rpcData, this.genTxHash));
        */
    }

    // generate the merkle root
    this.prevHashReversed = util.reverseBuffer(new Buffer(rpcData.previousblockhash, 'hex')).toString('hex');
    switch(options.coin.algorithm) {
        default:
            if (rpcData.finalsaplingroothash) {
                this.hashReserved = util.reverseBuffer(new Buffer(rpcData.finalsaplingroothash, 'hex')).toString('hex');
            } else {
                this.hashReserved = '0000000000000000000000000000000000000000000000000000000000000000'; //hashReserved
            }
            break;
        case 'kawpow':
            break;
    }
    this.merkleRoot = merkle.getRoot(rpcData, this.genTxHash);
    this.txCount = this.rpcData.transactions.length + 1; // add total txs and new coinbase
    this.merkleRootReversed = util.reverseBuffer(new Buffer(this.merkleRoot, 'hex')).toString('hex');
    // we can't do anything else until we have a submission

    this.serializeHeaderKawpow = function () {
        var headers =  new Buffer(80);
        var positions = 0;


        //Header Template per https://github.com/RavenCommunity/kawpow-stratum-pool/
        headers.write(util.packUInt32BE(this.rpcData.height).toString('hex'), positions, 4, 'hex'); // height 42-46
        headers.write(this.rpcData.bits, positions += 4, 4, 'hex'); // bits 47-50
        headers.write(nTime, positions += 4, 4, 'hex');                        // nTime          51-54
        headers.write(this.merkleRoot, positions += 4, 32, 'hex');                  // merkelRoot     55-87
        headers.write(this.rpcData.previousblockhash, positions += 32, 32, 'hex');  // prevblockhash  88-120
        headers.writeUInt32BE(this.rpcData.version, positions + 32, 4);                // version        121-153

        /*  console.log('this.rpcData.bits: ' + this.rpcData.bits);
          console.log('nTime: ' + nTime);
          console.log('this.merkleRoot: ' + this.merkleRoot);
          console.log('this.previousblockhash: ' + this.rpcData.previousblockhash);
          console.log('this.rpcData.version: ' + this.rpcData.version);
          console.log('this.rpcData.height '+ util.packUInt32BE(this.rpcData.height).toString('hex'), position, 4, 'hex');
        */
        var headerss = util.reverseBuffer(headers);
        return headerss;


    }





    //block header per https://github.com/zcash/zips/blob/master/protocol/protocol.pdf
    this.serializeHeader = function(nTime,nonce){
        var header =  new Buffer(140);
        var position = 0;

                console.log('nonce:' + nonce);
                console.log('this.rpcData.bits: ' + this.rpcData.bits);
                console.log('nTime: ' + nTime);
                console.log('this.merkleRootReversed: ' + this.merkleRootReversed);
                console.log('this.prevHashReversed: ' + this.prevHashReversed);
                console.log('this.hashReserved: ' + this.hashReserved);
                console.log('this.rpcData.version: ' + this.rpcData.version);


                header.writeUInt32LE(this.rpcData.version, position += 0, 4, 'hex');
                header.write(this.prevHashReversed, position += 4, 32, 'hex');
                header.write(this.merkleRootReversed, position += 32, 32, 'hex');
                header.write(this.hashReserved, position += 32, 32, 'hex');
                header.write(nTime, position += 32, 4, 'hex');
                header.write(util.reverseBuffer(new Buffer(rpcData.bits, 'hex')).toString('hex'), position += 4, 4, 'hex');
                header.write(nonce, position += 4, 32, 'hex');
        return header;
    };

    // join the header and txs together
    this.serializeBlock = function(header, soln){

        var txCount = this.txCount.toString(16);
        if (Math.abs(txCount.length % 2) == 1) {
          txCount = "0" + txCount;
        }

        if (this.txCount <= 0xfc){
            var varInt = new Buffer(txCount, 'hex');
        } else if (this.txCount <= 0x7fff) {
            if (txCount.length == 2) {
                txCount = "00" + txCount;
            }
            var varInt = new Buffer.concat([Buffer('FD', 'hex'), util.reverseBuffer(new Buffer(txCount, 'hex'))]);
        }

        buf = new Buffer.concat([
            header,
            soln,
            varInt,
            new Buffer(this.genTx, 'hex')
        ]);

        if (this.rpcData.transactions.length > 0) {
            this.rpcData.transactions.forEach(function (value) {
                tmpBuf = new Buffer.concat([buf, new Buffer(value.data, 'hex')]);
                buf = tmpBuf;
            });
        }


        console.log('header: ' + header.toString('hex'));
        console.log('soln: ' + soln.toString('hex'));
        console.log('varInt: ' + varInt.toString('hex'));
        console.log('this.genTx: ' + this.genTx);
        console.log('data: ' + value.data);
        console.log('buf_block: ' + buf.toString('hex'));

        return buf;
    };

    // submit the block header
    this.registerSubmit = function(header, soln){
        var submission = (header + soln).toLowerCase();
        if (submits.indexOf(submission) === -1){

            submits.push(submission);
            return true;
        }
        return false;
    };


    //powLimit * difficulty for Kawpow
    var powLimit = algos.kawpow.diff; // TODO: Get algos object from argument
    var adjPow = (powLimit / this.difficulty);
    if ((64 - adjPow.toString(16).length) === 0) {
        var zeroPad = '';
    }
    else {
        var zeroPad = '0';
        zeroPad = zeroPad.repeat((64 - (adjPow.toString(16).length)));
    }
    var target = (zeroPad + adjPow.toString(16)).substr(0,64);
    //this.target_share_hex = target;

    let d = new SHA3.SHA3Hash(256);
    var seedhash_buf = new Buffer(32);
    var seedhash = seedhash_buf.toString('hex');
    this.epoch_number = Math.floor(this.rpcData.height / EPOCH_LENGTH);
    for (var i=0; i<this.epoch_number; i++) {
        d = new SHA3.SHA3Hash(256);
        d.update(seedhash_buf);
        seedhash_buf = d.digest();
        seedhash = d.digest('hex');
        // console.log("seedhash(#"+i+")= "+seedhash.toString('hex'));
    }


    var header_hash = this.serializeHeader(); // 140 bytes (doesn't contain nonce or mixhash)
    // console.log("****************************");
    // console.log("Header hash sent to miners: "+header_hash.toString('hex'));
    // console.log("****************************");
    header_hash = util.reverseBuffer(util.sha256d(header_hash)).toString('hex');

    //change override_target to a minimum wanted target. This is useful for e.g. testing on testnet.
    var override_target = 0;
    //override_target = 0x0000000FFFFF0000000000000000000000000000000000000000000000000000;
    if ((override_target != 0) && (adjPow > override_target)) {
        zeroPad = '0';
        zeroPad = zeroPad.repeat((64 - (override_target.toString(16).length)));
        target = (zeroPad + override_target.toString(16)).substr(0,64);
    }


    // used for mining.notify
    this.getJobParams = function(){
        if (!this.jobParams){
            this.jobParams = [
                this.jobId,
                util.packUInt32LE(this.rpcData.version).toString('hex'),
                this.prevHashReversed,
                this.merkleRootReversed,
                this.hashReserved,
                util.packUInt32LE(rpcData.curtime).toString('hex'),
                util.reverseBuffer(new Buffer(this.rpcData.bits, 'hex')).toString('hex'),
                true
            ];
        }
        return this.jobParams;
    };
};
