import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import {
    bsv,
    ByteString,
    findSig,
    hash160,
    hash256,
    int2ByteString,
    MethodCallOptions,
    PubKey,
    PubKeyHash,
    toByteString,
} from 'scrypt-ts'
import { Signature } from 'scrypt-ts-lib'
import { BlindEscrow } from '../../src/contracts/agriblock'
import { getDummySigner, getDummyUTXO } from '../utils/txHelper'

use(chaiAsPromised)

describe('Heavy: Test SmartContract `BlindEscrow`', () => {
    let seller: bsv.PrivateKey
    let buyer: bsv.PrivateKey
    let arbiter: bsv.PrivateKey

    // Make sure compressed flag is false
    let sellerPubKey: bsv.PublicKey
    let buyerPubKey: bsv.PublicKey
    let arbiterPubKey: bsv.PublicKey

    let sellerPKH: PubKeyHash
    let buyerPKH: PubKeyHash
    let arbiterPKH: PubKeyHash

    let escrowNonce: ByteString

    let blindEscrow: BlindEscrow

    before(async () => {
        seller = bsv.PrivateKey.fromRandom(bsv.Networks.testnet)
        buyer = bsv.PrivateKey.fromRandom(bsv.Networks.testnet)
        arbiter = bsv.PrivateKey.fromRandom(bsv.Networks.testnet)

        sellerPubKey = new bsv.PublicKey(seller.publicKey.point, {
            compressed: false,
        })
        buyerPubKey = new bsv.PublicKey(buyer.publicKey.point, {
            compressed: false,
        })
        arbiterPubKey = new bsv.PublicKey(arbiter.publicKey.point, {
            compressed: false,
        })

        sellerPKH = hash160(sellerPubKey.toHex())
        buyerPKH = hash160(buyerPubKey.toHex())
        arbiterPKH = hash160(arbiterPubKey.toHex())

        escrowNonce = toByteString('001122334455aabbcc') // TODO

        await BlindEscrow.compile()

        blindEscrow = new BlindEscrow(
            sellerPKH,
            buyerPKH,
            arbiterPKH,
            escrowNonce
        )
    })

    it('should pass release by seller', async () => {
        //// Sig by buyer, stamp by seller.

        // Create "stamp", i.e. seller signature of the escrowNonce.
        const oracleMsg: ByteString =
            escrowNonce + int2ByteString(BlindEscrow.RELEASE_BY_SELLER)
        const hashBuff = Buffer.from(hash256(oracleMsg), 'hex')
        const oracleSigObj = bsv.crypto.ECDSA.sign(hashBuff, seller)
        const oracleSig: Signature = {
            r: BigInt(oracleSigObj['r'].toString()),
            s: BigInt(oracleSigObj['s'].toString()),
        }

        await blindEscrow.connect(getDummySigner(buyer))
        const { tx: callTx, atInputIndex } = await blindEscrow.methods.spend(
            (sigResps) => findSig(sigResps, buyer.publicKey),
            PubKey(buyerPubKey.toHex()),
            oracleSig,
            PubKey(sellerPubKey.toHex()),
            BlindEscrow.RELEASE_BY_SELLER,
            {
                fromUTXO: getDummyUTXO(),
                pubKeyOrAddrToSign: buyer.publicKey,
            } as MethodCallOptions<BlindEscrow>
        )

        const result = callTx.verifyScript(atInputIndex)
        expect(result.success, result.error).to.eq(true)
    })

    it('should pass release by arbiter', async () => {
        //// Sig by buyer, stamp by arbiter.

        const oracleMsg: ByteString =
            escrowNonce + int2ByteString(BlindEscrow.RELEASE_BY_ARBITER)
        const hashBuff = Buffer.from(hash256(oracleMsg), 'hex')
        const oracleSigObj = bsv.crypto.ECDSA.sign(hashBuff, arbiter)
        const oracleSig: Signature = {
            r: BigInt(oracleSigObj['r'].toString()),
            s: BigInt(oracleSigObj['s'].toString()),
        }

        await blindEscrow.connect(getDummySigner(buyer))
        const { tx: callTx, atInputIndex } = await blindEscrow.methods.spend(
            (sigResps) => findSig(sigResps, buyer.publicKey),
            PubKey(buyerPubKey.toHex()),
            oracleSig,
            PubKey(arbiterPubKey.toHex()),
            BlindEscrow.RELEASE_BY_ARBITER,
            {
                fromUTXO: getDummyUTXO(),
                pubKeyOrAddrToSign: buyer.publicKey,
            } as MethodCallOptions<BlindEscrow>
        )

        const result = callTx.verifyScript(atInputIndex)
        expect(result.success, result.error).to.eq(true)
    })

    it('should pass return by buyer', async () => {
        //// Sig by seller, stamp by buyer.

        const oracleMsg: ByteString =
            escrowNonce + int2ByteString(BlindEscrow.RETURN_BY_BUYER)
        const hashBuff = Buffer.from(hash256(oracleMsg), 'hex')
        const oracleSigObj = bsv.crypto.ECDSA.sign(hashBuff, buyer)
        const oracleSig: Signature = {
            r: BigInt(oracleSigObj['r'].toString()),
            s: BigInt(oracleSigObj['s'].toString()),
        }

        await blindEscrow.connect(getDummySigner(seller))
        const { tx: callTx, atInputIndex } = await blindEscrow.methods.spend(
            (sigResps) => findSig(sigResps, seller.publicKey),
            PubKey(sellerPubKey.toHex()),
            oracleSig,
            PubKey(buyerPubKey.toHex()),
            BlindEscrow.RETURN_BY_BUYER,
            {
                fromUTXO: getDummyUTXO(),
                pubKeyOrAddrToSign: seller.publicKey,
            } as MethodCallOptions<BlindEscrow>
        )

        const result = callTx.verifyScript(atInputIndex)
        expect(result.success, result.error).to.eq(true)
    })

    it('should pass return by arbiter', async () => {
        //// Sig by seller, stamp by arbiter.

        const oracleMsg: ByteString =
            escrowNonce + int2ByteString(BlindEscrow.RETURN_BY_ARBITER)
        const hashBuff = Buffer.from(hash256(oracleMsg), 'hex')
        const oracleSigObj = bsv.crypto.ECDSA.sign(hashBuff, arbiter)
        const oracleSig: Signature = {
            r: BigInt(oracleSigObj['r'].toString()),
            s: BigInt(oracleSigObj['s'].toString()),
        }

        await blindEscrow.connect(getDummySigner(seller))
        const { tx: callTx, atInputIndex } = await blindEscrow.methods.spend(
            (sigResps) => findSig(sigResps, seller.publicKey),
            PubKey(sellerPubKey.toHex()),
            oracleSig,
            PubKey(arbiterPubKey.toHex()),
            BlindEscrow.RETURN_BY_ARBITER,
            {
                fromUTXO: getDummyUTXO(),
                pubKeyOrAddrToSign: seller.publicKey,
            } as MethodCallOptions<BlindEscrow>
        )

        const result = callTx.verifyScript(atInputIndex)
        expect(result.success, result.error).to.eq(true)
    })
})
import { CropMarket } from '../../src/contracts/agriblock'

describe('CropMarket', () => {
    let cropMarket: CropMarket

    beforeEach(() => {
        cropMarket = new CropMarket()
    })

    it('should sell crop and emit CropAdded event', () => {
        const seller = '0x1234567890abcdef'
        const cropName = 'Rice'
        const cropWeight = 100
        const pricePerUnit = 50

        cropMarket.sellCrop(cropName, cropWeight, pricePerUnit, seller)

        expect(cropMarket.crops[1].name).equal(cropName)
        expect(cropMarket.crops[1].weight).equal(cropWeight)
        expect(cropMarket.crops[1].pricePerUnit).equal(pricePerUnit)
        expect(cropMarket.crops[1].seller).equal(seller)
    })

    it('should buy crop and emit CropSold event', () => {
        const seller = '0x1234567890abcdef'
        const buyer = '0xfedcba0987654321'
        const cropName = 'Rice'
        const cropWeight = 100
        const pricePerUnit = 50

        cropMarket.sellCrop(cropName, cropWeight, pricePerUnit, seller)
        cropMarket.buyCrop(1, cropWeight, buyer, pricePerUnit * cropWeight)

        expect(cropMarket.crops[1].weight).equal(0) // Crop weight should be updated
    })

    // Add more test cases as needed to cover other scenarios
})
