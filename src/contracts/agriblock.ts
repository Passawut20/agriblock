import {
    assert,
    ByteString,
    byteString2Int,
    exit,
    hash160,
    hash256,
    int2ByteString,
    method,
    prop,
    PubKey,
    PubKeyHash,
    reverseByteString,
    Sig,
    SmartContract,
    toByteString,
} from 'scrypt-ts'
import { SECP256K1, Signature } from 'scrypt-ts-lib'

// Important to keep in mind:
// All public keys must be in uncompressed form. This also affects
// the values of the pub key hashes i.e. addresses.

export class BlindEscrow extends SmartContract {
    // 4 possible actions:
    // - buyer signs and uses sellers stamp (releaseBySeller)
    // - buyer signs and uses arbiters stamp (releaseByArbiter)
    // - seller signs and uses buyers stamp (returnByBuyer)
    // - seller signs and uses arbiters stamp (returnByArbiter)
    static readonly RELEASE_BY_SELLER = 0n
    static readonly RELEASE_BY_ARBITER = 1n
    static readonly RETURN_BY_BUYER = 2n
    static readonly RETURN_BY_ARBITER = 3n

    @prop()
    seller: PubKeyHash

    @prop()
    buyer: PubKeyHash

    @prop()
    arbiter: PubKeyHash

    @prop()
    escrowNonce: ByteString

    constructor(
        seller: PubKeyHash,
        buyer: PubKeyHash,
        arbiter: PubKeyHash,
        escrowNonce: ByteString
    ) {
        super(...arguments)
        this.seller = seller
        this.buyer = buyer
        this.arbiter = arbiter
        this.escrowNonce = escrowNonce
    }
    @method()
    public buyCrops(crops: ByteString) {
        assert(hash256(crops) == crops, 'incorrect type')
    }

    @method()
    public sellCrops(crops: ByteString) {
        assert(hash256(crops) == crops, 'incorrect price')
    }

    @method()
    public spend(
        spenderSig: Sig,
        spenderPubKey: PubKey,
        oracleSig: Signature,
        oraclePubKey: PubKey,
        action: bigint
    ) {
        let spender = PubKeyHash(
            toByteString('0000000000000000000000000000000000000000')
        )
        let oracle = PubKeyHash(
            toByteString('0000000000000000000000000000000000000000')
        )

        // Load correct addresses.
        if (action == BlindEscrow.RELEASE_BY_SELLER) {
            spender = this.buyer
            oracle = this.seller
        } else if (action == BlindEscrow.RELEASE_BY_ARBITER) {
            spender = this.buyer
            oracle = this.arbiter
        } else if (action == BlindEscrow.RETURN_BY_BUYER) {
            spender = this.seller
            oracle = this.buyer
        } else if (action == BlindEscrow.RETURN_BY_ARBITER) {
            spender = this.seller
            oracle = this.arbiter
        } else {
            // Invalid action
            exit(false)
        }

        // Check public keys belong to the specified addresses
        assert(hash160(spenderPubKey) == spender, 'Wrong spender pub key')
        assert(hash160(oraclePubKey) == oracle, 'Wrong oracle pub key')

        // Check oracle signature, i.e. "stamp".
        const oracleMsg: ByteString = this.escrowNonce + int2ByteString(action)
        const hashInt = byteString2Int(
            reverseByteString(hash256(oracleMsg), 32n) + toByteString('00')
        )
        assert(
            SECP256K1.verifySig(
                hashInt,
                oracleSig,
                SECP256K1.pubKey2Point(oraclePubKey)
            ),
            'Oracle sig invalid'
        )

        // Check spender signature.
        assert(this.checkSig(spenderSig, spenderPubKey), 'Spender sig invalid')
    }
}

import axios from 'axios'
import dotenv from 'dotenv'

dotenv.config()

const apiUrl = 'https://api.stlouisfed.org/fred/series/observations'
const apiKey = process.env.FRED_API_KEY

// Function to fetch the global price of rice in Thailand
export async function fetchRicePrice(): Promise<number | undefined> {
    try {
        // FRED series ID for global price of rice in Thailand (replace with the actual series ID)
        const seriesId = 'PRICENPQUSDM'

        // Make the API request with the API key as a query parameter
        const response = await axios.get(apiUrl, {
            params: {
                series_id: seriesId,
                api_key: apiKey,
                file_type: 'json',
            },
        })

        // Process the API response data and return the price
        const data = response.data
        if (data.observations && data.observations.length > 0) {
            const latestObservation = data.observations[0]
            const ricePrice = parseFloat(latestObservation.value)
            return ricePrice
        } else {
            return undefined
        }
    } catch (error) {
        console.error('Error fetching data from FRED API:', error.message)
        return undefined
    }
}
interface Crop {
    name: string
    weight: number
    pricePerUnit: number
    seller: string
}

export class CropMarket {
    crops: Record<number, Crop> = {}
    cropId = 0

    sellCrop(
        name: string,
        weight: number,
        pricePerUnit: number,
        seller: string
    ): void {
        if (weight <= 0) {
            throw new Error('Weight must be greater than 0')
        }
        if (pricePerUnit <= 0) {
            throw new Error('Price per unit must be greater than 0')
        }

        this.cropId++
        this.crops[this.cropId] = {
            name,
            weight,
            pricePerUnit,
            seller,
        }

        // Emit the event
        this.emitCropAdded(this.cropId, name, weight, pricePerUnit, seller)
    }

    buyCrop(
        cropId: number,
        weight: number,
        buyer: string,
        value: number
    ): void {
        const crop = this.crops[cropId]
        if (!crop) {
            throw new Error('Crop does not exist')
        }
        if (weight <= 0) {
            throw new Error('Weight must be greater than 0')
        }
        if (crop.weight < weight) {
            throw new Error('Not enough Weight available')
        }

        const totalPrice = crop.pricePerUnit * weight

        // Calculate the commission fee
        const commissionFee = Math.floor(totalPrice * 0.02)

        // Calculate the amount to transfer to the seller (after deducting the commission fee)
        const amountToSeller = totalPrice - commissionFee

        // Transfer funds to the seller (after deducting the commission fee)
        this.transferFunds(crop.seller, amountToSeller)

        // Transfer the commission fee to the intermediary
        this.transferFunds(
            '0x5B38Da6a701c568545dCfcB03FcB875f56beddC4',
            commissionFee
        )

        // Refund excess amount to the buyer if any
        if (value > totalPrice + commissionFee) {
            this.transferFunds(buyer, value - totalPrice - commissionFee)
        }

        // Update crop weight after purchase
        crop.weight -= weight

        // Emit the event
        this.emitCropSold(cropId, weight, totalPrice, buyer)
    }

    private emitCropAdded(
        cropId: number,
        name: string,
        weight: number,
        pricePerUnit: number,
        seller: string
    ): void {
        console.log('CropAdded', cropId, name, weight, pricePerUnit, seller)
        // Emit the event logic here
    }

    private emitCropSold(
        cropId: number,
        weight: number,
        totalPrice: number,
        buyer: string
    ): void {
        console.log('CropSold', cropId, weight, totalPrice, buyer)
        // Emit the event logic here
    }

    private transferFunds(to: string, amount: number): void {
        console.log(`Transfer ${amount} wei to address ${to}`)
        // Actual fund transfer logic here
    }
}
