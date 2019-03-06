//
//  Card.swift
//  eNotes
//
//  Created by Smiacter on 2018/8/16.
//  Copyright © 2018 Smiacter. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//
import Foundation
import BigInt
import web3swift
import CryptoSwift

public struct Card {
    //这个key就是acitvePublickKey
    public var blockchainPublicKey = ""
    public var oneTimePrivateKey = ""
    public var oneTimePublicKey = ""
    public var oneTimeNonce = ""
    public var oneTimeSignature = ""
    
    public var transactionPinStatus = false
    public var oneTimeSignatureChecksum = 0
    public var oneTimePrivateKeyChecksum = 0
    public var account = ""
    
    public var cert = Cert()
    
    func validatorPin(_ pin: String) -> (success: Bool, signature: String, privateKey: String) {
        //需要先用pin码做1次sha256以后调用方法deCrypt3des解密oneTimeSignature得到R和S，然后调用方法toCanonicalised得到最后的S值，调用getRecId得到recId
        
        //test
        //        let pin = "123456"
        //        let pinSha256 = sha256(data: pin.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue))!).hexEncodedString()
        //        let deCodeSignature = deCrypt3des(coding: deriveSignatureData!, pin: pinSha256)
        //        let checkSumSignature = crc16(buf: dataWithHexString(hex: deCodeSignature))
        //
        //        let deCodePrivate = deCrypt3des(coding: oneTimePrivateKeyData!, pin: pinSha256)
        //        let checkSumPrivate = crc16(buf: dataWithHexString(hex: deCodePrivate))
        
        //        let checkSumSignature = crc16(buf: deriveSignatureData!)
        //        let checkSumPrivate = crc16(buf: oneTimePrivateKeyData!)
        return (true, "", "")
    }
    
    func getBlockchainSignature(_ signature: String) -> String {
        let r = (signature as NSString).substring(to: 64)
        let s = (signature as NSString).substring(with: NSMakeRange(64, 64))
        let hash = getDataHash(oneTimeNonce, onTimePublicKey: oneTimePublicKey)
        
        let sign = getSignData(r, s: Card.toCanonicalised(s: s), activePubkey: blockchainPublicKey, hashData: hash)!.hexEncodedString()
        
        return sign
    }
    
    func getDataHash(_ oneTimeNonce:String, onTimePublicKey:String) -> Data {
        let hashHexString = oneTimeNonce + onTimePublicKey
        let data = unhexlify(hashHexString)!
        
        return data.sha256().sha256()
    }
    
    func getSignData(_ r: String, s: String, activePubkey: String, hashData: Data) -> Data? {
        let sig = r + s
        
        for i in 0...3 {
            guard let signature = unhexlify("\(sig)0\(i)"), signature.count == 65 else { continue }
            let rData = signature[0..<32].bytes
            let sData = signature[32..<64].bytes
            let vData = signature[64]
            
            guard let signatureData = SECP256K1.marshalSignature(v: vData, r: rData, s: sData) else { continue }
            
            guard let publicKey = SECP256K1.recoverPublicKey(hash: hashData, signature: signatureData) else { continue }
            if publicKey.hexEncodedString() == activePubkey {
                return signatureData
            }
        }
        return nil
    }
    
    static func compressedPublicKey(_ pubKey: String) -> String {
        let pbkey = Data.fromHex(pubKey)!
        let b = SECP256K1.combineSerializedPublicKeys(keys: [pbkey], outputCompressed: true)!
        let encodedPbkey = b.bytes.base58CheckEncodedWithRipmendString
        return "CYB" + encodedPbkey
    }
    
    static func compressedPrivateKey(_ privateKey: String) -> String {
        var privateKey = Data.fromHex(privateKey)!
        privateKey.insert(0x80, at: 0)
        
        let encodedPvkey = privateKey.bytes.base58CheckEncodedString
        return encodedPvkey
    }
    
    static func toCanonicalised(s: String) -> String {
        var bnS = BigUInt(s,radix:16)!
        
        if(bnS > SECP256K1.secp256k1_halfN){
            bnS = SECP256K1.secp256k1_N - bnS
            return String(bnS, radix: 16, uppercase: true)
        }
        
        return s
    }
    
    
}
