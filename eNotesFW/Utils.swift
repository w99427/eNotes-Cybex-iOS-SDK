//
//  Utils.swift
//  NFC-Example
//
//  Created by Victor Xu on 2019/2/26.
//  Copyright © 2019 Hans Knoechel. All rights reserved.
//

import Foundation
import CoreNFC
import CommonCrypto
import BigInt
import web3swift


public class Utils:NSObject{
    
    public static func parseNDEFMessage(messages:[NFCNDEFMessage]) ->Card{
        var card = Card()
        for message in messages {
            if(message.records.count == 3){
                let re = message.records[2]
                card = parseNDEFData(data: re.payload)
            }
            
        }
        return card
    }
    
    public static func parseNDEFData(data:Data) -> Card{
        var card = Card()
        let tlv = Tlv.decode(data: data)
        let blockchainPublicKey = tlv[Data(hex: TlvTag.BlockChain_PublicKey)]?.hexEncodedString()
        let oneTimePrivateKeyData = tlv[Data(hex: TlvTag.OneTime_PrivateKey)]
        let oneTimePrivateKey = oneTimePrivateKeyData?.hexEncodedString()
        let oneTimePublicKey = tlv[Data(hex: TlvTag.OneTime_PublicKey)]?.hexEncodedString()
        let oneTimeNonce = tlv[Data(hex: TlvTag.OneTime_Nonce)]?.hexEncodedString()
        let oneTimeSignatureData = tlv[Data(hex: TlvTag.OneTime_Signature)]
        let oneTimeSignature = oneTimeSignatureData?.hexEncodedString()
        let accountData = tlv[Data(hex: TlvTag.Account)]
        let certificate = tlv[Data(hex: TlvTag.Device_Certificate)]
        let transactionPinStatus = tlv[Data(hex: TlvTag.TransactionPinStatus)]?.toInt()
        let oneTimeSignatureChecksumData = tlv[Data(hex: TlvTag.OneTime_SignatureChecksum)]
        let oneTimePrivateKeyChecksumData = tlv[Data(hex: TlvTag.OneTime_PrivateKeyChecksum)]
        let oneTimeSignatureChecksum = oneTimeSignatureChecksumData?.toInt()
        let oneTimePrivateKeyChecksum = oneTimePrivateKeyChecksumData?.toInt()
        let parser = CertificateParser(hexCert: certificate!.toBase64String())
        let cert = parser!.toCert()
        if(accountData != nil){
            let account =  NSString(data:accountData! ,encoding: String.Encoding.utf8.rawValue)
            card.account = account! as String
        }
        
        card.blockchainPublicKey = blockchainPublicKey!
        card.oneTimePrivateKey = oneTimePrivateKey!
        card.oneTimePublicKey = oneTimePublicKey!
        card.oneTimeNonce = oneTimeNonce!
        card.oneTimeSignature = oneTimeSignature!
        card.oneTimeSignatureChecksum = oneTimeSignatureChecksum!
        card.oneTimePrivateKeyChecksum = oneTimePrivateKeyChecksum!
        card.transactionPinStatus = transactionPinStatus!
        card.cert = cert
        
        if(transactionPinStatus==0){
            
            let r = (oneTimeSignature! as NSString).substring(to: 64)
            let s = (oneTimeSignature! as NSString).substring(with: NSMakeRange(64, 128))
            card.r = r
            card.s = toCanonicalised(s: s)
            do{
                card.recId = try getRecId(oneTimeNonce: oneTimeNonce!, r: r, s: s, onTimePublicKey: oneTimePublicKey!, blockchainPublicKey:blockchainPublicKey!)
            }catch{
                
            }
        }else {
            //需要先用pin码做一次sha256以后调用方法deCrypt3des解密oneTimeSignature得到R和S，然后调用方法toCanonicalised得到最后的S值，调用getRecId得到recId
            
            //        test
            //                let pin = "123456"
            //                let pinSha256 = sha256(data: pin.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue))!).hexEncodedString()
            //                let deCodeSignature = deCrypt3des(coding: oneTimeSignatureData!, pin: pinSha256)
            //                let checkSumSignature = crc16(buf: dataWithHexString(hex: deCodeSignature))
            //
            //        let deCodePrivate = deCrypt3des(coding: oneTimePrivateKeyData!, pin: pinSha256)
            //        let checkSumPrivate = crc16(buf: dataWithHexString(hex: deCodePrivate))
            // if(checkSumSignature == oneTimeSignatureChecksum && checkSumPrivate == oneTimePrivateKeyChecksum)
            //      pin is right
            //  let r = (deCodeSignature! as NSString).substring(to: 64)
            //        let s = (deCodeSignature! as NSString).substring(with: NSMakeRange(64, 128))
            //
            //        card.r = r
            //        card.s = toCanonicalised(s: s)
            //        card.recId = getRecId(oneTimeNonce: oneTimeNonce!, r: r, s: s, onTimePublicKey: oneTimePublicKey!, blockchainPublicKey:blockchainPublicKey)
        }
        return card
    }
    
    static func toCanonicalised(s:String) -> String {
        var bnS = BigUInt(s,radix:16)!
        if(bnS > SECP256K1.secp256k1_halfN){
            bnS = SECP256K1.secp256k1_N - bnS
            return String(bnS, radix: 16, uppercase: true)
        }
        return s
    }
    
    static func getRecId(oneTimeNonce:String, r:String, s:String, onTimePublicKey:String, blockchainPublicKey:String) throws -> Int {
        var recId = 0
        let hashHexString = oneTimeNonce+onTimePublicKey
        let hashSha256 = sha256(data: hashHexString.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue))!).hexEncodedString()
        let hashDBSha256 = sha256(data: hashSha256.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue))!).hexEncodedString()
        for i in 0 ..< 4{
            var sig = r + s
            sig = "\(sig)0\(i)"
            var signature = dataWithHexString(hex: sig)
            let hashData = dataWithHexString(hex: hashDBSha256)
            if signature.count != 65 { return 0}
            let rData = signature[0..<32].bytes
            let sData = signature[32..<64].bytes
            let vData = signature[64]
            let signatureData = SECP256K1.marshalSignature(v: vData, r: rData, s: sData)
            var hash: Data
            hash = hashData
            let publicKey = try SECP256K1.recoverPublicKey(hash: hash, signature: signatureData)
            
            let recoverPublicKey = publicKey.hexEncodedString()
            if(recoverPublicKey==blockchainPublicKey){
                recId = i
                break
            }
            
        }
        return recId
    }
    
    //crc16
    public static func crc16(buf:Data) -> UInt16{
        var fcs = UInt16(0xffff)
        let len = buf.count
        for i in 0 ..< len{
            var d = UInt16(buf[i])<<8
            for _ in 0 ..< 8{
                if(((fcs^d)&0x8000) != 0){
                    fcs = (fcs << 1) ^ 0x1021
                }else{
                    fcs <<= 1
                }
                d <<= 1
            }
        }
        return UInt16(~fcs)
    }
    
    //sha256
    static func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        return Data(bytes: hash)
    }
    
    //3des 加密
    public static func enCrypt3des(coding  data:Data , pin:String) -> String{
        let key = (pin as NSString).substring(to: 48)
        let iv = (pin as NSString).substring(with: NSMakeRange(48, 16))
        let ivData = dataWithHexString(hex: iv)
        let ivPoint = UnsafeRawPointer((ivData as NSData).bytes)
        // TODO: 创建要加密或解密的数据接受对象
        
        
        // 创建数据编码后的指针
        let dataPointer = UnsafeRawPointer((data as NSData).bytes)
        // 获取转码后数据的长度
        let dataLength = size_t(data.count)
        
        // TODO: 将加密或解密的密钥转化为Data数据
        let keyData = dataWithHexString(hex: key)
        // 创建密钥的指针
        let keyPointer = UnsafeRawPointer(keyData.bytes)
        // 设置密钥的长度
        let keyLength = size_t(kCCKeySize3DES)
        
        // TODO: 创建加密或解密后的数据对象
        let cryptData = NSMutableData(length: Int(dataLength) + kCCBlockSize3DES)
        // 获取返回数据(cryptData)的指针
        let cryptPointer = UnsafeMutableRawPointer(mutating: cryptData!.mutableBytes)
        // 获取接收数据的长度
        let cryptDataLength = size_t(cryptData!.length)
        // 加密或则解密后的数据长度
        var cryptBytesLength:size_t = 0
        
        // TODO: 数据参数的准备
        // 是解密或者加密操作(CCOperation 是32位的)
        let operation:CCOperation = UInt32(kCCEncrypt)
        // 算法的类型
        let algorithm:CCAlgorithm = UInt32(kCCAlgorithm3DES)
        // 设置密码的填充规则（ PKCS7 & ECB 两种填充规则）
        let options:CCOptions = UInt32(0)
        // 执行算法处理
        let cryptStatue = CCCrypt(operation, algorithm, options, keyPointer, keyLength,ivPoint, dataPointer, dataLength, cryptPointer, cryptDataLength, &cryptBytesLength)
        // 通过返回状态判断加密或者解密是否成功
        if  UInt32(cryptStatue) == kCCSuccess  {
            // 加密
            cryptData!.length = cryptBytesLength
            // 返回3des加密对象
            let cryData = Data(referencing: cryptData!)
            return cryData.hexEncodedString()
            
            //                return cryptData!.base64EncodedString(options: .lineLength64Characters)
        }
        // 3des 加密或者解密不成功
        return " 3des Encrypt or Decrypt is faill"
        
        
    }
    
    //3des 解密
    public static func deCrypt3des(coding  data:Data , pin:String) -> String{
        let key = (pin as NSString).substring(to: 48)
        let iv = (pin as NSString).substring(with: NSMakeRange(48, 16))
        let ivData = dataWithHexString(hex: iv)
        let ivPoint = UnsafeRawPointer((ivData as NSData).bytes)
        // TODO: 创建要加密或解密的数据接受对象
        
        
        // 创建数据编码后的指针
        let dataPointer = UnsafeRawPointer((data as NSData).bytes)
        // 获取转码后数据的长度
        let dataLength = size_t(data.count)
        
        // TODO: 将加密或解密的密钥转化为Data数据
        let keyData = dataWithHexString(hex: key)
        // 创建密钥的指针
        let keyPointer = UnsafeRawPointer(keyData.bytes)
        // 设置密钥的长度
        let keyLength = size_t(kCCKeySize3DES)
        
        // TODO: 创建加密或解密后的数据对象
        let cryptData = NSMutableData(length: Int(dataLength) )
        // 获取返回数据(cryptData)的指针
        let cryptPointer = UnsafeMutableRawPointer(mutating: cryptData!.mutableBytes)
        // 获取接收数据的长度
        let cryptDataLength = size_t(cryptData!.length)
        // 加密或则解密后的数据长度
        var cryptBytesLength:size_t = 0
        
        // TODO: 数据参数的准备
        // 是解密或者加密操作(CCOperation 是32位的)
        let operation:CCOperation = UInt32(kCCDecrypt)
        // 算法的类型
        let algorithm:CCAlgorithm = UInt32(kCCAlgorithm3DES)
        // 设置密码的填充规则（ PKCS7 & ECB 两种填充规则）
        let options:CCOptions = UInt32(0)
        // 执行算法处理
        let cryptStatue = CCCrypt(operation, algorithm, options, keyPointer, keyLength,ivPoint, dataPointer, dataLength, cryptPointer, cryptDataLength, &cryptBytesLength)
        // 通过返回状态判断加密或者解密是否成功
        if  UInt32(cryptStatue) == kCCSuccess  {
            // 加密
            cryptData!.length = cryptBytesLength
            // 返回3des加密对象
            let cryData = Data(referencing: cryptData!)
            return cryData.hexEncodedString()
            
            //                return cryptData!.base64EncodedString(options: .lineLength64Characters)
        }
        // 3des 加密或者解密不成功
        return " 3des Encrypt or Decrypt is faill"
        
        
    }
    
    static func dataWithHexString(hex: String) -> Data {
        var hex = hex
        var data = Data()
        while(hex.count > 0) {
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let c = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            var ch: UInt32 = 0
            Scanner(string: c).scanHexInt32(&ch)
            var char = UInt8(ch)
            data.append(&char, count: 1)
        }
        return data
    }
}
