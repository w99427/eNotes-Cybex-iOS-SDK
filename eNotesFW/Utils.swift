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

@available(iOS 11.0, *)
public class Utils {
    
    public static func parseNDEFMessage(messages: [NFCNDEFMessage]) -> Card? {
        for message in messages {
            if(message.records.count == 3){
                let re = message.records[2]
                return parseNDEFData(data: re.payload)
            }
        }
        return nil
    }
    
    public static func parseNDEFData(data:Data) -> Card? {
        var card = Card()
        let tlv = Tlv.decode(data: data)
        
        guard let blockchainPublicKey = tlv[Data(hex: TlvTag.BlockChain_PublicKey)],
            let oneTimePrivateKeyData = tlv[Data(hex: TlvTag.OneTime_PrivateKey)],
            let oneTimePublicKey = tlv[Data(hex: TlvTag.OneTime_PublicKey)],
            let oneTimeNonce = tlv[Data(hex: TlvTag.OneTime_Nonce)],
            let accountData = tlv[Data(hex: TlvTag.Account)],
            let oneTimeSignatureData = tlv[Data(hex: TlvTag.OneTime_Signature)],
            let transactionPinStatus = tlv[Data(hex: TlvTag.TransactionPinStatus)],
            let oneTimeSignatureChecksumData = tlv[Data(hex: TlvTag.OneTime_SignatureChecksum)],
            let oneTimePrivateKeyChecksumData = tlv[Data(hex: TlvTag.OneTime_PrivateKeyChecksum)],
            let certificate = tlv[Data(hex: TlvTag.Device_Certificate)] else {
                return nil
        }
        
        if let account = accountData.string(encoding: .utf8) {
            card.account = account
        }
        
        let parser = CertificateParser(hexCert: certificate.toBase64String())!
        
        card.blockchainPublicKey = blockchainPublicKey.hexEncodedString()
        card.oneTimePrivateKey = oneTimePrivateKeyData.hexEncodedString()
        card.oneTimePublicKey = oneTimePublicKey.hexEncodedString()
        card.oneTimeNonce = oneTimeNonce.hexEncodedString()
        card.oneTimeSignature = oneTimeSignatureData.hexEncodedString()
        card.oneTimeSignatureChecksum = oneTimeSignatureChecksumData.toInt()!
        card.oneTimePrivateKeyChecksum = oneTimePrivateKeyChecksumData.toInt()!
        card.transactionPinStatus = transactionPinStatus.toInt()! != 0
        card.cert = parser.toCert()
        
        return card
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
    
    //3des 加密
    public static func enCrypt3des(coding  data:Data , pin:String) -> String {
        let key = (pin as NSString).substring(to: 48)
        let iv = (pin as NSString).substring(with: NSMakeRange(48, 16))
        let ivData = unhexlify(iv)!
        let ivPoint = UnsafeRawPointer((ivData as NSData).bytes)
        // TODO: 创建要加密或解密的数据接受对象
        
        
        // 创建数据编码后的指针
        let dataPointer = UnsafeRawPointer((data as NSData).bytes)
        // 获取转码后数据的长度
        let dataLength = size_t(data.count)
        
        // TODO: 将加密或解密的密钥转化为Data数据
        let keyData = unhexlify(key)!
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
        let ivData = unhexlify(iv)!
        let ivPoint = UnsafeRawPointer((ivData as NSData).bytes)
        // TODO: 创建要加密或解密的数据接受对象
        
        
        // 创建数据编码后的指针
        let dataPointer = UnsafeRawPointer((data as NSData).bytes)
        // 获取转码后数据的长度
        let dataLength = size_t(data.count)
        
        // TODO: 将加密或解密的密钥转化为Data数据
        let keyData = unhexlify(key)!
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
}
