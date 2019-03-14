//
//  TlvTag.swift
//  NFC-Example
//
//  Created by Victor Xu on 2019/2/26.
//  Copyright © 2019 Hans Knoechel. All rights reserved.
//

import Foundation
public struct TlvTag{
    public static let Device_Certificate = "30";
    public static let Account = "32"
    public static let BlockChain_PublicKey = "55"
    public static let OneTime_PrivateKey = "56"
    public static let OneTime_PublicKey = "57"
    public static let OneTime_Nonce  = "74"
    public static let OneTime_Signature = "75"
    public static let TransactionPinStatus = "94"
    public static let OneTime_SignatureChecksum = "b1"
    public static let OneTime_PrivateKeyChecksum = "b0"
}
