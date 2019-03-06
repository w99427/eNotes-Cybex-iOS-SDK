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

public struct Card {
    //这个key就是acitvePublickKey
    public var blockchainPublicKey = ""
    public var oneTimePrivateKey = ""
    public var oneTimePublicKey = ""
    public var oneTimeNonce = ""
    public var oneTimeSignature = ""
    public var oneTimeSignatureChecksum = 0
    public var oneTimePrivateKeyChecksum = 0
    public var account = ""
    public var transactionPinStatus = 0
    public var r = ""
    public var s = ""
    public var recId = 0
    public var cert = Cert()
    
}
