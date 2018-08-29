//
//  RSACrypto.swift
//  JWA
//
//  Created by Michael Friedman on 8/20/18.
//

import Foundation
//import CommonCrypto

extension RSAAlgorithm: SignAlgorithm {
    public func sign(_ message: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        let keyParams: [String : Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                         kSecAttrKeySizeInBits as String : 2048,
                         kSecReturnPersistentRef as String: true]
        
        key.withUnsafeBytes { (bytes: UnsafePointer<UInt8>) in
            let keyData = CFDataCreate(kCFAllocatorDefault, bytes, key.count)
            let secKey = SecKeyCreateFromData(keyData, keyParams as CFDictionary, &error)
            guard SecKeyIsAlgorithmSupported(secKey!, .sign, hash.cryptoAlgorithm) else {
                if error == nil {
                    throw "Can't sign message" as! Error
                }
                throw error!.takeRetainedValue() as Error
            }
            
            guard let signature = SecKeyCreateSignature(secKey, hash.cryptoAlgorithm, message as CFData, &error) else {
                if error == nil {
                    throw "Can't sign message" as! Error
                }
                throw error!.takeRetainedValue() as Error
            }
            
            return signature as Data

        }
    }
}

extension RSAAlgorithm: VerifyAlgorithm {
    public func verify(_ message: Data, signature: Data) throws -> Bool {
        guard SecKeyIsAlgorithmSupported(key as! SecKey, .verify, hash.cryptoAlgorithm) else {
            return false
        }

        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(key as! SecKey, hash.cryptoAlgorithm, message as CFData, signature as CFData, &error) else {
            return false
        }
        
        // otherwise it worked
        return true
    }
}

extension RSAAlgorithm.Hash {
    var cryptoAlgorithm: SecKeyAlgorithm {
        switch self {
        case .sha256:
            return .rsaSignatureMessagePKCS1v15SHA256
        case .sha384:
            return .rsaSignatureMessagePKCS1v15SHA384
        case .sha512:
            return .rsaSignatureMessagePKCS1v15SHA512
        }
    }
    
//    var commonCryptoDigestLength: Int32 {
//        switch self {
//        case .sha256:
//            return CC_SHA256_DIGEST_LENGTH
//        case .sha384:
//            return CC_SHA384_DIGEST_LENGTH
//        case .sha512:
//            return CC_SHA512_DIGEST_LENGTH
//        }
//    }
}
