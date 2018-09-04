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
        
        let sig = try? key.withUnsafeBytes({ (bytes: UnsafePointer<UInt8>) -> Data? in
            guard SecKeyIsAlgorithmSupported(secKey, .sign, hash.cryptoAlgorithm) else {
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
        })
        guard let sign = sig else { return Data() }
        return sign!
    }
}

extension RSAAlgorithm: VerifyAlgorithm {
    public func verify(_ message: Data, signature: Data) throws -> Bool {
        var error: Unmanaged<CFError>?

        let verified = key.withUnsafeBytes({ (bytes: UnsafePointer<UInt8>) -> Bool in
            guard SecKeyIsAlgorithmSupported(secKey, .verify, hash.cryptoAlgorithm) else {
                return false
            }
            
            guard SecKeyVerifySignature(secKey, hash.cryptoAlgorithm, message as CFData, signature as CFData, &error) else {
                return false
            }
            
            // otherwise it worked
            return true
        })

        return verified
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
