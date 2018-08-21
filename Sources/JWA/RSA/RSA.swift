//
//  RSA.swift
//  JWA
//
//  Created by Michael Friedman on 8/20/18.
//

import Foundation

final public class RSAAlgorithm: Algorithm {
    public let key: Data
    public let hash: Hash
    
    public enum Hash {
        case sha256
        case sha384
        case sha512
    }
    
    public init(key: Data, hash: Hash) {
        self.key = key
        self.hash = hash
    }
    
    public init?(key: String, hash: Hash) {
        guard let key = key.data(using: .utf8) else { return nil }
        
        self.key = key
        self.hash = hash
    }
    
    public var name: String {
        switch hash {
        case .sha256:
            return "RS256"
        case .sha384:
            return "RS384"
        case .sha512:
            return "RS512"
        }
    }
}
