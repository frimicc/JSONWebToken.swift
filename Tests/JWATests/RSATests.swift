//
//  RSATests.swift
//  JWATests
//
//  Created by Michael Friedman on 8/20/18.
//

import Foundation
import XCTest
import JWA


class RSAAlgorithmTests: XCTestCase {
    
    var publicKey: Data?
    var privateKey: Data?
    
    let message = "message".data(using: .utf8)!
    let sha256Signature = Data(base64Encoded: "i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=")!
    let sha384Signature = Data(base64Encoded: "rQ706A2kJ7KjPURXyXK/dZ9Qdm+7ZlaQ1Qt8s43VIX21Wck+p8vuSOKuGltKr9NL")!
    let sha512Signature = Data(base64Encoded: "G7pYfHMO7box9Tq7C2ylieCd5OiU7kVeYUCAc5l1mtqvoGnux8AWR7sXPcsX9V0ir0mhgHG3SMXC7df3qCnGMg==")!
    
    override func setUp() {
        do {
            publicKey = try Data(contentsOf: URL(string: "file:///Users/michaelfriedman/src/JSONWebToken.swift/Tests/JWATests/rsa_public.pem")!)
            privateKey = try Data(contentsOf: URL(string: "file:///Users/michaelfriedman/src/JSONWebToken.swift/Tests/JWATests/rsa_private.pem")!)
        } catch {
            // ignore errors
        }
    }
    // MARK: Name
    
    func testSHA256Name() {
        let algorithm = RSAAlgorithm(key: privateKey!, hash: .sha256)
        XCTAssertEqual(algorithm.name, "RS256")
    }
    
    func testSHA384Name() {
        let algorithm = RSAAlgorithm(key: privateKey!, hash: .sha384)
        XCTAssertEqual(algorithm.name, "RS384")
    }
    
    func testSHA512Name() {
        let algorithm = RSAAlgorithm(key: privateKey!, hash: .sha512)
        XCTAssertEqual(algorithm.name, "RS512")
    }
    
    // MARK: Signing
    
    func testSHA256Sign() {
        let algorithm = RSAAlgorithm(key: privateKey!, hash: .sha256)
        XCTAssertEqual(try algorithm.sign(message), sha256Signature)
    }
    
    func testSHA384Sign() {
        let algorithm = RSAAlgorithm(key: privateKey!, hash: .sha384)
        XCTAssertEqual(try algorithm.sign(message), sha384Signature)
    }
    
    func testSHA512Sign() {
        let algorithm = RSAAlgorithm(key: privateKey!, hash: .sha512)
        XCTAssertEqual(try algorithm.sign(message), sha512Signature)
    }
    
    // MARK: Verify
    
    func testSHA256Verify() {
        let algorithm = RSAAlgorithm(key: publicKey!, hash: .sha256)
        XCTAssertTrue(try algorithm.verify(message, signature: sha256Signature))
    }
    
    func testSHA384Verify() {
        let algorithm = RSAAlgorithm(key: publicKey!, hash: .sha384)
        XCTAssertTrue(try algorithm.verify(message, signature: sha384Signature))
    }
    
    func testSHA512Verify() {
        let algorithm = RSAAlgorithm(key: publicKey!, hash: .sha512)
        XCTAssertTrue(try algorithm.verify(message, signature: sha512Signature))
    }
}
