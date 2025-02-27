

//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Simple example for BFVrns (integer arithmetic)
 */

 #include "openfhe.h"

 using namespace lbcrypto;
 
 int main() {
     // Sample Program: Step 1: Set CryptoContext
     CCParams<CryptoContextBFVRNS> parameters;
     parameters.SetPlaintextModulus(65537);
     parameters.SetMultiplicativeDepth(2);
 
     CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
     // Enable features that you wish to use
     cryptoContext->Enable(PKE);
     cryptoContext->Enable(KEYSWITCH);
     cryptoContext->Enable(LEVELEDSHE);
 
     // Sample Program: Step 2: Key Generation
 
     // Initialize Public Key Containers
     KeyPair<DCRTPoly> keyPair;
 
     // Generate a public/private key pair
     keyPair = cryptoContext->KeyGen();
 
     // Generate the relinearization key
     cryptoContext->EvalMultKeyGen(keyPair.secretKey);
 
     // Generate the rotation evaluation keys
     cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});
 
     // Sample Program: Step 3: Encryption
 
     // First plaintext vector is encoded
     std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
     Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
     // Second plaintext vector is encoded
     std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
     Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);
 
     // The encoded vectors are encrypted
     auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
     auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
 
     // Sample Program: Step 4: Evaluation
 
     // Homomorphic additions
     auto ciphertextAddResult     = cryptoContext->EvalExample(ciphertext1, ciphertext2);
 
     // Sample Program: Step 5: Decryption
 
     // Decrypt the result of additions
     Plaintext plaintextAddResult;
     cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &plaintextAddResult);
 
     std::cout << "Plaintext #1: " << plaintext1 << std::endl;
     std::cout << "Plaintext #2: " << plaintext2 << std::endl;
 
     // Output results
     std::cout << "\nResults of homomorphic computations" << std::endl;
     std::cout << "#1 + #2: " << plaintextAddResult << std::endl;
 
     return 0;
 }
 