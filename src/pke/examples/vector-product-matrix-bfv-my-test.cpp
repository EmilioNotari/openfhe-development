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
 #include <chrono>
 #include <iostream>
 #include <vector>
 
 using namespace lbcrypto;
 
 int main() {
     CCParams<CryptoContextBFVRNS> parameters;
     parameters.SetPlaintextModulus(65537);  
     parameters.SetMultiplicativeDepth(2);   
 
     CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
     cryptoContext->Enable(PKE);
     cryptoContext->Enable(KEYSWITCH);
     cryptoContext->Enable(LEVELEDSHE);
 
     // Generación de claves
     KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
     cryptoContext->EvalMultKeyGen(keyPair.secretKey);
 
     // Tamaño del vector y la matriz
     int64_t numElements = 2;
 
     // Crear un vector y una matriz cuadrada de tamaño numElements
     std::vector<int64_t> vectorOfInts(numElements);
     std::vector<std::vector<int64_t>> matrix(numElements, std::vector<int64_t>(numElements));
 
     // Inicializar el vector y la matriz con valores
     for (int i = 0; i < numElements; ++i) {
         vectorOfInts[i] = i+1;  
     }
 
     for (int i = 0; i < numElements; ++i) {
         for (int j = 0; j < numElements; ++j) {
             matrix[i][j] = i+j;  
         }
     }
 
    /// Codificar y cifrar el vector
    Plaintext plaintextVector = cryptoContext->MakePackedPlaintext(vectorOfInts);
    auto cipherVector = cryptoContext->Encrypt(keyPair.publicKey, plaintextVector);

    // Codificar y cifrar la matriz
    std::vector<std::vector<Ciphertext<DCRTPoly>>> cipherMatrix(numElements, std::vector<Ciphertext<DCRTPoly>>(numElements));
    for (int i = 0; i < numElements; ++i) {
        for (int j = 0; j < numElements; ++j) {
            Plaintext plaintextMatrixElement = cryptoContext->MakePackedPlaintext(std::vector<int64_t>{matrix[i][j]});
            cipherMatrix[i][j] = cryptoContext->Encrypt(keyPair.publicKey, plaintextMatrixElement);
        }
    }

    // Inicio de la medición del tiempo
    auto start = std::chrono::high_resolution_clock::now();

    // Multiplicación homomórfica de la matriz por el vector
    std::vector<Ciphertext<DCRTPoly>> resultVector(numElements);
    for (int i = 0; i < numElements; ++i) {
        Ciphertext<DCRTPoly> sum = cryptoContext->EvalMult(cipherMatrix[i][0], cipherVector);
        for (int j = 1; j < numElements; ++j) {
            auto product = cryptoContext->EvalMult(cipherMatrix[i][j], cipherVector);
            sum = cryptoContext->EvalAdd(sum, product);
        }
        resultVector[i] = sum;
    }

    // Fin de la medición del tiempo
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

 
     // Descifrado del resultado
     std::vector<int64_t> decryptedResult(numElements);
     for (int i = 0; i < numElements; ++i) {
         Plaintext plaintextResult;
         cryptoContext->Decrypt(keyPair.secretKey, resultVector[i], &plaintextResult);
         decryptedResult[i] = plaintextResult->GetPackedValue()[0];
     }
 
    // Impresión de resultados
    std::cout << "Matriz:\n";
    for (const auto& row : matrix) {
        for (auto val : row) std::cout << val << " ";
        std::cout << std::endl;
    }

    std::cout << "Vector: ";
    for (auto val : vectorOfInts) std::cout << val << " ";
    std::cout << std::endl;

    std::cout << "Resultado esperado: ";
    for (int i = 0; i < numElements; ++i) {
        int expected = 0;
        for (int j = 0; j < numElements; ++j) {
            expected += matrix[i][j] * vectorOfInts[j];
        }
        std::cout << expected << " ";
    }
    std::cout << std::endl;

    std::cout << "Resultado obtenido: ";
    for (auto val : decryptedResult) std::cout << val << " ";
    std::cout << std::endl;
 
     return 0;
 }