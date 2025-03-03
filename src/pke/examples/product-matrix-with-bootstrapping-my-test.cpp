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
 #include <iostream>
 #include <chrono> // Para medir el tiempo
 
 using namespace lbcrypto;
 
 int main() {
    // Configuración del contexto criptográfico
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(LEVELEDSHE);
 
    // Generación de claves
    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // Parámetro para definir el tamaño de las matrices cuadradas
    int numRowsAndCols = 2;
 
    // Generación automática de matrices con números consecutivos
    std::vector<std::vector<int64_t>> matrix1(numRowsAndCols, std::vector<int64_t>(numRowsAndCols));
    std::vector<std::vector<int64_t>> matrix2(numRowsAndCols, std::vector<int64_t>(numRowsAndCols));

    int value = 1;
    for (int i = 0; i < numRowsAndCols; ++i) {
        for (int j = 0; j < numRowsAndCols; ++j) {
            matrix1[i][j] = value++;
        }
    }

    for (int i = 0; i < numRowsAndCols; ++i) {
        for (int j = 0; j < numRowsAndCols; ++j) {
            matrix2[i][j] = value++;
        }
    }
 
    // Cálculo dinámico de dimensiones
    int rows1 = matrix1.size();
    int cols1 = matrix1[0].size();
    int rows2 = matrix2.size();
    int cols2 = matrix2[0].size();

    // Verificación de dimensiones
    if (cols1 != rows2) {
        std::cerr << "Error: Las dimensiones de las matrices no son compatibles para la multiplicación." << std::endl;
        return 1; 
    }

    // Cifrado de las matrices
    std::vector<std::vector<ConstCiphertext<DCRTPoly>>> encryptedMatrix1(rows1, std::vector<ConstCiphertext<DCRTPoly>>(cols1));
    std::vector<std::vector<ConstCiphertext<DCRTPoly>>> encryptedMatrix2(rows2, std::vector<ConstCiphertext<DCRTPoly>>(cols2));

    
    for (int i = 0; i < rows1; ++i) {
        for (int j = 0; j < cols1; ++j) {
            encryptedMatrix1[i][j] = cryptoContext->Encrypt(keyPair.publicKey, cryptoContext->MakePackedPlaintext(std::vector<int64_t>{matrix1[i][j]}));
        }
    }
    
    for (int i = 0; i < rows2; ++i) {
        for (int j = 0; j < cols2; ++j) {
            encryptedMatrix2[i][j] = cryptoContext->Encrypt(keyPair.publicKey, cryptoContext->MakePackedPlaintext(std::vector<int64_t>{matrix2[i][j]}));
        }
    }

    // Inicio de la medición del tiempo
    auto start = std::chrono::high_resolution_clock::now();

    auto resultMatrix = cryptoContext->EvalMultMatrixWithBootstrapping(encryptedMatrix1, encryptedMatrix2);

    // Fin de la medición del tiempo
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // Descifrado del resultado
    std::vector<std::vector<int64_t>> decryptedResult(rows1, std::vector<int64_t>(cols2));

    for (int i = 0; i < rows1; ++i) {
        for (int j = 0; j < cols2; ++j) {
            Plaintext plaintext;
            cryptoContext->Decrypt(keyPair.secretKey, resultMatrix[i][j], &plaintext);
            decryptedResult[i][j] = plaintext->GetPackedValue()[0];
        }
    }

    // Impresión del resultado
    std::cout << "Resultado de la multiplicación de matrices:" << std::endl;
    for (int i = 0; i < rows1; ++i) {
    for (int j = 0; j < cols2; ++j) {
        std::cout << decryptedResult[i][j] << " ";
        }
        std::cout << std::endl;
    }

    //Impresión del tiempo de ejecución
    std::cout << "Tiempo de ejecución: " << elapsed.count() << " segundos" << std::endl;
 
     return 0;
 }