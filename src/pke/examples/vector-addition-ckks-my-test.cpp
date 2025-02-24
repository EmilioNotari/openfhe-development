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
  // Sample Program: Step 1: Set CryptoContext (CKKS)
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetMultiplicativeDepth(2);  
  parameters.SetScalingModSize(50);     

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  // Habilitar características necesarias
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);

  // Sample Program: Step 2: Key Generation

  // Inicializar contenedores de claves
  KeyPair<DCRTPoly> keyPair;

  // Generar un par de claves pública/privada
  keyPair = cryptoContext->KeyGen();

  // Generar la clave de relinearización
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  // Generar las claves de rotación
  cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

  // Sample Program: Step 3: Encryption

  // Variable para definir el número de elementos de los vectores
  int64_t numElements = 8192;

  // Crear dos vectores de tamaño numElements con números decimales
  std::vector<double> vectorOfDoubles1(numElements);
  std::vector<double> vectorOfDoubles2(numElements);

  for (int i = 0; i < numElements; ++i) {
      vectorOfDoubles1[i] = i * 1.25;        
      vectorOfDoubles2[i] = i * 2.15;        
  }

  // Codificar los vectores en texto plano (CKKS)
  Plaintext plaintext1 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfDoubles1);
  Plaintext plaintext2 = cryptoContext->MakeCKKSPackedPlaintext(vectorOfDoubles2);

  // Inicio de la medición del tiempo
  auto start = std::chrono::high_resolution_clock::now();

  // Cifrar los vectores codificados
  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

  // Sample Program: Step 4: Evaluation

  // Suma homomórfica
  auto ciphertextAddResult = cryptoContext->EvalAdd(ciphertext1, ciphertext2);

  // Rotaciones homomórficas
  auto ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
  auto ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
  auto ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
  auto ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> elapsed = end - start;

  // Sample Program: Step 5: Decryption

  // Descifrar el resultado de la suma
  Plaintext plaintextAddResult;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &plaintextAddResult);

  // Descifrar los resultados de las rotaciones
  Plaintext plaintextRot1;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
  Plaintext plaintextRot2;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
  Plaintext plaintextRot3;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
  Plaintext plaintextRot4;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);

  // Establecer la longitud de los resultados
  plaintextRot1->SetLength(numElements);
  plaintextRot2->SetLength(numElements);
  plaintextRot3->SetLength(numElements);
  plaintextRot4->SetLength(numElements);

  // // Imprimir resultados
  // std::cout << "Vector #1: " << plaintext1 << std::endl;
  // std::cout << "Vector #2: " << plaintext2 << std::endl;
  // std::cout << "\nResultado de la suma homomórfica: " << plaintextAddResult << std::endl;

  // Imprimir el tiempo de ejecución
  std::cout << "Tiempo de ejecución: " << elapsed.count() * 1000 << " milisegundos" << std::endl;

  return 0;
}