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

Example for CKKS bootstrapping with full packing

*/

#define PROFILE

#include "openfhe.h"

using namespace lbcrypto;

void SimpleBootstrapExample();

int main(int argc, char* argv[]) {
    SimpleBootstrapExample();
}

void SimpleBootstrapExample() {
    CCParams<CryptoContextCKKSRNS> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
    * The secret key distribution for CKKS should either be SPARSE_TERNARY or UNIFORM_TERNARY.
    * The SPARSE_TERNARY distribution was used in the original CKKS paper,
    * but in this example, we use UNIFORM_TERNARY because this is included in the homomorphic
    * encryption standard.
    */
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    /*  A2) Desired security level based on FHE standards.
    * In this example, we use the "NotSet" option, so the example can run more quickly with
    * a smaller ring dimension. Note that this should be used only in
    * non-production environments, or by experts who understand the security
    * implications of their choices. In production-like environments, we recommend using
    * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
    * or 256-bit security, respectively. If you choose one of these as your security level,
    * you do not need to set the ring dimension.
    */
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12); // 2^12 = 4096

    /*  A3) Scaling parameters.
    * By default, we set the modulus sizes and rescaling technique to the following values
    * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
    * below unless you are an FHE expert.
    */
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    ScalingTechnique rescaleTech = FIXEDAUTO;
    usint dcrtBits               = 78;
    usint firstMod               = 89;
#else
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 59;
    usint firstMod               = 60;
#endif

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    /*  A4) Multiplicative depth.
    * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
    * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
    * needs to consume a few levels to run. We compute the number of bootstrapping levels required
    * using GetBootstrapDepth, and add it to levelsAvailableAfterBootstrap to set our initial multiplicative
    * depth. We recommend using the input parameters below to get started.
    */

    /*
    * levelBudget es un vector que define cómo se distribuirán los niveles de multiplicación durante el proceso de bootstrapping. 
    * En este caso, se asignarán 4 niveles para la primera fase del bootstrapping y 4 niveles para la segunda fase. 
    * Estos niveles se usarán para controlar el ruido durante las operaciones homomórficas.
    */
    std::vector<uint32_t> levelBudget = {4, 4};

    // Note that the actual number of levels avalailable after bootstrapping before next bootstrapping 
    // will be levelsAvailableAfterBootstrap - 1 because an additional level
    // is used for scaling the ciphertext before next bootstrapping (in 64-bit CKKS bootstrapping)
    /*
    * Indica cuantos niveles de multiplicación estarán disponibles después de realizar el bootstrapping.
    * En este caso se establece en 10, lo que significa que después del bootstrapping, el cifrado tendrá 
    * capacidad para multiplicaciones adicionales antes de que el ruido sea demasiado grande.
    */
    uint32_t levelsAvailableAfterBootstrap = 10;
    /*
    * depth es la profundidad total que se necesita para realizar las operaciones deseadas, incluyendo el bootstrapping.
    * levelsAvailableAfterBootstrapp son los niveles que quieres tener disponibles después del bootstrapping.
    * GetBootstrapDepth calcula cuántos niveles se consumirán durante el proceso de bootstrapping basándose en el levelBudget
    * y la distribución de la clave secreta. La suma de ambos valores determinan la profuncidad total o depth.
    */
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
    // This is the maximum number of slots that can be used for full packing.
    usint numSlots = ringDim / 2;
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

    cryptoContext->EvalBootstrapSetup(levelBudget);

    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x = {1.0, 2.0, 3.0};
    size_t encodedLength  = x.size();

    // We start with a depleted ciphertext that has used up all of its levels.
    /*
    * Aquí se crea un texto plano a partir de un vector de números x. 
    * MakeCKKSPackedPlainedText es una función que codifica el vector x en un 
    * formato compatible con el esquema CKKS.
    * depth-1 viene de que el texto plano está asociado a un cifrado que ya 
    * ha consumido casi toda su profundidad
    */
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x);

    ptxt->SetLength(encodedLength);
    std::cout << "Input: " << ptxt << std::endl;

    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    std::cout << "Initial number of levels remaining: " << depth - ciph->GetLevel() << std::endl;

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    std::vector<double> expected;
    std::vector<double> actual;
    
    Ciphertext<DCRTPoly> ciphertextIter = ciph;
    std::vector<double> plain = x;
    
    for (int i = 0; i < 45; ++i) {
        std::cout << "\n########## Iteración " << i + 1 << " ##########\n";
    
        // Multiplicación por 2 (homomórfica)
        ciphertextIter = cryptoContext->EvalMult(ciphertextIter, 2.0);
        for (auto& val : plain) {
            val *= 2;
        }
    
        // Bootstrapping
        auto start = std::chrono::high_resolution_clock::now();
        ciphertextIter = cryptoContext->EvalBootstrap(ciphertextIter);
        auto end = std::chrono::high_resolution_clock::now();
    
        std::chrono::duration<double> elapsed = end - start;
        std::cout << "Bootstrapping time (s): " << elapsed.count() << std::endl;
    
        // Decrypt and display result
        Plaintext result;
        cryptoContext->Decrypt(keyPair.secretKey, ciphertextIter, &result);
        result->SetLength(encodedLength);
    
        std::cout << "Decrypted \n\t" << result << std::endl;
    
        double exp_val = plain[0];
        double act_val = result->GetRealPackedValue()[0];
        double error = std::abs(exp_val - act_val);

        expected.push_back(exp_val);
        actual.push_back(act_val);

        std::cout << std::fixed << std::setprecision(15); 

        std::cout << "Expected: " << exp_val << "\n";
        std::cout << "Result  : " << act_val << "\n";
        std::cout << "Error   : " << error << "\n";

    }
    
}
