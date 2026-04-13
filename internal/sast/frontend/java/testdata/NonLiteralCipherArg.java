package com.example;

import javax.crypto.Cipher;

/**
 * The algorithm name is passed in via a parameter. Chunk SAST-2's AST-local
 * matcher cannot (by design) reach back to the parameter definition — the
 * taint engine in Chunk SAST-3 will do that. This fixture documents the
 * current limitation by asserting that ZERO findings are produced for this
 * file.
 */
public class NonLiteralCipherArg {
    public void fromParam(String algo) throws Exception {
        Cipher c = Cipher.getInstance(algo);
    }
}
