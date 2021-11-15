/**
 * MIT License
 *
 * Copyright (c) 2021 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

package com.ifx.keymaster;

import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.lang.reflect.*;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.Signature;
import java.util.Collections;
import java.util.Enumeration;
import javax.crypto.Cipher;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.util.Log;
import android.widget.EditText;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

public class MainActivity extends Activity {

    private String DEBUG_TAG = "IFXAPP";
    private EditText editText = null;
    
    static final String RSA_KEY_ALIAS = "rsa-key";
    static final String EC_KEY_ALIAS = "ec-key";
    static final String TEST_DATA_STR = "Hello world";
    static final byte[] TEST_DATA_ARRAY = TEST_DATA_STR.getBytes(Charset.forName("UTF-8"));

    /**
     * Called with the activity is first created.
     */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Set the layout for this activity.  You can find it
        // in res/layout/main_activity.xml
        View view = getLayoutInflater().inflate(R.layout.main_activity, null);
        setContentView(view);

        // After setContectView!
        editText = (EditText) findViewById(R.id.edit_text);
        Log.d(DEBUG_TAG , "onCreate done...");
        editText.append("\nonCreate done...");

        //testECKey(); // TPM EC key is not implemented
        testRSAKey();
    }

    private void testECKey() {
        try {
            /* https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html */

            Log.d(DEBUG_TAG , "testECKey() start...");
            editText.append("\ntestECKey() start...");

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            keyPairGenerator.initialize(
            new KeyGenParameterSpec.Builder(
                "key1", // key alias
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)
                .setIsStrongBoxBacked(false)
                .build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            Log.d(DEBUG_TAG , "testECKey() finish...");
            editText.append("\ntestECKey() finish...");

        } catch (Exception e) {
            Log.d(DEBUG_TAG , "testECKey() Exception: " + e.getClass().getCanonicalName());
            editText.append("\ntestECKey() Exception: " + e.getClass().getCanonicalName());
        }
    }
    
    private void testRSAKey() {
        try {
            /* https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html */
            /* https://developer.android.com/training/articles/keystore#java */

            Log.d(DEBUG_TAG , "testRSAKey() start...");
            editText.append("\ntestRSAKey() start...");
            
            KeyPair keyPair = null;

            /* Create key */

            Log.d(DEBUG_TAG, "testRSAKey() creating RSA key start...");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyPairGenerator.initialize(
            new KeyGenParameterSpec.Builder(
                RSA_KEY_ALIAS, // key alias
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY |
                KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(
                    2048, RSAKeyGenParameterSpec.F4)) // F4: exponent 65537
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1, KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1, KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setIsStrongBoxBacked(false)
                .build());
            keyPair = keyPairGenerator.generateKeyPair();
            Log.d(DEBUG_TAG, "testRSAKey() creating RSA key finish...");

            Log.d(DEBUG_TAG , "testRSAKey() getPublic start...");
            PublicKey pubKey = keyPair.getPublic();
            byte[] bPubkey = pubKey.getEncoded();
            Log.d(DEBUG_TAG , "testRSAKey() getPublic finish..." + encode(bPubkey));          

            Log.d(DEBUG_TAG , "testRSAKey() getPrivate start...");
            PrivateKey privkey = keyPair.getPrivate();
            if (privkey != null) {
                byte[] bPrivkey = privkey.getEncoded();
                if (bPrivkey != null)
                    Log.d(DEBUG_TAG , "testRSAKey() getPrivate finish..."+ Integer.toString(bPrivkey.length));
                else
                    Log.d(DEBUG_TAG , "testRSAKey() getPrivate finish...bPrivkey NULL");
            } else {
                Log.d(DEBUG_TAG , "testRSAKey() getPrivate finish...privkey NULL");
            }
            
            /* Signing & Verification */

            Signature signature = Signature.getInstance("SHA256withRSA/PSS");
            signature.initSign(keyPair.getPrivate());
            signature.update(TEST_DATA_ARRAY);
            byte[] sig = signature.sign();
            if (sig != null)
                Log.d(DEBUG_TAG , "testRSAKey() signature: "+ Integer.toString(sig.length) + " : " + encode(sig));
            else
                Log.d(DEBUG_TAG , "testRSAKey() signature null");

            Signature verifySig = Signature.getInstance("SHA256withRSA/PSS");
            verifySig.initVerify(keyPair.getPublic());
            verifySig.update(TEST_DATA_ARRAY);

            if (!verifySig.verify(sig)) {
                Log.d(DEBUG_TAG , "testRSAKey() signature verification failed...");
            } else {
            	Log.d(DEBUG_TAG , "testRSAKey() signature verification passed...");
            }

            /* Encryption & Decryption */

            Log.d(DEBUG_TAG , "testRSAKey() RSA encrypt start");
            Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            encrypt.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] bCiphertext = encrypt.doFinal(TEST_DATA_ARRAY);
            Log.d(DEBUG_TAG , "testRSAKey() RSA encrypt finish..." + encode(bCiphertext));

            Log.d(DEBUG_TAG , "testRSAKey() RSA decrypt start");
            Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            decrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            String plaintext = new String(decrypt.doFinal(bCiphertext), "UTF-8");
            if (plaintext.equals(TEST_DATA_STR))
                Log.d(DEBUG_TAG , "testRSAKey() RSA decrypt verification passed...");
            else
                Log.d(DEBUG_TAG , "testRSAKey() RSA decrypt verification failed...");
            Log.d(DEBUG_TAG , "testRSAKey() RSA decrypt finish...");

            /* Delete key */

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            Enumeration<String> aliases = ks.aliases();
            Collections.list(aliases).forEach((s) -> {
                Log.d(DEBUG_TAG, "testRSAKey() key alias found: " + s);
            });
            
            KeyStore.Entry entry = ks.getEntry(RSA_KEY_ALIAS, null);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                Log.d(DEBUG_TAG, "testRSAKey() deleting key alias: " + RSA_KEY_ALIAS);

                // retrieve the KeyPair
                //PublicKey pk = ((KeyStore.PrivateKeyEntry)entry).getCertificate().getPublicKey();
                //PrivateKey sk = ((KeyStore.PrivateKeyEntry)entry).getPrivateKey();
                //keyPair = new KeyPair(pk, sk);
                
                ks.deleteEntry(RSA_KEY_ALIAS);
                
                KeyStore ks2 = KeyStore.getInstance("AndroidKeyStore");
                ks2.load(null);
                Enumeration<String> aliases2 = ks2.aliases();
                Collections.list(aliases2).forEach((s) -> {
                    Log.d(DEBUG_TAG, "testRSAKey() key alias found after deletion: " + s);
                });
            }

            Log.d(DEBUG_TAG , "testRSAKey() finish...");
            editText.append("\ntestRSAKey() finish...");

        } catch (Exception e) {
            Log.d(DEBUG_TAG , "testRSAKey() Exception: " + e.getClass().getCanonicalName());
            editText.append("\ntestRSAKey() Exception: " + e.getClass().getCanonicalName());
        }
    }

    private static final char[] LOOKUP_TABLE_LOWER = new char[]{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66};
    private static final char[] LOOKUP_TABLE_UPPER = new char[]{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
        
    public static String encode(byte[] byteArray, boolean upperCase, ByteOrder byteOrder) {

        // our output size will be exactly 2x byte-array length
        final char[] buffer = new char[byteArray.length * 2];

        // choose lower or uppercase lookup table
        final char[] lookup = upperCase ? LOOKUP_TABLE_UPPER : LOOKUP_TABLE_LOWER;

        int index;
        for (int i = 0; i < byteArray.length; i++) {
            // for little endian we count from last to first
            index = (byteOrder == ByteOrder.BIG_ENDIAN) ? i : byteArray.length - i - 1;
        
            // extract the upper 4 bit and look up char (0-A)
            buffer[i << 1] = lookup[(byteArray[index] >> 4) & 0xF];
            // extract the lower 4 bit and look up char (0-A)
            buffer[(i << 1) + 1] = lookup[(byteArray[index] & 0xF)];
        }
        return new String(buffer);
    }

    public static String encode(byte[] byteArray) {
        return encode(byteArray, false, ByteOrder.BIG_ENDIAN);
    }


}

