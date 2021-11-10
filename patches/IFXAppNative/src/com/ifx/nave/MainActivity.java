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

package com.ifx.nave;

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

import com.ifx.nave.JavaNative;

public class MainActivity extends Activity {

    private String DEBUG_TAG = "IFXAPP";
    private EditText editText = null;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        View view = getLayoutInflater().inflate(R.layout.main_activity, null);
        setContentView(view);

        editText = (EditText) findViewById(R.id.edit_text);
        Log.d(DEBUG_TAG , "onCreate done...");
        editText.append("\nonCreate done...");

        jniTest();
    }

    private void jniTest() {
        try {

            Log.d(DEBUG_TAG , "jniTest enter...");
            editText.append("\njniTest enter...");
            
            JavaNative jn = new JavaNative();
            jn.test();

            Log.d(DEBUG_TAG , "jniTest exit...");
            editText.append("\njniTest exit...");

        } catch (Exception e) {
            Log.d(DEBUG_TAG , "jniTest Exception: " + e.getClass().getCanonicalName());
            editText.append("\njniTest Exception: " + e.getClass().getCanonicalName());
        }
    }

}

