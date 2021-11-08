/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

/**
 * A minimal "Hello, World!" application.
 */
public class MainActivity extends Activity {

    private String DEBUG_TAG = "IFXAPP";
    private EditText editText = null;
    
    static final String RSA_KEY_ALIAS = "rsa-key";
    static final String EC_KEY_ALIAS = "ec-key";
    static final byte[] TEST_DATA = "Hello world".getBytes(Charset.forName("UTF-8"));

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

