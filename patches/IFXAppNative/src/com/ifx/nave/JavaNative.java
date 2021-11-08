
package com.ifx.nave;

public class JavaNative {

    native protected void nativeHelloWorld();
    native protected void nativeTestTPMEngine();
    
    public void test() {
        nativeHelloWorld();
        nativeTestTPMEngine();
    }
    
    static {
        System.loadLibrary("jni-ifx-demoapp-native");
    }    

}
