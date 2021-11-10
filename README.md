# Introduction

Trusted Platform Module 2.0 (TPM) integrate guide for Android Open Source Project (AOSP).

Software flowchart: Android application (IFXAppNative) -> OpenSSL -> Engine (tpm2-tss-engine) -> TSS (tpm2-tss) -> TPM2.0 simulator (ms-tpm-20-ref)

# Table of Contents

- **[1. Prerequisites](#1-prerequisites)**
- **[2. Setup AOSP](#2-setup-aosp)**
  - **[2.1 Preparing the Environment](#21-preparing-the-environment)**
  - **[2.2 Download AOSP](#22-download-aosp)**
  - **[2.3 Build AOSP](#23-build-aosp)**
  - **[2.4 Run AOSP Emulator](#24-run-aosp-emulator)**
  - **[2.5 Android Debug Bridge](#25-android-debug-bridge)**
- **[3. Fetch TPM Software Packages and Dependencies](#3-fetch-tpm-software-packages-and-dependencies)**
  - **[3.1 JSON](#31-json)**
  - **[3.2 YAML](#32-yaml)**
  - **[3.3 OpenSSL](#33-openssl)**
  - **[3.4 TPM Simulator](#34-tpm-simulator)**
  - **[3.5 TPM TSS](#35-tpm-tss)**
  - **[3.6 TPM TSS Engine](#36-tpm-tss-engine)**
  - **[3.7 TPM Tools](#37-tpm-tools)**
  - **[3.8 AOSP Build Config](#38-aosp-build-config)**
- **[4. Access TPM using JNI Framework](#4-access-tpm-using-jni-framework)**
- **[5. References](#5-references)**
- **[License](#license)**

# 1. Prerequisites

- Tested on Ubuntu 20.04.3 LTS x86_64
- Find the hardware requirements at \[[1]\]

# 2. Setup AOSP

## 2.1 Preparing the Environment

This section is a summary of \[[2]\], \[[3]\], and \[[4]\].

Install required packages:
```
$ sudo apt-get install git-core gnupg flex bison build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 libncurses5 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig
```

Install additional packages:
```
$ sudo apt-get install git
```

Download this repository:
```
$ git clone https://github.com/wxleong/tpm2-aosp-jni ~/tpm2-aosp-jni
```

Install repo:
```
$ export REPO=$(mktemp /tmp/repo.XXXXXXXXX)
$ curl -o ${REPO} https://storage.googleapis.com/git-repo-downloads/repo
$ sudo install -m 755 ${REPO} /usr/bin/repo
```

<!-- **! CHECK IF THIS COMMAND OK "update-alternatives --install /usr/bin/python python /usr/bin/python3 1" ref: https://unix.stackexchange.com/questions/410579/change-the-python3-default-version-in-ubuntu/410851** -->

Set Python3 as default:
```
$ sudo mv /usr/bin/python /usr/bin/python.bkup
$ sudo ln -s /usr/bin/python3.6 /usr/bin/python
```

Check if repo is installed correctly:
```
$ repo version
```

Download [Android NDK r23 LTS (August 2021)](https://developer.android.com/ndk/downloads/revision_history) to `~/android-ndk-r23`.

## 2.2 Download AOSP

Download Android 11.0.0_r37, approximately 118GB:
```
$ mkdir ~/aosp
$ cd ~/aosp
$ repo init -u https://android.googlesource.com/platform/manifest -b android-11.0.0_r37
$ repo sync -c -j$(nproc)
```

## 2.3 Build AOSP

Build AOSP emulator, grow to approximately 250GB:
```
$ cd ~/aosp
$ source build/envsetup.sh
$ lunch aosp_x86_64-eng
$ m -j$(nproc)
```

For subsequent build, if you wish to reset the emulator filesystem, delete the following files before rebuilding:
```
$ rm ~/aosp/out/target/product/generic_x86_64/system-qemu.img
$ rm ~/aosp/out/target/product/generic_x86_64/userdata-qemu.img
```

## 2.4 Run AOSP Emulator

Grant access permission to kernel-based Virtual Machine (KVM):
```
$ sudo chmod a+rw /dev/kvm
``` 

Run the emulator in permissive mode to suppress SELinux errors:
```
$ cd ~/aosp
$ source build/envsetup.sh
$ emulator -verbose -gpu swiftshader -selinux permissive -logcat *:v
```

## 2.5 Android Debug Bridge

```
$ cd ~/aosp/out/host/linux-x86/bin
$ ./adb shell
```

# 3. Fetch TPM Software Packages and Dependencies

## 3.1 JSON

The project is taken from `~/aosp/device/google/bonito/json-c` and modified.

```
$ cp -r ~/tpm2-aosp-jni/patches/json-c ~/aosp/external/json-c
```

## 3.2 YAML

```
$ cd ~/aosp/external
$ git clone https://github.com/yaml/libyaml
$ cd libyaml
$ git checkout 0.2.5
$ git am ~/tpm2-aosp-jni/patches/libyaml.patch
```

## 3.3 OpenSSL

Find the official build instruction at \[[7]\].

```
$ cd ~/aosp/external
$ git clone https://github.com/openssl/openssl
$ cd openssl
$ git checkout OpenSSL_1_1_1l
$ git am ~/tpm2-aosp-jni/patches/openssl.patch
$ export ANDROID_NDK_HOME=$HOME/android-ndk-r23
$ PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_HOME/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH
$ ./Configure android-x86_64 -D__ANDROID_API__=30
$ make -j$(nproc)
```

## 3.4 TPM Simulator

```
$ cd ~/aosp/external
$ git clone https://android.googlesource.com/platform/external/ms-tpm-20-ref
$ cd ms-tpm-20-ref
$ git checkout android-s-beta-4
$ git am --ignore-space-change ~/tpm2-aosp-jni/patches/ms-tpm-20-ref.patch
```

## 3.5 TPM TSS

```
$ cd ~/aosp/external
$ git clone https://github.com/tpm2-software/tpm2-tss
$ cd tpm2-tss
$ git checkout 3.1.0
$ git am ~/tpm2-aosp-jni/patches/tpm2-tss.patch
```

## 3.6 TPM TSS Engine

```
$ cd ~/aosp/external
$ git clone https://github.com/tpm2-software/tpm2-tss-engine
$ cd tpm2-tss-engine
$ git checkout v1.1.0
$ git am ~/tpm2-aosp-jni/patches/tpm2-tss-engine.patch
```

## 3.7 TPM Tools

```
$ cd ~/aosp/external
$ git clone https://github.com/tpm2-software/tpm2-tools
$ cd tpm2-tools
$ git checkout 5.1.1
$ git am ~/tpm2-aosp-jni/patches/tpm2-tools.patch
```

## 3.8 AOSP Build Config

```
$ cd ~/aosp/build/make
$ git am ~/tpm2-aosp-jni/patches/build-make.patch
$ cd ~/aosp/device/generic/goldfish
$ git am ~/tpm2-aosp-jni/patches/device-generic-goldfish.patch
```

# 4. Access TPM using JNI Framework


Copy the sample application to AOSP:

```
$ cp -r ~/tpm2-aosp-jni/patches/IFXAppNative ~/aosp/packages/apps/IFXAppNative
```

Rebuild and launch the AOSP emulator. Now start an adb shell session:

```
$ cd ~/aosp/out/host/linux-x86/bin
$ ./adb shell
```

Check if TPM simulator is running and listening to port 2321 and 2322. Execute the following command in adb shell:

```
$ netstat -plnt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program Name
tcp        0      0 0.0.0.0:2321            0.0.0.0:*               LISTEN      357/ms-tpm-20-ref
tcp        0      0 0.0.0.0:2322            0.0.0.0:*               LISTEN      357/ms-tpm-20-ref
```

Execute the command `tpm2_startup -T mssim:host=localhost,port=2321 -c` in adb shell before launching the IFXAppNative application. Showing below is the application log:

```
11-09 15:35:45.390  1845  1845 D IFXAPP  : onCreate done...
11-09 15:35:45.390  1845  1845 D IFXAPP  : jniTest enter...
11-09 15:35:45.412  1845  1845 I com.ifx.nave: Invoked Java_com_ifx_nave_JavaNative_nativeHelloWorld
11-09 15:35:45.412  1845  1845 I com.ifx.nave: Exit Java_com_ifx_nave_JavaNative_nativeHelloWorld
11-09 15:35:45.412  1845  1845 I com.ifx.nave: Invoked Java_com_ifx_nave_JavaNative_nativeTestTPMEngine
11-09 15:35:45.416  1845  1845 I com.ifx.nave: Generating RSA key using TPM
11-09 15:35:45.487  1845  1845 I com.ifx.nave: RSA Key generated
11-09 15:35:45.492  1845  1845 I com.ifx.nave: RSA Key written to /storage/emulated/0/Download/rsa-key
11-09 15:35:45.492  1845  1845 I com.ifx.nave: Generating EC key using TPM
11-09 15:35:45.496  1845  1845 I com.ifx.nave: EC Key generated
11-09 15:35:45.498  1845  1845 I com.ifx.nave: EC Key written to /storage/emulated/0/Download/ec-key
11-09 15:35:45.501  1845  1845 I com.ifx.nave: Loaded RSA key
11-09 15:35:45.502  1845  1845 I com.ifx.nave: Loaded EC key
11-09 15:35:45.502  1845  1845 I com.ifx.nave: EC signing
11-09 15:35:45.502  1845  1845 I com.ifx.nave: EC generating signature
11-09 15:35:45.506  1845  1845 I com.ifx.nave: EC verify signature
11-09 15:35:45.506  1845  1845 I com.ifx.nave: EC signature verification ok
11-09 15:35:45.506  1845  1845 I com.ifx.nave: EC signature verification expected to fail, ok
11-09 15:35:45.506  1845  1845 I com.ifx.nave: EC Generating signature
11-09 15:35:45.509  1845  1845 I com.ifx.nave: EC verify signature
11-09 15:35:45.510  1845  1845 I com.ifx.nave: EC signature verification ok
11-09 15:35:45.510  1845  1845 I com.ifx.nave: EC signature verification expected to fail, ok
11-09 15:35:45.510  1845  1845 I com.ifx.nave: RSA signing
11-09 15:35:45.510  1845  1845 I com.ifx.nave: RSA generating signature
11-09 15:35:45.514  1845  1845 I com.ifx.nave: RSA verify signature
11-09 15:35:45.514  1845  1845 I com.ifx.nave: RSA signature verification ok
11-09 15:35:45.514  1845  1845 I com.ifx.nave: RSA signature verification expected to fail, ok
11-09 15:35:45.514  1845  1845 I com.ifx.nave: RSA generating signature
11-09 15:35:45.517  1845  1845 I com.ifx.nave: RSA verify signature
11-09 15:35:45.517  1845  1845 I com.ifx.nave: RSA signature verification ok
11-09 15:35:45.517  1845  1845 I com.ifx.nave: RSA signature verification expected to fail, ok
11-09 15:35:45.517  1845  1845 I com.ifx.nave: Generating encryption blob
11-09 15:35:45.520  1845  1845 I com.ifx.nave: Decrypting encrypted blob
11-09 15:35:45.526  1845  1845 I com.ifx.nave: Decryption verification ok
11-09 15:35:45.526  1845  1845 I com.ifx.nave: Generating encryption blob
11-09 15:35:45.529  1845  1845 I com.ifx.nave: Decrypting encrypted blob
11-09 15:35:45.534  1845  1845 I com.ifx.nave: Decryption verification ok
11-09 15:35:45.534  1845  1845 I com.ifx.nave: Exit Java_com_ifx_nave_JavaNative_nativeTestTPMEngine
11-09 15:35:45.534  1845  1845 D IFXAPP  : jniTest exit...
```

<!-- # 5. Access TPM from KeyStore (via Keymaster Hardware Abstraction Layers) -->

# 5. References

- \[1\] https://source.android.com/setup/build/requirements
- \[2\] https://source.android.com/setup/build/initializing
- \[3\] https://source.android.com/setup/develop#installing-repo
- \[4\] https://developer.android.com/ndk/downloads
- \[5\] https://source.android.com/setup/build/downloading
- \[6\] https://developer.android.com/studio/run/emulator-commandline
- \[7\] https://github.com/openssl/openssl/blob/master/NOTES-ANDROID.md

[1]: https://source.android.com/setup/build/requirements
[2]: https://source.android.com/setup/build/initializing
[3]: https://source.android.com/setup/develop#installing-repo
[4]: https://developer.android.com/ndk/downloads
[5]: https://source.android.com/setup/build/downloading
[6]: https://developer.android.com/studio/run/emulator-commandline
[7]: https://github.com/openssl/openssl/blob/master/NOTES-ANDROID.md

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
