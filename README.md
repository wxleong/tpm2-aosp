# Introduction

Integration of OPTIGA™ TPM 2.0 into Android Open Source Project (AOSP).

Access TPM via:
1. JNI Framework<br>Software flow: Android application (IFXAppNative) -> OpenSSL -> Engine (tpm2-tss-engine) -> TSS (tpm2-tss) -> TPM2.0 simulator (ms-tpm-20-ref)
2. Android KeyStore<br>Software flow: Android application (IFXAppKeymaster) -> Keymaster 3.0 (tpm2-km) -> PKCS #11 (tpm2-pkcs11) -> TSS (tpm2-tss) -> TPM2.0 simulator (ms-tpm-20-ref)

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
- **[4. Access TPM via JNI Framework](#4-access-tpm-via-jni-framework)**
- **[5. Fetch Additional Software Packages and Dependencies](#5-fetch-additional-software-packages-and-dependencies)**
  - **[5.1 TPM PKCS#11](#51-tpm-pkcs11)**
  - **[5.2 OpenSC](#52-opensc)**
  - **[5.3 TPM Keymaster](#53-tpm-keymaster)**
  - **[5.4 Other Modifications](#54-other-modifications)**
- **[6. Access TPM via Android KeyStore (Keymaster Hardware Abstraction Layers)](#6-access-tpm-via-keystore-keymaster-hardware-abstraction-layers)**
- **[7. References](#7-references)**
- **[License](#license)**

# 1. Prerequisites

- Tested on: 
  ```
  $ lsb_release -a
  No LSB modules are available.
  Distributor ID:	Ubuntu
  Description:	Ubuntu 20.04.3 LTS
  Release:	20.04
  Codename:	focal

  $ uname -a
  Linux ubuntu 5.11.0-40-generic #44~20.04.2-Ubuntu SMP Tue Oct 26 18:07:44 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
  ```
- Find the hardware requirements at \[[1]\]

# 2. Setup AOSP

## 2.1 Preparing the Environment

This section is a summary of \[[2]\], \[[3]\], and \[[4]\].

Install required packages:
```
$ sudo apt-get update
$ sudo apt-get install git-core gnupg flex bison build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 libncurses5 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig
```

Install Git:
```
$ sudo apt-get install git
$ git config --global user.email "you@example.com"
$ git config --global user.name "Your Name"
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

Set Python3 as default:
```
$ sudo mv /usr/bin/python /usr/bin/python.bkup
$ sudo ln -s /usr/bin/python3.8 /usr/bin/python
$ python --version
Python 3.8.5
```

Reboot your system:
```
$ sudo reboot
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

For subsequent build, if you wish to factory reset the emulator filesystem, delete the following files before rebuilding:
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
$ lunch aosp_x86_64-eng
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

# 4. Access TPM via JNI Framework


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

Execute the command `tpm2_startup -T mssim:host=localhost,port=2321 -c` in adb shell before launching the IFXAppNative application from GUI. The application log should look like:

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

# 5. Fetch Additional Software Packages and Dependencies

Remember to complete section [3](#3-fetch-tpm-software-packages-and-dependencies) and [4](#4-access-tpm-via-jni-framework).

## 5.1 TPM PKCS#11

```
$ cd ~/aosp/external
$ git clone https://github.com/tpm2-software/tpm2-pkcs11
$ cd tpm2-pkcs11
$ git checkout 1.6.0
$ git am ~/tpm2-aosp-jni/patches/tpm2-pkcs11.patch
```

## 5.2 OpenSC

```
$ cd ~/aosp/external
$ git clone https://github.com/OpenSC/OpenSC
$ cd OpenSC
$ git checkout 0.22.0
$ git am ~/tpm2-aosp-jni/patches/opensc.patch
```

## 5.3 TPM Keymaster

```
$ cp -r ~/tpm2-aosp-jni/patches/tpm2-km ~/aosp/external/tpm2-km
```

## 5.4 Other Modifications

```
$ rm -rf ~/aosp/packages/apps/IFXAppNative
$ cp -f ~/tpm2-aosp-jni/patches/Android.bp ~/aosp/external/json-c/Android.bp
$ cd ~/aosp/build/make
$ git am ~/tpm2-aosp-jni/patches/build-make-pt2.patch
$ cd ~/aosp/device/generic/goldfish
$ git am ~/tpm2-aosp-jni/patches/device-generic-goldfish-pt2.patch
$ cd ~/aosp/hardware/interfaces
$ git am ~/tpm2-aosp-jni/patches/hardware-interfaces.patch
$ cd ~/aosp/system/keymaster
$ git am ~/tpm2-aosp-jni/patches/system-keymaster.patch
$ cd ~/aosp/external/libyaml
$ git am ~/tpm2-aosp-jni/patches/libyaml-pt2.patch
$ cd ~/aosp/external/openssl
$ git am ~/tpm2-aosp-jni/patches/openssl-pt2.patch
$ cd ~/aosp/external/tpm2-tools
$ git am ~/tpm2-aosp-jni/patches/tpm2-tools-pt2.patch
$ cd ~/aosp/external/tpm2-tss
$ git am ~/tpm2-aosp-jni/patches/tpm2-tss-pt2.patch
$ cd ~/aosp/external/tpm2-tss-engine
$ git am ~/tpm2-aosp-jni/patches/tpm2-tss-engine-pt2.patch
```

# 6. Access TPM via KeyStore (Keymaster Hardware Abstraction Layers)

Copy the sample application to AOSP:

```
$ cp -r ~/tpm2-aosp-jni/patches/IFXAppKeymaster ~/aosp/packages/apps/IFXAppKeymaster
```

Factory reset the emulator filesystem:

```
$ rm ~/aosp/out/target/product/generic_x86_64/system-qemu.img
$ rm ~/aosp/out/target/product/generic_x86_64/userdata-qemu.img
```

Rebuild and launch the emulator. In the boot log you will find the activation of TPM backed keymaster@3.0:

```
11-16 11:59:33.550   170   170 I android.hardware.keymaster@3.0-impl: Fetching keymaster device name default
11-16 11:59:33.551   171   171 I HidlServiceManagement: Registered android.hardware.keymaster@4.1::IKeymasterDevice/default
11-16 11:59:33.551   171   171 I HidlServiceManagement: Removing namespace from process name android.hardware.keymaster@4.1-service to keymaster@4.1-service.
11-16 11:59:33.551   147   147 I hw-BpHwBinder: onLastStrongRef automatically unlinking death recipients
11-16 11:59:33.552   147   147 I hwservicemanager: Since android.hardware.keymaster@3.0::IKeymasterDevice/default is not registered, trying to start it as a lazy HAL.
11-16 11:59:33.552   147   147 I hwservicemanager: Since android.hardware.keymaster@3.0::IKeymasterDevice/default is not registered, trying to start it as a lazy HAL.
11-16 11:59:33.552   152   157 I HidlServiceManagement: getService: Trying again for android.hardware.keymaster@3.0::IKeymasterDevice/default...
11-16 11:59:33.556   170   170 I TEEKeyMaster: tee_open
11-16 11:59:33.559   170   170 I HidlServiceManagement: Registered android.hardware.keymaster@3.0::IKeymasterDevice/default
11-16 11:59:33.559   170   170 I HidlServiceManagement: Removing namespace from process name android.hardware.keymaster@3.0-service to keymaster@3.0-service.
11-16 11:59:33.559   170   170 I LegacySupport: Registration complete for android.hardware.keymaster@3.0::IKeymasterDevice/default.
11-16 11:59:33.559   147   147 I hw-BpHwBinder: onLastStrongRef automatically unlinking death recipients
11-16 11:59:33.559   152   157 I vold    : List of Keymaster HALs found:
11-16 11:59:33.559   152   157 I vold    : Keymaster HAL #1: SoftwareWrappedKeymaster0Device from Google SecurityLevel: TRUSTED_ENVIRONMENT HAL: android.hardware.keymaster@3.0::IKeymasterDevice/default
11-16 11:59:33.559   152   157 I vold    : Keymaster HAL #2: SoftwareKeymasterDevice from Google SecurityLevel: SOFTWARE HAL: android.hardware.keymaster@4.1::IKeymasterDevice/default
11-16 11:59:33.559   152   157 D vold    : Computing HMAC with params { (seed: , nonce: 93a667cbefd43546dfe71426311794327d72793b8861834cb38421ba225b1a2) }
11-16 11:59:33.559   152   157 D vold    : Computing HMAC for SoftwareKeymasterDevice from Google SecurityLevel: SOFTWARE HAL: android.hardware.keymaster@4.1::IKeymasterDevice/default
11-16 11:59:33.559   152   157 I vold    : Using SoftwareWrappedKeymaster0Device from Google for encryption.  Security level: TRUSTED_ENVIRONMENT, HAL: android.hardware.keymaster@3.0::IKeymasterDevice/default
```

Start an adb shell session:

```
$ cd ~/aosp/out/host/linux-x86/bin
$ ./adb shell
```

Initialize TPM:

```
$ rm -rf /data/tpm2-tss/*
$ tpm2_startup -T mssim:host=localhost,port=2321 -c
$ tpm2_clear -T mssim:host=localhost,port=2321 -c p
$ tss2_provision
WARNING:fapi:external/tpm2-tss/src/tss2-fapi/ifapi_io.c:333:ifapi_io_check_create_dir() Directory /data/tpm2-tss/eventlog/ does not exist, creating
WARNING:fapi:external/tpm2-tss/src/tss2-fapi/ifapi_io.c:333:ifapi_io_check_create_dir() Directory /data/tpm2-tss/user/keystore does not exist, creating
WARNING:fapi:external/tpm2-tss/src/tss2-fapi/ifapi_io.c:333:ifapi_io_check_create_dir() Directory /data/tpm2-tss/system/keystore/policy does not exist, creating
$ tpm2_getcap -T mssim:host=localhost,port=2321 handles-persistent
- 0x81000001
```

Initialize TPM-based PKCS #11 token:

```
$ pkcs11-tool --module /vendor/lib64/tpm2-pkcs11.so --slot-index=0 --init-token --label="pkcs11 token" --so-pin="sopin"
Using slot with index 0 (0x1)
Token successfully initialized
$ pkcs11-tool --module /vendor/lib64/tpm2-pkcs11.so --slot-index=0 --init-pin --so-pin="sopin" --login --pin="userpin"
ERROR:fapi:external/tpm2-tss/src/tss2-fapi/ifapi_keystore.c:533:rel_path_to_abs_path() ErrorCode (0x00060020) Key /HS/SRK/tpm2-pkcs11-token-usr-00000001 not found. 
ERROR:fapi:external/tpm2-tss/src/tss2-fapi/ifapi_keystore.c:581:ifapi_keystore_load_async() ErrorCode (0x00060020) Object /HS/SRK/tpm2-pkcs11-token-usr-00000001 not found. 
ERROR:fapi:external/tpm2-tss/src/tss2-fapi/api/Fapi_GetAppData.c:139:Fapi_GetAppData_Async() ErrorCode (0x00060020) Could not open: /HS/SRK/tpm2-pkcs11-token-usr-00000001 
ERROR:fapi:external/tpm2-tss/src/tss2-fapi/api/Fapi_GetAppData.c:72:Fapi_GetAppData() ErrorCode (0x00060020) Path_SetDescription 
Using slot with index 0 (0x1)
User PIN successfully initialized
$ pkcs11-tool --module /vendor/lib64/tpm2-pkcs11.so --list-token-slots
Available slots:
Slot 0 (0x1): pkcs11 token                    MSFT
  token label        : pkcs11 token
  token manufacturer : MSFT
  token model        : xCG fTPM
  token flags        : login required, rng, token initialized, PIN initialized
  hardware version   : 1.62
  firmware version   : 23.25
  serial num         : 0000000000000000
  pin min/max        : 0/128
Slot 1 (0x2):                                 MSFT
  token state:   uninitialized
$ pkcs11-tool --module /vendor/lib64/tpm2-pkcs11.so --slot 1 --list-mechanisms
Supported mechanisms:
  RSA-PKCS-KEY-PAIR-GEN, keySize={1024,2048}, hw, generate_key_pair
  RSA-X-509, keySize={1024,2048}, hw, encrypt, decrypt, sign, verify
  RSA-PKCS, keySize={1024,2048}, hw, encrypt, decrypt, sign, verify
  RSA-PKCS-PSS, keySize={1024,2048}, hw, sign, verify
  RSA-PKCS-OAEP, keySize={1024,2048}, hw, encrypt, decrypt
  SHA1-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
  SHA256-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
  SHA384-RSA-PKCS, keySize={1024,2048}, hw, sign, verify
  SHA1-RSA-PKCS-PSS, keySize={1024,2048}, hw, sign, verify
  SHA256-RSA-PKCS-PSS, keySize={1024,2048}, hw, sign, verify
  SHA384-RSA-PKCS-PSS, keySize={1024,2048}, hw, sign, verify
  ECDSA-KEY-PAIR-GEN, keySize={256,384}, hw, generate_key_pair
  ECDSA, keySize={256,384}, hw, sign, verify
  ECDSA-SHA1, keySize={256,384}, hw, sign, verify
  AES-KEY-GEN, keySize={16,32}, hw, generate
  AES-CBC, keySize={16,32}, hw, encrypt, decrypt
  AES-CBC-PAD, keySize={16,32}, hw, encrypt, decrypt
  mechtype-0x2107, keySize={16,32}, hw, encrypt, decrypt
  AES-ECB, keySize={16,32}, hw, encrypt, decrypt
  AES-CTR, keySize={16,32}, hw, encrypt, decrypt
  SHA-1, digest
  SHA256, digest
  SHA384, digest
  SHA512, digest
```

Launch the IFXAppKeymaster application from GUI. The application log should look like:

```
11-16 14:09:29.333  2697  2697 D IFXAPP  : onCreate done...
11-16 14:09:29.333  2697  2697 D IFXAPP  : testRSAKey() start...
11-16 14:09:29.333  2697  2697 D IFXAPP  : testRSAKey() creating RSA key start...
11-16 14:09:29.336   178   178 I TEEKeyMaster: tee_generate_keypair start
11-16 14:09:29.336   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.355   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.357   178   178 E TEEKeyMaster: publicExponent 1 8 8 8
11-16 14:09:29.357   178   178 E TEEKeyMaster: publicExponent 0 8 8 8
11-16 14:09:29.357   178   178 E TEEKeyMaster: publicExponent 1 8 8 8
11-16 14:09:29.357   178   178 E TEEKeyMaster: publicExponent 0 8 8 8
11-16 14:09:29.357   178   178 E TEEKeyMaster: publicExponent 0 8 8 8
11-16 14:09:29.357   178   178 E TEEKeyMaster: publicExponent 0 0 0 0 0 1 0 1
11-16 14:09:29.489   178   178 I TEEKeyMaster: public handle = 0x1, private handle = 0x2
11-16 14:09:29.489   178   178 I TEEKeyMaster: tee_generate_keypair end
11-16 14:09:29.495   178   178 I TEEKeyMaster: tee_get_keypair_public start
11-16 14:09:29.495   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.509   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.511   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.511   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.511   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.511   178   178 I TEEKeyMaster: modulus is 256 (ret=256), exponent is 4 (ret=4)
11-16 14:09:29.511   178   178 I TEEKeyMaster: Length of x509 data is 294
11-16 14:09:29.511   178   178 I TEEKeyMaster: tee_get_keypair_public end
11-16 14:09:29.516   178   178 I TEEKeyMaster: tee_get_keypair_public start
11-16 14:09:29.516   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.526   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.528   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.528   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.528   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.528   178   178 I TEEKeyMaster: modulus is 256 (ret=256), exponent is 4 (ret=4)
11-16 14:09:29.528   178   178 I TEEKeyMaster: Length of x509 data is 294
11-16 14:09:29.528   178   178 I TEEKeyMaster: tee_get_keypair_public end
11-16 14:09:29.529   178   178 I TEEKeyMaster: tee_sign_data(0x71d4321a9fd0, 0x71d3c21aa950, 36, 0x71d4421adfd8, 256, 0x7fff2f6a8c38, 0x7fff2f6a8c28)
11-16 14:09:29.529   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.534   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.536   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.536   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.536   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.536   178   178 I TEEKeyMaster: public handle = 0x1, private handle = 0x2
11-16 14:09:29.537   178   178 I TEEKeyMaster: tee_sign_data(0x71d4321a9fd0, 0x71d3c21aa950, 36, 0x71d4421adfd8, 256, 0x7fff2f6a8c38, 0x7fff2f6a8c28) => 0x71d4421afe30 size 256
11-16 14:09:29.541  2697  2697 D IFXAPP  : testRSAKey() creating RSA key finish...
11-16 14:09:29.541  2697  2697 D IFXAPP  : testRSAKey() getPublic start...
11-16 14:09:29.541  2697  2697 D IFXAPP  : testRSAKey() getPublic finish...30820122300d06092a864886f70d01010105000382010f003082010a0282010100ab6366c784913675a8bde000c3410a346cdfc05db2e41252b9ca2685ddbd3282d60a9d90340e79ef28d1520ce227bdf2c512165bcda633166cf0f087bdccfa653aab86150d99dab889ce5812637d0d0a5d8f1d8b4289ccd23ca6257fc0aaa2a27bf61e7b8e551ba1b841021921b8b703523abdbbe8b2bc480c215ee0b385eea6ebe2c9d6ba4ee980758ccaf6194841cf4b293bd4f3b1eed7e8653c2fe673a68d4a7dd1a0326c83847c93c2f56c7d5a8fc9d07b3deb223629e3f76626b90ff017034363c4f387daf89a80b4ff7b4f00e203a44d1484f78398a0f752b92aa81304dfad6ae504e39165f1afe22cbded01bde9cb80493f36985a98203fa28a7e4c590203010001
11-16 14:09:29.541  2697  2697 D IFXAPP  : testRSAKey() getPrivate start...
11-16 14:09:29.541  2697  2697 D IFXAPP  : testRSAKey() getPrivate finish...bPrivkey NULL
11-16 14:09:29.541   178   178 I TEEKeyMaster: tee_get_keypair_public start
11-16 14:09:29.541   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.550   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.552   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.552   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.552   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.552   178   178 I TEEKeyMaster: modulus is 256 (ret=256), exponent is 4 (ret=4)
11-16 14:09:29.552   178   178 I TEEKeyMaster: Length of x509 data is 294
11-16 14:09:29.552   178   178 I TEEKeyMaster: tee_get_keypair_public end
11-16 14:09:29.553   178   178 I TEEKeyMaster: tee_sign_data(0x71d4321a9fd0, 0x71d3c21aa010, 36, 0x71d4421afe38, 256, 0x7fff2f6a8c48, 0x7fff2f6a8c38)
11-16 14:09:29.553   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.559   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.560   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.560   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.560   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.560   178   178 I TEEKeyMaster: public handle = 0x1, private handle = 0x2
11-16 14:09:29.562   178   178 I TEEKeyMaster: tee_sign_data(0x71d4321a9fd0, 0x71d3c21aa010, 36, 0x71d4421afe38, 256, 0x7fff2f6a8c48, 0x7fff2f6a8c38) => 0x71d4421aec30 size 256
11-16 14:09:29.562  2697  2697 D IFXAPP  : testRSAKey() signature: 256 : 76820f066ed68a0dfa99d8a9e58adcb5298802c183bdf828e8b8f22f723f45ebb3da0cd23b9ad8d878112f82ccc251a60ac71f7107f52515df90010ff921fe7613c13eff50a8bc65eeb2f31302a93c84d8dd343d6d488ba5ce804c5ccb9000af84603bf3048903df118e4c87cb517406aa85d035480c1e561f5e39962db85183cd0d66d90bed1b81aac33153064a2920ddb82970d5c9ba82735869e3ea0dd689f9b1e0c4ba900abbe952c637ffe37c8d10245ae29bd9bfd28d38f0ab7d861dd0da883436fd6d3c444ce22870195245627600d6b0df00cefb4fe714539792496291fd06553a76fd4caf4121eb8d750766a948c46ae1cb341c83e7888878b43a5a
11-16 14:09:29.563  2697  2697 D IFXAPP  : testRSAKey() signature verification passed...
11-16 14:09:29.563  2697  2697 D IFXAPP  : testRSAKey() RSA encrypt start
11-16 14:09:29.563  2697  2697 D IFXAPP  : testRSAKey() RSA encrypt finish...17194a69a1c09f09f1828c449538c16cbf4f53f1c6ae1b9115944c5d40ef4136bc72045a08d8218b6f6a88ff23a5da69b8577c1e2f3348d1b58b15ef8ab5408f40babb6f76b3b4ccc7e48db248e2fbb3993d315bc4a6b6ae596a1cfe6ed5fb2b7580abcb09289f8a3d6d1bb958fe1fe05a7ff5043d21d25a9f6ee1e7d85b08694be50a6203b9fb937e11b8e3bdf55c06adc1e213b006948319d8f9d50dbb3d7efef87844b7b2f4b44f12265d03cde0517e4882a4bb8274fd1608932a5b48284ef7d932fd89d6d303d073bc49731564ce35867f58d8368bad3cfbe35ed83fd36df897d8e6dcc90f9970bbecce8f7361408a81e360a6d5d57deb7be1af0938632f
11-16 14:09:29.563  2697  2697 D IFXAPP  : testRSAKey() RSA decrypt start
11-16 14:09:29.564   178   178 I TEEKeyMaster: tee_get_keypair_public start
11-16 14:09:29.564   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.569   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.571   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.571   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.571   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.571   178   178 I TEEKeyMaster: modulus is 256 (ret=256), exponent is 4 (ret=4)
11-16 14:09:29.571   178   178 I TEEKeyMaster: Length of x509 data is 294
11-16 14:09:29.571   178   178 I TEEKeyMaster: tee_get_keypair_public end
11-16 14:09:29.572   178   178 I TEEKeyMaster: tee_sign_data(0x71d4321a9fd0, 0x71d3c21aa490, 36, 0x71d4721aa950, 256, 0x7fff2f6a8ce8, 0x7fff2f6a8cd8)
11-16 14:09:29.572   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.576   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.578   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.578   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.578   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.578   178   178 I TEEKeyMaster: public handle = 0x1, private handle = 0x2
11-16 14:09:29.579   178   178 I TEEKeyMaster: tee_sign_data(0x71d4321a9fd0, 0x71d3c21aa490, 36, 0x71d4721aa950, 256, 0x7fff2f6a8ce8, 0x7fff2f6a8cd8) => 0x71d4421aec30 size 256
11-16 14:09:29.580  2697  2697 D IFXAPP  : testRSAKey() RSA decrypt finish...Hello world
11-16 14:09:29.580  2697  2697 D IFXAPP  : testRSAKey() key alias found: rsa-key
11-16 14:09:29.581   178   178 I TEEKeyMaster: tee_get_keypair_public start
11-16 14:09:29.581   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.586   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.588   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.588   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.588   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.588   178   178 I TEEKeyMaster: modulus is 256 (ret=256), exponent is 4 (ret=4)
11-16 14:09:29.588   178   178 I TEEKeyMaster: Length of x509 data is 294
11-16 14:09:29.588   178   178 I TEEKeyMaster: tee_get_keypair_public end
11-16 14:09:29.590  2697  2697 D IFXAPP  : testRSAKey() deleting key alias: rsa-key
11-16 14:09:29.590  2697  2697 D IFXAPP  : testRSAKey() finish...
11-16 14:09:29.594   178   178 I TEEKeyMaster: tee_get_keypair_public start
11-16 14:09:29.594   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.604  2697  2717 D HostConnection: HostConnection::get() New Host Connection established 0x73033f80e640, tid 2717
11-16 14:09:29.607  2697  2717 D HostConnection: HostComposition ext ANDROID_EMU_CHECKSUM_HELPER_v1 ANDROID_EMU_dma_v1 ANDROID_EMU_direct_mem ANDROID_EMU_host_composition_v1 ANDROID_EMU_host_composition_v2 ANDROID_EMU_vulkan ANDROID_EMU_deferred_vulkan_commands ANDROID_EMU_vulkan_null_optional_strings ANDROID_EMU_vulkan_create_resources_with_requirements ANDROID_EMU_YUV_Cache ANDROID_EMU_async_unmap_buffer ANDROID_EMU_vulkan_ignored_handles ANDROID_EMU_vulkan_free_memory_sync ANDROID_EMU_vulkan_shader_float16_int8 ANDROID_EMU_vulkan_async_queue_submit GL_OES_EGL_image_external_essl3 GL_OES_vertex_array_object GL_KHR_texture_compression_astc_ldr ANDROID_EMU_host_side_tracing ANDROID_EMU_gles_max_version_3_0 
11-16 14:09:29.609   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.610   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.610   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.610   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.610   178   178 I TEEKeyMaster: modulus is 256 (ret=256), exponent is 4 (ret=4)
11-16 14:09:29.610   178   178 I TEEKeyMaster: Length of x509 data is 294
11-16 14:09:29.611   178   178 I TEEKeyMaster: tee_get_keypair_public end
11-16 14:09:29.611   178   178 I TEEKeyMaster: tee_delete_keypair start key_blob_length 36
11-16 14:09:29.611   178   178 I TEEKeyMaster: tee_late_open
11-16 14:09:29.613   295   375 W EmuHWC2 : No layers, exit, buffer 0x7c5d2d751610
11-16 14:09:29.614   295   375 W EmuHWC2 : validate: layer 11 CompositionType 1, fallback
11-16 14:09:29.618   178   178 I TEEKeyMaster: C_GetInfo cryptokiVer=2.40 manufID=tpm2-software.github.io          flags=0 libDesc=TPM2.0 Cryptoki                  libVer=0.0
11-16 14:09:29.621   178   178 I TEEKeyMaster: tee_delete_keypair start1
11-16 14:09:29.621   178   178 I TEEKeyMaster: tee_delete_keypair start2
11-16 14:09:29.621   178   178 E TEEKeyMaster: Good key version 1
11-16 14:09:29.621   178   178 I TEEKeyMaster: Found 1 object 0x1 : class 0x2
11-16 14:09:29.621   178   178 I TEEKeyMaster: Found 1 object 0x2 : class 0x3
11-16 14:09:29.621   178   178 I TEEKeyMaster: tee_delete_keypair start3
11-16 14:09:29.622   178   178 I TEEKeyMaster: tee_delete_keypair start4
11-16 14:09:29.622   178   178 I TEEKeyMaster: tee_delete_keypair end
```


# 7. References

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
