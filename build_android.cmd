@echo off
set NDK_HOME=C:\Users\User\AppData\Local\Android\Sdk\ndk\28.2.13676358
set TOOLCHAIN=%NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64

set CC_aarch64_linux_android=%TOOLCHAIN%\bin\aarch64-linux-android28-clang.cmd
set AR_aarch64_linux_android=%TOOLCHAIN%\bin\llvm-ar.exe
set CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=%TOOLCHAIN%\bin\aarch64-linux-android28-clang.cmd

set CFLAGS_aarch64_linux_android=--sysroot=%TOOLCHAIN%\sysroot -I%TOOLCHAIN%\sysroot\usr\include

cargo build --target aarch64-linux-android --release