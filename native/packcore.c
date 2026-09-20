/*
 * packcore.c - native crypto core for the fabric-packer runtime loader.
 *
 * Key handling design (see also fabricpacker/N0.java):
 *   - Java-visible key material is XOR-combined with a native HKDF mask; the
 *     real AES key exists only inside this library and never on the Java heap.
 *   - Keys live in opaque slots; n1 decrypts AES-GCM blobs with the slot key,
 *     n3 destroys the slot (loader close()).
 *   - No Java fallback path on purpose: without this DLL the loader refuses
 *     to run, so an attacker cannot bypass the native layer.
 *
 * JNI bridge: fabricpacker.N0 - class name, method names and exported symbols
 * must stay in sync. Build: native/build-native.ps1 (clang / LLVM-MinGW).
 */
#include "pk_sha1.h"
#include "pk_sha2.h"
#include "pk_aes.h"
#include "pk_gcm.h"
#include "pk_slot.h"
#include "pk_jni.h"
