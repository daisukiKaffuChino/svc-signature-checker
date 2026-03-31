# svc-signature-checker
Android SVC-based anti-hooking signature checker.

## Usage

### Step 1: Load native library

```kotlin
companion object {
    init {
        System.loadLibrary("your-lib-name")
    }
}
```

### Step 2: Declare native methods

```kotlin
object NativeBridge {
    external fun checkNative(): Boolean

    // Development only
    external fun getSignatureString(): String
}
```

### Step 3: Get your signature hash (development only)

```kotlin
val hash = NativeBridge.getSignatureString()
println("Signature SHA256: $hash")
```

Copy the output and fill it into:

```c
#define APK_EXPECTED_SIGNATURE_HASH "YOUR_HASH"
```

⚠️ After obtaining the hash:

- Remove `getSignatureString()` from your code
- Or disable it in release builds

### Step 4: Verify signature

```kotlin
if (NativeBridge.checkNative()) {
    // valid
} else {
    // tampered
}
```

## How it works

- Reads `/proc/self/maps` to locate the real APK path
- Parses ZIP structure to find Signing Block
- Extracts certificate from v2/v3 signature
- Computes SHA256 using built-in implementation

## Notes

- No libc file APIs (uses raw syscall svc)
- Designed for anti-tampering / integrity check
- **ARM64** only (uses syscall numbers)

## Thanks 😘

- Gemini 3.1 Pro
- GPT-5.4

