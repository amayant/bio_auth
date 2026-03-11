# bio-auth

> **Tool 01 of the open-identity ecosystem.**  
> One problem. One solution. Zero compromise.

---

## What it does

`bio-auth` asks the device TEE (Trusted Execution Environment) one question:

```
Is this person who they claim to be?
```

It returns `true` or `false`. Nothing else.

No biometric data is read, stored, or transmitted. Ever.  
The device OS and its secure hardware handle the verification entirely.

---

## Behavior

| Scenario | Result |
|---|---|
| Fingerprint recognized | `AuthStatus.success` |
| User dismisses dialog | `AuthStatus.cancelled` |
| No biometric enrolled | Falls back to PIN/password |
| No hardware, no PIN | `AuthStatus.notEnrolled` |
| 3 consecutive failures | `AuthStatus.lockedOut` for 30 seconds |
| OS-level lockout | `AuthStatus.lockedOut` |
| Unexpected platform error | `AuthStatus.error` with message |

---

## Usage

```dart
import 'package:bio_auth/bio_auth.dart';

final auth = BioAuth();
final result = await auth.authenticate(reason: 'Verify your identity.');

switch (result.status) {
  case AuthStatus.success:
    // Proceed.
    break;
  case AuthStatus.lockedOut:
    final seconds = result.lockedUntil!.difference(DateTime.now()).inSeconds;
    print('Locked. Retry in $seconds seconds.');
    break;
  case AuthStatus.notEnrolled:
    print('Please enroll a fingerprint or PIN in device settings.');
    break;
  case AuthStatus.cancelled:
    // User dismissed — do nothing.
    break;
  case AuthStatus.failure:
  case AuthStatus.error:
    print('Authentication failed: ${result.errorMessage}');
    break;
}
```

---

## Platform setup

### Android

Add to `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC"/>
```

### iOS

Add to `ios/Runner/Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Used to verify your identity.</string>
```

---

## Run tests

```bash
flutter pub get
flutter pub run build_runner build   # generates mocks
flutter test
```

---

## Design principles

- **Single responsibility** — one tool, one problem.
- **Never throws** — all outcomes are typed in `AuthResult`.
- **No stored state** — lockout counter is in-memory only.
- **Auditable** — every decision is documented in the source.
- **No hidden dependencies** — only `local_auth` from the Flutter team.

---

## Part of the open-identity ecosystem

```
[ bio-auth ]  ←  you are here
      ↓
[ key-gen ]   — derive a cryptographic key from verified identity
      ↓
[ zkp-proof ] — prove identity without revealing anything
      ↓
[ did-anchor] — anchor your public identity, decentralized
```

---

## License

MIT — free for everyone, forever.
