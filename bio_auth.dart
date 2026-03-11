/// bio_auth — Biometric authentication tool (fingerprint + PIN fallback)
///
/// Behavior:
/// - Uses device fingerprint sensor via TEE (Trusted Execution Environment)
/// - Falls back to PIN/password if no biometric hardware is available
/// - Locks for 30 seconds after 3 consecutive failures
/// - Returns a typed [AuthResult] — never throws silently
///
/// No biometric data ever leaves the device TEE.

library bio_auth;

import 'dart:async';
import 'package:local_auth/local_auth.dart';
import 'package:local_auth/error_codes.dart' as auth_error;
import 'package:flutter/services.dart';

/// All possible outcomes of an authentication attempt.
enum AuthStatus {
  /// Authentication succeeded.
  success,

  /// Authentication failed (wrong fingerprint or PIN).
  failure,

  /// Device has no biometric hardware and no PIN/password enrolled.
  notEnrolled,

  /// Authentication is temporarily locked (too many failures).
  /// [AuthResult.lockedUntil] indicates when it will unlock.
  lockedOut,

  /// User cancelled the authentication dialog.
  cancelled,

  /// An unexpected platform error occurred.
  /// [AuthResult.errorMessage] contains details.
  error,
}

/// The result returned by [BioAuth.authenticate].
class AuthResult {
  final AuthStatus status;

  /// Human-readable error message, populated on [AuthStatus.error].
  final String? errorMessage;

  /// Populated when [status] == [AuthStatus.lockedOut].
  /// Indicates the earliest time the user may retry.
  final DateTime? lockedUntil;

  const AuthResult._({
    required this.status,
    this.errorMessage,
    this.lockedUntil,
  });

  /// Convenience getter.
  bool get isSuccess => status == AuthStatus.success;

  @override
  String toString() => 'AuthResult(status: $status, '
      'errorMessage: $errorMessage, lockedUntil: $lockedUntil)';
}

/// Tracks failure attempts and lockout state in memory.
///
/// This is intentionally in-memory only — no persistence across app restarts,
/// which avoids creating an attack surface on stored state.
class _LockoutGuard {
  static const int _maxAttempts = 3;
  static const Duration _lockDuration = Duration(seconds: 30);

  int _failureCount = 0;
  DateTime? _lockedUntil;

  /// Returns the lockout expiry if currently locked, otherwise null.
  DateTime? get currentLockout {
    if (_lockedUntil == null) return null;
    if (DateTime.now().isAfter(_lockedUntil!)) {
      // Lockout expired — reset automatically.
      _reset();
      return null;
    }
    return _lockedUntil;
  }

  bool get isLocked => currentLockout != null;

  /// Record a failure. Returns the lockout expiry if the limit was just hit.
  DateTime? recordFailure() {
    _failureCount++;
    if (_failureCount >= _maxAttempts) {
      _lockedUntil = DateTime.now().add(_lockDuration);
      return _lockedUntil;
    }
    return null;
  }

  void recordSuccess() => _reset();

  void _reset() {
    _failureCount = 0;
    _lockedUntil = null;
  }
}

/// The main entry point for biometric authentication.
///
/// Usage:
/// ```dart
/// final auth = BioAuth();
/// final result = await auth.authenticate(reason: 'Verify your identity');
/// if (result.isSuccess) { ... }
/// ```
class BioAuth {
  BioAuth({LocalAuthentication? localAuth})
      : _auth = localAuth ?? LocalAuthentication();

  final LocalAuthentication _auth;
  final _LockoutGuard _guard = _LockoutGuard();

  /// Attempt to authenticate the user.
  ///
  /// [reason] is displayed in the system biometric dialog.
  /// Fingerprint is preferred; falls back to PIN/password if unavailable.
  ///
  /// Never throws — all outcomes are encoded in [AuthResult].
  Future<AuthResult> authenticate({
    String reason = 'Verify your identity to continue.',
  }) async {
    // 1. Check lockout before doing anything.
    final lockout = _guard.currentLockout;
    if (lockout != null) {
      return AuthResult._(
        status: AuthStatus.lockedOut,
        lockedUntil: lockout,
      );
    }

    // 2. Check device capability.
    final capabilityCheck = await _checkCapability();
    if (capabilityCheck != null) return capabilityCheck;

    // 3. Attempt authentication.
    try {
      final authenticated = await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          biometricOnly: false, // Allow PIN fallback.
          stickyAuth: true,     // Keep dialog open if app goes background.
          useErrorDialogs: true,
        ),
      );

      if (authenticated) {
        _guard.recordSuccess();
        return const AuthResult._(status: AuthStatus.success);
      } else {
        // The user dismissed the dialog without authenticating.
        return const AuthResult._(status: AuthStatus.cancelled);
      }
    } on PlatformException catch (e) {
      return _handlePlatformException(e);
    } catch (e) {
      return AuthResult._(
        status: AuthStatus.error,
        errorMessage: 'Unexpected error: $e',
      );
    }
  }

  /// Returns the number of remaining attempts before lockout.
  /// Returns 0 if currently locked.
  int get remainingAttempts {
    if (_guard.isLocked) return 0;
    // Exposed for UI feedback only.
    return 3 - (_guard._failureCount);
  }

  /// Returns lockout expiry if currently locked, otherwise null.
  DateTime? get lockedUntil => _guard.currentLockout;

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  Future<AuthResult?> _checkCapability() async {
    try {
      final canCheck = await _auth.canCheckBiometrics;
      final isDeviceSupported = await _auth.isDeviceSupported();

      if (!isDeviceSupported) {
        return const AuthResult._(
          status: AuthStatus.notEnrolled,
          errorMessage: 'This device does not support authentication.',
        );
      }

      if (!canCheck) {
        // No biometrics available — PIN fallback is still possible.
        // local_auth handles this automatically via biometricOnly: false.
        // We proceed and let the system decide.
      }

      final availableBiometrics = await _auth.getAvailableBiometrics();
      final hasFingerprint =
          availableBiometrics.contains(BiometricType.fingerprint) ||
          availableBiometrics.contains(BiometricType.strong);

      if (!hasFingerprint && availableBiometrics.isEmpty) {
        // No biometrics enrolled — PIN/password fallback will be used.
        // This is acceptable per spec. We continue.
      }
    } on PlatformException catch (e) {
      return _handlePlatformException(e);
    }
    return null; // All good, proceed.
  }

  AuthResult _handlePlatformException(PlatformException e) {
    switch (e.code) {
      case auth_error.notAvailable:
        return const AuthResult._(
          status: AuthStatus.notEnrolled,
          errorMessage: 'No authentication method enrolled on this device.',
        );

      case auth_error.notEnrolled:
        return const AuthResult._(
          status: AuthStatus.notEnrolled,
          errorMessage: 'No fingerprint or PIN enrolled. '
              'Please set one up in device settings.',
        );

      case auth_error.lockedOut:
      case auth_error.permanentlyLockedOut:
        final lockout = _guard.recordFailure();
        return AuthResult._(
          status: AuthStatus.lockedOut,
          lockedUntil: lockout ?? DateTime.now().add(const Duration(seconds: 30)),
          errorMessage: 'Too many failed attempts. '
              'Authentication locked for 30 seconds.',
        );

      case auth_error.passcodeNotSet:
        return const AuthResult._(
          status: AuthStatus.notEnrolled,
          errorMessage: 'No passcode set on device. '
              'Please configure one in security settings.',
        );

      default:
        // Record as a failure to count toward lockout.
        final lockout = _guard.recordFailure();
        if (lockout != null) {
          return AuthResult._(
            status: AuthStatus.lockedOut,
            lockedUntil: lockout,
          );
        }
        return AuthResult._(
          status: AuthStatus.failure,
          errorMessage: 'Authentication failed: ${e.message}',
        );
    }
  }
}
