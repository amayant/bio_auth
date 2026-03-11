import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'package:local_auth/local_auth.dart';
import 'package:local_auth/error_codes.dart' as auth_error;
import 'package:flutter/services.dart';

import 'package:bio_auth/bio_auth.dart';

import 'bio_auth_test.mocks.dart';

@GenerateMocks([LocalAuthentication])
void main() {
  late MockLocalAuthentication mockAuth;
  late BioAuth bioAuth;

  setUp(() {
    mockAuth = MockLocalAuthentication();
    bioAuth = BioAuth(localAuth: mockAuth);

    // Default: device is supported and has fingerprint.
    when(mockAuth.isDeviceSupported()).thenAnswer((_) async => true);
    when(mockAuth.canCheckBiometrics).thenAnswer((_) async => true);
    when(mockAuth.getAvailableBiometrics())
        .thenAnswer((_) async => [BiometricType.fingerprint]);
  });

  group('Successful authentication', () {
    test('returns AuthStatus.success when fingerprint is recognized', () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenAnswer((_) async => true);

      final result = await bioAuth.authenticate();

      expect(result.status, AuthStatus.success);
      expect(result.isSuccess, isTrue);
      expect(result.errorMessage, isNull);
    });
  });

  group('Cancelled authentication', () {
    test('returns AuthStatus.cancelled when user dismisses dialog', () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenAnswer((_) async => false);

      final result = await bioAuth.authenticate();

      expect(result.status, AuthStatus.cancelled);
    });
  });

  group('Lockout after 3 failures', () {
    test('locks for 30 seconds after 3 consecutive platform failures',
        () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenThrow(PlatformException(
        code: 'AuthenticationFailed',
        message: 'Fingerprint not recognized',
      ));

      // Attempts 1 and 2: failure, not yet locked.
      final r1 = await bioAuth.authenticate();
      expect(r1.status, AuthStatus.failure);
      expect(bioAuth.remainingAttempts, 2);

      final r2 = await bioAuth.authenticate();
      expect(r2.status, AuthStatus.failure);
      expect(bioAuth.remainingAttempts, 1);

      // Attempt 3: triggers lockout.
      final r3 = await bioAuth.authenticate();
      expect(r3.status, AuthStatus.lockedOut);
      expect(r3.lockedUntil, isNotNull);
      expect(
        r3.lockedUntil!.isAfter(DateTime.now()),
        isTrue,
        reason: 'Lockout expiry must be in the future',
      );
      expect(
        r3.lockedUntil!.difference(DateTime.now()).inSeconds,
        greaterThanOrEqualTo(28), // Allow 2s margin for test execution.
      );
    });

    test('blocks immediately on 4th attempt without calling platform', () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedRamed'),
        options: anyNamed('options'),
      )).thenThrow(PlatformException(
        code: 'AuthenticationFailed',
        message: 'Fingerprint not recognized',
      ));

      await bioAuth.authenticate(); // 1
      await bioAuth.authenticate(); // 2
      await bioAuth.authenticate(); // 3 — triggers lockout

      // 4th attempt must be blocked before reaching the platform.
      final r4 = await bioAuth.authenticate();
      expect(r4.status, AuthStatus.lockedOut);

      // authenticate() should have been called exactly 3 times (not 4).
      verify(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).called(3);
    });

    test('resets failure count after successful authentication', () async {
      // Two failures.
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenThrow(PlatformException(code: 'AuthenticationFailed'));

      await bioAuth.authenticate();
      await bioAuth.authenticate();
      expect(bioAuth.remainingAttempts, 1);

      // Success resets the counter.
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenAnswer((_) async => true);

      final success = await bioAuth.authenticate();
      expect(success.status, AuthStatus.success);
      expect(bioAuth.remainingAttempts, 3); // Fully reset.
    });
  });

  group('Device capability checks', () {
    test('returns notEnrolled when device is not supported', () async {
      when(mockAuth.isDeviceSupported()).thenAnswer((_) async => false);

      final result = await bioAuth.authenticate();

      expect(result.status, AuthStatus.notEnrolled);
      expect(result.errorMessage, contains('does not support'));
    });

    test('returns notEnrolled on notEnrolled platform exception', () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenThrow(PlatformException(code: auth_error.notEnrolled));

      final result = await bioAuth.authenticate();

      expect(result.status, AuthStatus.notEnrolled);
    });

    test('returns notEnrolled on passcodeNotSet platform exception', () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenThrow(PlatformException(code: auth_error.passcodeNotSet));

      final result = await bioAuth.authenticate();

      expect(result.status, AuthStatus.notEnrolled);
    });
  });

  group('System-level lockout (OS-reported)', () {
    test('handles OS-level lockedOut exception', () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenThrow(PlatformException(code: auth_error.lockedOut));

      final result = await bioAuth.authenticate();

      expect(result.status, AuthStatus.lockedOut);
      expect(result.lockedUntil, isNotNull);
    });

    test('handles OS-level permanentlyLockedOut exception', () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenThrow(PlatformException(code: auth_error.permanentlyLockedOut));

      final result = await bioAuth.authenticate();

      expect(result.status, AuthStatus.lockedOut);
    });
  });

  group('PIN fallback', () {
    test('proceeds to authenticate even without biometrics enrolled '
        '(PIN fallback expected)', () async {
      when(mockAuth.getAvailableBiometrics()).thenAnswer((_) async => []);
      when(mockAuth.canCheckBiometrics).thenAnswer((_) async => false);
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenAnswer((_) async => true);

      final result = await bioAuth.authenticate();

      // Must still reach the authenticate call (PIN fallback path).
      expect(result.status, AuthStatus.success);
    });
  });

  group('Unexpected errors', () {
    test('catches non-platform exceptions and returns error status', () async {
      when(mockAuth.authenticate(
        localizedReason: anyNamed('localizedReason'),
        options: anyNamed('options'),
      )).thenThrow(Exception('Unexpected crash'));

      final result = await bioAuth.authenticate();

      expect(result.status, AuthStatus.error);
      expect(result.errorMessage, contains('Unexpected error'));
    });
  });
}
