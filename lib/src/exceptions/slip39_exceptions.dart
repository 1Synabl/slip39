/// Base exception for all SLIP39 related errors
class Slip39Exception implements Exception {
  /// Error message
  final String message;

  /// Optional error code for programmatic handling
  final String? code;

  /// Optional underlying cause
  final dynamic cause;

  const Slip39Exception(this.message, {this.code, this.cause});

  @override
  String toString() {
    if (code != null) {
      return 'Slip39Exception($code): $message';
    }
    return 'Slip39Exception: $message';
  }
}

/// Exception thrown when share validation fails
class Slip39ValidationException extends Slip39Exception {
  const Slip39ValidationException(String message, {String? code, dynamic cause})
    : super(message, code: code, cause: cause);
}

/// Exception thrown when mnemonic encoding/decoding fails
class Slip39MnemonicException extends Slip39Exception {
  const Slip39MnemonicException(String message, {String? code, dynamic cause})
    : super(message, code: code, cause: cause);
}

/// Exception thrown when configuration is invalid
class Slip39ConfigurationException extends Slip39Exception {
  const Slip39ConfigurationException(
    String message, {
    String? code,
    dynamic cause,
  }) : super(message, code: code, cause: cause);
}

/// Exception thrown when secret recovery fails
class Slip39RecoveryException extends Slip39Exception {
  const Slip39RecoveryException(String message, {String? code, dynamic cause})
    : super(message, code: code, cause: cause);
}

/// Exception thrown when cryptographic operations fail
class Slip39CryptoException extends Slip39Exception {
  const Slip39CryptoException(String message, {String? code, dynamic cause})
    : super(message, code: code, cause: cause);
}

/// Exception thrown when there are insufficient shares for recovery
class Slip39InsufficientSharesException extends Slip39RecoveryException {
  final int required;
  final int available;
  final String shareType;

  const Slip39InsufficientSharesException({
    required this.required,
    required this.available,
    required this.shareType,
    String? code,
    dynamic cause,
  }) : super(
         'Insufficient $shareType shares: need $required, have $available',
         code: code,
         cause: cause,
       );
}

/// Exception thrown when shares have incompatible identifiers or parameters
class Slip39IncompatibleSharesException extends Slip39ValidationException {
  const Slip39IncompatibleSharesException(
    String message, {
    String? code,
    dynamic cause,
  }) : super(message, code: code, cause: cause);
}

/// Exception thrown when passphrase operations fail
class Slip39PassphraseException extends Slip39Exception {
  const Slip39PassphraseException(String message, {String? code, dynamic cause})
    : super(message, code: code, cause: cause);
}

/// Common SLIP39 error codes
class Slip39ErrorCodes {
  static const String invalidMnemonic = 'INVALID_MNEMONIC';
  static const String invalidChecksum = 'INVALID_CHECKSUM';
  static const String invalidWordCount = 'INVALID_WORD_COUNT';
  static const String invalidWord = 'INVALID_WORD';
  static const String invalidThreshold = 'INVALID_THRESHOLD';
  static const String invalidGroupCount = 'INVALID_GROUP_COUNT';
  static const String invalidShareCount = 'INVALID_SHARE_COUNT';
  static const String incompatibleShares = 'INCOMPATIBLE_SHARES';
  static const String insufficientShares = 'INSUFFICIENT_SHARES';
  static const String cryptoError = 'CRYPTO_ERROR';
  static const String encodingError = 'ENCODING_ERROR';
  static const String configurationError = 'CONFIGURATION_ERROR';
  static const String recoveryError = 'RECOVERY_ERROR';
}

/// Helper functions for creating common exceptions
class Slip39Exceptions {
  /// Creates a validation exception for invalid mnemonic
  static Slip39MnemonicException invalidMnemonic(String reason) {
    return Slip39MnemonicException(
      'Invalid mnemonic: $reason',
      code: Slip39ErrorCodes.invalidMnemonic,
    );
  }

  /// Creates a validation exception for invalid checksum
  static Slip39MnemonicException invalidChecksum() {
    return const Slip39MnemonicException(
      'Mnemonic checksum validation failed',
      code: Slip39ErrorCodes.invalidChecksum,
    );
  }

  /// Creates a configuration exception for invalid threshold
  static Slip39ConfigurationException invalidThreshold(
    int threshold,
    int maximum,
  ) {
    return Slip39ConfigurationException(
      'Invalid threshold: $threshold (maximum: $maximum)',
      code: Slip39ErrorCodes.invalidThreshold,
    );
  }

  /// Creates an exception for insufficient shares
  static Slip39InsufficientSharesException insufficientShares({
    required String shareType,
    required int required,
    required int available,
  }) {
    return Slip39InsufficientSharesException(
      required: required,
      available: available,
      shareType: shareType,
      code: Slip39ErrorCodes.insufficientShares,
    );
  }

  /// Creates an exception for incompatible shares
  static Slip39IncompatibleSharesException incompatibleShares(String reason) {
    return Slip39IncompatibleSharesException(
      'Incompatible shares: $reason',
      code: Slip39ErrorCodes.incompatibleShares,
    );
  }

  /// Creates a crypto exception
  static Slip39CryptoException cryptoError(String operation, [dynamic cause]) {
    return Slip39CryptoException(
      'Cryptographic operation failed: $operation',
      code: Slip39ErrorCodes.cryptoError,
      cause: cause,
    );
  }
}
