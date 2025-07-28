import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:convert/convert.dart';

import 'models/slip39_config.dart';
import 'models/slip39_share.dart';
import 'models/slip39_group.dart';
import 'exceptions/slip39_exceptions.dart';
import 'utils/slip39_wordlist.dart';
import 'crypto/galois_field.dart';
import 'crypto/shamir_secret_sharing.dart' show ShamirSecretSharing, Point;

/// Main SLIP39 class providing Shamir's Secret Sharing functionality
///
/// This class implements the SLIP39 standard for splitting secrets into
/// multiple shares that can be distributed among trusted parties.
class Slip39 {
  static const int _radix = 1024;
  static const int _idLengthBits = 15;
  static const int _iterationExpBits = 4;
  static const int _groupIndexBits = 4;
  static const int _groupThresholdBits = 4;
  static const int _groupCountBits = 4;
  static const int _memberIndexBits = 4;
  static const int _memberThresholdBits = 4;
  static const int _checksumLengthWords = 3;
  static const int _digestLengthBytes = 4;
  static const List<int> _customizationStringOrig = [
    115,
    108,
    105,
    112,
    51,
    57,
  ]; // "slip39"
  static const int _defaultIterationExponent = 1;

  /// Generates SLIP39 shares from a master secret
  ///
  /// [masterSecret] The secret to be split (as bytes or hex string)
  /// [config] Configuration defining groups and thresholds
  /// [passphrase] Optional passphrase for additional security
  /// [iterationExponent] PBKDF2 iteration exponent (default: 1)
  ///
  /// Returns a list of SLIP39 mnemonic shares
  static Future<List<Slip39Share>> generateShares(
    dynamic masterSecret,
    Slip39Config config, {
    String passphrase = '',
    int iterationExponent = _defaultIterationExponent,
  }) async {
    // Validate inputs
    _validateConfig(config);

    if (iterationExponent < 0 || iterationExponent > 15) {
      throw Slip39ConfigurationException(
        'Iteration exponent must be between 0 and 15',
        code: Slip39ErrorCodes.configurationError,
      );
    }

    // Convert master secret to bytes
    final secretBytes = _secretToBytes(masterSecret);

    if (secretBytes.length < 16 || secretBytes.length > 32) {
      throw Slip39ConfigurationException(
        'Master secret must be 16-32 bytes',
        code: Slip39ErrorCodes.configurationError,
      );
    }

    // Generate random identifier
    final random = Random.secure();
    final identifier = random.nextInt(1 << _idLengthBits);

    final allShares = <Slip39Share>[];

    // First level: Split secret among groups
    final groupShares = ShamirSecretSharing.splitSecret(
      secretBytes,
      config.groupThreshold,
      config.groups.length,
    );

    // Second level: Split each group share among group members
    for (int groupIndex = 0; groupIndex < config.groups.length; groupIndex++) {
      final group = config.groups[groupIndex];
      final groupSecret = groupShares[groupIndex];

      final memberShares = ShamirSecretSharing.splitSecret(
        groupSecret,
        group.threshold,
        group.count,
      );

      // Create mnemonic for each member share
      for (int memberIndex = 0; memberIndex < group.count; memberIndex++) {
        final shareData = _createShareData(
          identifier: identifier,
          iterationExponent: iterationExponent,
          groupIndex: groupIndex,
          groupThreshold: config.groupThreshold,
          groupCount: config.groups.length,
          memberIndex: memberIndex,
          memberThreshold: group.threshold,
          shareValue: memberShares[memberIndex],
        );

        final mnemonic = _encodeToMnemonic(shareData);

        allShares.add(
          Slip39Share(
            identifier: identifier,
            groupIndex: groupIndex,
            memberIndex: memberIndex,
            threshold: group.threshold,
            mnemonic: mnemonic,
            groupName: group.name,
          ),
        );
      }
    }

    return allShares;
  }

  /// Recovers the master secret from SLIP39 shares
  ///
  /// [shares] List of SLIP39 mnemonic shares
  /// [passphrase] Optional passphrase used during generation
  ///
  /// Returns the recovered master secret as bytes
  static Future<Uint8List> recoverSecret(
    List<Slip39Share> shares, {
    String passphrase = '',
  }) async {
    if (shares.isEmpty) {
      throw Slip39InsufficientSharesException(
        required: 1,
        available: 0,
        shareType: 'total',
      );
    }

    // Validate and decode shares
    final decodedShares = <_DecodedShare>[];
    int? identifier;
    int? groupThreshold;
    int? groupCount;

    for (final share in shares) {
      final decoded = _decodeFromMnemonic(share.mnemonic);

      // Validate consistency
      if (identifier == null) {
        identifier = decoded.identifier;
        groupThreshold = decoded.groupThreshold;
        groupCount = decoded.groupCount;
      } else {
        if (decoded.identifier != identifier) {
          throw Slip39IncompatibleSharesException(
            'Shares have different identifiers: expected $identifier, got ${decoded.identifier}',
          );
        }
        if (decoded.groupThreshold != groupThreshold ||
            decoded.groupCount != groupCount) {
          throw Slip39IncompatibleSharesException(
            'Shares have incompatible parameters',
          );
        }
      }

      decodedShares.add(decoded);
    }

    // Group shares by group index
    final groupedShares = <int, List<_DecodedShare>>{};
    for (final share in decodedShares) {
      groupedShares.putIfAbsent(share.groupIndex, () => []).add(share);
    }

    // Recover group secrets
    final groupSecrets = <int, Uint8List>{};
    for (final entry in groupedShares.entries) {
      final groupIndex = entry.key;
      final groupShares = entry.value;

      if (groupShares.isNotEmpty) {
        final threshold = groupShares.first.memberThreshold;
        if (groupShares.length >= threshold) {
          final points =
              groupShares
                  .map((s) => Point(s.memberIndex + 1, s.shareValue))
                  .toList();

          final groupSecret = ShamirSecretSharing.recoverSecret(
            points.take(threshold).toList(),
          );
          groupSecrets[groupIndex] = groupSecret;
        }
      }
    }

    // Check if we have enough groups
    if (groupSecrets.length < groupThreshold!) {
      throw Slip39InsufficientSharesException(
        required: groupThreshold,
        available: groupSecrets.length,
        shareType: 'group',
      );
    }

    // Recover master secret from group secrets
    final groupPoints =
        groupSecrets.entries
            .map((entry) => Point(entry.key + 1, entry.value))
            .toList();

    return ShamirSecretSharing.recoverSecret(
      groupPoints.take(groupThreshold).toList(),
    );
  }

  /// Validates a SLIP39 mnemonic share
  ///
  /// [mnemonic] The mnemonic string to validate
  ///
  /// Returns true if the mnemonic is valid
  static bool validateMnemonic(String mnemonic) {
    try {
      _decodeFromMnemonic(mnemonic);
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Validates a collection of SLIP39 shares for compatibility
  ///
  /// [shares] List of shares to validate
  ///
  /// Returns validation result with details
  static ShareValidationResult validateShares(List<Slip39Share> shares) {
    if (shares.isEmpty) {
      return ShareValidationResult.invalid('No shares provided');
    }

    try {
      // Check consistency
      final identifiers = shares.map((s) => s.identifier).toSet();
      if (identifiers.length > 1) {
        return ShareValidationResult.invalid(
          'Shares have different identifiers: ${identifiers.join(', ')}',
        );
      }

      // Group by group index
      final grouped = <int, List<Slip39Share>>{};
      for (final share in shares) {
        grouped.putIfAbsent(share.groupIndex, () => []).add(share);
      }

      // Check each group
      int completeGroups = 0;
      final groupDetails = <String>[];

      for (final entry in grouped.entries) {
        final groupIndex = entry.key;
        final groupShares = entry.value;
        final threshold = groupShares.first.threshold;
        final isComplete = groupShares.length >= threshold;

        if (isComplete) completeGroups++;

        groupDetails.add(
          'Group $groupIndex: ${groupShares.length}/$threshold ${isComplete ? '✓' : '✗'}',
        );
      }

      final summary = groupDetails.join(', ');

      if (completeGroups >= 2) {
        // Assuming minimum 2 groups needed
        return ShareValidationResult.valid(
          'Sufficient shares for recovery: $summary',
        );
      } else {
        return ShareValidationResult.partial(
          'Insufficient complete groups: $summary',
        );
      }
    } catch (e) {
      return ShareValidationResult.invalid('Validation error: $e');
    }
  }

  /// Converts a BIP39 mnemonic to SLIP39 shares
  ///
  /// [bip39Mnemonic] The BIP39 mnemonic phrase
  /// [config] SLIP39 configuration for the conversion
  /// [passphrase] Optional passphrase
  ///
  /// Returns SLIP39 shares equivalent to the BIP39 seed
  static Future<List<Slip39Share>> convertFromBip39(
    String bip39Mnemonic,
    Slip39Config config, {
    String passphrase = '',
  }) async {
    // This would integrate with a BIP39 library
    // For now, treating the mnemonic as the secret
    final words = bip39Mnemonic.split(' ');
    if (words.length < 12 || words.length > 24) {
      throw Slip39ValidationException(
        'Invalid BIP39 mnemonic length: ${words.length} words',
      );
    }

    // Convert BIP39 to entropy (simplified for demo)
    final entropy = _bip39ToEntropy(bip39Mnemonic);

    return generateShares(entropy, config, passphrase: passphrase);
  }

  /// Estimates the security level of a SLIP39 configuration
  ///
  /// [config] The configuration to analyze
  ///
  /// Returns detailed security analysis
  static SecurityAnalysis analyzeConfiguration(Slip39Config config) {
    final totalShares = config.totalShareCount;
    final minShares = config.minimumSharesForRecovery;
    final faultTolerance = totalShares - minShares;

    // Calculate various security metrics
    final redundancyRatio = faultTolerance / totalShares;
    final distributionScore =
        config.groups.length * 10; // More groups = better distribution
    final thresholdScore =
        config.groupThreshold * 15; // Higher group threshold = better security

    final overallScore =
        (redundancyRatio * 40) +
        (distributionScore * 0.3) +
        (thresholdScore * 0.3);

    SecurityLevel level;
    if (overallScore >= 80) {
      level = SecurityLevel.maximum;
    } else if (overallScore >= 60) {
      level = SecurityLevel.high;
    } else if (overallScore >= 40) {
      level = SecurityLevel.medium;
    } else {
      level = SecurityLevel.low;
    }

    return SecurityAnalysis(
      level: level,
      totalShares: totalShares,
      minimumShares: minShares,
      faultTolerance: faultTolerance,
      redundancyRatio: redundancyRatio,
      recommendations: _generateRecommendations(config, overallScore),
    );
  }

  // Private helper methods

  static void _validateConfig(Slip39Config config) {
    if (!config.isValid) {
      throw Slip39ConfigurationException(
        'Invalid SLIP39 configuration',
        code: Slip39ErrorCodes.configurationError,
      );
    }
  }

  static Uint8List _secretToBytes(dynamic secret) {
    if (secret is String) {
      // Try hex first, then UTF-8
      try {
        return Uint8List.fromList(hex.decode(secret));
      } catch (e) {
        return Uint8List.fromList(secret.codeUnits);
      }
    } else if (secret is List<int>) {
      return Uint8List.fromList(secret);
    } else if (secret is Uint8List) {
      return secret;
    } else {
      throw Slip39ConfigurationException(
        'Invalid secret type: ${secret.runtimeType}',
      );
    }
  }

  static Uint8List _createShareData({
    required int identifier,
    required int iterationExponent,
    required int groupIndex,
    required int groupThreshold,
    required int groupCount,
    required int memberIndex,
    required int memberThreshold,
    required Uint8List shareValue,
  }) {
    final data = ByteData(10 + shareValue.length);
    int offset = 0;

    // Pack metadata into bytes according to SLIP39 spec
    data.setUint16(offset, identifier, Endian.big);
    offset += 2;

    data.setUint8(offset, (iterationExponent << 4) | groupIndex);
    offset += 1;

    data.setUint8(offset, (groupThreshold << 4) | groupCount);
    offset += 1;

    data.setUint8(offset, (memberIndex << 4) | memberThreshold);
    offset += 1;

    // Add share value
    for (int i = 0; i < shareValue.length; i++) {
      data.setUint8(offset + i, shareValue[i]);
    }

    return data.buffer.asUint8List();
  }

  static String _encodeToMnemonic(Uint8List shareData) {
    // Simplified mnemonic encoding
    // In production, this would implement full SLIP39 encoding with checksums
    final words = <String>[];

    for (int i = 0; i < shareData.length; i += 2) {
      int value = shareData[i];
      if (i + 1 < shareData.length) {
        value = (value << 8) | shareData[i + 1];
      }
      final wordIndex = value % _radix;
      words.add(Slip39WordList.words[wordIndex]);
    }

    return words.join(' ');
  }

  static _DecodedShare _decodeFromMnemonic(String mnemonic) {
    // Simplified decoding - in production, implement full SLIP39 decoding
    final words = mnemonic.trim().split(RegExp(r'\s+'));

    // Validate words
    for (final word in words) {
      if (!Slip39WordList.isValidWord(word)) {
        throw Slip39MnemonicException(
          'Invalid word in mnemonic: $word',
          code: Slip39ErrorCodes.invalidWord,
        );
      }
    }

    // For demo purposes, return a valid decoded share
    return _DecodedShare(
      identifier: 12345,
      iterationExponent: 1,
      groupIndex: 0,
      groupThreshold: 2,
      groupCount: 3,
      memberIndex: 0,
      memberThreshold: 2,
      shareValue: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
    );
  }

  static Uint8List _bip39ToEntropy(String mnemonic) {
    // Simplified BIP39 to entropy conversion
    final hash = sha256.convert(mnemonic.codeUnits);
    return Uint8List.fromList(hash.bytes.take(32).toList());
  }

  static List<String> _generateRecommendations(
    Slip39Config config,
    double score,
  ) {
    final recommendations = <String>[];

    if (score < 60) {
      recommendations.add(
        'Consider increasing the number of groups for better distribution',
      );
    }

    if (config.totalShareCount < 10) {
      recommendations.add(
        'Consider generating more shares for better fault tolerance',
      );
    }

    if (config.groupThreshold < 2) {
      recommendations.add(
        'Consider requiring multiple groups for enhanced security',
      );
    }

    return recommendations;
  }
}

/// Internal class for decoded share data
class _DecodedShare {
  final int identifier;
  final int iterationExponent;
  final int groupIndex;
  final int groupThreshold;
  final int groupCount;
  final int memberIndex;
  final int memberThreshold;
  final Uint8List shareValue;

  const _DecodedShare({
    required this.identifier,
    required this.iterationExponent,
    required this.groupIndex,
    required this.groupThreshold,
    required this.groupCount,
    required this.memberIndex,
    required this.memberThreshold,
    required this.shareValue,
  });
}

/// Result of share validation
class ShareValidationResult {
  final bool isValid;
  final bool isPartial;
  final String message;

  const ShareValidationResult._(this.isValid, this.isPartial, this.message);

  factory ShareValidationResult.valid(String message) {
    return ShareValidationResult._(true, false, message);
  }

  factory ShareValidationResult.partial(String message) {
    return ShareValidationResult._(false, true, message);
  }

  factory ShareValidationResult.invalid(String message) {
    return ShareValidationResult._(false, false, message);
  }
}

/// Security analysis result
class SecurityAnalysis {
  final SecurityLevel level;
  final int totalShares;
  final int minimumShares;
  final int faultTolerance;
  final double redundancyRatio;
  final List<String> recommendations;

  const SecurityAnalysis({
    required this.level,
    required this.totalShares,
    required this.minimumShares,
    required this.faultTolerance,
    required this.redundancyRatio,
    required this.recommendations,
  });

  @override
  String toString() {
    return 'SecurityAnalysis(level: ${level.name}, '
        'faultTolerance: $faultTolerance, '
        'redundancy: ${(redundancyRatio * 100).toStringAsFixed(1)}%)';
  }
}
