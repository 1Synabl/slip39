/// A pure Dart implementation of SLIP39 (Shamir's Secret Sharing for Mnemonic Codes)
///
/// This library provides secure, family-friendly secret sharing capabilities
/// using the SLIP39 standard for cryptocurrency and secret recovery.
///
/// ## Features
///
/// - **Pure Dart Implementation**: No native dependencies
/// - **Family Sharing**: Distribute trust among family members and advisors
/// - **Fault Tolerant**: Lose some shares, still recoverable
/// - **Flexible Thresholds**: Configure security levels per group
/// - **Multiple Groups**: Family, confidants, professionals
/// - **Emergency Recovery**: Multiple recovery scenarios
/// - **BIP39 Compatible**: Convert existing BIP39 seeds to SLIP39
///
/// ## Quick Start
///
/// ```dart
/// import 'package:slip39_dart/slip39_dart.dart';
///
/// // Create a family sharing configuration
/// final config = Slip39Config(
///   groupThreshold: 2,
///   groups: [
///     Slip39Group(name: "Family", threshold: 2, count: 3),
///     Slip39Group(name: "Confidants", threshold: 1, count: 2),
///   ],
/// );
///
/// // Generate shares from a secret
/// final secret = "your master secret here";
/// final shares = await Slip39.generateShares(secret, config);
///
/// // Recover secret from shares
/// final recoveredSecret = await Slip39.recoverSecret(shares);
/// ```
library slip39_dart;

export 'src/slip39.dart';
export 'src/models/slip39_group.dart';
export 'src/models/slip39_share.dart';
export 'src/models/slip39_config.dart';
export 'src/exceptions/slip39_exceptions.dart';
export 'src/utils/slip39_wordlist.dart';
