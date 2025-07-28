import 'slip39_group.dart';

/// Configuration for SLIP39 secret sharing
///
/// Defines how a secret should be split across multiple groups and
/// what thresholds are required for recovery.
class Slip39Config {
  /// Number of groups required to recover the secret
  final int groupThreshold;

  /// List of groups and their configurations
  final List<Slip39Group> groups;

  /// Optional passphrase for additional security
  final String? passphrase;

  /// PBKDF2 iteration exponent (affects key derivation strength)
  final int iterationExponent;

  /// Optional label/name for this configuration
  final String? label;

  /// Creates a SLIP39 configuration
  const Slip39Config({
    required this.groupThreshold,
    required this.groups,
    this.passphrase,
    this.iterationExponent = 1,
    this.label,
  });

  /// Creates a simple family configuration
  ///
  /// Example: Requires 2 out of 3 groups (Family + one backup group)
  /// - Family: 2 of 3 family members
  /// - Confidants: 1 of 2 trusted friends
  /// - Professionals: 1 of 2 professional advisors
  factory Slip39Config.familyDefault({
    int familyMembers = 3,
    int requiredFamilyMembers = 2,
    int confidants = 2,
    int professionals = 2,
    String? passphrase,
  }) {
    return Slip39Config(
      groupThreshold: 2, // Need family + one backup group
      passphrase: passphrase,
      label: 'Family Default Configuration',
      groups: [
        Slip39Group.family(
          memberCount: familyMembers,
          requiredMembers: requiredFamilyMembers,
        ),
        Slip39Group.confidants(count: confidants),
        Slip39Group.professionals(count: professionals),
      ],
    );
  }

  /// Creates a high-security configuration
  ///
  /// Requires multiple groups with higher thresholds
  factory Slip39Config.highSecurity({
    int familyMembers = 4,
    int confidants = 3,
    int professionals = 3,
    String? passphrase,
  }) {
    return Slip39Config(
      groupThreshold: 3, // All groups required
      passphrase: passphrase,
      iterationExponent: 2, // Higher iteration count
      label: 'High Security Configuration',
      groups: [
        Slip39Group.family(
          memberCount: familyMembers,
          requiredMembers: 3, // Require 3 out of 4 family members
        ),
        Slip39Group.confidants(
          count: confidants,
          threshold: 2, // Require 2 out of 3 confidants
        ),
        Slip39Group.professionals(
          count: professionals,
          threshold: 2, // Require 2 out of 3 professionals
        ),
      ],
    );
  }

  /// Creates a simple single-group configuration
  ///
  /// For basic secret sharing without family complexity
  factory Slip39Config.simple({
    required int totalShares,
    required int threshold,
    String? passphrase,
    String groupName = 'Main Group',
  }) {
    return Slip39Config(
      groupThreshold: 1,
      passphrase: passphrase,
      label: 'Simple Configuration',
      groups: [
        Slip39Group(name: groupName, threshold: threshold, count: totalShares),
      ],
    );
  }

  /// Validates this configuration
  bool get isValid {
    if (groupThreshold <= 0 || groupThreshold > groups.length) {
      return false;
    }

    if (groups.isEmpty || groups.length > 16) {
      return false;
    }

    if (iterationExponent < 0 || iterationExponent > 15) {
      return false;
    }

    return groups.every((group) => group.isValid);
  }

  /// Total number of shares that will be generated
  int get totalShareCount {
    return groups.fold(0, (sum, group) => sum + group.count);
  }

  /// Minimum number of shares needed for recovery
  int get minimumSharesForRecovery {
    // Sort groups by threshold and take the required number
    final sortedGroups = List<Slip39Group>.from(groups)
      ..sort((a, b) => a.threshold.compareTo(b.threshold));

    return sortedGroups
        .take(groupThreshold)
        .fold(0, (sum, group) => sum + group.threshold);
  }

  /// Security assessment of this configuration
  SecurityAssessment get securityAssessment {
    final totalShares = totalShareCount;
    final minShares = minimumSharesForRecovery;
    final ratio = minShares / totalShares;

    final groupLevels = groups.map((g) => g.securityLevel).toList();
    final avgGroupSecurity =
        groupLevels.map((level) => level.index).reduce((a, b) => a + b) /
        groupLevels.length;

    if (ratio >= 0.7 && avgGroupSecurity >= 2.5) {
      return SecurityAssessment.maximum;
    } else if (ratio >= 0.5 && avgGroupSecurity >= 2.0) {
      return SecurityAssessment.high;
    } else if (ratio >= 0.3 && avgGroupSecurity >= 1.5) {
      return SecurityAssessment.medium;
    } else {
      return SecurityAssessment.low;
    }
  }

  /// Recovery scenarios this configuration supports
  List<RecoveryScenario> get recoveryScenarios {
    final scenarios = <RecoveryScenario>[];

    // Generate all possible combinations of groups that meet threshold
    final groupCombinations = _generateGroupCombinations(
      groups,
      groupThreshold,
    );

    for (final combination in groupCombinations) {
      final requiredShares = combination.fold(
        0,
        (sum, group) => sum + group.threshold,
      );
      final totalAvailable = combination.fold(
        0,
        (sum, group) => sum + group.count,
      );

      scenarios.add(
        RecoveryScenario(
          name: combination.map((g) => g.name).join(' + '),
          groups: combination,
          requiredShares: requiredShares,
          totalAvailableShares: totalAvailable,
        ),
      );
    }

    return scenarios;
  }

  /// Human-readable summary of this configuration
  String get summary {
    final groupSummaries = groups
        .map((g) => '${g.name}: ${g.threshold}/${g.count}')
        .join(', ');

    return 'SLIP39 Config: ${groupThreshold}/${groups.length} groups ($groupSummaries)';
  }

  List<List<Slip39Group>> _generateGroupCombinations(
    List<Slip39Group> groups,
    int k,
  ) {
    if (k == 0) return [[]];
    if (groups.isEmpty) return [];

    final first = groups.first;
    final rest = groups.sublist(1);

    final withFirst =
        _generateGroupCombinations(
          rest,
          k - 1,
        ).map((combo) => [first, ...combo]).toList();
    final withoutFirst = _generateGroupCombinations(rest, k);

    return [...withFirst, ...withoutFirst];
  }

  @override
  String toString() => summary;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is Slip39Config &&
        other.groupThreshold == groupThreshold &&
        other.iterationExponent == iterationExponent &&
        other.passphrase == passphrase &&
        _listEquals(other.groups, groups);
  }

  @override
  int get hashCode {
    return Object.hash(
      groupThreshold,
      iterationExponent,
      passphrase,
      Object.hashAll(groups),
    );
  }

  bool _listEquals<T>(List<T>? a, List<T>? b) {
    if (a == null) return b == null;
    if (b == null || a.length != b.length) return false;
    for (int index = 0; index < a.length; index += 1) {
      if (a[index] != b[index]) return false;
    }
    return true;
  }
}

/// Security assessment levels
enum SecurityAssessment {
  low('Low Risk', 'Basic protection - suitable for low-value secrets'),
  medium('Medium Risk', 'Moderate protection - good for most use cases'),
  high('High Risk', 'Strong protection - recommended for valuable secrets'),
  maximum(
    'Maximum Security',
    'Military-grade protection - for critical secrets',
  );

  const SecurityAssessment(this.name, this.description);

  final String name;
  final String description;
}

/// Represents a possible recovery scenario
class RecoveryScenario {
  final String name;
  final List<Slip39Group> groups;
  final int requiredShares;
  final int totalAvailableShares;

  const RecoveryScenario({
    required this.name,
    required this.groups,
    required this.requiredShares,
    required this.totalAvailableShares,
  });

  /// Fault tolerance (how many shares can be lost)
  int get faultTolerance => totalAvailableShares - requiredShares;

  /// Success probability if shares are randomly lost
  double get successProbability {
    if (faultTolerance <= 0)
      return requiredShares == totalAvailableShares ? 1.0 : 0.0;

    // Simplified probability calculation
    final ratio = requiredShares / totalAvailableShares;
    return 1.0 - (ratio * 0.8); // Rough estimate
  }

  @override
  String toString() {
    return '$name: ${requiredShares}/${totalAvailableShares} shares (${faultTolerance} fault tolerance)';
  }
}
