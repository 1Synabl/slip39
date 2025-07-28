/// Represents a SLIP39 group for Shamir's Secret Sharing
///
/// A group defines a set of shares that work together. For example,
/// a family group might require 2 out of 3 family members to participate
/// in recovery.
class Slip39Group {
  /// Name of the group (e.g., "Family", "Confidants", "Lawyers")
  final String name;

  /// Number of shares required from this group for recovery
  final int threshold;

  /// Total number of shares to generate for this group
  final int count;

  /// Optional description of the group
  final String? description;

  /// Creates a new SLIP39 group
  ///
  /// [name] Human-readable name for the group
  /// [threshold] Minimum shares needed from this group
  /// [count] Total shares to generate for this group
  /// [description] Optional description
  const Slip39Group({
    required this.name,
    required this.threshold,
    required this.count,
    this.description,
  });

  /// Creates a family group with sensible defaults
  ///
  /// [memberCount] Number of family members
  /// [requiredMembers] How many members needed for recovery (defaults to majority)
  factory Slip39Group.family({required int memberCount, int? requiredMembers}) {
    final threshold =
        requiredMembers ??
        ((memberCount ~/ 2) + 1); // True majority: 2 for 3, 3 for 5, etc.
    return Slip39Group(
      name: 'Family',
      threshold: threshold,
      count: memberCount,
      description: 'Immediate family members',
    );
  }

  /// Creates a confidants group (trusted friends/advisors)
  ///
  /// [count] Number of confidants
  /// [threshold] How many confidants needed (defaults to 1)
  factory Slip39Group.confidants({required int count, int threshold = 1}) {
    return Slip39Group(
      name: 'Confidants',
      threshold: threshold,
      count: count,
      description: 'Trusted friends and personal advisors',
    );
  }

  /// Creates a professional advisors group (lawyers, accountants, etc.)
  ///
  /// [count] Number of professionals
  /// [threshold] How many professionals needed (defaults to 1)
  factory Slip39Group.professionals({required int count, int threshold = 1}) {
    return Slip39Group(
      name: 'Professionals',
      threshold: threshold,
      count: count,
      description: 'Professional advisors (lawyers, accountants, etc.)',
    );
  }

  /// Validates this group configuration
  bool get isValid {
    return threshold > 0 &&
        threshold <= count &&
        count > 0 &&
        count <= 16 && // SLIP39 limit
        name.isNotEmpty;
  }

  /// Security level based on threshold ratio
  SecurityLevel get securityLevel {
    final ratio = threshold / count;
    if (ratio >= 0.8) return SecurityLevel.maximum;
    if (ratio >= 0.6) return SecurityLevel.high;
    if (ratio >= 0.4) return SecurityLevel.medium;
    return SecurityLevel.low;
  }

  @override
  String toString() {
    return 'Slip39Group(name: $name, threshold: $threshold, count: $count)';
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is Slip39Group &&
        other.name == name &&
        other.threshold == threshold &&
        other.count == count &&
        other.description == description;
  }

  @override
  int get hashCode {
    return Object.hash(name, threshold, count, description);
  }
}

/// Security levels for groups
enum SecurityLevel {
  low('Low', 'Basic security'),
  medium('Medium', 'Moderate security'),
  high('High', 'Strong security'),
  maximum('Maximum', 'Maximum security');

  const SecurityLevel(this.name, this.description);

  final String name;
  final String description;
}
