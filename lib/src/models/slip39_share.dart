/// Represents a single SLIP39 mnemonic share
///
/// Each share contains part of the secret and can be combined with other
/// shares according to the threshold scheme to recover the original secret.
class Slip39Share {
  /// Unique identifier for this share set
  final int identifier;

  /// Index of the group this share belongs to
  final int groupIndex;

  /// Index of this share within its group
  final int memberIndex;

  /// Number of shares required from this group
  final int threshold;

  /// The actual mnemonic words
  final String mnemonic;

  /// Human-readable group name
  final String? groupName;

  /// Optional metadata for the share
  final Map<String, dynamic>? metadata;

  /// Creates a new SLIP39 share
  const Slip39Share({
    required this.identifier,
    required this.groupIndex,
    required this.memberIndex,
    required this.threshold,
    required this.mnemonic,
    this.groupName,
    this.metadata,
  });

  /// List of mnemonic words
  List<String> get words => mnemonic.split(' ');

  /// Number of words in the mnemonic
  int get wordCount => words.length;

  /// Validates the mnemonic format
  bool get isValidFormat {
    return mnemonic.isNotEmpty &&
        words.isNotEmpty &&
        words.every((word) => word.isNotEmpty);
  }

  /// Creates a displayable summary of this share
  String get displaySummary {
    final groupDisplay = groupName ?? 'Group $groupIndex';
    return '$groupDisplay - Share ${memberIndex + 1}';
  }

  /// First few words for preview (security safe)
  String get preview {
    if (words.length < 3) return '***';
    return '${words[0]} ${words[1]} ${words[2]} ...';
  }

  /// Creates a copy of this share with updated metadata
  Slip39Share copyWith({String? groupName, Map<String, dynamic>? metadata}) {
    return Slip39Share(
      identifier: identifier,
      groupIndex: groupIndex,
      memberIndex: memberIndex,
      threshold: threshold,
      mnemonic: mnemonic,
      groupName: groupName ?? this.groupName,
      metadata: metadata ?? this.metadata,
    );
  }

  @override
  String toString() {
    return 'Slip39Share(id: $identifier, group: $groupIndex, member: $memberIndex, preview: $preview)';
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is Slip39Share &&
        other.identifier == identifier &&
        other.groupIndex == groupIndex &&
        other.memberIndex == memberIndex &&
        other.threshold == threshold &&
        other.mnemonic == mnemonic;
  }

  @override
  int get hashCode {
    return Object.hash(
      identifier,
      groupIndex,
      memberIndex,
      threshold,
      mnemonic,
    );
  }
}

/// Collection of shares with utility methods
class Slip39ShareSet {
  final List<Slip39Share> shares;

  const Slip39ShareSet(this.shares);

  /// Groups shares by their group index
  Map<int, List<Slip39Share>> get groupedShares {
    final grouped = <int, List<Slip39Share>>{};
    for (final share in shares) {
      grouped.putIfAbsent(share.groupIndex, () => []).add(share);
    }
    return grouped;
  }

  /// Unique identifiers in this set
  Set<int> get identifiers => shares.map((s) => s.identifier).toSet();

  /// Whether this set has consistent identifiers
  bool get hasConsistentIdentifiers => identifiers.length <= 1;

  /// Number of complete groups (meeting threshold requirements)
  int get completeGroupCount {
    return groupedShares.values
        .where(
          (groupShares) =>
              groupShares.isNotEmpty &&
              groupShares.length >= groupShares.first.threshold,
        )
        .length;
  }

  /// Whether this set can potentially recover a secret
  bool canRecover(int groupThreshold) {
    return hasConsistentIdentifiers && completeGroupCount >= groupThreshold;
  }

  /// Summary of this share set
  String get summary {
    final groups = groupedShares;
    final groupSummaries = groups.entries
        .map((entry) {
          final groupIndex = entry.key;
          final groupShares = entry.value;
          final threshold =
              groupShares.isNotEmpty ? groupShares.first.threshold : 0;
          final groupName =
              groupShares.isNotEmpty
                  ? (groupShares.first.groupName ?? 'Group $groupIndex')
                  : 'Group $groupIndex';

          return '$groupName: ${groupShares.length}/$threshold';
        })
        .join(', ');

    return 'Shares: $groupSummaries (${shares.length} total)';
  }
}

/// Helper extension for working with lists of shares
extension Slip39ShareListExtension on List<Slip39Share> {
  /// Converts to a ShareSet for easier manipulation
  Slip39ShareSet get asShareSet => Slip39ShareSet(this);

  /// Filters shares by group
  List<Slip39Share> forGroup(int groupIndex) {
    return where((share) => share.groupIndex == groupIndex).toList();
  }

  /// Filters shares by identifier
  List<Slip39Share> forIdentifier(int identifier) {
    return where((share) => share.identifier == identifier).toList();
  }
}
