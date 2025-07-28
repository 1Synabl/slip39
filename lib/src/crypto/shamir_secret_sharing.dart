import 'dart:typed_data';
import 'dart:math';
import 'galois_field.dart';

/// Shamir's Secret Sharing implementation for SLIP39
///
/// This class implements the cryptographic core of SLIP39, splitting secrets
/// into multiple shares using polynomial interpolation over GF(256).
class ShamirSecretSharing {
  /// Split a secret into multiple shares
  ///
  /// [secret] The secret to split (as bytes)
  /// [threshold] Minimum number of shares needed to reconstruct secret
  /// [shareCount] Total number of shares to generate
  /// [randomSeed] Optional seed for testing (use null for production)
  ///
  /// Returns a list of byte arrays, each representing a share
  static List<Uint8List> splitSecret(
    Uint8List secret,
    int threshold,
    int shareCount, {
    int? randomSeed,
  }) {
    // Validation
    validateParameters(
      threshold: threshold,
      shareCount: shareCount,
      secretLength: secret.length,
    );

    // Generate random polynomial coefficients using GF operations
    final coefficients = <Uint8List>[];
    coefficients.add(Uint8List.fromList(secret)); // a0 = secret (constant term)

    // Pre-generate random values for each byte position and coefficient
    // This ensures deterministic results regardless of secret length
    final maxBytes = 32; // Maximum reasonable secret length for SLIP39
    final randomValues = <List<int>>[];

    if (randomSeed != null) {
      final random = Random(randomSeed);
      for (int i = 1; i < threshold; i++) {
        final coeffValues = <int>[];
        for (int j = 0; j < maxBytes; j++) {
          coeffValues.add(random.nextInt(256));
        }
        randomValues.add(coeffValues);
      }
    }

    // Generate coefficients using pre-generated values
    for (int i = 1; i < threshold; i++) {
      final coeff = Uint8List(secret.length);
      for (int j = 0; j < secret.length; j++) {
        if (randomSeed != null) {
          coeff[j] = randomValues[i - 1][j]; // Use pre-generated value
        } else {
          // For secure random, use fresh values each time
          coeff[j] = Random.secure().nextInt(256);
        }
      }
      coefficients.add(coeff);
    }

    // Generate shares by evaluating polynomial at different points
    final shares = <Uint8List>[];
    for (int x = 1; x <= shareCount; x++) {
      final share = _evaluatePolynomialAt(coefficients, x);
      shares.add(share);
    }

    return shares;
  }

  /// Evaluate polynomial at a given x coordinate
  static Uint8List _evaluatePolynomialAt(List<Uint8List> coefficients, int x) {
    if (coefficients.isEmpty) return Uint8List(0);

    final result = Uint8List(coefficients[0].length);

    // Evaluate polynomial for each byte position
    for (int byteIndex = 0; byteIndex < result.length; byteIndex++) {
      int value = 0;
      int xPower = 1;

      // P(x) = a0 + a1*x + a2*x^2 + ... + a(n-1)*x^(n-1)
      for (int coeffIndex = 0; coeffIndex < coefficients.length; coeffIndex++) {
        final term = GaloisField.multiply(
          coefficients[coeffIndex][byteIndex],
          xPower,
        );
        value = GaloisField.add(value, term);
        xPower = GaloisField.multiply(xPower, x);
      }

      result[byteIndex] = value;
    }

    return result;
  }

  /// Recover secret from shares
  ///
  /// [points] List of (x, y) points where x is the share index (1-based)
  ///          and y is the share value
  ///
  /// Returns the reconstructed secret
  static Uint8List recoverSecret(List<Point> points) {
    if (points.isEmpty) {
      throw ArgumentError('No points provided for recovery');
    }

    // Validate points
    final xValues = points.map((p) => p.x).toSet();
    if (xValues.length != points.length) {
      throw ArgumentError('Duplicate x-coordinates found');
    }

    for (final point in points) {
      if (!GaloisField.isValidPoint(point.x)) {
        throw ArgumentError('Invalid x-coordinate: ${point.x}');
      }
    }

    // Use Lagrange interpolation to find polynomial value at x=0 (the secret)
    final secretLength = points.first.y.length;
    final result = Uint8List(secretLength);

    // For each byte position, do Lagrange interpolation
    for (int byteIndex = 0; byteIndex < secretLength; byteIndex++) {
      int secretByte = 0;

      // Lagrange interpolation: P(0) = Σ(yi * Li(0)) where Li(0) is the Lagrange basis polynomial
      for (int i = 0; i < points.length; i++) {
        final xi = points[i].x;
        final yi = points[i].y[byteIndex];

        // Calculate Lagrange basis polynomial Li(0)
        // Li(0) = Π(0 - xj) / Π(xi - xj) for all j ≠ i
        int lagrangeCoeff = 1;

        for (int j = 0; j < points.length; j++) {
          if (i != j) {
            final xj = points[j].x;
            // Calculate (0 - xj) / (xi - xj)
            final numerator = GaloisField.subtract(
              0,
              xj,
            ); // 0 - xj (which is just xj in GF256)
            final denominator = GaloisField.subtract(xi, xj); // xi - xj
            final fraction = GaloisField.divide(numerator, denominator);
            lagrangeCoeff = GaloisField.multiply(lagrangeCoeff, fraction);
          }
        }

        // Add yi * Li(0) to the result
        final term = GaloisField.multiply(yi, lagrangeCoeff);
        secretByte = GaloisField.add(secretByte, term);
      }

      result[byteIndex] = secretByte;
    }

    return result;
  }

  /// Verify that shares can reconstruct the original secret
  ///
  /// [secret] Original secret
  /// [shares] Generated shares (with their x-coordinates)
  /// [threshold] Minimum shares needed
  ///
  /// Returns true if verification passes
  static bool verifyShares(
    Uint8List secret,
    List<Point> shares,
    int threshold,
  ) {
    if (shares.length < threshold) return false;

    try {
      // Try to recover using exactly threshold shares
      final testShares = shares.take(threshold).toList();
      final recovered = recoverSecret(testShares);

      // Compare with original secret
      return _arraysEqual(secret, recovered);
    } catch (e) {
      return false;
    }
  }

  /// Generate shares for testing with predictable results
  ///
  /// This method is primarily for testing and debugging
  static List<Point> generateTestShares(
    Uint8List secret,
    int threshold,
    int shareCount, {
    int seed = 12345,
  }) {
    final shareBytes = splitSecret(
      secret,
      threshold,
      shareCount,
      randomSeed: seed,
    );

    return List.generate(shareCount, (index) {
      return Point(index + 1, shareBytes[index]);
    });
  }

  /// Calculate the minimum number of shares needed to have a high probability
  /// of recovery given a certain loss rate
  ///
  /// [threshold] Required threshold
  /// [lossRate] Expected loss rate (0.0 to 1.0)
  /// [targetProbability] Desired success probability (0.0 to 1.0)
  ///
  /// Returns recommended total number of shares
  static int recommendShareCount(
    int threshold,
    double lossRate,
    double targetProbability,
  ) {
    if (lossRate <= 0) return threshold;
    if (lossRate >= 1) throw ArgumentError('Loss rate cannot be 100%');

    // Use binomial probability to calculate recommended share count
    for (int n = threshold; n <= 255; n++) {
      final probability = _binomialProbability(n, threshold, 1 - lossRate);
      if (probability >= targetProbability) {
        return n;
      }
    }

    return 255; // Maximum possible shares
  }

  /// Calculate binomial probability
  static double _binomialProbability(int n, int k, double p) {
    if (k > n) return 0.0;

    double result = 0.0;
    for (int i = k; i <= n; i++) {
      final coefficient = _binomialCoefficient(n, i);
      final term = coefficient * pow(p, i) * pow(1 - p, n - i);
      result += term;
    }

    return result;
  }

  /// Calculate binomial coefficient (n choose k)
  static double _binomialCoefficient(int n, int k) {
    if (k > n - k) k = n - k; // Take advantage of symmetry

    double result = 1.0;
    for (int i = 0; i < k; i++) {
      result = result * (n - i) / (i + 1);
    }

    return result;
  }

  /// Compare two byte arrays for equality
  static bool _arraysEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;

    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }

    return true;
  }

  /// Validate secret sharing parameters
  static void validateParameters({
    required int threshold,
    required int shareCount,
    required int secretLength,
  }) {
    if (threshold <= 0) {
      throw ArgumentError('Threshold must be positive');
    }

    if (shareCount <= 0) {
      throw ArgumentError('Share count must be positive');
    }

    if (threshold > shareCount) {
      throw ArgumentError('Threshold cannot exceed share count');
    }

    if (shareCount > 255) {
      throw ArgumentError('Share count cannot exceed 255 (GF(256) limitation)');
    }

    if (secretLength <= 0) {
      throw ArgumentError('Secret length must be positive');
    }

    if (secretLength > 32) {
      throw ArgumentError(
        'Secret length should not exceed 32 bytes for SLIP39',
      );
    }
  }

  /// Get security assessment for given parameters
  static SecurityAssessment assessSecurity({
    required int threshold,
    required int shareCount,
    double expectedLossRate = 0.1,
  }) {
    final faultTolerance = shareCount - threshold;
    final faultToleranceRatio = faultTolerance / shareCount;

    if (faultToleranceRatio >= 0.6) {
      return SecurityAssessment.high;
    } else if (faultToleranceRatio >= 0.4) {
      return SecurityAssessment.medium;
    } else if (faultToleranceRatio >= 0.2) {
      return SecurityAssessment.basic;
    } else {
      return SecurityAssessment.minimal;
    }
  }
}

/// Represents a point in the secret sharing scheme
class Point {
  /// X-coordinate (share index, 1-based)
  final int x;

  /// Y-coordinate (share value as bytes)
  final Uint8List y;

  const Point(this.x, this.y);

  @override
  String toString() {
    final yHex = y.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return 'Point($x, 0x$yHex)';
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is Point && other.x == x && _arraysEqual(other.y, y);
  }

  @override
  int get hashCode {
    return Object.hash(x, Object.hashAll(y));
  }

  /// Helper method for array equality
  static bool _arraysEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// Create a copy of this point with a new y value
  Point copyWith({Uint8List? y}) {
    return Point(x, y ?? this.y);
  }
}

/// Security assessment for secret sharing parameters
enum SecurityAssessment {
  minimal('Minimal', 'Very low fault tolerance'),
  basic('Basic', 'Limited fault tolerance'),
  medium('Medium', 'Reasonable fault tolerance'),
  high('High', 'Good fault tolerance');

  const SecurityAssessment(this.name, this.description);

  final String name;
  final String description;
}
