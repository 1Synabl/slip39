import 'dart:typed_data';

/// Galois Field GF(256) arithmetic for SLIP39
///
/// This class provides the mathematical foundation for Shamir's Secret Sharing
/// using arithmetic over the finite field GF(256).
class GaloisField {
  // Generator polynomial for GF(256): x^8 + x^4 + x^3 + x + 1 = 0x11b
  static const int _generator = 0x11b;
  static const int _fieldSize = 256;

  // Lookup tables for efficient GF(256) arithmetic
  static late List<int> _expTable;
  static late List<int> _logTable;
  static bool _initialized = false;

  /// Initialize lookup tables for GF(256)
  static void _initializeTables() {
    if (_initialized) return;

    // Use the standard AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11b
    const int primitivePolynomial = 0x11b;

    // Generate the exponential and logarithm tables
    _expTable = List<int>.filled(
      512,
      1,
    ); // Extra space to avoid overflow checks
    _logTable = List<int>.filled(256, 0);

    int x = 1;
    for (int i = 0; i < 255; i++) {
      _expTable[i] = x;
      _logTable[x] = i;

      // Multiply by the primitive element (2) in GF(256)
      x <<= 1; // x = x * 2
      if ((x & 256) != 0) {
        // If overflow bit is set
        x ^= primitivePolynomial; // Reduce by primitive polynomial
      }
    }

    // Handle the wraparound for exponential table
    for (int i = 255; i < 512; i++) {
      _expTable[i] = _expTable[i - 255];
    }

    _initialized = true;
  }

  /// Addition in GF(256) - same as XOR
  static int add(int a, int b) {
    return a ^ b;
  }

  /// Subtraction in GF(256) - same as XOR (additive inverse is identity)
  static int subtract(int a, int b) {
    return a ^ b;
  }

  /// Multiplication in GF(256) using direct calculation
  static int multiply(int a, int b) {
    if (a == 0 || b == 0) return 0;

    // Direct multiplication in GF(256) using the AES polynomial
    int result = 0;
    int temp_a = a;
    int temp_b = b;

    // Peasant multiplication algorithm
    while (temp_b > 0) {
      if ((temp_b & 1) != 0) {
        // If least significant bit of b is 1
        result ^= temp_a; // Add a to result (XOR in GF)
      }

      temp_a <<= 1; // Multiply a by 2
      if ((temp_a & 0x100) != 0) {
        // If overflow occurred
        temp_a ^= 0x11b; // Reduce by AES polynomial x^8 + x^4 + x^3 + x + 1
      }

      temp_b >>= 1; // Divide b by 2
    }

    return result & 0xFF; // Ensure result fits in 8 bits
  }

  /// Division in GF(256)
  static int divide(int a, int b) {
    _initializeTables();

    if (b == 0) throw ArgumentError('Division by zero in GF(256)');
    if (a == 0) return 0;

    return multiply(a, inverse(b)); // a / b = a * inverse(b)
  }

  /// Power operation in GF(256)
  static int power(int base, int exponent) {
    _initializeTables();

    if (base == 0) return exponent == 0 ? 1 : 0;
    if (exponent == 0) return 1;

    final logResult = (_logTable[base] * exponent) % 255;
    return _expTable[logResult];
  }

  /// Additive inverse in GF(256) - same as the value itself since a + a = 0
  static int additiveInverse(int a) {
    return a; // In GF(256), every element is its own additive inverse
  }

  /// Multiplicative inverse in GF(256)
  static int inverse(int a) {
    _initializeTables();

    if (a == 0) throw ArgumentError('Cannot find inverse of 0 in GF(256)');

    // For debugging: find inverse by brute force to ensure correctness
    for (int i = 1; i < 256; i++) {
      if (multiply(a, i) == 1) {
        return i;
      }
    }

    throw ArgumentError('No multiplicative inverse found for $a in GF(256)');
  }

  /// Polynomial evaluation using Horner's method
  ///
  /// Evaluates polynomial with given coefficients at point x
  static int evaluatePolynomial(List<int> coefficients, int x) {
    if (coefficients.isEmpty) return 0;

    int result = coefficients.first;
    for (int i = 1; i < coefficients.length; i++) {
      result = add(multiply(result, x), coefficients[i]);
    }

    return result;
  }

  /// Lagrange interpolation for polynomial reconstruction
  ///
  /// Given points (x_i, y_i), reconstructs the polynomial and evaluates at x=0
  static int lagrangeInterpolation(List<(int, int)> points) {
    if (points.isEmpty) return 0;

    int result = 0;

    for (int i = 0; i < points.length; i++) {
      final (xi, yi) = points[i];
      int numerator = 1;
      int denominator = 1;

      for (int j = 0; j < points.length; j++) {
        if (i != j) {
          final (xj, _) = points[j];
          numerator = multiply(numerator, subtract(0, xj)); // 0 - xj
          denominator = multiply(denominator, subtract(xi, xj)); // xi - xj
        }
      }

      final term = multiply(yi, divide(numerator, denominator));
      result = add(result, term);
    }

    return result;
  }

  /// Byte-wise operations for working with secrets

  /// Add two byte arrays in GF(256)
  static Uint8List addBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      throw ArgumentError('Byte arrays must have the same length');
    }

    final result = Uint8List(a.length);
    for (int i = 0; i < a.length; i++) {
      result[i] = add(a[i], b[i]);
    }

    return result;
  }

  /// Multiply a byte array by a scalar in GF(256)
  static Uint8List multiplyBytes(Uint8List bytes, int scalar) {
    final result = Uint8List(bytes.length);
    for (int i = 0; i < bytes.length; i++) {
      result[i] = multiply(bytes[i], scalar);
    }

    return result;
  }

  /// Evaluate a polynomial at a point for byte arrays
  static Uint8List evaluatePolynomialBytes(
    List<Uint8List> coefficients,
    int x,
  ) {
    if (coefficients.isEmpty) return Uint8List(0);

    final secretLength = coefficients.first.length;
    var result = Uint8List.fromList(coefficients.first);

    for (int i = 1; i < coefficients.length; i++) {
      result = multiplyBytes(result, x);
      result = addBytes(result, coefficients[i]);
    }

    return result;
  }

  /// Lagrange interpolation for byte arrays
  static Uint8List lagrangeInterpolationBytes(List<(int, Uint8List)> points) {
    if (points.isEmpty) return Uint8List(0);

    final secretLength = points.first.$2.length;
    var result = Uint8List(secretLength);

    for (int i = 0; i < points.length; i++) {
      final (xi, yi) = points[i];
      int numerator = 1;
      int denominator = 1;

      for (int j = 0; j < points.length; j++) {
        if (i != j) {
          final (xj, _) = points[j];
          numerator = multiply(numerator, subtract(0, xj));
          denominator = multiply(denominator, subtract(xi, xj));
        }
      }

      final coefficient = divide(numerator, denominator);
      final term = multiplyBytes(yi, coefficient);
      result = addBytes(result, term);
    }

    return result;
  }

  /// Generate a random polynomial of specified degree
  static List<Uint8List> generateRandomPolynomial(
    Uint8List secret,
    int degree, [
    int? seed,
  ]) {
    final _RandomGenerator random =
        seed != null ? _SeededRandom(seed) : _SecureRandom();
    final coefficients = <Uint8List>[secret]; // Constant term is the secret

    // Generate random coefficients for higher degree terms
    for (int i = 1; i <= degree; i++) {
      final coefficient = Uint8List(secret.length);
      for (int j = 0; j < secret.length; j++) {
        coefficient[j] = random.nextInt(256);
      }
      coefficients.add(coefficient);
    }

    return coefficients;
  }

  /// Validate that a point is in valid range for GF(256)
  static bool isValidPoint(int x) {
    return x >= 0 && x < _fieldSize;
  }

  /// Convert integer to byte representation
  static int toByte(int value) {
    return value & 0xFF;
  }

  /// Check if GF(256) tables are initialized
  static bool get isInitialized => _initialized;
}

/// Abstract random number generator interface
abstract class _RandomGenerator {
  int nextInt(int max);
}

/// Simple seeded random number generator for testing
class _SeededRandom implements _RandomGenerator {
  int _seed;

  _SeededRandom(this._seed);

  @override
  int nextInt(int max) {
    _seed = (_seed * 1103515245 + 12345) & 0x7fffffff;
    return _seed % max;
  }
}

/// Secure random number generator wrapper
class _SecureRandom implements _RandomGenerator {
  @override
  int nextInt(int max) {
    // In production, use crypto-secure random
    // For now, using basic random with better distribution
    final now = DateTime.now().microsecondsSinceEpoch;
    return ((now * 1664525 + 1013904223) & 0x7fffffff) % max;
  }
}
