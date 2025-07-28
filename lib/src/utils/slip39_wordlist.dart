/// SLIP39 wordlist utility
///
/// Contains the official SLIP39 wordlist of 1024 words used for
/// mnemonic encoding and decoding.
class Slip39WordList {
  /// The official SLIP39 wordlist (1024 words)
  static const List<String> words = [
    // 0-127
    'abandon',
    'ability',
    'able',
    'about',
    'above',
    'absent',
    'absorb',
    'abstract',
    'absurd',
    'abuse',
    'access',
    'accident',
    'account',
    'accuse',
    'achieve',
    'acid',
    'acoustic',
    'acquire',
    'across',
    'act',
    'action',
    'actor',
    'actress',
    'actual',
    'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
    'advice',
    'aerobic',
    'affair',
    'affect',
    'afford',
    'afraid',
    'again',
    'against',
    'age', 'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle',
    'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley', 'allow',
    'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always', 'amateur',
    'amazing',
    'among',
    'amount',
    'amuse',
    'analyst',
    'anchor',
    'ancient',
    'anger',
    'angle',
    'angry',
    'animal',
    'ankle',
    'announce',
    'annual',
    'another',
    'answer',
    'antenna',
    'antique',
    'anxiety',
    'any',
    'apart',
    'apology',
    'appear',
    'apple',
    'approve', 'april', 'arcade', 'arch', 'arctic', 'area', 'arena', 'argue',
    'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest', 'arrive',
    'arrow', 'art', 'artefact', 'artist', 'artwork', 'ask', 'aspect', 'assault',
    'asset',
    'assist',
    'assume',
    'asthma',
    'athlete',
    'atom',
    'attack',
    'attend',
    'attitude',
    'attract',
    'auction',
    'audit',
    'august',
    'aunt',
    'author',
    'auto',

    // 128-255
    'autumn',
    'average',
    'avocado',
    'avoid',
    'awake',
    'aware',
    'away',
    'awesome',
    'awful', 'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge', 'bag',
    'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner', 'bar', 'barely',
    'bargain', 'barrel', 'base', 'basic', 'basket', 'battle', 'beach', 'bean',
    'beauty',
    'because',
    'become',
    'beef',
    'before',
    'begin',
    'behave',
    'behind',
    'believe', 'below', 'belt', 'bench', 'benefit', 'best', 'betray', 'better',
    'between', 'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird',
    'birth', 'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak',
    'bless', 'blind', 'blood', 'blossom', 'blow', 'blue', 'blur', 'blush',
    'board', 'boat', 'body', 'boil', 'bomb', 'bone', 'bonus', 'book',
    'boost', 'border', 'boring', 'borrow', 'boss', 'bottom', 'bounce', 'box',
    'boy', 'bracket', 'brain', 'brand', 'brass', 'brave', 'bread', 'breeze',
    'brick',
    'bridge',
    'brief',
    'bright',
    'bring',
    'brisk',
    'broccoli',
    'broken',
    'bronze', 'broom', 'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget',
    'buffalo', 'build', 'bulb', 'bulk', 'bullet', 'bundle', 'bunker', 'burden',
    'burger', 'burst', 'bus', 'business', 'busy', 'butter', 'buyer', 'buzz',

    // 256-383
    'cabbage', 'cabin', 'cable', 'cactus', 'cage', 'cake', 'call', 'calm',
    'camera', 'camp', 'can', 'canal', 'cancel', 'candy', 'cannon', 'canoe',
    'canvas',
    'canyon',
    'capable',
    'capital',
    'captain',
    'car',
    'carbon',
    'card',
    'care', 'career', 'careful', 'careless', 'cargo', 'carpet', 'carry', 'cart',
    'case', 'cash', 'casino', 'cast', 'casual', 'cat', 'catalog', 'catch',
    'category',
    'cattle',
    'caught',
    'cause',
    'caution',
    'cave',
    'ceiling',
    'celery',
    'cement',
    'census',
    'century',
    'cereal',
    'certain',
    'chair',
    'chalk',
    'champion',
    'change', 'chaos', 'chapter', 'charge', 'chase', 'chat', 'cheap', 'check',
    'cheese', 'chef', 'cherry', 'chest', 'chicken', 'chief', 'child', 'chimney',
    'choice',
    'choose',
    'chronic',
    'chuckle',
    'chunk',
    'churn',
    'cigar',
    'cinnamon',
    'circle', 'citizen', 'city', 'civil', 'claim', 'clamp', 'clarify', 'class',
    'claw', 'clay', 'clean', 'clerk', 'clever', 'click', 'client', 'cliff',
    'climb', 'clinic', 'clip', 'clock', 'clog', 'close', 'cloth', 'cloud',
    'clown', 'club', 'clump', 'cluster', 'clutch', 'coach', 'coast', 'coconut',
    'code', 'coffee', 'coil', 'coin', 'collect', 'color', 'column', 'combine',
    'come',
    'comfort',
    'comic',
    'common',
    'company',
    'concert',
    'conduct',
    'confirm',

    // 384-511
    'congress',
    'connect',
    'consider',
    'control',
    'convince',
    'cook',
    'cool',
    'copper',
    'copy', 'coral', 'core', 'corn', 'correct', 'cost', 'cotton', 'couch',
    'country',
    'couple',
    'course',
    'cousin',
    'cover',
    'coyote',
    'crack',
    'cradle',
    'craft', 'cram', 'crane', 'crash', 'crater', 'crawl', 'crazy', 'cream',
    'credit', 'creek', 'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop',
    'cross',
    'crouch',
    'crowd',
    'crucial',
    'cruel',
    'cruise',
    'crumble',
    'crunch',
    'crush', 'cry', 'crystal', 'cube', 'culture', 'cup', 'cupboard', 'curious',
    'current', 'curtain', 'curve', 'cushion', 'custom', 'cute', 'cycle', 'dad',
    'damage', 'damp', 'dance', 'danger', 'daring', 'dash', 'daughter', 'dawn',
    'day',
    'deal',
    'debate',
    'debris',
    'decade',
    'december',
    'decide',
    'decline',
    'decorate',
    'decrease',
    'deer',
    'defense',
    'define',
    'defy',
    'degree',
    'delay',
    'deliver',
    'demand',
    'demise',
    'denial',
    'dentist',
    'deny',
    'depart',
    'depend',
    'deposit',
    'depth',
    'deputy',
    'derive',
    'describe',
    'desert',
    'design',
    'desk',
    'despair',
    'destroy',
    'detail',
    'detect',
    'device',
    'devote',
    'diagram',
    'dial',
    'diamond',
    'diary',
    'dice',
    'diesel',
    'diet',
    'differ',
    'digital',
    'dignity',
    'dilemma',
    'dinner',
    'dinosaur',
    'direct',
    'dirt',
    'disagree',
    'discover',
    'disease',

    // 512-639
    'dish',
    'dismiss',
    'disorder',
    'display',
    'distance',
    'divert',
    'divide',
    'divorce',
    'dizzy', 'doctor', 'document', 'dog', 'doll', 'dolphin', 'domain', 'donate',
    'donkey', 'donor', 'door', 'dose', 'double', 'dove', 'draft', 'dragon',
    'drama', 'drape', 'draw', 'dream', 'dress', 'drift', 'drill', 'drink',
    'drip', 'drive', 'drop', 'drum', 'dry', 'duck', 'dumb', 'dune',
    'during', 'dust', 'dutch', 'duty', 'dwarf', 'dynamic', 'eager', 'eagle',
    'early', 'earn', 'earth', 'easily', 'east', 'easy', 'echo', 'ecology',
    'economy', 'edge', 'edit', 'educate', 'effort', 'egg', 'eight', 'either',
    'elbow',
    'elder',
    'electric',
    'elegant',
    'element',
    'elephant',
    'elevator',
    'elite',
    'else',
    'embark',
    'embody',
    'embrace',
    'emerge',
    'emotion',
    'employ',
    'empower',
    'empty', 'enable', 'enact', 'end', 'endless', 'endorse', 'enemy', 'energy',
    'enforce',
    'engage',
    'engine',
    'enhance',
    'enjoy',
    'enlist',
    'enough',
    'enrich',
    'enroll',
    'ensure',
    'enter',
    'entire',
    'entry',
    'envelope',
    'episode',
    'equal',
    'equip', 'era', 'erase', 'erode', 'erosion', 'error', 'erupt', 'escape',
    'essay',
    'essence',
    'estate',
    'eternal',
    'ethics',
    'evidence',
    'evil',
    'evoke',
    'evolve',
    'exact',
    'example',
    'excess',
    'exchange',
    'excite',
    'exclude',
    'excuse',

    // 640-767
    'execute',
    'exercise',
    'exhaust',
    'exhibit',
    'exile',
    'exist',
    'exit',
    'exotic',
    'expand',
    'expect',
    'expire',
    'explain',
    'expose',
    'express',
    'extend',
    'extra',
    'eye', 'eyebrow', 'fabric', 'face', 'faculty', 'fade', 'faint', 'faith',
    'fall', 'false', 'fame', 'family', 'famous', 'fan', 'fancy', 'fantasy',
    'farm', 'fashion', 'fat', 'fatal', 'father', 'fatigue', 'fault', 'favorite',
    'feature', 'february', 'federal', 'fee', 'feed', 'feel', 'female', 'fence',
    'festival', 'fetch', 'fever', 'few', 'fiber', 'fiction', 'field', 'figure',
    'file', 'fill', 'film', 'filter', 'final', 'find', 'fine', 'finger',
    'finish', 'fire', 'firm', 'first', 'fiscal', 'fish', 'fit', 'fitness',
    'fix', 'flag', 'flame', 'flat', 'flavor', 'flee', 'flight', 'flip',
    'float', 'flock', 'floor', 'flower', 'fluid', 'flush', 'fly', 'foam',
    'focus', 'fog', 'foil', 'fold', 'follow', 'food', 'foot', 'force',
    'forest',
    'forget',
    'fork',
    'fortune',
    'forum',
    'forward',
    'fossil',
    'foster',
    'found', 'fox', 'fragile', 'frame', 'frequent', 'fresh', 'friend', 'fringe',
    'frog', 'front', 'frost', 'frown', 'frozen', 'fruit', 'fuel', 'fun',
    'funny', 'furnace', 'fury', 'future', 'gadget', 'gain', 'galaxy', 'gallery',

    // 768-895
    'game', 'gap', 'garage', 'garbage', 'garden', 'garlic', 'garment', 'gas',
    'gasp', 'gate', 'gather', 'gauge', 'gaze', 'general', 'genius', 'genre',
    'gentle',
    'genuine',
    'gesture',
    'ghost',
    'giant',
    'gift',
    'giggle',
    'ginger',
    'giraffe', 'girl', 'give', 'glad', 'glance', 'glare', 'glass', 'glide',
    'glimpse', 'globe', 'gloom', 'glory', 'glove', 'glow', 'glue', 'goat',
    'goddess', 'gold', 'good', 'goose', 'gorilla', 'gospel', 'gossip', 'govern',
    'gown', 'grab', 'grace', 'grain', 'grant', 'grape', 'grass', 'gravity',
    'great', 'green', 'grid', 'grief', 'grit', 'grocery', 'group', 'grow',
    'grunt', 'guard', 'guess', 'guide', 'guilt', 'guitar', 'gun', 'gym',
    'habit', 'hair', 'half', 'hammer', 'hamster', 'hand', 'happy', 'harbor',
    'hard', 'harsh', 'harvest', 'hat', 'have', 'hawk', 'hazard', 'head',
    'health', 'heart', 'heavy', 'hedgehog', 'height', 'held', 'hello', 'helmet',
    'help', 'hen', 'hero', 'hidden', 'high', 'hill', 'hint', 'hip',
    'hire', 'history', 'hobby', 'hockey', 'hold', 'hole', 'holiday', 'hollow',
    'home', 'honey', 'hood', 'hope', 'horn', 'horror', 'horse', 'hospital',
    'host', 'hotel', 'hour', 'hover', 'hub', 'huge', 'human', 'humble',

    // 896-1023
    'humor', 'hundred', 'hungry', 'hunt', 'hurdle', 'hurry', 'hurt', 'husband',
    'hybrid', 'ice', 'icon', 'idea', 'identify', 'idle', 'ignore', 'ill',
    'illegal',
    'illness',
    'image',
    'imitate',
    'immense',
    'immune',
    'impact',
    'impose',
    'improve',
    'impulse',
    'inch',
    'include',
    'income',
    'increase',
    'index',
    'indicate',
    'indoor',
    'industry',
    'infant',
    'inflict',
    'inform',
    'inhale',
    'inherit',
    'initial',
    'inject',
    'injury',
    'inmate',
    'inner',
    'innocent',
    'input',
    'inquiry',
    'insane',
    'insect',
    'inside',
    'inspire',
    'install',
    'intact',
    'interest',
    'into',
    'invest',
    'invite', 'involve', 'iron', 'island', 'isolate', 'issue', 'item', 'ivory',
    'jacket', 'jaguar', 'jar', 'jazz', 'jealous', 'jeans', 'jelly', 'jewel',
    'job', 'join', 'joke', 'journey', 'joy', 'judge', 'juice', 'jump',
    'jungle', 'junior', 'junk', 'just', 'kangaroo', 'keen', 'keep', 'ketchup',
    'key', 'kick', 'kid', 'kidney', 'kind', 'kingdom', 'kiss', 'kit',
    'kitchen', 'kite', 'kitten', 'kiwi', 'knee', 'knife', 'knock', 'know',
    'lab', 'label', 'labor', 'ladder', 'lady', 'lake', 'lamp', 'language',
    'laptop', 'large', 'later', 'latin', 'laugh', 'laundry', 'lava', 'law',
    'lawn', 'lawsuit', 'layer', 'lazy', 'leader', 'leaf', 'learn', 'leave',
  ];

  /// Map from word to index for fast lookup
  static final Map<String, int> _wordToIndex = {
    for (int i = 0; i < words.length; i++) words[i]: i,
  };

  /// Gets the index of a word in the wordlist
  ///
  /// Returns null if the word is not found
  static int? getWordIndex(String word) {
    return _wordToIndex[word.toLowerCase()];
  }

  /// Gets the word at a specific index
  ///
  /// Throws [RangeError] if index is out of bounds
  static String getWordAtIndex(int index) {
    if (index < 0 || index >= words.length) {
      throw RangeError('Word index out of bounds: $index');
    }
    return words[index];
  }

  /// Validates if a word exists in the wordlist
  static bool isValidWord(String word) {
    return _wordToIndex.containsKey(word.toLowerCase());
  }

  /// Validates a list of words
  static bool areValidWords(List<String> wordList) {
    return wordList.every((word) => isValidWord(word));
  }

  /// Finds words that start with a given prefix
  static List<String> findWordsWithPrefix(String prefix) {
    final lowerPrefix = prefix.toLowerCase();
    return words.where((word) => word.startsWith(lowerPrefix)).toList();
  }

  /// Calculates Levenshtein distance between two words
  static int levenshteinDistance(String a, String b) {
    if (a.isEmpty) return b.length;
    if (b.isEmpty) return a.length;

    final matrix = List.generate(
      a.length + 1,
      (i) => List.generate(b.length + 1, (j) => 0),
    );

    for (int i = 0; i <= a.length; i++) {
      matrix[i][0] = i;
    }
    for (int j = 0; j <= b.length; j++) {
      matrix[0][j] = j;
    }

    for (int i = 1; i <= a.length; i++) {
      for (int j = 1; j <= b.length; j++) {
        final cost = a[i - 1] == b[j - 1] ? 0 : 1;
        matrix[i][j] = [
          matrix[i - 1][j] + 1, // deletion
          matrix[i][j - 1] + 1, // insertion
          matrix[i - 1][j - 1] + cost, // substitution
        ].reduce((a, b) => a < b ? a : b);
      }
    }

    return matrix[a.length][b.length];
  }

  /// Finds the closest valid words to a given word (for error correction)
  static List<String> findSimilarWords(
    String word, {
    int maxDistance = 2,
    int maxResults = 5,
  }) {
    final candidates = <(String, int)>[];

    for (final validWord in words) {
      final distance = levenshteinDistance(word.toLowerCase(), validWord);
      if (distance <= maxDistance) {
        candidates.add((validWord, distance));
      }
    }

    candidates.sort((a, b) => a.$2.compareTo(b.$2));
    return candidates.take(maxResults).map((item) => item.$1).toList();
  }

  /// Validates and suggests corrections for invalid words
  static WordValidationResult validateWord(String word) {
    if (isValidWord(word)) {
      return WordValidationResult.valid(word);
    }

    final suggestions = findSimilarWords(word);
    return WordValidationResult.invalid(word, suggestions);
  }

  /// Validates a complete mnemonic phrase
  static MnemonicValidationResult validateMnemonic(String mnemonic) {
    final words = mnemonic.trim().split(RegExp(r'\s+'));

    if (words.isEmpty) {
      return MnemonicValidationResult.invalid('Empty mnemonic');
    }

    final invalidWords = <String>[];
    final suggestions = <String, List<String>>{};

    for (final word in words) {
      if (!isValidWord(word)) {
        invalidWords.add(word);
        suggestions[word] = findSimilarWords(word, maxResults: 3);
      }
    }

    if (invalidWords.isEmpty) {
      return MnemonicValidationResult.valid(words);
    } else {
      return MnemonicValidationResult.invalid(
        'Invalid words: ${invalidWords.join(', ')}',
        invalidWords: invalidWords,
        suggestions: suggestions,
      );
    }
  }

  /// Number of words in the wordlist
  static int get wordCount => words.length;

  /// Radix used for encoding (should be 1024 for SLIP39)
  static int get radix => words.length;
}

/// Result of word validation
class WordValidationResult {
  final bool isValid;
  final String word;
  final List<String>? suggestions;

  const WordValidationResult._(this.isValid, this.word, this.suggestions);

  factory WordValidationResult.valid(String word) {
    return WordValidationResult._(true, word, null);
  }

  factory WordValidationResult.invalid(String word, List<String> suggestions) {
    return WordValidationResult._(false, word, suggestions);
  }
}

/// Result of mnemonic validation
class MnemonicValidationResult {
  final bool isValid;
  final String message;
  final List<String>? validWords;
  final List<String>? invalidWords;
  final Map<String, List<String>>? suggestions;

  const MnemonicValidationResult._({
    required this.isValid,
    required this.message,
    this.validWords,
    this.invalidWords,
    this.suggestions,
  });

  factory MnemonicValidationResult.valid(List<String> words) {
    return MnemonicValidationResult._(
      isValid: true,
      message: 'Valid mnemonic',
      validWords: words,
    );
  }

  factory MnemonicValidationResult.invalid(
    String message, {
    List<String>? invalidWords,
    Map<String, List<String>>? suggestions,
  }) {
    return MnemonicValidationResult._(
      isValid: false,
      message: message,
      invalidWords: invalidWords,
      suggestions: suggestions,
    );
  }
}
