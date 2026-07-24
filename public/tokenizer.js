// tokenizer.js
// Reproduces the exact preprocessing used by train_and_export.py's
// TfidfVectorizer(max_features=300, stop_words="english", lowercase=True,
//                 token_pattern=r"\b[a-zA-Z]{2,}\b")
//
// Note: we don't need a separate stopword list here. The trained vocab
// (model.vocab) only contains the 300 non-stopword terms sklearn kept,
// so any stopword or out-of-vocab word simply won't match during lookup.

/**
 * Split text into lowercase word tokens of 2+ letters, matching
 * sklearn's default token_pattern \b[a-zA-Z]{2,}\b.
 * @param {string} text
 * @returns {string[]} tokens
 */
function tokenize(text) {
  if (!text) return [];
  const lower = text.toLowerCase();
  const matches = lower.match(/\b[a-z]{2,}\b/g);
  return matches || [];
}

/**
 * Convert raw text into the sparse TF-IDF feature vector the model expects.
 * Steps mirror sklearn's TfidfVectorizer at transform time:
 *   1. tokenize + count raw term frequency for vocab terms only
 *   2. tf-idf value = count * idf[term]
 *   3. L2-normalize the resulting vector
 *
 * @param {string} text - raw email text (subject + body)
 * @param {Object.<string, number>} vocab - word -> feature index
 * @param {number[]} idf - idf value per feature index
 * @returns {Object.<number, number>} sparse vector: {featureIndex: tfidfValue}
 */
function vectorize(text, vocab, idf) {
  const tokens = tokenize(text);

  // Raw term counts, restricted to words that exist in the trained vocab.
  const counts = {};
  for (const tok of tokens) {
    if (Object.prototype.hasOwnProperty.call(vocab, tok)) {
      const idx = vocab[tok];
      counts[idx] = (counts[idx] || 0) + 1;
    }
  }

  // tf-idf = count * idf, then L2-normalize across the feature vector.
  const vec = {};
  let sumSquares = 0;
  for (const idxStr in counts) {
    const idx = Number(idxStr);
    const tfidf = counts[idx] * idf[idx];
    vec[idx] = tfidf;
    sumSquares += tfidf * tfidf;
  }

  const norm = Math.sqrt(sumSquares);
  if (norm > 0) {
    for (const idxStr in vec) {
      vec[idxStr] = vec[idxStr] / norm;
    }
  }

  return vec;
}

if (typeof module !== "undefined") {
  module.exports = { tokenize, vectorize };
}
