// classifier.js
// Runs a TF-IDF feature vector through the trained logistic regression
// model (model.js) to produce a phishing probability.
//
// Depends on tokenize()/vectorize() from tokenizer.js being loaded first.

function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

/**
 * Classify raw email text as phishing or legit.
 * @param {string} text - raw email text (recommend: subject + " " + body)
 * @param {Object} model - the PHISHING_MODEL object from model.js
 *   ({ weights, intercept, vocab, idf, meta })
 * @param {number} [threshold=0.5] - probability cutoff for flagging as phishing
 * @returns {{ probability: number, isPhishing: boolean }}
 */
function classifyText(text, model, threshold = 0.5) {
  const vec = vectorize(text, model.vocab, model.idf);

  let score = model.intercept;
  for (const idxStr in vec) {
    const idx = Number(idxStr);
    score += model.weights[idx] * vec[idxStr];
  }

  const probability = sigmoid(score);
  return {
    probability,
    isPhishing: probability > threshold,
  };
}

if (typeof module !== "undefined") {
  module.exports = { classifyText, sigmoid };
}
