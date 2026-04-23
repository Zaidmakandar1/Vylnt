"""
ML Filter Training Pipeline — Vylnt (DevGuard)
Bidirectional LSTM for DOM manipulation pattern classification.
Trains on a synthetic dataset and saves model artifacts to ml-filter/model/.
Requirements: 6.1, 6.6
"""

import os
import json
import random
import string
import numpy as np

# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

SPECIAL_TOKENS = ["<PAD>", "<UNK>"]

# Common JS tokens that appear around dangerous patterns
JS_VOCAB = [
    "var", "let", "const", "function", "return", "if", "else", "for", "while",
    "eval", "innerHTML", "document", "write", "setTimeout", "setInterval",
    "window", "document", "element", "node", "script", "src", "href",
    "(", ")", "{", "}", "[", "]", ";", "=", "==", "===", "!=", "!==",
    "+", "-", "*", "/", ".", ",", ":", "=>", "&&", "||", "!",
    "string", "number", "boolean", "null", "undefined", "true", "false",
    "new", "this", "prototype", "class", "extends", "import", "export",
    "try", "catch", "throw", "async", "await", "Promise", "then",
    "getElementById", "querySelector", "querySelectorAll", "addEventListener",
    "removeEventListener", "appendChild", "removeChild", "createElement",
    "textContent", "value", "style", "className", "setAttribute",
    "fetch", "XMLHttpRequest", "JSON", "parse", "stringify",
    "location", "href", "hash", "search", "pathname",
    "cookie", "localStorage", "sessionStorage", "getItem", "setItem",
]

PAD_IDX = 0
UNK_IDX = 1


class JSTokenizer:
    """Simple whitespace/punctuation tokenizer for JavaScript context windows."""

    def __init__(self):
        self.vocab = SPECIAL_TOKENS + JS_VOCAB
        self.token2idx = {tok: idx for idx, tok in enumerate(self.vocab)}
        self.idx2token = {idx: tok for tok, idx in self.token2idx.items()}
        self.vocab_size = len(self.vocab)

    def tokenize(self, text: str) -> list[str]:
        """Split text into tokens (simple split on whitespace and common punctuation)."""
        import re
        # Split on whitespace and keep punctuation as separate tokens
        tokens = re.findall(r'[a-zA-Z_$][a-zA-Z0-9_$]*|[^\s\w]|\d+', text)
        return tokens

    def encode(self, tokens: list[str]) -> list[int]:
        return [self.token2idx.get(t, UNK_IDX) for t in tokens]

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"vocab": self.vocab, "token2idx": self.token2idx}, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "JSTokenizer":
        with open(path) as f:
            data = json.load(f)
        tok = cls.__new__(cls)
        tok.vocab = data["vocab"]
        tok.token2idx = data["token2idx"]
        tok.idx2token = {int(v): k for k, v in tok.token2idx.items()}
        tok.vocab_size = len(tok.vocab)
        return tok


# ---------------------------------------------------------------------------
# Context window extractor
# ---------------------------------------------------------------------------

CONTEXT_WINDOW = 10  # ±10 tokens around the dangerous pattern


def extract_context_window(tokens: list[str], pattern_idx: int, window: int = CONTEXT_WINDOW) -> list[str]:
    """Extract ±window tokens around pattern_idx, padding with <PAD> as needed."""
    start = max(0, pattern_idx - window)
    end = min(len(tokens), pattern_idx + window + 1)
    context = tokens[start:end]
    # Pad to fixed length 2*window+1
    total = 2 * window + 1
    if len(context) < total:
        context = ["<PAD>"] * (total - len(context)) + context
    return context[:total]


# ---------------------------------------------------------------------------
# Synthetic dataset generator
# ---------------------------------------------------------------------------

DANGEROUS_PATTERNS = ["eval", "innerHTML", "document.write", "setTimeout", "setInterval"]

SAFE_TEMPLATES = [
    "var x = document . getElementById ( 'id' ) ; x . textContent = value ;",
    "const el = document . querySelector ( '.class' ) ; el . style . display = 'none' ;",
    "element . addEventListener ( 'click' , function ( ) { return true ; } ) ;",
    "let result = JSON . parse ( data ) ; console . log ( result ) ;",
    "fetch ( url ) . then ( function ( r ) { return r . json ( ) ; } ) ;",
    "document . createElement ( 'div' ) ; node . appendChild ( child ) ;",
    "const val = localStorage . getItem ( 'key' ) ; if ( val ) { return val ; }",
    "window . location . href = '/safe-path' ;",
    "element . setAttribute ( 'data-id' , id ) ;",
    "const items = document . querySelectorAll ( 'li' ) ;",
]

MALICIOUS_TEMPLATES = [
    "eval ( userInput ) ;",
    "element . innerHTML = untrustedData ;",
    "document . write ( '<script>' + payload + '</script>' ) ;",
    "setTimeout ( 'eval(' + code + ')' , 0 ) ;",
    "setInterval ( 'document.write(' + data + ')' , 100 ) ;",
    "eval ( atob ( encodedPayload ) ) ;",
    "document . body . innerHTML = response . text ;",
    "document . write ( location . hash . slice ( 1 ) ) ;",
    "setTimeout ( userControlledString , delay ) ;",
    "setInterval ( 'fetch(\"' + exfiltrationUrl + '\")' , 1000 ) ;",
]


def _random_js_context(n_tokens: int = 5) -> str:
    """Generate random benign JS tokens as surrounding context."""
    benign = ["var", "let", "const", "function", "return", "if", "else",
              "element", "document", "window", "value", "result", "data",
              "(", ")", "{", "}", ";", "=", ".", ","]
    return " ".join(random.choices(benign, k=n_tokens))


def generate_synthetic_dataset(n_samples: int = 2000, seed: int = 42) -> tuple[list[list[str]], list[int]]:
    """
    Generate synthetic labeled dataset.
    Returns (context_token_lists, labels) where label 0=safe, 1=malicious.
    Each sample is a list of tokens representing the context window.
    """
    random.seed(seed)
    np.random.seed(seed)

    samples: list[list[str]] = []
    labels: list[int] = []

    half = n_samples // 2

    # Safe samples
    for _ in range(half):
        template = random.choice(SAFE_TEMPLATES)
        prefix = _random_js_context(random.randint(3, 8))
        suffix = _random_js_context(random.randint(3, 8))
        full = f"{prefix} {template} {suffix}"
        tokens = full.split()
        # Pick a random position as the "pattern" center
        center = random.randint(CONTEXT_WINDOW, max(CONTEXT_WINDOW, len(tokens) - CONTEXT_WINDOW - 1))
        context = extract_context_window(tokens, center, CONTEXT_WINDOW)
        samples.append(context)
        labels.append(0)

    # Malicious samples
    for _ in range(half):
        template = random.choice(MALICIOUS_TEMPLATES)
        prefix = _random_js_context(random.randint(3, 8))
        suffix = _random_js_context(random.randint(3, 8))
        full = f"{prefix} {template} {suffix}"
        tokens = full.split()
        center = random.randint(CONTEXT_WINDOW, max(CONTEXT_WINDOW, len(tokens) - CONTEXT_WINDOW - 1))
        context = extract_context_window(tokens, center, CONTEXT_WINDOW)
        samples.append(context)
        labels.append(1)

    # Shuffle
    combined = list(zip(samples, labels))
    random.shuffle(combined)
    samples, labels = zip(*combined)
    return list(samples), list(labels)


# ---------------------------------------------------------------------------
# Model definition
# ---------------------------------------------------------------------------

def build_model(vocab_size: int, embedding_dim: int = 32, lstm_units: int = 64, input_length: int = 21):
    """Build bidirectional LSTM model for binary classification."""
    import tensorflow as tf
    from tensorflow import keras

    model = keras.Sequential([
        keras.layers.Embedding(
            input_dim=vocab_size,
            output_dim=embedding_dim,
            input_length=input_length,
            mask_zero=True,
            name="embedding"
        ),
        keras.layers.Bidirectional(
            keras.layers.LSTM(lstm_units, dropout=0.2, recurrent_dropout=0.1),
            name="bilstm"
        ),
        keras.layers.Dense(32, activation="relu", name="dense"),
        keras.layers.Dropout(0.3),
        keras.layers.Dense(1, activation="sigmoid", name="output"),
    ])

    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.AUC(name="auc")]
    )
    return model


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------

def train(
    n_samples: int = 2000,
    epochs: int = 10,
    batch_size: int = 32,
    validation_split: float = 0.2,
    model_dir: str = "model",
    seed: int = 42,
):
    import tensorflow as tf

    print("=== Vylnt ML Filter — Training Pipeline ===")
    print(f"Generating {n_samples} synthetic samples...")

    tokenizer = JSTokenizer()
    samples, labels = generate_synthetic_dataset(n_samples=n_samples, seed=seed)

    # Encode tokens to integer sequences
    X = np.array([tokenizer.encode(ctx) for ctx in samples], dtype=np.int32)
    y = np.array(labels, dtype=np.float32)

    input_length = X.shape[1]  # 2*CONTEXT_WINDOW+1 = 21
    print(f"Input shape: {X.shape}, vocab size: {tokenizer.vocab_size}")

    # Build model
    model = build_model(
        vocab_size=tokenizer.vocab_size,
        embedding_dim=32,
        lstm_units=64,
        input_length=input_length,
    )
    model.summary()

    # Train
    print(f"\nTraining for {epochs} epochs...")
    history = model.fit(
        X, y,
        epochs=epochs,
        batch_size=batch_size,
        validation_split=validation_split,
        verbose=1,
    )

    # Evaluate on validation set
    val_loss = history.history.get("val_loss", [None])[-1]
    val_acc = history.history.get("val_accuracy", [None])[-1]
    print(f"\nFinal val_loss={val_loss:.4f}, val_accuracy={val_acc:.4f}")

    # Save artifacts
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "lstm_model.keras")
    tokenizer_path = os.path.join(model_dir, "tokenizer.json")
    config_path = os.path.join(model_dir, "config.json")

    model.save(model_path)
    tokenizer.save(tokenizer_path)

    config = {
        "input_length": int(input_length),
        "context_window": CONTEXT_WINDOW,
        "vocab_size": tokenizer.vocab_size,
        "embedding_dim": 32,
        "lstm_units": 64,
        "model_file": "lstm_model.keras",
        "tokenizer_file": "tokenizer.json",
        "val_accuracy": float(val_acc) if val_acc is not None else None,
    }
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    print(f"\nModel artifacts saved to '{model_dir}/':")
    print(f"  {model_path}")
    print(f"  {tokenizer_path}")
    print(f"  {config_path}")
    print("=== Training complete ===")

    return model, tokenizer, config


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train ML Filter LSTM model")
    parser.add_argument("--samples", type=int, default=2000, help="Number of synthetic training samples")
    parser.add_argument("--epochs", type=int, default=10, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--model-dir", type=str, default="model", help="Output directory for model artifacts")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    train(
        n_samples=args.samples,
        epochs=args.epochs,
        batch_size=args.batch_size,
        model_dir=args.model_dir,
        seed=args.seed,
    )
