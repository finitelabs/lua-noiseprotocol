# Test Vector Management

## Overview

This directory contains test vectors for the Noise Protocol implementation and tools to manage them.

## Files

- `vectors_full/` - Full test vector files from official Noise Protocol test suites
  - `cacophony.json` - 944 vectors including X448 support
  - `snow.json` - 408 vectors with Curve25519
  - `snow_multi_psk.json` - 104 vectors testing PSK functionality

- `vectors_sampled/` - Sampled subset (~5%) for faster testing
  - Same filenames but with diverse coverage maintained
  - Created by `sample_vectors.py`

- `sample_vectors.py` - Python script to create diverse sampled vectors

## Usage

### Using Sampled Test Vectors (default)
```bash
./run_tests.sh noise_vectors
```

### Using Full Test Vectors
```bash
NOISE_VECTORS_DIR=vectors_full ./run_tests.sh noise_vectors
```

### Regenerating Sampled Vectors
```bash
python tests/sample_vectors.py
```

## Sampling Strategy

The `sample_vectors.py` script ensures diverse coverage by:

1. Including at least one example of each unique pattern
2. Covering all DH curves (Curve25519, X448)
3. Covering all ciphers (AESGCM, ChaChaPoly)
4. Covering all hash functions (BLAKE2b, BLAKE2s, SHA256, SHA512)
5. Prioritizing less common patterns (PSK variants, X448, etc.)
6. Maintaining ~5% of original vectors for efficiency

## Environment Variables

- `NOISE_VECTORS_DIR` - Directory containing test vectors to use
  - Default: `vectors_sampled`
  - For full set: `vectors_full`
