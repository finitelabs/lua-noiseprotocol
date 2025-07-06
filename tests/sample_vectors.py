#!/usr/bin/env python3
"""
Sample diverse test vectors from Noise protocol test files.

This script creates a smaller, diverse subset of test vectors that covers:
- All unique protocol patterns
- All cipher/hash combinations
- Both DH curves (Curve25519 and X448)
- PSK variants
"""

import json
import random
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Union

# Set random seed for reproducibility
random.seed(42)

def parse_protocol_name(protocol_name: str) -> Dict[str, Union[str, bool]]:
    """Parse a Noise protocol name into its components."""
    # Example: Noise_NNpsk0_25519_AESGCM_BLAKE2b
    parts = protocol_name.split('_')
    assert len(parts) == 5, f"Unexpected protocol format: {protocol_name}"
    return {
        'pattern': parts[1],
        'dh': parts[2],
        'cipher': parts[3],
        'hash': parts[4],
        'has_psk': 'psk' in parts[1],
    }

def categorize_vectors(vectors: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Categorize vectors by their protocol components."""
    categories = defaultdict(list)

    for vector in vectors:
        protocol = parse_protocol_name(vector['protocol_name'])

        # Create category keys for different aspects
        pattern_key = protocol['pattern']
        dh_key = protocol['dh']
        cipher_key = protocol['cipher']
        hash_key = protocol['hash']
        has_psk = str(protocol['has_psk']).lower()
        full_key = f"{pattern_key}_{dh_key}_{cipher_key}_{hash_key}"

        # Store in multiple categories for flexible sampling
        categories[f'pattern:{pattern_key}'].append(vector)
        categories[f'dh:{dh_key}'].append(vector)
        categories[f'cipher:{cipher_key}'].append(vector)
        categories[f'hash:{hash_key}'].append(vector)
        categories[f'full:{full_key}'].append(vector)
        categories[f'has_psk:{has_psk}'].append(vector)

    return dict(categories)

def sample_diverse_vectors(all_vectors: List[Dict[str, Any]],
                         target_count: int = 50) -> List[Dict[str, Any]]:
    """Sample a diverse set of vectors ensuring coverage of all variants."""
    categories = categorize_vectors(all_vectors)
    selected = set()
    selected_indices = set()

    # First, ensure we have at least one of each unique pattern
    patterns = set()
    dh_curves = set()
    ciphers = set()
    hashes = set()

    # Collect all unique values
    for vector in all_vectors:
        protocol = parse_protocol_name(vector['protocol_name'])
        patterns.add(protocol['pattern'])
        dh_curves.add(protocol['dh'])
        ciphers.add(protocol['cipher'])
        hashes.add(protocol['hash'])

    # Try to get at least one example of each pattern (up to target_count/2)
    pattern_budget = target_count // 2
    for pattern in sorted(patterns):
        if len(selected) >= pattern_budget:
            break
        pattern_vectors = categories[f'pattern:{pattern}']
        if pattern_vectors:
            vector = random.choice(pattern_vectors)
            idx = all_vectors.index(vector)
            if idx not in selected_indices:
                selected.add(idx)
                selected_indices.add(idx)

    # Ensure we have examples of each DH curve, cipher, and hash
    for component_name, component_types in [('dh', dh_curves), ('cipher', ciphers), ('hash', hashes)]:
        for component in component_types:
            if len(selected) >= target_count:
                break
            component_vectors = categories[f'{component_name}:{component}']
            if component_vectors:
                vector = random.choice(component_vectors)
                idx = all_vectors.index(vector)
                if idx not in selected_indices:
                    selected.add(idx)
                    selected_indices.add(idx)
                    break

    # If we haven't reached target count, add more diverse samples
    remaining = target_count - len(selected)
    if remaining > 0:
        # Prioritize less common patterns
        priority_patterns = ['psk', 'X448', 'SHA512', 'BLAKE2s']

        for pattern in priority_patterns:
            if remaining <= 0:
                break
            pattern_vectors = []
            for key, vectors in categories.items():
                if pattern in key or any(pattern in v['protocol_name'] for v in vectors):
                    for v in vectors:
                        idx = all_vectors.index(v)
                        if idx not in selected_indices:
                            pattern_vectors.append(idx)

            if pattern_vectors:
                sample_size = min(remaining // len(priority_patterns), len(pattern_vectors))
                sampled = random.sample(pattern_vectors, min(sample_size, len(pattern_vectors)))
                selected.update(sampled)
                selected_indices.update(sampled)
                remaining = target_count - len(selected)

        # Fill remaining with random samples
        remaining = target_count - len(selected)
        if remaining > 0:
            available_indices = list(set(range(len(all_vectors))) - selected_indices)
            if available_indices:
                additional = random.sample(available_indices,
                                         min(remaining, len(available_indices)))
                selected.update(additional)

    # Return vectors in original order
    return [all_vectors[i] for i in sorted(selected)]

def main():
    """Main function to create sampled vector files."""
    vectors_dir = Path(__file__).parent / 'vectors_full'
    sampled_dir = Path(__file__).parent / 'vectors_sampled'

    # Create sampled directory
    sampled_dir.mkdir(exist_ok=True)

    # Process each JSON file
    json_files = list(vectors_dir.glob('*.json'))

    total_original = 0
    total_sampled = 0
    target_sample_percent = 0.05 # Target ~5% of original vectors

    for json_file in json_files:
        print(f"\nProcessing {json_file.name}...")

        # Load vectors
        with open(json_file, 'r') as f:
            data = json.load(f)

        original_count = len(data['vectors'])
        total_original += original_count

        target_size = round(original_count * target_sample_percent)

        # Sample vectors
        sampled_vectors = sample_diverse_vectors(data['vectors'], target_size)
        sampled_count = len(sampled_vectors)
        total_sampled += sampled_count

        # Create sampled data structure
        sampled_data = {
            'vectors': sampled_vectors
        }

        # Save sampled file
        output_file = sampled_dir / json_file.name
        with open(output_file, 'w') as f:
            json.dump(sampled_data, f, indent=2)

        print(f"  Original: {original_count} vectors")
        print(f"  Sampled: {sampled_count} vectors ({sampled_count/original_count*100:.1f}%)")

        # Show diversity statistics
        patterns = set()
        dhs = set()
        ciphers = set()
        hashes = set()

        for vector in sampled_vectors:
            protocol = parse_protocol_name(vector['protocol_name'])
            patterns.add(protocol['pattern'])
            dhs.add(protocol['dh'])
            ciphers.add(protocol['cipher'])
            hashes.add(protocol['hash'])

        print(f"  Coverage: {len(patterns)} patterns, {len(dhs)} DH, "
              f"{len(ciphers)} ciphers, {len(hashes)} hashes")

    print(f"\nTotal vectors: {total_original} -> {total_sampled} "
          f"({total_sampled/total_original*100:.1f}% overall)")

if __name__ == '__main__':
    main()
