"""
Shared utilities for adapted scripts working with filtered_complete_chains_cleaned.jsonl

This module provides common functions for:
- Loading and parsing the new JSONL format
- Extracting licenses from metadata and scancode
- License categorization and normalization
- Chain building and upstream tracing
- Copyright text handling
- File type categorization
"""

import json
import re
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict


# ============================================================================
# File Loading
# ============================================================================

def load_jsonl_file(filepath: str) -> Dict[str, Dict]:
    """
    Load JSONL file with case-insensitive ID indexing.

    Note: There are ~161 ID collisions where the same ID is used for different entity types.
    This function keeps the last entity loaded for each ID. For type-safe lookup, use get_entity().

    Args:
        filepath: Path to the JSONL file

    Returns:
        Dictionary mapping lowercase IDs to entity data
    """
    entities = {}
    entities_by_type = {'dataset': {}, 'model': {}, 'application': {}}

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                entity = json.loads(line)
                entity_id = entity['id'].lower()
                entity_type = entity.get('type', 'unknown')

                # Store in both simple dict (for backward compatibility) and typed dict (for safety)
                entities[entity_id] = entity
                if entity_type in entities_by_type:
                    entities_by_type[entity_type][entity_id] = entity

    # Add the typed dicts as metadata
    entities['__by_type__'] = entities_by_type
    return entities


def get_entity(entities: Dict[str, Dict], entity_id: str, entity_type: str) -> Optional[Dict]:
    """
    Look up entity by ID and type (type-safe lookup that handles ID collisions).

    Args:
        entities: Dictionary from load_jsonl_file()
        entity_id: Entity ID (will be lowercased)
        entity_type: Entity type ('model', 'dataset', 'application')

    Returns:
        Entity dict if found, None otherwise
    """
    by_type = entities.get('__by_type__', {})
    if entity_type in by_type:
        return by_type[entity_type].get(entity_id.lower())
    return None


# ============================================================================
# License Extraction
# ============================================================================

def extract_licenses_metadata(entity: Dict) -> List[str]:
    """
    Extract licenses from metadata 'licenses' field.

    Args:
        entity: Entity dictionary with 'licenses' field

    Returns:
        List of license identifiers (may be empty)
    """
    return entity.get('licenses', [])


def extract_licenses_scancode(entity: Dict) -> List[str]:
    """
    Extract licenses from 'scancode' field.

    Args:
        entity: Entity dictionary with 'scancode' field

    Returns:
        List of unique license SPDX expressions
    """
    scancode = entity.get('scancode', [])
    if scancode is None:
        return []
    licenses = []
    for item in scancode:
        lic = item.get('license_expression_spdx')
        if lic and lic not in licenses:
            licenses.append(lic)
    return licenses


def split_license_expression(expr):
    """
    FLAW 2 FIX (v1.1) — Decompose an SPDX-style license expression into its
    OPERAND set, splitting on AND and OR. WITH is preserved (because
    "GPL-3.0-only WITH GCC-exception-3.1" carries meaningful exception info
    that should be kept as a single token). Parens and trailing '+' are stripped.

    Returns a set of lowercased operand strings.

    Examples:
        "MIT"                              -> {"mit"}
        "MIT AND Apache-2.0"               -> {"mit", "apache-2.0"}
        "(BSD-3-Clause OR Apache-2.0)"     -> {"bsd-3-clause", "apache-2.0"}
        "GPL-3.0-only WITH GCC-exception-3.1"
                                           -> {"gpl-3.0-only with gcc-exception-3.1"}
        "Apache-2.0 AND (MIT OR BSD-3-Clause)"
                                           -> {"apache-2.0", "mit", "bsd-3-clause"}
    """
    if expr is None:
        return set()
    if isinstance(expr, (list, set, tuple)):
        out = set()
        for e in expr:
            out |= split_license_expression(e)
        return out
    if not isinstance(expr, str):
        return set()

    s = expr.strip()
    if not s:
        return set()

    # Lowercase for splitting on operators, but only on AND/OR (not WITH).
    lower = s.lower()
    # Strip parens
    lower = lower.replace('(', ' ').replace(')', ' ')
    # Split on AND / OR (word-bounded) via sentinel separator.
    SEP = '\x1f'
    padded = ' ' + lower + ' '
    padded = padded.replace(' and ', SEP).replace(' or ', SEP)
    parts = [p.strip() for p in padded.split(SEP)]
    out = set()
    for p in parts:
        if not p:
            continue
        # Drop trailing '+' (license-version-or-later marker)
        if p.endswith('+'):
            p = p[:-1].rstrip()
        # Drop stray commas/semicolons
        p = p.strip(' ,;')
        if p:
            out.add(p)
    return out


def has_target_license(licenses: List[str], targets: Set[str] = None) -> bool:
    """
    Check if entity has any of the target licenses (MIT/Apache/BSD).

    FLAW 2 FIX (v1.1): decomposes each declared license entry through
    split_license_expression() so that compound entries like
    "MIT AND Apache-2.0" are treated as containing both MIT and Apache-2.0.

    Args:
        licenses: List of license identifiers (each may be a compound SPDX expr)
        targets: Set of target licenses (default: MIT, Apache-2.0, BSD-3-Clause)

    Returns:
        True if any operand of any declared license entry is in targets.
    """
    if targets is None:
        targets = {'MIT', 'Apache-2.0', 'BSD-3-Clause'}
    targets_lower = {t.lower() for t in targets}
    declared_operands = split_license_expression(licenses)
    return bool(declared_operands & targets_lower)


# ============================================================================
# License Categorization
# ============================================================================

# Standard license category mappings
LICENSE_CATEGORIES = {
    # Permissive
    'MIT': 'Permissive',
    'Apache-2.0': 'Permissive',
    'BSD-3-Clause': 'Permissive',
    'BSD-2-Clause': 'Permissive',
    'ISC': 'Permissive',
    '0BSD': 'Permissive',
    'Unlicense': 'Permissive',
    'WTFPL': 'Permissive',
    'Zlib': 'Permissive',

    # Copyleft - Strong
    'GPL-3.0': 'Copyleft-Strong',
    'GPL-2.0': 'Copyleft-Strong',
    'GPL-3.0-or-later': 'Copyleft-Strong',
    'GPL-2.0-or-later': 'Copyleft-Strong',
    'AGPL-3.0': 'Copyleft-Strong',
    'AGPL-3.0-or-later': 'Copyleft-Strong',

    # Copyleft - Weak
    'LGPL-3.0': 'Copyleft-Weak',
    'LGPL-2.1': 'Copyleft-Weak',
    'LGPL-3.0-or-later': 'Copyleft-Weak',
    'LGPL-2.1-or-later': 'Copyleft-Weak',
    'MPL-2.0': 'Copyleft-Weak',
    'EPL-1.0': 'Copyleft-Weak',
    'EPL-2.0': 'Copyleft-Weak',

    # ML-Specific
    'BigScience-RAIL-1.0': 'ML-Specific',
    'BigScience-OpenRAIL-M': 'ML-Specific',
    'CreativeML-OpenRAIL-M': 'ML-Specific',
    'bigscience-bloom-rail-1.0': 'ML-Specific',
    'bigcode-openrail-m': 'ML-Specific',
    'llama2': 'ML-Specific',
    'llama3': 'ML-Specific',
    'llama3.1': 'ML-Specific',
    'llama3.2': 'ML-Specific',
    'other-open-rail': 'ML-Specific',

    # Creative Commons
    'CC-BY-4.0': 'Creative-Commons',
    'CC-BY-SA-4.0': 'Creative-Commons',
    'CC-BY-3.0': 'Creative-Commons',
    'CC-BY-SA-3.0': 'Creative-Commons',
    'CC0-1.0': 'Creative-Commons',

    # Proprietary/Other
    'UNKNOWN': 'Other',
    'other': 'Other',
}


def categorize_license(license_id: str) -> str:
    """
    Categorize a license into standard groups.

    Args:
        license_id: SPDX license identifier

    Returns:
        Category string (e.g., 'Permissive', 'Copyleft-Strong', etc.)
    """
    # Direct lookup
    if license_id in LICENSE_CATEGORIES:
        return LICENSE_CATEGORIES[license_id]

    # Pattern matching for variations
    license_lower = license_id.lower()

    if 'gpl' in license_lower and 'lgpl' not in license_lower:
        return 'Copyleft-Strong'
    if 'lgpl' in license_lower or 'mpl' in license_lower or 'epl' in license_lower:
        return 'Copyleft-Weak'
    if any(x in license_lower for x in ['rail', 'llama', 'openai', 'bigscience', 'bigcode']):
        return 'ML-Specific'
    if 'cc-by' in license_lower or 'cc0' in license_lower:
        return 'Creative-Commons'
    if any(x in license_lower for x in ['mit', 'apache', 'bsd', 'isc']):
        return 'Permissive'

    return 'Other'


def categorize_licenses(licenses: List[str]) -> str:
    """
    Categorize a list of licenses, handling multiple licenses.

    Args:
        licenses: List of license identifiers

    Returns:
        Single category string (most restrictive wins)
    """
    if not licenses:
        return 'Empty'

    categories = [categorize_license(lic) for lic in licenses]

    # Priority order (most restrictive to least)
    priority = [
        'Copyleft-Strong',
        'Copyleft-Weak',
        'ML-Specific',
        'Creative-Commons',
        'Permissive',
        'Other',
        'Empty'
    ]

    for cat in priority:
        if cat in categories:
            return cat

    return 'Other'


# ============================================================================
# Chain Building and Tracing
# ============================================================================

def build_chains(entities: Dict[str, Dict], target_licenses: Set[str] = None) -> List[Tuple[str, str]]:
    """
    Build all application → model chains.

    Args:
        entities: Dictionary of all entities (lowercase IDs)
        target_licenses: Optional set of target licenses to filter by

    Returns:
        List of (app_id, model_id) tuples
    """
    chains = []

    for entity_id, entity in entities.items():
        if entity.get('type') != 'application':
            continue

        # Filter by licenses if specified
        if target_licenses is not None:
            licenses = extract_licenses_metadata(entity)
            if not has_target_license(licenses, target_licenses):
                continue

        # Get linked models
        models = entity.get('models', [])
        for model_id in models:
            chains.append((entity_id, model_id.lower()))

    return chains


def trace_upstream_models(model_id: str, entities: Dict[str, Dict],
                          visited: Set[str] = None) -> List[str]:
    """
    Recursively trace upstream base models with cycle detection.

    Args:
        model_id: Starting model ID (lowercase)
        entities: Dictionary of all entities
        visited: Set of already visited model IDs (for cycle detection)

    Returns:
        List of all upstream model IDs (including starting model)
    """
    if visited is None:
        visited = set()

    # Avoid cycles
    if model_id in visited:
        return []

    visited.add(model_id)
    upstream = [model_id]

    # Get the model entity (using type-safe lookup to avoid ID collisions)
    model = get_entity(entities, model_id, 'model')
    if not model:
        return upstream

    # Recursively trace base models
    base_models = model.get('base_models', [])
    for base_id in base_models:
        base_id_lower = base_id.lower()
        upstream.extend(trace_upstream_models(base_id_lower, entities, visited))

    return upstream


def get_training_datasets(model_id: str, entities: Dict[str, Dict]) -> List[str]:
    """
    Get training datasets for a model.

    Args:
        model_id: Model ID (lowercase)
        entities: Dictionary of all entities

    Returns:
        List of dataset IDs (lowercase)
    """
    # Use type-safe lookup to avoid ID collisions
    model = get_entity(entities, model_id, 'model')
    if not model:
        return []

    # New format uses 'datasets' field
    datasets = model.get('datasets', [])
    return [d.lower() for d in datasets]


# ============================================================================
# Copyright Handling
# ============================================================================

def normalize_copyright(text: str) -> str:
    """
    Normalize copyright text for matching.

    Args:
        text: Copyright statement text

    Returns:
        Normalized text (lowercase, whitespace collapsed, punctuation removed)
    """
    # Lowercase
    text = text.lower()

    # Remove common variations
    text = re.sub(r'copyright\s*(\(c\)|©|&copy;)?\s*', '', text)

    # Remove years (single or ranges)
    text = re.sub(r'\b\d{4}(\s*-\s*\d{4})?\b', '', text)

    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text)

    # Remove punctuation
    text = re.sub(r'[^\w\s]', '', text)

    return text.strip()


def extract_copyrights(entity: Dict) -> List[str]:
    """
    Extract copyright statements from entity.

    Args:
        entity: Entity dictionary with 'copyrights' field

    Returns:
        List of copyright statement texts
    """
    copyrights = entity.get('copyrights', [])
    statements = []

    for item in copyrights:
        stmt = item.get('copyright', '')
        if stmt and stmt not in statements:
            statements.append(stmt)

    return statements


def extract_holders(entity: Dict) -> List[str]:
    """
    Extract copyright holders from entity.

    Args:
        entity: Entity dictionary with 'holders' field

    Returns:
        List of holder names
    """
    holders = entity.get('holders', [])
    names = []

    for item in holders:
        holder = item.get('holder', '')
        if holder and holder not in names:
            names.append(holder)

    return names


# ============================================================================
# File Type Categorization
# ============================================================================

def categorize_file_type(file_path: str) -> str:
    """
    Categorize file type based on path.

    Args:
        file_path: File path from scancode origins

    Returns:
        Category: 'LICENSE', 'README', 'NOTICE', 'SOURCE', or 'OTHER'
    """
    path_lower = file_path.lower()
    filename = path_lower.split('/')[-1]

    # LICENSE files
    if 'license' in path_lower or 'copying' in path_lower:
        return 'LICENSE'

    # README files
    if 'readme' in path_lower:
        return 'README'

    # NOTICE files
    if 'notice' in path_lower:
        return 'NOTICE'

    # Source code (common extensions)
    source_exts = ['.py', '.js', '.java', '.cpp', '.c', '.h', '.rs', '.go', '.ts', '.jsx', '.tsx']
    if any(filename.endswith(ext) for ext in source_exts):
        return 'SOURCE'

    return 'OTHER'


def has_full_license_text(entity: Dict, threshold: float = 90.0,
                          require_declared: bool = True,
                          precise: bool = True) -> bool:
    """
    Check if entity has full license text (match_coverage >= threshold).

    FLAW 1 FIX (v1.1, require_declared=True default):
        Require the matched scancode entry's license_expression_spdx to
        reference at least one of the entity's DECLARED license labels.
        Without this, an entity declared "MIT" could pass on an Apache-2.0
        full-text match in an unrelated file.

    FLAW 4 FIX (v1.1, precise=True default — requires v1.1+ dataset):
        Use the per-origin `match_license_expression` /
        `match_license_expression_spdx` and `rule_category` fields (added
        by build_v3_precise_scancode.py) to verify the SPECIFIC origin's
        matched license is one of the declared licenses AND that origin's
        rule was a FULL_TEXT rule. This eliminates the compound-license
        ambiguity where the per-origin match_coverage of a compound entry
        like "MIT AND CC-BY-4.0" can't be attributed to the right
        sub-license under the v1.0 schema.

        Falls back to the legacy entry-level check on origins that don't
        carry the new fields (backward-compatible with v1.0 datasets).

    Args:
        entity: Entity dictionary with 'scancode' and 'licenses' fields
        threshold: Minimum match coverage percentage (default: 90.0)
        require_declared: If True (default), require the matched license to
            equal one of the entity's declared licenses. Set False to
            reproduce the legacy v1.0 paper behaviour.
        precise: If True (default), use per-origin license/rule_category
            for verification on v1.1+ datasets. Set False to reproduce
            v1.0 (entry-level only) behaviour.

    Returns:
        True if any license has match_coverage >= threshold AND (if
        require_declared) the matched license matches one of the entity's
        declared licenses.
    """
    scancode = entity.get('scancode', [])
    if scancode is None:
        return False

    declared_operands = set()
    if require_declared:
        # FLAW 2 FIX: decompose declared licenses (which may be compound SPDX
        # expressions like "MIT AND Apache-2.0") into operand set.
        declared_operands = split_license_expression(entity.get('licenses') or [])
        if not declared_operands:
            return False

    for item in scancode:
        if require_declared:
            spdx = item.get('license_expression_spdx') or ''
            if not spdx:
                continue
            # Decompose the scancode expression the same way so that a
            # per-license item like 'MIT' will match a declared
            # 'MIT AND Apache-2.0', and a compound scancode item like
            # 'MIT AND Apache-2.0' will match a declared 'MIT'.
            scancode_operands = split_license_expression(spdx)
            if not (declared_operands & scancode_operands):
                continue

        for origin in item.get('origins', []) or []:
            coverage = origin.get('match_coverage', 0.0)
            if coverage is None:
                coverage = 0.0
            if coverage < threshold:
                continue

            if precise and ('match_license_expression_spdx' in origin
                            or 'match_license_expression' in origin):
                # FLAW 4 (precise) mode: require the SPECIFIC match to be for
                # one of the declared licenses AND be a FULL_TEXT category.
                #
                # Compare against the SPDX form of the match's license, not
                # the internal ScanCode key — the entity's declared
                # `licenses` is in SPDX form (e.g. 'BSD-3-Clause') but the
                # match's `license_expression` is internal (e.g. 'bsd-new').
                # Falls back to internal key for older records without the
                # spdx field.
                spdx = origin.get('match_license_expression_spdx')
                if spdx:
                    match_operands = split_license_expression(spdx)
                else:
                    match_operands = {
                        (origin.get('match_license_expression') or '').lower()
                    }
                    match_operands.discard('')
                if not match_operands:
                    continue
                if require_declared and not (match_operands & declared_operands):
                    continue
                if origin.get('rule_category') != 'FULL_TEXT':
                    # The match was a TAG/NOTICE/REFERENCE — not the actual
                    # license text. Only FULL_TEXT counts.
                    continue
                return True
            else:
                # Legacy path (v1.0 data without per-origin precision)
                return True

    return False


# ============================================================================
# License Matrix Loading
# ============================================================================

def load_license_matrix(filepath: str = 'matrix.json') -> Dict:
    """
    Load license category transition matrix.

    Args:
        filepath: Path to matrix.json file

    Returns:
        Dictionary with license category mappings
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # Return empty dict if file doesn't exist
        return {}


# ============================================================================
# Statistics Helpers
# ============================================================================

def count_by_type(entities: Dict[str, Dict]) -> Dict[str, int]:
    """
    Count entities by type.

    Args:
        entities: Dictionary of all entities

    Returns:
        Dictionary mapping type to count
    """
    # Use type-indexed data if available (preserves all entities without ID collisions)
    by_type = entities.get('__by_type__', {})
    if by_type:
        return {
            entity_type: len(entity_dict)
            for entity_type, entity_dict in by_type.items()
        }

    # Fallback to counting from main dict
    counts = defaultdict(int)
    for eid, entity in entities.items():
        if eid == '__by_type__':
            continue
        entity_type = entity.get('type', 'unknown')
        counts[entity_type] += 1
    return dict(counts)


def filter_by_type(entities: Dict[str, Dict], entity_type: str) -> Dict[str, Dict]:
    """
    Filter entities by type.

    Args:
        entities: Dictionary of all entities
        entity_type: Type to filter by ('dataset', 'model', 'application')

    Returns:
        Dictionary of entities of specified type
    """
    # Use type-indexed data if available for efficiency
    by_type = entities.get('__by_type__', {})
    if entity_type in by_type:
        return by_type[entity_type]

    # Fallback to filtering
    return {
        eid: entity
        for eid, entity in entities.items()
        if eid != '__by_type__' and entity.get('type') == entity_type
    }


def iter_all_entities(entities: Dict[str, Dict]):
    """
    Iterate through all entities without ID collisions.

    Yields all entities from the collision-free __by_type__ storage.

    Args:
        entities: Dictionary from load_jsonl_file()

    Yields:
        Tuple of (entity_id, entity_dict) for each entity
    """
    by_type = entities.get('__by_type__', {})
    if by_type:
        # Iterate through type-indexed storage (no collisions)
        for entity_type, entity_dict in by_type.items():
            for entity_id, entity in entity_dict.items():
                yield entity_id, entity
    else:
        # Fallback to main dict
        for entity_id, entity in entities.items():
            if entity_id != '__by_type__':
                yield entity_id, entity


def get_popular_entities(entities: Dict[str, Dict], n: int = 10,
                         entity_type: str = None) -> List[Tuple[str, int]]:
    """
    Get most popular entities by likes.

    Args:
        entities: Dictionary of all entities
        n: Number of top entities to return
        entity_type: Optional type filter

    Returns:
        List of (entity_id, likes) tuples sorted by likes descending
    """
    filtered = entities
    if entity_type:
        filtered = filter_by_type(entities, entity_type)

    # Sort by likes
    sorted_entities = sorted(
        [(eid, entity.get('likes', 0)) for eid, entity in filtered.items() if eid != '__by_type__'],
        key=lambda x: x[1],
        reverse=True
    )

    return sorted_entities[:n]


# ============================================================================
# Output Formatting
# ============================================================================

def format_percentage(numerator: int, denominator: int, decimals: int = 2) -> str:
    """
    Format a percentage with specified decimal places.

    Args:
        numerator: Numerator value
        denominator: Denominator value
        decimals: Number of decimal places

    Returns:
        Formatted percentage string (e.g., "12.34%")
    """
    if denominator == 0:
        return "0.00%"

    percentage = (numerator / denominator) * 100
    return f"{percentage:.{decimals}f}%"


def format_count_with_percentage(count: int, total: int, decimals: int = 2) -> str:
    """
    Format count with percentage.

    Args:
        count: Count value
        total: Total value
        decimals: Number of decimal places for percentage

    Returns:
        Formatted string (e.g., "123 (12.34%)")
    """
    pct = format_percentage(count, total, decimals)
    return f"{count:,} ({pct})"
