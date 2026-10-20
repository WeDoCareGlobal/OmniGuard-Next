"""Minimal migration checks that require no running services."""
from pathlib import Path
import ast

ROOT = Path(__file__).resolve().parents[1]


def test_gateway_entrypoint_exists_and_parses():
    path = ROOT / 'main.py'
    assert path.is_file(), 'Missing gateway entrypoint'
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))


def test_security_modules_parse():
    modules = sorted((ROOT / 'security').glob('*.py'))
    assert modules, 'Security modules are missing'
    for path in modules:
        ast.parse(path.read_text(encoding='utf-8'), filename=str(path))


def test_dependency_manifest_exists():
    manifest = ROOT / 'requirements.txt'
    assert manifest.is_file()
    assert 'fastapi' in manifest.read_text(encoding='utf-8').lower()
