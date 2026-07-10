import json
from crypto_native_ledger_pro.ledger import load_secret, new_secret
from crypto_native_ledger_pro.pq_signature_adapter import generate_test_keypair
from crypto_native_ledger_pro.unified_attack_simulator import run_default_demo, run_unified_attack_simulation, write_unified_attack_report
from crypto_native_ledger_pro.unified_runtime import UnifiedRecognitionRuntime

def _runtime():
    secret = load_secret(new_secret())
    key = generate_test_keypair('hmac-sha256')
    return UnifiedRecognitionRuntime(curvature_secret=secret, signature_key=key)

def test_unified_simulator_summary():
    runtime = _runtime()
    report = run_unified_attack_simulation(runtime, {'document': 'main.tex'}, {'repo': 'Cryptography'}, dimension=4)
    assert report.summary['total_attacks'] == 9
    assert report.summary['detected_attacks'] == 9
    assert report.summary['missed_attacks'] == 0
    assert report.summary['all_unified_attacks_detected'] is True

def test_unified_simulator_report_file(tmp_path):
    runtime = _runtime()
    report = run_unified_attack_simulation(runtime, {'document': 'main.tex'}, {'repo': 'Cryptography'}, dimension=4)
    out = write_unified_attack_report(report, tmp_path / 'unified-report.json')
    loaded = json.loads(out.read_text(encoding='utf-8'))
    assert loaded['summary']['all_unified_attacks_detected'] is True

def test_unified_simulator_demo_file(tmp_path):
    out = tmp_path / 'demo_unified_attack_simulation_v1.json'
    report = run_default_demo(out)
    assert out.exists()
    assert report.summary['all_unified_attacks_detected'] is True
