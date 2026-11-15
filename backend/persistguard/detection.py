from dataclasses import dataclass

@dataclass(frozen=True)
class Artifact:
    endpoint_id: str
    os_family: str
    mechanism: str
    path: str
    signature_status: str = 'unknown'
    is_new: bool = False
    encoded_command: bool = False
    user_writable_executable: bool = False
    known_malicious_hash: bool = False

def severity_for(score: int) -> str:
    if not 0 <= score <= 100:
        raise ValueError('score must be between 0 and 100')
    return ('critical' if score >= 90 else 'high' if score >= 70 else
            'medium' if score >= 40 else 'low' if score >= 15 else 'info')

def assess(artifact: Artifact, custom_signals: tuple[tuple[int, str], ...] = ()) -> dict:
    signals = [
        (artifact.known_malicious_hash, 90, 'Known malicious hash match'),
        (artifact.encoded_command, 25, 'Encoded startup command'),
        (artifact.user_writable_executable, 20, 'Executable in writable location'),
        (artifact.signature_status == 'invalid', 15, 'Invalid signature'),
        (artifact.signature_status == 'unsigned', 10, 'Unsigned executable'),
        (artifact.is_new, 10, 'New persistence entry'),
    ]
    matched_signals = [(weight, reason) for matched, weight, reason in signals if matched]
    matched_signals.extend(custom_signals)
    reasons = [reason for _, reason in matched_signals]
    score = min(100, sum(weight for weight, _ in matched_signals))
    return {'score': score, 'severity': severity_for(score),
            'verdict': 'confirmed_malicious' if artifact.known_malicious_hash else 'suspicious' if score >= 40 else 'unknown',
            'confidence': 'high' if artifact.known_malicious_hash else 'medium' if len(reasons) >= 2 else 'low',
            'reasons': reasons}
