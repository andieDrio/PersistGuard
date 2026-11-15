import unittest
from persistguard.detection import Artifact, assess, severity_for

class DetectionTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual([severity_for(i) for i in (0, 15, 40, 70, 90)], ['info','low','medium','high','critical'])
    def test_benign(self):
        self.assertEqual(assess(Artifact('e1','windows','service','test'))['verdict'], 'unknown')
    def test_multiple_signals(self):
        f = assess(Artifact('e1','windows','run','HKCU', signature_status='unsigned', is_new=True, encoded_command=True, user_writable_executable=True))
        self.assertEqual((f['score'],f['severity']), (65,'medium'))
    def test_known_hash(self):
        self.assertEqual(assess(Artifact('e1','linux','cron','/etc/cron.d/a',known_malicious_hash=True))['severity'],'critical')
