import base64
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

import protected


class ProtectedQualification(unittest.TestCase):
    def test_enrollment_only_changes_authority_and_never_uses_host_state_key(self):
        import yaml
        image = {'mrtd': 'a'*96, 'rtmr': [None, 'b'*96, 'c'*96, None]}
        original = {'nodes': json.dumps({'measurements': [dict(image, name='a'), dict(image, name='b')]}),
                    'ha': {'voters': 3, 'replicas': ['a', 'b', 'c']}}
        config = protected.protected_config(original, 'https://metadata.invalid', 'public test CA', 'fixture')
        self.assertNotIn('objectWALPilot', original['ha'])
        self.assertNotIn('keySHA256', config['ha']['objectWALPilot'])
        self.assertEqual(len(json.loads(config['nodes'])['measurements']), 1)
        enrolled = copy.deepcopy(config)
        authority = base64.b64encode(b'a'*32).decode()
        enrolled['ha']['objectWALPilot']['recoveryAuthority'] = authority
        def receipt(value):
            return {'result': {'launch': base64.b64encode(yaml.safe_dump(value).encode()).decode(),
                               'derivation': {'authority_public': authority}}}
        self.assertEqual(yaml.safe_load(protected.enrolled_launch(config, receipt(enrolled))), enrolled)
        enrolled['ha']['objectWALPilot']['metadataEndpoint'] = 'https://other.invalid'
        with self.assertRaisesRegex(ValueError, 'exactly the public authority'):
            protected.enrolled_launch(config, receipt(enrolled))

    def barrier(self, survivor=None, custody_error=None, pods=None):
        runner = object.__new__(protected.Run)
        runner.run = 'cds-ha-test'
        runner.state = {'guest_placements': [{'variant': 'a', 'vmi_uid': str(i)} for i in range(3)]}
        runner.guests = {i: {'path': '/vm/'+str(i), 'item': {'metadata': {'name': str(i)}}} for i in range(3)}
        runner.tunnels = {i: [Mock()] for i in range(3)}
        runner.remove = runner.save = runner.event = Mock()
        runner.kube = Mock()
        runner.kube.call.side_effect = lambda method, path, **kw: ((200, {'items': pods or []})
            if '/pods?' in path else (200 if path == survivor else 404, {}))
        runner.custody = Mock()
        runner.custody.stop.return_value = 'custodian-uid'
        runner.custody.stop.side_effect = custody_error
        return runner

    def test_total_loss_barrier_requires_every_original_and_custodian_absent(self):
        for survivor in ('/vm/1', protected.ha.VMI+'2'):
            runner = self.barrier(survivor)
            with self.assertRaisesRegex(ValueError, 'still present'): runner.destroy_initial()
            self.assertNotIn('all_cds_lost', runner.state)
        runner = self.barrier(custody_error=RuntimeError('custodian removal uncertain'))
        with self.assertRaisesRegex(RuntimeError, 'uncertain'): runner.destroy_initial()
        self.assertNotIn('all_cds_lost', runner.state)
        runner = self.barrier(pods=[{'metadata': {'ownerReferences': [{'uid': '1'}]}}])
        with self.assertRaisesRegex(ValueError, 'launcher still present'): runner.destroy_initial()
        self.assertNotIn('all_cds_lost', runner.state)
        runner = self.barrier()
        runner.destroy_initial()
        self.assertEqual(runner.state['all_cds_lost']['vmi_uids'], ['0', '1', '2'])
        self.assertEqual(runner.guests, {})
        self.assertEqual(runner.kube.call.call_count, 7)

    def test_replacement_cannot_start_without_barrier(self):
        runner = object.__new__(protected.Run); runner.state = {}
        with self.assertRaisesRegex(ValueError, 'all-loss barrier'): runner.boot_generation({}, 'b')

    def test_uncertain_custody_batch_dispatch_is_never_repeated(self):
        with tempfile.TemporaryDirectory() as directory:
            custody = object.__new__(protected.Custody)
            custody.directory = Path(directory)
            custody.args = SimpleNamespace(probe='frozen-probe', tdx_image=directory)
            custody.state = {'measurement': 'a'*96}
            custody.parameters = {}; custody.custody_copy = None; custody.custodian_port = 10001
            custody.atomic = lambda path, value: path.write_text(json.dumps(value))
            def verify(label, argv, **kw):
                proof = dict.fromkeys(('attestation_chain_verified', 'collateral_verified', 'revocations_checked',
                                       'image_pins_verified', 'launch_binding_verified'), True)
                proof['platform'] = 'tdx'
                Path(argv[argv.index('-receipt')+1]).write_text(json.dumps(proof))
                Path(argv[argv.index('-collateral')+1]).write_text('{}')
            custody.command = verify
            custody.http = Mock(return_value=(503, {}))
            recipients = [{'public_key': str(i), 'nonce': str(i)} for i in range(3)]
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                custody.delegate_three('initial', recipients, Path(directory)/'launch.yaml')
            custody.http.assert_called_once()
            self.assertEqual(custody.http.call_args.args[1:3], ('POST', '/v1/start'))

    def test_cleanup_attempts_both_journals_even_if_first_fails(self):
        from unittest.mock import patch
        runner = object.__new__(protected.Run); runner.custody = Mock()
        with patch.object(protected.ha.Run, 'cleanup', side_effect=RuntimeError('HA cleanup pending')):
            with self.assertRaisesRegex(ValueError, 'cleanup incomplete'): runner.cleanup()
        runner.custody.cleanup.assert_called_once()


if __name__ == '__main__': unittest.main()
