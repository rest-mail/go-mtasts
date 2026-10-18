"""Offline fixtures for the caller of go-spf's reusable RFC verification workflow.

The proof itself (race coverage, checklist, fuzzing) runs in go-spf's pinned
workflow. These tests check what this repository passes it and that the
required Build & Test verdict fails closed. The workflow is read as text so the
job needs nothing beyond the runner's Python.

Set RFC_PRODUCER_WORKFLOW to a copy of rfc-verification.yml at the pinned
commit to also run the producer's own input validation on these inputs.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
CALLER = (ROOT / '.github/workflows/ci.yml').read_text()
PIN = '7d291c08d310b9c62afc287e75a534a39150fafb'
PRODUCER = 'rest-mail/go-spf/.github/workflows/rfc-verification.yml@' + PIN


def jobs():
    body = CALLER.split('\njobs:\n', 1)[1]
    return re.findall(r'^  ([A-Za-z0-9_-]+):\s*$', body, re.M)


def job(name):
    body = CALLER.split('\njobs:\n', 1)[1]
    return re.split(r'^  [A-Za-z0-9_-]+:\s*$', body, flags=re.M)[jobs().index(name) + 1]


def quoted_input(name):
    match = re.search(r"^      " + re.escape(name) + r": '([^']*)'\s*$", job('rfc'), re.M)
    return json.loads(match[1])


def folded_input(name):
    lines = job('rfc').splitlines()
    start = lines.index('      ' + name + ': >-')
    block = []
    for line in lines[start + 1:]:
        if not line.startswith('        '):
            break
        block.append(line.strip())
    return json.loads(' '.join(block))


def inputs():
    return {
        'RFC_PACKAGES': json.dumps(quoted_input('packages')),
        'RFC_CHECKLIST_DIRS': json.dumps(quoted_input('checklist-dirs')),
        'RFC_FUZZ_TARGETS': json.dumps(folded_input('fuzz-targets')),
    }


def repository_fuzz_targets():
    found = []
    for path in sorted(ROOT.rglob('*_test.go')):
        relative = path.relative_to(ROOT)
        if relative.parts[0].startswith('.') or 'testdata' in relative.parts:
            continue
        package = '.' if relative.parent == Path('.') else './' + relative.parent.as_posix()
        for target in re.findall(r'^func (Fuzz\w*)\(\w+ \*testing\.F\)', path.read_text(), re.M):
            found.append({'package': package, 'target': target})
    return found


class CallerFixtures(unittest.TestCase):
    def test_proof_is_the_pinned_go_spf_workflow(self):
        self.assertEqual(re.findall(r'^    uses: (\S+)\s*$', job('rfc'), re.M), [PRODUCER])
        workflows = [ref for ref in re.findall(r'uses:\s*(\S+)', CALLER) if '/.github/workflows/' in ref]
        self.assertEqual(workflows, [PRODUCER])
        self.assertNotIn('secrets:', CALLER)
        self.assertEqual(re.findall(r'^permissions:\n((?:  .*\n)+)', CALLER, re.M), ['  contents: read\n'])
        self.assertEqual(CALLER.count('permissions:'), 1)

    def test_events_are_unchanged(self):
        self.assertIn('on:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\n', CALLER)

    def test_packages_and_checklist_dirs(self):
        self.assertEqual(quoted_input('packages'), ['./...'])
        self.assertEqual(quoted_input('checklist-dirs'), ['.'])

    def test_fuzz_targets_are_exactly_the_repository_targets(self):
        targets = folded_input('fuzz-targets')
        self.assertEqual(targets, [{'package': '.', 'target': name} for name in
                                   ['FuzzParsePolicy', 'FuzzParseTXTRecord', 'FuzzMatchesMX']])
        key = lambda item: (item['package'], item['target'])
        self.assertEqual(sorted(targets, key=key), sorted(repository_fuzz_targets(), key=key))

    def test_required_context_needs_every_other_job(self):
        self.assertEqual(jobs(), ['rfc', 'fixtures', 'build'])
        build = job('build')
        self.assertIn('    name: Build & Test\n', build)
        self.assertIn('    needs: [rfc, fixtures]\n', build)
        self.assertIn('    if: ${{ always() }}\n', build)
        self.assertIn('RFC_RESULT: ${{ needs.rfc.result }}', build)
        self.assertIn('FIXTURE_RESULT: ${{ needs.fixtures.result }}', build)
        self.assertNotIn('continue-on-error', CALLER)

    def test_required_verdict_fails_closed(self):
        command = next(line.strip().removeprefix('run: ') for line in job('build').splitlines()
                       if line.strip().startswith('run: test '))
        outcomes = ['success', 'failure', 'cancelled', 'skipped', '', None]
        for rfc in outcomes:
            for fixtures in outcomes:
                env = {k: v for k, v in os.environ.items()
                       if k not in ('RFC_RESULT', 'FIXTURE_RESULT')}
                env.update({k: v for k, v in [('RFC_RESULT', rfc), ('FIXTURE_RESULT', fixtures)]
                            if v is not None})
                result = subprocess.run(['sh', '-c', command], env=env, check=False)
                with self.subTest(rfc=rfc, fixtures=fixtures):
                    self.assertEqual(result.returncode == 0, rfc == fixtures == 'success')


@unittest.skipUnless(os.environ.get('RFC_PRODUCER_WORKFLOW'), 'needs the pinned producer workflow')
class ProducerContractFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = Path(os.environ['RFC_PRODUCER_WORKFLOW']).read_text()
        cls.declared = re.findall(r'^      ([a-z-]+):\n        description:', text, re.M)
        source = textwrap.dedent(text.split('# BEGIN RFC PROOF\n', 1)[1]
                                 .split('          # END RFC PROOF', 1)[0])
        cls.proof = {'__name__': 'rfc_proof_fixture'}
        exec(compile(source, os.environ['RFC_PRODUCER_WORKFLOW'], 'exec'), cls.proof)

    def test_caller_passes_only_declared_inputs(self):
        passed = re.findall(r'^      ([a-z-]+):', job('rfc'), re.M)
        self.assertEqual(sorted(passed), sorted(self.declared))

    def test_producer_accepts_inputs_and_runs_every_proof(self):
        calls = []

        def go(*args, **kwargs):
            calls.append(args)
            if args[:2] == ('test', '-list=^Fuzz'):
                return '\n'.join(item['target'] for item in repository_fuzz_targets()) + '\n'
            if args[:2] == ('tool', 'cover'):
                return 'total: (statements) 100.0%\n'

        with patch.dict(self.proof, go=go), contextlib.redirect_stdout(io.StringIO()):
            self.proof['verify'](inputs())
        names = ['FuzzParsePolicy', 'FuzzParseTXTRecord', 'FuzzMatchesMX']
        self.assertEqual(calls, [
            *[('test', '-list=^Fuzz', '.')] * 3,
            ('test', '-race', '-count=1', '-covermode=atomic', '-coverprofile=coverage.out', './...'),
            ('tool', 'cover', '-func=coverage.out'),
            ('run', './internal/checklist', '-file', 'CHECKLIST.md', '.'),
            *[('test', '-run=^$', f'-fuzz=^{name}$', '-fuzztime=30s', '.') for name in names],
        ])


if __name__ == '__main__':
    unittest.main()
