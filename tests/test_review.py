"""Review contract tests: real Git/index/files, deterministic scan provider."""
import subprocess
from pathlib import Path
import pytest
from barakagate.models import Finding, ScanResult
from barakagate.review_policy import ReviewPolicy
from barakagate.review import ReviewSession, ReviewError


def git(root, *args, input=None):
    return subprocess.run(['git', '-C', str(root), *args], input=input, capture_output=True, check=True).stdout


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, 'init', '-q')
    git(tmp_path, 'config', 'user.email', 'test@example.com')
    git(tmp_path, 'config', 'user.name', 'Review Test')
    (tmp_path / 'app.py').write_text('secret = "unsafe"\n' + '\n' * 10 + 'other = 1\n')
    git(tmp_path, 'add', '.')
    return tmp_path


def finding():
    return Finding(id='secret', target_type='text', category='security_leak', file_path='app.py', line_start=1,
                   rule_id='test.secret', severity='HIGH', confidence=1, title='Secret',
                   reason='A credential is exposed.', offending_snippet='"unsafe"',
                   replacement_snippet='"safe"', recommended_action='code_patch')


def scan(root, paths, policy):
    findings = [finding()] if '"unsafe"' in (root / 'app.py').read_text() else []
    return ScanResult(verdict='BLOCK' if findings else 'PASS', engine_used='test',
                      preset_used='all', summary='Test scan', findings=findings)


def session(repo, **kwargs):
    return ReviewSession(repo, scan_provider=scan, **kwargs)


def test_policy_precedence_and_invalid_settings():
    p = ReviewPolicy.from_raw({'block_on': ['HIGH'], 'review': {'dismissal': {
        'default': True, 'severity': {'HIGH': False}, 'category': {'security_leak': True},
        'rule': {'test.secret': False}}}})
    assert not p.can_dismiss(finding())
    assert ReviewPolicy.from_raw({'review': {'dismissal': {'default': True}}}).can_dismiss(finding())
    with pytest.raises(ValueError):
        ReviewPolicy.from_raw({'review': {'dismissal': {'default': 'yes'}}})


def test_snapshot_uses_index_and_cancel_is_read_only(repo):
    staged = git(repo, 'show', ':app.py')
    (repo / 'app.py').write_text('working changes\n')
    with session(repo) as s:
        assert s.files['app.py']['original'].encode() == staged
        assert s.findings
        s.cancel()
    assert git(repo, 'show', ':app.py') == staged
    assert (repo / 'app.py').read_text() == 'working changes\n'


def test_approve_preserves_unstaged_changes_and_commits_proposal(repo):
    original = (repo / 'app.py').read_text()
    (repo / 'app.py').write_text(original.replace('other = 1', 'other = 2'))
    with session(repo) as s:
        assert '"safe"' in s.files['app.py']['proposed']
        s.validate(s.revision)
        s.approve(s.revision)
        s.approve(s.revision)  # idempotent
    assert '"safe"' in git(repo, 'show', ':app.py').decode()
    assert 'other = 1' in git(repo, 'show', ':app.py').decode()
    assert 'other = 2' in (repo / 'app.py').read_text()
    git(repo, 'commit', '-qm', 'Reviewed')
    assert '"safe"' in git(repo, 'show', 'HEAD:app.py').decode()


def test_stale_index_and_conflicting_working_edits_rejected(repo):
    with session(repo) as s:
        s.validate(s.revision)
        (repo / 'app.py').write_text('concurrent edit\n')
        with pytest.raises(ReviewError):
            s.approve(s.revision)
    assert '"unsafe"' in git(repo, 'show', ':app.py').decode()


def test_enforced_dismissal_and_stale_validation(repo):
    with session(repo) as s:
        with pytest.raises(ReviewError):
            s.update(s.revision, decisions={'secret': 'dismiss'})
        s.validate(s.revision)
        s.update(s.revision, path='app.py', content='secret = "unsafe"\n')
        with pytest.raises(ReviewError):
            s.approve(s.revision)
        assert not s.validate(s.revision)['valid']


def test_personal_dismissal_is_bound_to_content(repo):
    p = ReviewPolicy.from_raw({'review': {'dismissal': {'default': True}}})
    with session(repo, policy=p) as s:
        s.update(s.revision, path='app.py', content=s.files['app.py']['original'])
        s.update(s.revision, decisions={'secret': 'dismiss'})
        assert s.validate(s.revision)['valid']
        s.update(s.revision, path='app.py', content='secret = "unsafe"\n# changed\n')
        assert s.decisions == {}


def test_noninteractive_review_never_applies(repo):
    from typer.testing import CliRunner
    from barakagate.cli import app
    (repo / 'app.py').write_text('cin = \"BE847291\"\n')
    git(repo, 'add', 'app.py')
    before = git(repo, 'show', ':app.py')
    r = CliRunner().invoke(app, ['review', '--root', str(repo), '--offline', '--non-interactive'])
    assert r.exit_code == 1, r.output
    assert git(repo, 'show', ':app.py') == before


def test_explicit_terminal_approval_and_cancel(repo, monkeypatch):
    from typer.testing import CliRunner
    from barakagate.cli import app
    import barakagate.review as review
    real = review.ReviewSession
    monkeypatch.setattr(review, 'ReviewSession', lambda root, **kw: real(root, scan_provider=scan, **kw))
    cancelled = CliRunner().invoke(app, ['review', '--root', str(repo), '--interactive'], input='c\n')
    assert cancelled.exit_code == 1, cancelled.output
    assert 'unsafe' in git(repo, 'show', ':app.py').decode()
    approved = CliRunner().invoke(app, ['review', '--root', str(repo), '--interactive'], input='a\n')
    assert approved.exit_code == 0, approved.output
    assert '"safe"' in git(repo, 'show', ':app.py').decode()


def test_new_policy_rules_have_stable_ids_and_validate():
    from barakagate.config import BarakaConfig, validate_yaml
    cfg = BarakaConfig({'presets': {'test': {'nl_rules': [{'id': 'org.auth', 'text': 'Require auth'}, 'Reject leaks']}}})
    assert '[org.auth]' in cfg.nl_rules('all')[0]
    assert cfg.nl_rules('all')[1].startswith('[nl.test.')
    with pytest.raises(ValueError):
        validate_yaml('presets: {}\nreview:\n  timeout_seconds: -1\n')


def test_ci_uses_trusted_policy_and_never_applies(repo):
    from barakagate.review_check import check_revision
    (repo / '.barakagate.yaml').write_text('presets: {}\nreview:\n  dismissal:\n    default: false\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'base')
    base = git(repo, 'rev-parse', 'HEAD').decode().strip()
    (repo / '.barakagate.yaml').write_text('presets: {}\nreview:\n  dismissal:\n    default: true\n')
    (repo / 'app.py').write_text('secret = "unsafe"\n# changed\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'proposal')
    report = check_revision(repo, base, 'HEAD', scan_provider=scan)
    assert not report['passed']
    assert report['findings'][0]['rule_id'] == 'test.secret'
    assert 'unsafe' in (repo / 'app.py').read_text()


def test_conflicting_partial_stage_is_not_overwritten(repo):
    (repo / 'app.py').write_text('secret = "different"\n')
    before = git(repo, 'show', ':app.py')
    with session(repo) as s:
        s.validate(s.revision)
        with pytest.raises(ReviewError, match='conflict'):
            s.approve(s.revision)
    assert git(repo, 'show', ':app.py') == before
    assert (repo / 'app.py').read_text() == 'secret = "different"\n'


def test_changed_index_rejects_approval(repo):
    with session(repo) as s:
        s.validate(s.revision)
        (repo / 'new.txt').write_text('unrelated')
        git(repo, 'add', 'new.txt')
        with pytest.raises(ReviewError, match='index changed'):
            s.approve(s.revision)


def test_image_regions_preserve_format_and_pixels(repo):
    import io
    from PIL import Image
    Image.new('RGB', (80, 80), 'white').save(repo / 'photo.jpg')
    git(repo, 'add', 'photo.jpg')
    with session(repo) as s:
        s.update(s.revision, path='photo.jpg', regions=[[250, 250, 500, 500]])
        img = Image.open(io.BytesIO(s.image_bytes('photo.jpg')))
        assert img.format == 'JPEG'
        assert max(img.getpixel((30, 30))) < 30
        assert min(img.getpixel((75, 75))) > 240
        with pytest.raises(ReviewError):
            s.update(s.revision, path='photo.jpg', regions=[[400, 400, 200, 200]])


def test_linked_worktree_and_alternate_index(repo, tmp_path):
    git(repo, 'commit', '-qm', 'base')
    work = tmp_path / 'linked'
    git(repo, 'worktree', 'add', '-qb', 'review-test', str(work))
    (work / 'app.py').write_text('secret = "unsafe"\n# staged\n')
    git(work, 'add', 'app.py')
    with session(work) as s:
        assert s.index != work / '.git' / 'index'
        s.validate(s.revision)
        s.approve(s.revision)
    assert '"safe"' in git(work, 'show', ':app.py').decode()


def test_rollback_restores_written_files(repo, monkeypatch):
    with session(repo) as s:
        s.validate(s.revision)
        before = (repo / 'app.py').read_bytes()
        index = s.index.read_bytes()
        import barakagate.review as module
        replace = module.os.replace
        def fail(src, dest):
            if Path(dest) == s.index:
                raise OSError('simulated index replacement failure')
            return replace(src, dest)
        monkeypatch.setattr(module.os, 'replace', fail)
        with pytest.raises(OSError):
            s.approve(s.revision)
        assert (repo / 'app.py').read_bytes() == before
        assert s.index.read_bytes() == index


def test_manual_edits_preserve_crlf(repo):
    (repo / 'app.py').write_bytes(b'secret = "unsafe"\r\nother = 1\r\n')
    git(repo, 'add', 'app.py')
    with session(repo) as s:
        assert '\r\n' in s.files['app.py']['proposed']


def test_invalid_edit_is_atomic(repo):
    with session(repo) as s:
        s.validate(s.revision)
        before = s.files['app.py']['proposed']
        with pytest.raises(ReviewError):
            s.update(s.revision, path='app.py', content='unvalidated', decisions={'secret': 'dismiss'})
        assert s.files['app.py']['proposed'] == before


def test_embedded_notebook_image_redaction_updates_notebook(repo):
    import base64, io, json
    from PIL import Image
    out = io.BytesIO(); Image.new('RGB', (40, 40), 'white').save(out, 'PNG')
    nb = {'nbformat': 4, 'cells': [{'cell_type':'code','source':['x = 1\n'], 'outputs':[
        {'output_type':'display_data','data':{'image/png':base64.b64encode(out.getvalue()).decode()}}]}]}
    (repo / 'demo.ipynb').write_text(json.dumps(nb))
    git(repo, 'add', 'demo.ipynb')
    with session(repo) as s:
        image_file = next(p for p, f in s.files.items() if f.get('parent') == 'demo.ipynb')
        s.update(s.revision, path=image_file, regions=[[100,100,700,700]])
        s.validate(s.revision)
        s.approve(s.revision)
    committed = json.loads(git(repo, 'show', ':demo.ipynb'))
    image = Image.open(io.BytesIO(base64.b64decode(committed['cells'][0]['outputs'][0]['data']['image/png'])))
    assert image.getpixel((15,15)) == (0,0,0)
    assert not (repo / image_file).exists()


@pytest.mark.parametrize('choice,committed', [('a', True), ('c', False), ('w', True)])
def test_real_commit_waits_for_terminal_decision(tmp_path, choice, committed):
    """The installed hook must release the ORIGINAL Git process, not run a second commit."""
    import os, pty, select, signal, sys, time, yaml
    from typer.testing import CliRunner
    from barakagate.cli import app
    git(tmp_path, 'init', '-q')
    git(tmp_path, 'config', 'user.email', 'test@example.com')
    git(tmp_path, 'config', 'user.name', 'Review Test')
    config = {'default_engine':'cloud_fast','default_preset':'all','review':{'offline':True,'open_browser':False},
              'presets':{'demo':{'regex_rules':[{'id':'demo.secret','category':'privacy_pii',
              'severity':'HIGH','title':'Sensitive value','pattern':'BE847291','action':'synthetic_twin'}]}}}
    (tmp_path / '.barakagate.yaml').write_text(yaml.safe_dump(config))
    (tmp_path / 'app.py').write_text('customer = "BE847291"\n')
    git(tmp_path, 'add', '.')
    assert CliRunner().invoke(app, ['install-hook','--root',str(tmp_path)]).exit_code == 0
    pid, fd = pty.fork()
    if pid == 0:
        os.environ['PATH'] = str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH']
        os.environ['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
        os.chdir(tmp_path)
        os.execlp('git','git','commit','-qm','Reviewed commit')
    output = b''; status = None; answered = False; web_approved = False
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if select.select([fd], [], [], .1)[0]:
                try:
                    chunk = os.read(fd, 8192)
                except OSError:
                    break
                output += chunk
                if b'Review in browser' in output and not answered:
                    os.write(fd, (choice+'\n').encode()); answered = True
                if choice == 'w' and not web_approved:
                    import re, httpx
                    match = re.search(rb'http://127.0.0.1:(\d+)/#token=([A-Za-z0-9_-]+)', output)
                    if match:
                        url = 'http://127.0.0.1:' + match[1].decode()
                        with httpx.Client(base_url=url, headers={'Authorization':'Bearer '+match[2].decode()}) as client:
                            # Listener is bound before startup is announced; retry until ready.
                            for _ in range(50):
                                try:
                                    current = client.get('/api/review').json()
                                    break
                                except httpx.TransportError:
                                    time.sleep(.05)
                            proposed = next(f['proposed'] for f in current['files'] if f['path'] == 'app.py')
                            edited = client.put('/api/review', json={'revision':current['revision'], 'path':'app.py', 'content':proposed+'# reviewed in browser\n'}).json()
                            assert client.post('/api/review/validate', json={'revision':edited['revision']}).json()['valid']
                            assert client.post('/api/review/approve', json={'revision':edited['revision']}).json()['state'] == 'approved'
                            web_approved = True
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                pid = None
                break
        if pid:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                pid = None
        assert answered, output.decode(errors='replace')
        assert pid is None, output.decode(errors='replace')
        assert os.waitstatus_to_exitcode(status) == (0 if committed else 1), output.decode(errors='replace')
        head = subprocess.run(['git','-C',str(tmp_path),'rev-parse','--verify','HEAD'],capture_output=True)
        assert (head.returncode == 0) == committed
        if committed:
            assert b'BE847291' not in git(tmp_path,'show','HEAD:app.py')
            if choice == 'w':
                assert web_approved
                assert b'# reviewed in browser' in git(tmp_path,'show','HEAD:app.py')
        else:
            assert (tmp_path/'app.py').read_text() == 'customer = "BE847291"\n'
            assert b'BE847291' in git(tmp_path,'show',':app.py')
    finally:
        os.close(fd)
        if pid:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid,0)
