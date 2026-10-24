from fastapi.testclient import TestClient
from tests.test_review import repo, session
from plutonium.review_server import create_review_app


def test_auth_revision_validation_approval(repo):
    with session(repo) as s:
        c = TestClient(create_review_app(s))
        assert c.get('/api/review').status_code == 401
        c.headers['Authorization'] = 'Bearer ' + s.token
        assert c.get('/api/review').json()['repository'] == repo.name
        assert c.post('/api/review/approve', json={'revision': 0}).status_code == 409
        assert c.put('/api/review', json={'revision': -1, 'path': 'app.py', 'content': 'x'}).status_code == 409
        assert c.post('/api/review/validate', json={'revision': 0}).json()['valid']
        assert c.post('/api/review/approve', json={'revision': 0}).json()['state'] == 'approved'
        assert c.post('/api/review/approve', json={'revision': 0}).status_code == 200


def test_cross_origin_and_file_escape_rejected(repo):
    with session(repo) as s:
        c = TestClient(create_review_app(s), headers={'Authorization': 'Bearer ' + s.token})
        assert c.post('/api/review/cancel', headers={'Origin': 'https://evil.example'}).status_code == 403
        assert c.get('/api/review/image', params={'path': '../secret'}).status_code == 404
        assert c.put('/api/review', json={'revision': 0, 'path': '../secret', 'content': 'x'}).status_code == 409
        assert c.post('/api/review/cancel').json()['state'] == 'cancelled'
