import json
import unittest
from unittest.mock import MagicMock, patch, call

import common.vars as common_vars
from common.graylog import graylog_handle
from common.stream_sharing import get_stream_id, get_streams, share_stream
from config.graylog import GraylogConfig


def _make_graylog_config(**overrides):
    """Create a GraylogConfig with sensible test defaults."""
    defaults = dict(
        host='http://localhost:9000',
        ca_cert_path='',
        cert_path='',
        key_path='',
        insecure_skip_verify='false',
        admin_user='admin',
        pre_created_users='admin',
        role_mapping='',
        stream_mapping='',
        requests_timeout=5,
    )
    defaults.update(overrides)
    return GraylogConfig(**defaults)


def _mock_templates_env():
    """Create a mock TEMPLATES_ENV that returns templates producing valid JSON."""
    mock_env = MagicMock()

    # new-graylog-user template
    new_user_tpl = MagicMock()
    new_user_tpl.render.side_effect = lambda **kw: json.dumps({
        'username': kw['username'],
        'password': kw['password'],
        'email': f"{kw['username']}@test.org",
        'first_name': kw['username'],
        'last_name': kw['username'],
        'permissions': [],
        'roles': kw['roles'],
        'session_timeout_ms': 3600000,
    })

    # update-graylog-user template
    update_user_tpl = MagicMock()
    update_user_tpl.render.side_effect = lambda **kw: json.dumps({
        'email': f"{kw['username']}@test.org",
        'first_name': kw['username'],
        'last_name': kw['username'],
        'permissions': [],
        'roles': kw['roles'],
        'session_timeout_ms': 3600000,
    })

    # share-stream template
    share_stream_tpl = MagicMock()
    share_stream_tpl.render.side_effect = lambda **kw: json.dumps({
        'selected_grantee_capabilities': {f"grn::::user:{kw['user_id']}": kw['capability']}
    })

    def get_template(name):
        templates = {
            'new-graylog-user.json.j2': new_user_tpl,
            'update-graylog-user.json.j2': update_user_tpl,
            'share-stream.json.j2': share_stream_tpl,
        }
        return templates[name]

    mock_env.get_template.side_effect = get_template
    return mock_env


class TestGraylogConfig(unittest.TestCase):
    """Tests for GraylogConfig URL helpers and config validation."""

    def setUp(self):
        self.cfg = _make_graylog_config()

    def test_url_get_users_list(self):
        self.assertEqual(self.cfg.url_get_users_list(), 'http://localhost:9000/api/users/')

    def test_url_get_user_by_name(self):
        url = self.cfg.url_get_user_by_name('testuser')
        self.assertIn('testuser', url)
        self.assertIn('/api/users/', url)

    def test_url_get_streams(self):
        self.assertEqual(self.cfg.url_get_streams(), 'http://localhost:9000/api/streams/')

    def test_url_stream_share(self):
        url = self.cfg.url_stream_share('stream123')
        self.assertIn('stream123', url)
        self.assertIn('/api/authz/shares/entities/', url)

    def test_verify_config_valid(self):
        self.assertTrue(self.cfg.verify_config())

    def test_verify_config_empty_host(self):
        cfg = _make_graylog_config(host='')
        self.assertFalse(cfg.verify_config())

    def test_verify_config_bad_scheme(self):
        cfg = _make_graylog_config(host='ftp://localhost:9000')
        self.assertFalse(cfg.verify_config())

    def test_verify_config_empty_admin_user(self):
        cfg = _make_graylog_config(admin_user='')
        self.assertFalse(cfg.verify_config())

    def test_insecure_skip_verify_sets_verify_false(self):
        cfg = _make_graylog_config(insecure_skip_verify='true')
        self.assertFalse(cfg.verify)


class TestGraylogHandleNewUser(unittest.TestCase):
    """Tests for graylog_handle when the user does not exist yet (404 → create)."""

    def setUp(self):
        self.cfg = _make_graylog_config(
            role_mapping="'*':['Reader']",
            stream_mapping='',
        )

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_creates_user_on_404(self, mock_requests, mock_stream_sharing):
        # First GET → 404 (user not found)
        resp_get_404 = MagicMock(status_code=404)
        # POST → 201 (user created)
        resp_post_201 = MagicMock(status_code=201)
        # Second GET to fetch user_id after creation
        resp_get_200 = MagicMock(status_code=200, content=json.dumps({'id': 'uid123'}).encode())
        mock_requests.get.side_effect = [resp_get_404, resp_get_200]
        mock_requests.post.return_value = resp_post_201
        mock_stream_sharing.get_streams.return_value = {'streams': []}

        graylog_handle(self.cfg, ['some-group'], 'newuser')

        # Should have called POST to create user
        mock_requests.post.assert_called_once()
        post_args = mock_requests.post.call_args
        self.assertIn('/api/users/', post_args[0][0])

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_create_user_failure_returns_early(self, mock_requests, mock_stream_sharing):
        resp_get_404 = MagicMock(status_code=404)
        resp_post_500 = MagicMock(status_code=500)
        mock_requests.get.return_value = resp_get_404
        mock_requests.post.return_value = resp_post_500

        graylog_handle(self.cfg, ['some-group'], 'newuser')

        # Should not attempt to get streams after creation failure
        mock_stream_sharing.get_streams.assert_not_called()


class TestGraylogHandleExistingUser(unittest.TestCase):
    """Tests for graylog_handle when the user already exists (200 → update)."""

    def setUp(self):
        self.cfg = _make_graylog_config(
            role_mapping="'*':['Admin']",
        )

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_updates_existing_user(self, mock_requests, mock_stream_sharing):
        user_data = json.dumps({'id': 'uid456'}).encode()
        resp_get_200 = MagicMock(status_code=200, content=user_data)
        resp_put_204 = MagicMock(status_code=204)
        mock_requests.get.return_value = resp_get_200
        mock_requests.put.return_value = resp_put_204
        mock_stream_sharing.get_streams.return_value = {'streams': []}

        graylog_handle(self.cfg, ['some-group'], 'existinguser')

        mock_requests.put.assert_called_once()
        put_args = mock_requests.put.call_args
        # The update URL should include the user_id
        self.assertIn('uid456', put_args[0][0])

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_update_failure_returns_early(self, mock_requests, mock_stream_sharing):
        user_data = json.dumps({'id': 'uid456'}).encode()
        resp_get_200 = MagicMock(status_code=200, content=user_data)
        resp_put_500 = MagicMock(status_code=500)
        mock_requests.get.return_value = resp_get_200
        mock_requests.put.return_value = resp_put_500

        graylog_handle(self.cfg, ['some-group'], 'existinguser')

        mock_stream_sharing.get_streams.assert_not_called()

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_empty_content_returns_early(self, mock_requests, mock_stream_sharing):
        resp_get_200 = MagicMock(status_code=200, content=b'')
        mock_requests.get.return_value = resp_get_200

        graylog_handle(self.cfg, ['some-group'], 'existinguser')

        mock_requests.put.assert_not_called()
        mock_stream_sharing.get_streams.assert_not_called()


class TestGraylogHandleApiError(unittest.TestCase):
    """Tests for graylog_handle when Graylog API returns unexpected status."""

    def setUp(self):
        self.cfg = _make_graylog_config()

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_unexpected_status_returns_early(self, mock_requests, mock_stream_sharing):
        resp_get_503 = MagicMock(status_code=503)
        mock_requests.get.return_value = resp_get_503

        graylog_handle(self.cfg, [], 'testuser')

        mock_requests.post.assert_not_called()
        mock_requests.put.assert_not_called()
        mock_stream_sharing.get_streams.assert_not_called()


class TestGraylogHandleRoleMapping(unittest.TestCase):
    """Tests for role and stream mapping logic within graylog_handle."""

    def setUp(self):
        self.cfg = _make_graylog_config()

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_empty_member_of_uses_default_roles(self, mock_requests, mock_stream_sharing):
        resp_get_404 = MagicMock(status_code=404)
        resp_post_201 = MagicMock(status_code=201)
        resp_get_200 = MagicMock(status_code=200, content=json.dumps({'id': 'uid1'}).encode())
        mock_requests.get.side_effect = [resp_get_404, resp_get_200]
        mock_requests.post.return_value = resp_post_201
        mock_stream_sharing.get_streams.return_value = {'streams': []}

        graylog_handle(self.cfg, [], 'testuser')

        # User should be created with default roles
        mock_requests.post.assert_called_once()
        post_json = mock_requests.post.call_args[1].get('json', {})
        self.assertEqual(post_json.get('roles'), common_vars.DEFAULT_ROLES)

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_bytes_member_of_decoded(self, mock_requests, mock_stream_sharing):
        """Verify that bytes-type memberOf entries are decoded to str."""
        self.cfg = _make_graylog_config(role_mapping="'*':['Reader']")
        resp_get_404 = MagicMock(status_code=404)
        resp_post_201 = MagicMock(status_code=201)
        resp_get_200 = MagicMock(status_code=200, content=json.dumps({'id': 'uid2'}).encode())
        mock_requests.get.side_effect = [resp_get_404, resp_get_200]
        mock_requests.post.return_value = resp_post_201
        mock_stream_sharing.get_streams.return_value = {'streams': []}

        # Pass bytes instead of str
        graylog_handle(self.cfg, [b'CN=admins,OU=Groups'], 'testuser')

        mock_requests.post.assert_called_once()


class TestGraylogHandleStreamSharing(unittest.TestCase):
    """Tests for stream sharing logic in graylog_handle."""

    def setUp(self):
        self.cfg = _make_graylog_config(
            role_mapping="'*':['Reader']",
            stream_mapping="'*':['Default Stream/view']",
        )

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_streams_shared_after_user_creation(self, mock_requests, mock_stream_sharing):
        resp_get_404 = MagicMock(status_code=404)
        resp_post_201 = MagicMock(status_code=201)
        resp_get_200 = MagicMock(status_code=200, content=json.dumps({'id': 'uid789'}).encode())
        mock_requests.get.side_effect = [resp_get_404, resp_get_200]
        mock_requests.post.return_value = resp_post_201

        mock_stream_sharing.get_streams.return_value = {
            'streams': [{'title': 'Default Stream', 'id': 'stream-id-1'}]
        }
        mock_stream_sharing.get_stream_id.return_value = 'stream-id-1'

        graylog_handle(self.cfg, ['some-group'], 'newuser')

        mock_stream_sharing.share_stream.assert_called_once_with(
            self.cfg, 'stream-id-1', 'uid789', 'view'
        )

    @patch('common.graylog.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.graylog.stream_sharing')
    @patch('common.graylog.requests')
    def test_existing_user_streams_shared_with_known_id(self, mock_requests, mock_stream_sharing):
        """When user already exists, user_id is known - no extra GET needed."""
        user_data = json.dumps({'id': 'uid-existing'}).encode()
        resp_get_200 = MagicMock(status_code=200, content=user_data)
        resp_put_204 = MagicMock(status_code=204)
        mock_requests.get.return_value = resp_get_200
        mock_requests.put.return_value = resp_put_204

        mock_stream_sharing.get_streams.return_value = {
            'streams': [{'title': 'Default Stream', 'id': 'stream-id-2'}]
        }
        mock_stream_sharing.get_stream_id.return_value = 'stream-id-2'

        graylog_handle(self.cfg, ['some-group'], 'existinguser')

        mock_stream_sharing.share_stream.assert_called_once_with(
            self.cfg, 'stream-id-2', 'uid-existing', 'view'
        )
        # GET should only be called once (for the initial user check)
        self.assertEqual(mock_requests.get.call_count, 1)


class TestStreamSharing(unittest.TestCase):
    """Tests for stream_sharing module functions."""

    def test_get_stream_id_found(self):
        streams = {'streams': [
            {'title': 'Default Stream', 'id': 'id-1'},
            {'title': 'Audit Stream', 'id': 'id-2'},
        ]}
        self.assertEqual(get_stream_id(streams, 'Default Stream'), 'id-1')
        self.assertEqual(get_stream_id(streams, 'Audit Stream'), 'id-2')

    def test_get_stream_id_case_insensitive(self):
        streams = {'streams': [{'title': 'Default Stream', 'id': 'id-1'}]}
        self.assertEqual(get_stream_id(streams, 'default stream'), 'id-1')

    def test_get_stream_id_not_found(self):
        streams = {'streams': [{'title': 'Default Stream', 'id': 'id-1'}]}
        self.assertIsNone(get_stream_id(streams, 'Nonexistent'))

    def test_get_stream_id_empty_streams(self):
        self.assertIsNone(get_stream_id({}, 'Default Stream'))
        self.assertIsNone(get_stream_id({'streams': []}, 'Default Stream'))

    @patch('common.stream_sharing.requests')
    def test_get_streams_success(self, mock_requests):
        cfg = _make_graylog_config()
        mock_resp = MagicMock(status_code=200, text='{"streams": []}')
        mock_requests.get.return_value = mock_resp

        result = get_streams(cfg)
        self.assertEqual(result, {'streams': []})

    @patch('common.stream_sharing.requests')
    def test_get_streams_failure(self, mock_requests):
        cfg = _make_graylog_config()
        mock_resp = MagicMock(status_code=500)
        mock_requests.get.return_value = mock_resp

        result = get_streams(cfg)
        self.assertEqual(result, {})

    @patch('common.stream_sharing.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.stream_sharing.requests')
    def test_share_stream_success(self, mock_requests):
        cfg = _make_graylog_config()
        mock_resp = MagicMock(status_code=200)
        mock_requests.post.return_value = mock_resp

        share_stream(cfg, 'stream-1', 'user-1', 'view')

        mock_requests.post.assert_called_once()
        post_url = mock_requests.post.call_args[0][0]
        self.assertIn('stream-1', post_url)

    @patch('common.stream_sharing.common_vars.TEMPLATES_ENV', _mock_templates_env())
    @patch('common.stream_sharing.requests')
    def test_share_stream_failure_logs_error(self, mock_requests):
        cfg = _make_graylog_config()
        mock_resp = MagicMock(status_code=403)
        mock_requests.post.return_value = mock_resp

        # Should not raise, just log error
        share_stream(cfg, 'stream-1', 'user-1', 'view')


class TestRoleMapping(unittest.TestCase):
    """Tests for the mapping module."""

    def test_wildcard_role_mapping(self):
        from common.mapping import role_mapping
        roles, priority = role_mapping("'*':['Reader']", 'CN=users,OU=Groups')
        self.assertEqual(roles, ['Reader'])
        self.assertEqual(priority, 0)

    def test_no_match_role_mapping(self):
        from common.mapping import role_mapping
        roles, priority = role_mapping("'CN=admins*':['Admin']", 'CN=users,OU=Groups')
        self.assertEqual(roles, [])

    def test_multi_group_role_mapping(self):
        from common.mapping import role_mapping
        mapping_str = "'CN=admins*':['Admin'] | 'CN=users*':['Reader']"
        roles, priority = role_mapping(mapping_str, 'CN=users,OU=Groups')
        self.assertEqual(roles, ['Reader'])
        self.assertEqual(priority, 1)

    def test_stream_mapping_with_capability(self):
        from common.mapping import stream_mapping
        streams, priority = stream_mapping("'*':['Default Stream/view']", 'CN=users')
        self.assertEqual(streams, [('Default Stream', 'view')])

    def test_stream_mapping_default_capability(self):
        from common.mapping import stream_mapping
        streams, priority = stream_mapping("'*':['Default Stream']", 'CN=users')
        self.assertEqual(streams, [('Default Stream', 'view')])


if __name__ == '__main__':
    unittest.main()
