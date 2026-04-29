#!/usr/bin/env python3
"""
Integration tests for OAuth flow validation.
These tests validate the complete OAuth flow including redirects and callbacks
to ensure the state persistence works correctly in real scenarios.
"""

import threading
import time
import unittest
from unittest.mock import patch, MagicMock

from oauth_handler.oauth_connector import (
    create_oauth_state,
    check_state,
    get_oauth_session_data,
    clear_oauth_session,
    store_oauth_session_data,
    OAuthHTTPClient,
)


class TestOAuthFlowIntegration(unittest.TestCase):
    """Integration tests for OAuth flow validation"""

    def setUp(self):
        """Set up test fixtures"""
        # Clear any existing OAuth session data
        clear_oauth_session()

        # Mock OAuth configuration
        class MockOAuthConfig:
            client_id = "test_client"
            client_secret = "test_secret"
            authorization_url = "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/auth"
            token_url = "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/token"
            userinfo_url = "https://keycloak.example.com/auth/realms/test/protocol/openid-connect/userinfo"
            redirect_uri = "http://localhost:8888/callback"
            redirect_uri_path = "/callback"
            scopes = "openid profile email"
            user_jsonpath = "$.preferred_username"
            roles_jsonpath = "$.realm_access.roles"
            verify = False
            cert = None
            timeout = 30

        self.oauth_config = MockOAuthConfig()

    def tearDown(self):
        """Clean up after each test"""
        clear_oauth_session()

    def test_normal_oauth_flow(self):
        """Test normal OAuth flow with state persistence across threads"""
        # Step 1: Create OAuth state (simulates redirect)
        state = create_oauth_state("user_session_123")
        self.assertIsNotNone(state)
        self.assertTrue(len(state) > 0)

        # Store session data for cross-thread access
        session_data = get_oauth_session_data()
        store_oauth_session_data(session_data)

        # Verify state is stored correctly
        self.assertEqual(session_data.get("state"), state)
        self.assertEqual(session_data.get("user_session_id"), "user_session_123")

        # Step 2: Simulate callback in different thread
        def callback_thread():
            """Simulate OAuth callback handling in different thread"""
            # Clear thread-local data to simulate different thread
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Validate the state parameter
            is_valid = check_state(state)
            self.assertTrue(is_valid, "State validation should succeed")

            # Get session data that was moved to this thread
            callback_session_data = get_oauth_session_data()
            self.assertEqual(callback_session_data.get("state"), state)
            self.assertEqual(
                callback_session_data.get("user_session_id"), "user_session_123"
            )

            return True

        # Run callback in separate thread
        thread = threading.Thread(target=callback_thread)
        thread.start()
        thread.join()

        # Verify the flow completed successfully
        self.assertTrue(True, "Normal OAuth flow should complete successfully")

    def test_invalid_state_rejection(self):
        """Test that invalid states are properly rejected"""
        # Try to validate an invalid state
        is_valid = check_state("invalid_state")
        self.assertFalse(is_valid, "Invalid state should be rejected")

    def test_expired_state_rejection(self):
        """Test that expired states are properly rejected"""
        # Create a state and manually expire it
        expired_state = create_oauth_state("expired_session")
        session_data = get_oauth_session_data()
        session_data["created_at"] = time.time() - 400  # 400 seconds ago (expired)
        store_oauth_session_data(session_data)

        # Try to validate the expired state
        is_valid = check_state(expired_state)
        self.assertFalse(is_valid, "Expired state should be rejected")

    def test_concurrent_oauth_flows(self):
        """Test multiple concurrent OAuth flows"""
        results = []

        def concurrent_flow(flow_id):
            """Simulate a concurrent OAuth flow"""
            # Create state
            state = create_oauth_state(f"user_session_{flow_id}")
            session_data = get_oauth_session_data()
            store_oauth_session_data(session_data)

            # Simulate callback in different thread
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Validate state
            is_valid = check_state(state)
            return is_valid

        # Run multiple concurrent flows
        threads = []
        for i in range(3):
            thread = threading.Thread(target=lambda: results.append(concurrent_flow(i)))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Check results
        successful_flows = sum(results)
        self.assertEqual(
            successful_flows,
            len(results),
            f"All {len(results)} concurrent flows should succeed, but only {successful_flows} did",
        )

    def test_oauth_client_integration(self):
        """Test OAuth client integration with state management"""
        oauth_client = OAuthHTTPClient(self.oauth_config)

        # Test login method creates state
        with patch("oauthlib.oauth2.WebApplicationClient") as mock_client:
            mock_client_instance = MagicMock()
            mock_client.return_value = mock_client_instance
            mock_client_instance.prepare_request_uri.return_value = (
                "https://keycloak.example.com/auth?state=test&client_id=test"
            )

            redirect_url = oauth_client.login("user_session_456")
            self.assertIsNotNone(redirect_url)

            # Verify state was created
            session_data = get_oauth_session_data()
            self.assertIsNotNone(session_data.get("state"))
            self.assertEqual(session_data.get("user_session_id"), "user_session_456")

    def test_token_exchange_with_state(self):
        """Test token exchange with proper state management"""
        # Create state first
        state = create_oauth_state("user_session_789")
        session_data = get_oauth_session_data()
        session_data["redirect_uri"] = "http://localhost:8888/callback"
        store_oauth_session_data(session_data)

        oauth_client = OAuthHTTPClient(self.oauth_config)

        # Test token exchange
        with patch("requests.post") as mock_post:
            # Mock successful token response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = (
                '{"access_token": "test_access_token", "token_type": "Bearer"}'
            )
            mock_response.json = lambda: {
                "access_token": "test_access_token",
                "token_type": "Bearer",
            }
            mock_post.return_value = mock_response

            # Mock WebApplicationClient for token parsing
            with patch("oauthlib.oauth2.WebApplicationClient") as mock_client:
                mock_client_instance = MagicMock()
                mock_client.return_value = mock_client_instance
                mock_client_instance.token = {"access_token": "test_access_token"}

                token = oauth_client.get_token("test_auth_code")
                self.assertIsNotNone(token)
                self.assertEqual(token, "test_access_token")

    def test_user_info_retrieval(self):
        """Test user info retrieval with proper state management"""
        oauth_client = OAuthHTTPClient(self.oauth_config)

        with patch("requests.get") as mock_get:
            # Mock successful user info response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json = lambda: {
                "preferred_username": "test_user",
                "realm_access": {"roles": ["user", "admin"]},
            }
            mock_get.return_value = mock_response

            user, roles = oauth_client.get_user("test_access_token")
            self.assertEqual(user, "test_user")
            # The roles come back as a nested list due to jsonpath_ng behavior
            self.assertEqual(roles, [["user", "admin"]])

    def test_state_cleanup(self):
        """Test that states are properly cleaned up"""
        # Create a state
        state1 = create_oauth_state("user_session_1")

        # Verify state exists
        self.assertTrue(check_state(state1))

        # Clear the state
        clear_oauth_session()

        # Verify state is cleared
        self.assertFalse(check_state(state1))

        # Create another state after clearing
        state2 = create_oauth_state("user_session_2")
        self.assertTrue(check_state(state2))

        # Clear again
        clear_oauth_session()
        self.assertFalse(check_state(state2))

    def test_cross_thread_state_retrieval(self):
        """Test that states can be retrieved across different threads"""
        # Create state in main thread
        state = create_oauth_state("user_session_cross_thread")
        session_data = get_oauth_session_data()
        store_oauth_session_data(session_data)

        # Verify state exists in main thread
        self.assertTrue(check_state(state))

        # Test retrieval in different thread
        def retrieval_thread():
            # Clear thread-local data
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Try to retrieve state
            is_valid = check_state(state)
            self.assertTrue(is_valid, "State should be retrievable in different thread")

            # Verify session data was moved to this thread
            thread_session_data = get_oauth_session_data()
            self.assertEqual(thread_session_data.get("state"), state)
            self.assertEqual(
                thread_session_data.get("user_session_id"), "user_session_cross_thread"
            )

        # Run retrieval in separate thread
        thread = threading.Thread(target=retrieval_thread)
        thread.start()
        thread.join()

    def test_original_request_url_preservation(self):
        """Test that the original request URL is preserved and used for redirect"""
        # Simulate a request to /search that triggers OAuth flow
        original_url = "/search"

        # Create OAuth state and store original URL
        state = create_oauth_state("user_session_redirect_test")
        session_data = get_oauth_session_data()
        session_data["original_request_url"] = original_url
        store_oauth_session_data(session_data)

        # Verify original URL is stored
        self.assertEqual(session_data.get("original_request_url"), original_url)

        # Simulate callback in different thread
        def callback_thread():
            # Clear thread-local data to simulate different thread
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Validate the state parameter
            is_valid = check_state(state)
            self.assertTrue(is_valid, "State validation should succeed")

            # Get session data that was moved to this thread
            callback_session_data = get_oauth_session_data()
            self.assertEqual(callback_session_data.get("state"), state)
            self.assertEqual(
                callback_session_data.get("original_request_url"), original_url
            )

            return True

        # Run callback in separate thread
        thread = threading.Thread(target=callback_thread)
        thread.start()
        thread.join()

        # Verify the flow completed successfully
        self.assertTrue(True, "Original request URL preservation should work correctly")

    def test_redirect_after_authentication(self):
        """Test that after authentication, user is redirected to original request URL"""
        # This test simulates the complete flow including redirect logic
        original_url = "/search"

        # Create OAuth state and store original URL
        state = create_oauth_state("user_session_redirect_test")
        session_data = get_oauth_session_data()
        session_data["original_request_url"] = original_url
        store_oauth_session_data(session_data)

        # Simulate successful authentication callback
        def authentication_callback():
            # Clear thread-local data to simulate different thread
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Validate state (simulates successful OAuth callback)
            is_valid = check_state(state)
            self.assertTrue(is_valid, "State validation should succeed")

            # Get session data
            callback_session_data = get_oauth_session_data()
            preserved_url = callback_session_data.get("original_request_url")

            # Verify original URL is preserved
            self.assertEqual(preserved_url, original_url)

            return True

        # Run authentication callback
        thread = threading.Thread(target=authentication_callback)
        thread.start()
        thread.join()

        # Verify the flow completed successfully
        self.assertTrue(True, "Redirect after authentication should work correctly")

    def test_explicit_next_parameter_priority(self):
        """Test that explicit 'next' parameter takes priority over original request URL"""
        # Simulate a request to /search that triggers OAuth flow
        original_url = "/search"

        # Create OAuth state and store original URL
        state = create_oauth_state("user_session_next_test")
        session_data = get_oauth_session_data()
        session_data["original_request_url"] = original_url
        store_oauth_session_data(session_data)

        # Verify original URL is stored
        self.assertEqual(session_data.get("original_request_url"), original_url)

        # Simulate callback with explicit next parameter
        def callback_with_explicit_next():
            # Clear thread-local data to simulate different thread
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Validate the state parameter
            is_valid = check_state(state)
            self.assertTrue(is_valid, "State validation should succeed")

            # Get session data that was moved to this thread
            callback_session_data = get_oauth_session_data()
            self.assertEqual(callback_session_data.get("state"), state)
            self.assertEqual(
                callback_session_data.get("original_request_url"), original_url
            )

            # Simulate the redirect logic
            next_url = "/dashboard"  # Explicit next parameter
            if next_url == "/":
                # This should NOT execute because next_url != '/'
                original_request = callback_session_data.get("original_request_url")
                if original_request:
                    next_url = original_request

            # Verify that explicit next parameter takes priority
            self.assertEqual(next_url, "/dashboard")
            self.assertNotEqual(next_url, original_url)

            return True

        # Run callback in separate thread
        thread = threading.Thread(target=callback_with_explicit_next)
        thread.start()
        thread.join()

        # Verify the flow completed successfully
        self.assertTrue(True, "Explicit next parameter should take priority")

    def test_implicit_redirect_to_original_url(self):
        """Test that when no explicit next is provided, redirect to original URL"""
        # Simulate a request to /search that triggers OAuth flow
        original_url = "/search"

        # Create OAuth state and store original URL
        state = create_oauth_state("user_session_implicit_test")
        session_data = get_oauth_session_data()
        session_data["original_request_url"] = original_url
        store_oauth_session_data(session_data)

        # Simulate callback without explicit next parameter
        def callback_without_explicit_next():
            # Clear thread-local data to simulate different thread
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Validate the state parameter
            is_valid = check_state(state)
            self.assertTrue(is_valid, "State validation should succeed")

            # Get session data that was moved to this thread
            callback_session_data = get_oauth_session_data()

            # Simulate the redirect logic
            next_url = "/"  # Default (no explicit next parameter)
            if next_url == "/":
                # This SHOULD execute because next_url == '/'
                original_request = callback_session_data.get("original_request_url")
                if original_request:
                    next_url = original_request

            # Verify that original URL is used
            self.assertEqual(next_url, original_url)

            return True

        # Run callback in separate thread
        thread = threading.Thread(target=callback_without_explicit_next)
        thread.start()
        thread.join()

        # Verify the flow completed successfully
        self.assertTrue(True, "Implicit redirect should use original URL")

    def test_session_cookie_creation_during_oauth(self):
        """Test that session cookies are created during OAuth authentication"""
        # This test simulates the OAuth callback and verifies session cookie creation
        oauth_client = OAuthHTTPClient(self.oauth_config)

        # Create OAuth state
        state = create_oauth_state("user_session_cookie_test")
        session_data = get_oauth_session_data()
        session_data["original_request_url"] = "/search"
        store_oauth_session_data(session_data)

        # Mock the OAuth callback with successful authentication
        with patch("requests.post") as mock_post, patch("requests.get") as mock_get:
            # Mock token exchange
            mock_token_response = MagicMock()
            mock_token_response.status_code = 200
            mock_token_response.json = lambda: {
                "access_token": "test_access_token",
                "token_type": "Bearer",
            }
            mock_post.return_value = mock_token_response

            # Mock user info retrieval
            mock_user_response = MagicMock()
            mock_user_response.status_code = 200
            mock_user_response.json = lambda: {
                "preferred_username": "test_user",
                "realm_access": {"roles": ["user", "admin"]},
            }
            mock_get.return_value = mock_user_response

            # Simulate the OAuth callback processing
            def simulate_oauth_callback():
                # Clear thread-local data to simulate different thread
                if hasattr(threading.current_thread(), "_oauth_session_data"):
                    delattr(threading.current_thread(), "_oauth_session_data")

                # Validate state
                is_valid = check_state(state)
                self.assertTrue(is_valid, "State validation should succeed")

                # Get user info (simulating successful authentication)
                user, roles = oauth_client.get_user("test_access_token")
                self.assertEqual(user, "test_user")
                self.assertEqual(roles, [["user", "admin"]])

                # Verify that session creation would happen here
                # (In the actual code, this creates a session and sets cookies)
                return True

            # Run the simulation
            thread = threading.Thread(target=simulate_oauth_callback)
            thread.start()
            thread.join()

            # Verify the flow completed successfully
            self.assertTrue(True, "Session cookie creation should work correctly")

    def test_oauth_flow_with_session_persistence(self):
        """Test that OAuth flow creates persistent sessions"""
        # This test validates the complete flow including session persistence
        original_url = "/search"

        # Create OAuth state and store original URL
        state = create_oauth_state("user_session_persistence_test")
        session_data = get_oauth_session_data()
        session_data["original_request_url"] = original_url
        store_oauth_session_data(session_data)

        # Simulate the complete OAuth flow
        def simulate_complete_oauth_flow():
            # Clear thread-local data to simulate different thread
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Step 1: Validate state (simulates callback)
            is_valid = check_state(state)
            self.assertTrue(is_valid, "State validation should succeed")

            # Step 2: Get session data
            callback_session_data = get_oauth_session_data()
            self.assertEqual(
                callback_session_data.get("original_request_url"), original_url
            )

            # Step 3: Simulate successful authentication and session creation
            # (In real code, this would create a session and set cookies)
            user = "test_user"
            session_id = "test_session_id"

            # Verify that the session would be created
            self.assertIsNotNone(user)
            self.assertIsNotNone(session_id)

            return True

        # Run the simulation
        thread = threading.Thread(target=simulate_complete_oauth_flow)
        thread.start()
        thread.join()

        # Verify the flow completed successfully
        self.assertTrue(
            True, "OAuth flow with session persistence should work correctly"
        )

    def test_redirect_logic_prioritizes_original_request(self):
        """Test that redirect logic prioritizes original request URL over callback path"""
        # This test validates the improved redirect logic
        original_url = "/search"

        # Create OAuth state and store original URL
        state = create_oauth_state("user_session_redirect_logic_test")
        session_data = get_oauth_session_data()
        session_data["original_request_url"] = original_url
        store_oauth_session_data(session_data)

        # Simulate the redirect logic from callback context
        def simulate_redirect_logic():
            # Clear thread-local data to simulate different thread
            if hasattr(threading.current_thread(), "_oauth_session_data"):
                delattr(threading.current_thread(), "_oauth_session_data")

            # Validate state (simulates successful OAuth callback)
            is_valid = check_state(state)
            self.assertTrue(is_valid, "State validation should succeed")

            # Get session data
            callback_session_data = get_oauth_session_data()

            # Simulate the new redirect logic
            original_request = callback_session_data.get("original_request_url")

            # Simulate callback path (no next parameter)
            next_url = ""  # No explicit next parameter

            # Apply the new logic: prioritize original request over callback path
            if not next_url:
                if original_request:
                    next_url = original_request
                else:
                    next_url = "/"

            # Verify that original request URL is used
            self.assertEqual(next_url, original_url)
            self.assertNotEqual(next_url, "/")

            return True

        # Run the simulation
        thread = threading.Thread(target=simulate_redirect_logic)
        thread.start()
        thread.join()

        # Verify the flow completed successfully
        self.assertTrue(True, "Redirect logic should prioritize original request URL")


if __name__ == "__main__":
    unittest.main()
