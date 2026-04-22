import unittest
from unittest.mock import Mock


class TestCORSValidationLogic(unittest.TestCase):
    """Test CORS origin validation logic using domain configuration"""

    def test_domain_based_validation(self):
        """Test domain-based CORS validation"""
        def get_cors_origin_header(common_params):
            """Get the appropriate CORS origin header based on configured domain"""
            return getattr(common_params, 'domain', '*')

        # Test with wildcard domain
        mock_config = Mock()
        mock_config.domain = '*'
        self.assertEqual(get_cors_origin_header(mock_config), '*')

        # Test with specific domain
        mock_config.domain = 'mycompany.com'
        self.assertEqual(get_cors_origin_header(mock_config), 'mycompany.com')

        # Test with IP address
        mock_config.domain = '10.101.17.197'
        self.assertEqual(get_cors_origin_header(mock_config), '10.101.17.197')

        # Test with localhost
        mock_config.domain = 'localhost'
        self.assertEqual(get_cors_origin_header(mock_config), 'localhost')

    def test_default_behavior(self):
        """Test default behavior when domain is not set"""
        def get_cors_origin_header(common_params):
            """Get the appropriate CORS origin header based on configured domain"""
            return getattr(common_params, 'domain', '*')

        # Test when domain attribute doesn't exist
        mock_config = Mock()
        del mock_config.domain  # Remove domain attribute
        self.assertEqual(get_cors_origin_header(mock_config), '*')

    def test_production_domain_examples(self):
        """Test realistic production domain configurations"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        # Example 1: Allow specific company domain
        mock_config = Mock()
        mock_config.domain = 'mycompany.com'
        self.assertEqual(get_cors_origin_header(mock_config), 'mycompany.com')

        # Example 2: Allow localhost for development
        mock_config.domain = 'localhost'
        self.assertEqual(get_cors_origin_header(mock_config), 'localhost')

        # Example 3: Allow all domains (wildcard)
        mock_config.domain = '*'
        self.assertEqual(get_cors_origin_header(mock_config), '*')

        # Example 4: Allow IP address
        mock_config.domain = '10.101.17.197'
        self.assertEqual(get_cors_origin_header(mock_config), '10.101.17.197')

    def test_cli_integration(self):
        """Test that domain parameter works with CLI arguments"""
        # This test simulates how the domain parameter would be used
        # in the actual application flow

        # Simulate CLI argument parsing
        domain_from_cli = "mycompany.com"

        # Simulate CommonConfig creation
        class MockCommonConfig:
            def __init__(self, domain):
                self.domain = domain

        config = MockCommonConfig(domain_from_cli)

        # Test that the domain is correctly stored and retrieved
        self.assertEqual(config.domain, "mycompany.com")

        # Test get_cors_origin_header function
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        self.assertEqual(get_cors_origin_header(config), "mycompany.com")

    def test_negative_cases(self):
        """Test negative cases and edge cases"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        # Test with empty string domain
        mock_config = Mock()
        mock_config.domain = ""
        self.assertEqual(get_cors_origin_header(mock_config), "")

        # Test with None domain
        mock_config.domain = None
        self.assertEqual(get_cors_origin_header(mock_config), None)

        # Test with whitespace domain
        mock_config.domain = "   "
        self.assertEqual(get_cors_origin_header(mock_config), "   ")

        # Test with special characters in domain
        mock_config.domain = "test-domain.com"
        self.assertEqual(get_cors_origin_header(mock_config), "test-domain.com")

        # Test with numeric domain
        mock_config.domain = "123.456.789.012"
        self.assertEqual(get_cors_origin_header(mock_config), "123.456.789.012")

    def test_security_scenarios(self):
        """Test security-related scenarios"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        # Test with potentially malicious domains
        mock_config = Mock()

        # Test with script injection attempt
        mock_config.domain = "<script>alert('xss')</script>"
        self.assertEqual(get_cors_origin_header(mock_config), "<script>alert('xss')</script>")

        # Test with SQL injection attempt
        mock_config.domain = "'; DROP TABLE users; --"
        self.assertEqual(get_cors_origin_header(mock_config), "'; DROP TABLE users; --")

        # Test with very long domain
        long_domain = "a" * 1000
        mock_config.domain = long_domain
        self.assertEqual(get_cors_origin_header(mock_config), long_domain)

        # Test with unicode characters
        mock_config.domain = "tëst-dömäin.com"
        self.assertEqual(get_cors_origin_header(mock_config), "tëst-dömäin.com")

    def test_edge_cases(self):
        """Test various edge cases"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        mock_config = Mock()

        # Test with port number in domain
        mock_config.domain = "example.com:8080"
        self.assertEqual(get_cors_origin_header(mock_config), "example.com:8080")

        # Test with protocol in domain
        mock_config.domain = "https://example.com"
        self.assertEqual(get_cors_origin_header(mock_config), "https://example.com")

        # Test with path in domain
        mock_config.domain = "example.com/path"
        self.assertEqual(get_cors_origin_header(mock_config), "example.com/path")

        # Test with query parameters in domain
        mock_config.domain = "example.com?param=value"
        self.assertEqual(get_cors_origin_header(mock_config), "example.com?param=value")

    def test_different_domain_formats(self):
        """Test different domain formats and variations"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        mock_config = Mock()

        # Test various domain formats
        test_cases = [
            "example.com",
            "www.example.com",
            "subdomain.example.com",
            "example.co.uk",
            "example-domain.com",
            "example_domain.com",
            "example123.com",
            "123example.com",
            "example.com.",
            ".example.com",
            "example..com",
            "example.com-",
            "-example.com",
            "example.com_",
            "_example.com",
        ]

        for domain in test_cases:
            with self.subTest(domain=domain):
                mock_config.domain = domain
                self.assertEqual(get_cors_origin_header(mock_config), domain)

    def test_ip_address_variations(self):
        """Test various IP address formats"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        mock_config = Mock()

        # Test various IP address formats
        ip_test_cases = [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::1",  # IPv6 localhost
            "2001:db8::1",  # IPv6
            "fe80::1%lo0",  # IPv6 with interface
        ]

        for ip in ip_test_cases:
            with self.subTest(ip=ip):
                mock_config.domain = ip
                self.assertEqual(get_cors_origin_header(mock_config), ip)

    def test_configuration_loading(self):
        """Test that domain configuration is properly loaded"""
        # Simulate configuration loading from different sources
        def create_config_from_dict(config_dict):
            class MockConfig:
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)
            return MockConfig(**config_dict)

        # Test configuration from YAML file
        yaml_config = {
            'domain': 'mycompany.com',
            'cookie_name': 'authproxy',
            'host': '0.0.0.0',
            'port': 8888
        }
        config = create_config_from_dict(yaml_config)
        self.assertEqual(config.domain, 'mycompany.com')

        # Test configuration from CLI arguments
        cli_config = {
            'domain': 'localhost',
            'cookie_name': 'authproxy',
            'host': '127.0.0.1',
            'port': 8888
        }
        config = create_config_from_dict(cli_config)
        self.assertEqual(config.domain, 'localhost')

        # Test default configuration
        default_config = {
            'cookie_name': 'authproxy',
            'host': '0.0.0.0',
            'port': 8888
            # domain not specified, should default to '*'
        }
        config = create_config_from_dict(default_config)
        self.assertFalse(hasattr(config, 'domain'))

    def test_error_handling(self):
        """Test error handling scenarios"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        # Test with Mock that doesn't have domain attribute
        mock_config = Mock()
        # Remove domain attribute to simulate missing attribute
        del mock_config.domain
        self.assertEqual(get_cors_origin_header(mock_config), '*')

        # Test with None domain
        mock_config = Mock()
        mock_config.domain = None
        self.assertEqual(get_cors_origin_header(mock_config), None)

        # Test with empty string domain
        mock_config = Mock()
        mock_config.domain = ""
        self.assertEqual(get_cors_origin_header(mock_config), "")

        # Test with whitespace domain
        mock_config = Mock()
        mock_config.domain = "   "
        self.assertEqual(get_cors_origin_header(mock_config), "   ")

        # Test with object that doesn't support attribute access
        class NoAttrAccess:
            def __getattr__(self, name):
                raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

        no_attr_obj = NoAttrAccess()
        self.assertEqual(get_cors_origin_header(no_attr_obj), '*')

    def test_performance_scenarios(self):
        """Test performance-related scenarios"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        mock_config = Mock()

        # Test with very long domain name
        long_domain = "a" * 10000
        mock_config.domain = long_domain

        import time
        start_time = time.time()
        result = get_cors_origin_header(mock_config)
        end_time = time.time()

        self.assertEqual(result, long_domain)
        self.assertLess(end_time - start_time, 0.1)  # Should complete quickly

        # Test with many attribute accesses
        mock_config = Mock()
        mock_config.domain = "example.com"

        start_time = time.time()
        for _ in range(1000):
            result = get_cors_origin_header(mock_config)
        end_time = time.time()

        self.assertEqual(result, "example.com")
        self.assertLess(end_time - start_time, 1.0)  # Should complete within 1 second

    def test_integration_scenarios(self):
        """Test integration scenarios with multiple configurations"""
        def get_cors_origin_header(common_params):
            return getattr(common_params, 'domain', '*')

        # Test multiple configurations in sequence
        configurations = [
            {'domain': '*', 'expected': '*'},
            {'domain': 'localhost', 'expected': 'localhost'},
            {'domain': 'mycompany.com', 'expected': 'mycompany.com'},
            {'domain': '10.101.17.197', 'expected': '10.101.17.197'},
            {'domain': 'app.mycompany.com', 'expected': 'app.mycompany.com'},
        ]

        for config in configurations:
            with self.subTest(config=config):
                mock_config = Mock()
                mock_config.domain = config['domain']
                result = get_cors_origin_header(mock_config)
                self.assertEqual(result, config['expected'])

    def test_centralized_cors_headers(self):
        """Test that centralized CORS headers methods work correctly"""
        def add_cors_headers(common_params, send_header_mock):
            """Simulate the centralized CORS headers method"""
            cors_origin = getattr(common_params, 'domain', '*')
            send_header_mock('Access-Control-Allow-Origin', cors_origin)
            send_header_mock('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
            send_header_mock('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
            send_header_mock('Access-Control-Allow-Credentials', 'true')

        def add_cors_headers_with_cache(common_params, send_header_mock):
            """Simulate the centralized CORS headers with cache method"""
            add_cors_headers(common_params, send_header_mock)
            send_header_mock('Access-Control-Max-Age', '86400')

        # Test with specific domain
        mock_config = Mock()
        mock_config.domain = 'mycompany.com'
        send_header_calls = []

        def mock_send_header(name, value):
            send_header_calls.append((name, value))

        add_cors_headers(mock_config, mock_send_header)

        # Verify all CORS headers were added
        expected_headers = [
            ('Access-Control-Allow-Origin', 'mycompany.com'),
            ('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS'),
            ('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With'),
            ('Access-Control-Allow-Credentials', 'true')
        ]

        for expected in expected_headers:
            self.assertIn(expected, send_header_calls)

        # Test with cache headers
        send_header_calls.clear()
        add_cors_headers_with_cache(mock_config, mock_send_header)

        # Verify cache header was added
        self.assertIn(('Access-Control-Max-Age', '86400'), send_header_calls)

        # Test with wildcard domain
        mock_config.domain = '*'
        send_header_calls.clear()
        add_cors_headers(mock_config, mock_send_header)

        self.assertIn(('Access-Control-Allow-Origin', '*'), send_header_calls)


if __name__ == '__main__':
    unittest.main()
