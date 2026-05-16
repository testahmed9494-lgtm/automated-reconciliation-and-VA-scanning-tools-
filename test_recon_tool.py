"""
Unit tests for ReconAutomation tool.
Run with:  python -m pytest tests/ -v
"""

import json
import os
import shutil
import socket
import unittest
from unittest.mock import MagicMock, patch

from recon_tool import ReconAutomation, PORT_SERVICES, COMMON_PORTS


class TestReconInit(unittest.TestCase):
    """Tests for class initialisation."""

    def setUp(self):
        self.recon = ReconAutomation("example.com", output_dir="/tmp/test_recon_output")

    def tearDown(self):
        shutil.rmtree("/tmp/test_recon_output", ignore_errors=True)

    def test_output_dir_created(self):
        self.assertTrue(os.path.isdir("/tmp/test_recon_output"))

    def test_results_keys_present(self):
        expected_keys = {'target', 'scan_date', 'subdomains', 'open_ports',
                         'dns_info', 'whois_info', 'http_headers', 'technologies',
                         'ssl_info', 'directories'}
        self.assertEqual(set(self.recon.results.keys()), expected_keys)

    def test_target_stored(self):
        self.assertEqual(self.recon.target, "example.com")


class TestPortServices(unittest.TestCase):
    """Tests for port-service name mapping."""

    def test_known_port_returns_service(self):
        self.assertEqual(PORT_SERVICES[22], 'SSH')
        self.assertEqual(PORT_SERVICES[80], 'HTTP')
        self.assertEqual(PORT_SERVICES[443], 'HTTPS')
        self.assertEqual(PORT_SERVICES[3306], 'MySQL')

    def test_unknown_port_returns_unknown(self):
        self.assertEqual(PORT_SERVICES.get(99999, 'Unknown'), 'Unknown')

    def test_all_common_ports_have_service_entry(self):
        for port in COMMON_PORTS:
            self.assertIn(port, PORT_SERVICES, f"Port {port} missing from PORT_SERVICES")


class TestSubdomainEnumeration(unittest.TestCase):
    """Tests for enumerate_subdomains()."""

    def setUp(self):
        self.recon = ReconAutomation("example.com", output_dir="/tmp/test_recon_sub")

    def tearDown(self):
        shutil.rmtree("/tmp/test_recon_sub", ignore_errors=True)

    @patch('recon_tool.socket.gethostbyname')
    def test_found_subdomain_appended(self, mock_resolve):
        mock_resolve.return_value = '93.184.216.34'
        self.recon.enumerate_subdomains()
        self.assertGreater(len(self.recon.results['subdomains']), 0)
        entry = self.recon.results['subdomains'][0]
        self.assertIn('domain', entry)
        self.assertIn('ip', entry)
        self.assertEqual(entry['status'], 'resolved')

    @patch('recon_tool.socket.gethostbyname', side_effect=socket.gaierror)
    def test_no_subdomains_when_all_fail(self, _mock):
        self.recon.enumerate_subdomains()
        self.assertEqual(self.recon.results['subdomains'], [])


class TestPortScanning(unittest.TestCase):
    """Tests for scan_ports()."""

    def setUp(self):
        self.recon = ReconAutomation("example.com", output_dir="/tmp/test_recon_ports")

    def tearDown(self):
        shutil.rmtree("/tmp/test_recon_ports", ignore_errors=True)

    @patch('recon_tool.socket.socket')
    def test_open_port_recorded(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 0   # 0 = open
        mock_socket_class.return_value = mock_sock

        self.recon.scan_ports(ports=[80])
        self.assertEqual(len(self.recon.results['open_ports']), 1)
        self.assertEqual(self.recon.results['open_ports'][0]['port'], 80)
        self.assertEqual(self.recon.results['open_ports'][0]['service'], 'HTTP')

    @patch('recon_tool.socket.socket')
    def test_closed_port_not_recorded(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 1   # non-zero = closed
        mock_socket_class.return_value = mock_sock

        self.recon.scan_ports(ports=[9999])
        self.assertEqual(self.recon.results['open_ports'], [])


class TestSaveResults(unittest.TestCase):
    """Tests for save_results()."""

    def setUp(self):
        self.recon = ReconAutomation("example.com", output_dir="/tmp/test_recon_save")

    def tearDown(self):
        shutil.rmtree("/tmp/test_recon_save", ignore_errors=True)

    def test_json_file_created(self):
        self.recon.save_results()
        json_path = os.path.join(self.recon.output_dir, 'recon_results.json')
        self.assertTrue(os.path.isfile(json_path))

    def test_json_content_valid(self):
        self.recon.save_results()
        json_path = os.path.join(self.recon.output_dir, 'recon_results.json')
        with open(json_path, encoding='utf-8') as fh:
            data = json.load(fh)
        self.assertEqual(data['target'], 'example.com')

    def test_csv_file_created(self):
        self.recon.save_results()
        csv_path = os.path.join(self.recon.output_dir, 'subdomains.csv')
        self.assertTrue(os.path.isfile(csv_path))


class TestHTMLReport(unittest.TestCase):
    """Tests for generate_report()."""

    def setUp(self):
        self.recon = ReconAutomation("example.com", output_dir="/tmp/test_recon_html")

    def tearDown(self):
        shutil.rmtree("/tmp/test_recon_html", ignore_errors=True)

    def test_html_file_created(self):
        self.recon.generate_report()
        html_path = os.path.join(self.recon.output_dir, 'recon_report.html')
        self.assertTrue(os.path.isfile(html_path))

    def test_html_contains_target(self):
        self.recon.generate_report()
        html_path = os.path.join(self.recon.output_dir, 'recon_report.html')
        with open(html_path, encoding='utf-8') as fh:
            content = fh.read()
        self.assertIn('example.com', content)


if __name__ == '__main__':
    unittest.main()
