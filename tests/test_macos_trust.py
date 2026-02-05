"""Tests for macos-trust utilities."""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from macos_trust.util.process import run_macos_binary, get_macos_version
from macos_trust.util.shell import run, ShellResult


class TestShellUtils(unittest.TestCase):
    """Test shell utilities."""
    
    def test_run_command_success(self):
        """Test running a successful command."""
        result = run(["/usr/bin/sw_vers", "-productVersion"])
        self.assertTrue(result.success)
        self.assertIsNotNone(result.out)
        self.assertEqual(result.code, 0)
    
    def test_run_command_failure(self):
        """Test running a failed command."""
        result = run(["/usr/bin/false"])
        self.assertFalse(result.success)
        self.assertEqual(result.code, 1)
    
    def test_shell_result_structure(self):
        """Test ShellResult structure."""
        result = run(["/usr/bin/sw_vers"])
        self.assertIsInstance(result, ShellResult)
        self.assertIsInstance(result.out, str)
        self.assertIsInstance(result.err, str)
        self.assertIsInstance(result.code, int)
        self.assertIsInstance(result.success, bool)


class TestProcessUtils(unittest.TestCase):
    """Test process utilities."""
    
    def test_run_existing_binary(self):
        """Test running an existing macOS binary."""
        result = run_macos_binary("/usr/bin/sw_vers", ["-productVersion"])
        self.assertTrue(result.success)
        self.assertIsNotNone(result.stdout)
        self.assertEqual(result.returncode, 0)
    
    def test_run_nonexistent_binary(self):
        """Test running a non-existent binary."""
        result = run_macos_binary("/usr/bin/nonexistent", [])
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.returncode, -1)
    
    def test_get_macos_version(self):
        """Test getting macOS version."""
        version = get_macos_version()
        self.assertIsNotNone(version)
        if version:  # Type narrowing for Pylance
            self.assertGreater(len(version), 0)


class TestModels(unittest.TestCase):
    """Test data models."""
    
    def test_risk_ordering(self):
        """Test Risk enum ordering (HIGH > MED for sorting, so HIGH appears first)."""
        from macos_trust.models import Risk
        
        # In the implementation, HIGH > MED > LOW > INFO (for sorting purposes)
        # This ensures HIGH risk items appear first when sorted
        self.assertGreater(Risk.HIGH, Risk.MED)
        self.assertGreater(Risk.MED, Risk.LOW)
        self.assertGreater(Risk.LOW, Risk.INFO)
        
        self.assertLess(Risk.INFO, Risk.LOW)
        self.assertLess(Risk.LOW, Risk.MED)
        self.assertLess(Risk.MED, Risk.HIGH)
    
    def test_finding_model(self):
        """Test Finding model structure."""
        from macos_trust.models import Finding, Risk
        
        finding = Finding(
            id="test:app:com.example:unsigned",
            risk=Risk.HIGH,
            category="application",
            title="Unsigned application",
            details="Application is not signed",
            recommendation="Sign the application",
            evidence={"signed": "False"},
            path="/Applications/Test.app"
        )
        
        self.assertEqual(finding.risk, Risk.HIGH)
        self.assertEqual(finding.category, "application")
    
    def test_scan_report_model(self):
        """Test ScanReport model structure."""
        from macos_trust.models import ScanReport, HostInfo
        from datetime import datetime
        
        host = HostInfo(
            hostname="test-host",
            os_version="15.0",
            build="24A5264n",
            arch="arm64"
        )
        
        report = ScanReport(
            timestamp=datetime.now().isoformat(),
            host=host,
            findings=[]
        )
        
        self.assertEqual(report.host.hostname, "test-host")
        self.assertEqual(len(report.findings), 0)
        self.assertIsInstance(report.timestamp, str)


class TestVendors(unittest.TestCase):
    """Test vendor utilities."""
    
    def test_known_vendor_detection(self):
        """Test detection of known vendors."""
        from macos_trust.vendors import is_known_vendor, get_vendor_name
        
        # Test known vendors
        self.assertTrue(is_known_vendor("9BNSXJN65R"))  # Docker
        self.assertEqual(get_vendor_name("9BNSXJN65R"), "Docker Inc")
        
        self.assertTrue(is_known_vendor("UBF8T346G9"))  # Microsoft
        self.assertEqual(get_vendor_name("UBF8T346G9"), "Microsoft Corporation")
        
        # Test unknown vendor - returns the team_id itself when unknown
        self.assertFalse(is_known_vendor("UNKNOWN123"))
        self.assertEqual(get_vendor_name("UNKNOWN123"), "UNKNOWN123")
    
    def test_system_helper_paths(self):
        """Test system helper path detection."""
        from macos_trust.vendors import is_system_helper_path
        
        # Known system helper patterns (PrivilegedHelperTools, XPCServices, Frameworks, etc.)
        self.assertTrue(is_system_helper_path("/Library/PrivilegedHelperTools/com.example.helper"))
        self.assertTrue(is_system_helper_path("/Applications/Test.app/Contents/XPCServices/helper"))
        self.assertTrue(is_system_helper_path("/Library/Frameworks/Test.framework/helper"))
        
        # Non-helper paths
        self.assertFalse(is_system_helper_path("/Applications/MyApp.app"))
        self.assertFalse(is_system_helper_path("/usr/local/bin/helper"))


class TestCollectors(unittest.TestCase):
    """Test collectors."""
    
    def test_codesign_verify_structure(self):
        """Test codesign verify returns expected structure."""
        from macos_trust.collectors.codesign import codesign_verify
        
        # Test with a system app
        result = codesign_verify("/System/Applications/Safari.app")
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)
        self.assertIn("team_id", result)
    
    def test_spctl_assess_structure(self):
        """Test spctl assess returns expected structure."""
        from macos_trust.collectors.spctl import spctl_assess
        
        # Test with a system app
        result = spctl_assess("/System/Applications/Safari.app")
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)
    
    def test_quarantine_check_structure(self):
        """Test quarantine check returns expected structure."""
        from macos_trust.collectors.quarantine import get_quarantine
        
        # Test with a system app (should not be quarantined)
        result = get_quarantine("/System/Applications/Safari.app")
        self.assertIsInstance(result, dict)
        self.assertIn("is_quarantined", result)


class TestScanners(unittest.TestCase):
    """Test scanners."""
    
    def test_scan_applications(self):
        """Test application scanning."""
        from macos_trust.scanners.apps import scan_applications
        
        apps = scan_applications()
        self.assertIsInstance(apps, list)
        
        if apps:
            app = apps[0]
            self.assertIn("app_path", app)
            self.assertIn("bundle_id", app)
    
    def test_scan_launchd(self):
        """Test LaunchD scanning."""
        from macos_trust.scanners.launchd import scan_launchd
        
        items = scan_launchd()
        self.assertIsInstance(items, list)
        
        if items:
            item = items[0]
            self.assertIn("plist_path", item)
            self.assertIn("label", item)


class TestRules(unittest.TestCase):
    """Test security rules."""
    
    def test_analyze_app_unsigned(self):
        """Test app analysis with unsigned app."""
        from macos_trust.rules import analyze_app
        
        app = {
            "app_path": "/Applications/Test.app",
            "name": "Test",
            "bundle_id": "com.test.app"
        }
        
        codesign_result = {
            "status": "fail",
            "error": "code object is not signed at all"
        }
        
        findings = analyze_app(app, codesign_result=codesign_result)
        self.assertIsInstance(findings, list)
        if findings:
            # Finding ID format is 'app:bundle_id:codesign_fail' or similar
            self.assertIn("codesign", findings[0].id.lower())
            self.assertEqual(findings[0].risk.value, "HIGH")
    
    def test_analyze_app_spctl_rejected(self):
        """Test app analysis with Gatekeeper rejection."""
        from macos_trust.rules import analyze_app
        
        app = {
            "app_path": "/Applications/Test.app",
            "name": "Test",
            "bundle_id": "com.test.app"
        }
        
        codesign_result = {
            "status": "ok",
            "team_id": "TEST123"
        }
        
        spctl_result = {
            "status": "rejected"
        }
        
        findings = analyze_app(app, codesign_result=codesign_result, spctl_result=spctl_result)
        self.assertIsInstance(findings, list)
        if findings:
            self.assertIn("spctl", findings[0].id.lower())
    
    def test_analyze_launchd(self):
        """Test LaunchD item analysis."""
        from macos_trust.rules import analyze_launchd
        
        item = {
            "plist_path": "/Library/LaunchDaemons/com.test.plist",
            "label": "com.test",
            "exec_path": "/usr/local/bin/test",
            "scope": "system"
        }
        
        findings = analyze_launchd(item)
        self.assertIsInstance(findings, list)


class TestOutput(unittest.TestCase):
    """Test output rendering."""
    
    def test_render_json_structure(self):
        """Test JSON rendering."""
        from macos_trust.output.render import render_json
        from macos_trust.models import ScanReport, HostInfo, Finding, Risk
        from datetime import datetime
        
        host = HostInfo(
            hostname="test-host",
            os_version="15.0",
            build="24A5264n",
            arch="arm64"
        )
        
        finding = Finding(
            id="test:finding",
            risk=Risk.HIGH,
            category="test",
            title="Test finding",
            details="Test description",
            recommendation="Test recommendation",
            evidence={},
            path="/test/path"
        )
        
        report = ScanReport(
            timestamp=datetime.now().isoformat(),
            host=host,
            findings=[finding]
        )
        
        output = render_json(report)
        self.assertIsInstance(output, str)
        
        import json
        data = json.loads(output)
        self.assertIn("timestamp", data)
        self.assertIn("host", data)
        self.assertIn("findings", data)
        self.assertEqual(len(data["findings"]), 1)
    
    def test_render_human_structure(self):
        """Test human-readable rendering."""
        from macos_trust.output.render import render_human
        from macos_trust.models import ScanReport, HostInfo
        from datetime import datetime
        
        host = HostInfo(
            hostname="test-host",
            os_version="15.0",
            build="24A5264n",
            arch="arm64"
        )
        
        report = ScanReport(
            timestamp=datetime.now().isoformat(),
            host=host,
            findings=[]
        )
        
        output = render_human(report)
        self.assertIsInstance(output, str)
        self.assertIn("macOS Trust Scanner", output)


if __name__ == "__main__":
    unittest.main()
