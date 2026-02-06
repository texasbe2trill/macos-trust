"""Tests for new v0.2 features: config, baseline, context enrichment."""

import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from macos_trust.config import Config
from macos_trust.baseline import Baseline
from macos_trust.context import (
    AppContext,
    parse_quarantine_source,
    is_homebrew_quarantine,
    is_browser_quarantine,
    should_trust_by_age
)
from macos_trust.models import Finding, Risk, ScanReport, HostInfo
from macos_trust.engine import _apply_config_filters
from macos_trust.rules import analyze_app, analyze_launchd


class TestConfig(unittest.TestCase):
    """Test configuration management."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        self.assertEqual(config.min_risk, "MED")
        self.assertTrue(config.trust_app_store)
        self.assertFalse(config.trust_homebrew_cask)
        self.assertFalse(config.trust_old_apps)
        self.assertEqual(config.old_app_days, 30)
        self.assertEqual(len(config.exclude_vendors), 0)
        self.assertEqual(len(config.trusted_vendors), 0)
    
    def test_config_with_values(self):
        """Test configuration with custom values."""
        config = Config(
            min_risk="HIGH",
            exclude_vendors=["UBF8T346G9", "9BNSXJN65R"],
            trusted_vendors=["H7H8Q7M5CK"],
            trust_homebrew_cask=True,
            ignore_patterns=[".*:quarantined$"]
        )
        self.assertEqual(config.min_risk, "HIGH")
        self.assertEqual(len(config.exclude_vendors), 2)
        self.assertEqual(len(config.trusted_vendors), 1)
        self.assertTrue(config.trust_homebrew_cask)
        self.assertEqual(len(config.ignore_patterns), 1)
    
    def test_config_regex_validation(self):
        """Test that invalid regex patterns raise errors."""
        with self.assertRaises(ValueError):
            Config(ignore_patterns=["[invalid(regex"])
    
    def test_load_config_no_file(self):
        """Test loading config when file doesn't exist."""
        from macos_trust.config import load_config
        # When explicit path provided that doesn't exist, raises error
        with self.assertRaises(FileNotFoundError):
            config = load_config("/nonexistent/path/config.yaml")
        
        # When no path provided and no default exists, returns default config
        config = load_config(None)
        self.assertEqual(config.min_risk, "MED")


class TestBaseline(unittest.TestCase):
    """Test baseline functionality."""
    
    def setUp(self):
        """Create temporary baseline file for testing."""
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        self.baseline_path = Path(self.temp_file.name)
        self.temp_file.close()
    
    def tearDown(self):
        """Clean up temporary baseline file."""
        if self.baseline_path.exists():
            self.baseline_path.unlink()
    
    def test_baseline_init(self):
        """Test baseline initialization."""
        baseline = Baseline(self.baseline_path)
        self.assertEqual(baseline.path, self.baseline_path)
        self.assertEqual(len(baseline.findings), 0)
    
    def test_baseline_load_nonexistent(self):
        """Test loading baseline when file doesn't exist."""
        baseline = Baseline(self.baseline_path)
        self.assertFalse(baseline.load())
    
    def test_baseline_save_and_load(self):
        """Test saving and loading baseline."""
        baseline = Baseline(self.baseline_path)
        
        # Create sample report
        host = HostInfo(os_version="15.0", build="24A335", arch="arm64", hostname="test")
        finding1 = Finding(
            id="test:1",
            category="app",
            risk=Risk.HIGH,
            title="Test Finding 1",
            details="Test details",
            recommendation="Test"
        )
        finding2 = Finding(
            id="test:2",
            category="app",
            risk=Risk.MED,
            title="Test Finding 2",
            details="Test details",
            recommendation="Test"
        )
        report = ScanReport(host=host, findings=[finding1, finding2], timestamp="2026-01-01T00:00:00Z")
        
        # Save baseline
        baseline.save(report)
        self.assertTrue(self.baseline_path.exists())
        
        # Load baseline
        baseline2 = Baseline(self.baseline_path)
        self.assertTrue(baseline2.load())
        self.assertEqual(baseline2.get_baseline_count(), 2)
        self.assertTrue(baseline2.is_in_baseline("test:1"))
        self.assertTrue(baseline2.is_in_baseline("test:2"))
        self.assertFalse(baseline2.is_in_baseline("test:3"))
    
    def test_baseline_filter_new_findings(self):
        """Test filtering out baseline findings."""
        baseline = Baseline(self.baseline_path)
        
        # Create and save baseline
        host = HostInfo(os_version="15.0", build="24A335", arch="arm64", hostname="test")
        finding1 = Finding(id="test:1", category="app", risk=Risk.HIGH, title="Test 1", details="Test", recommendation="Test")
        finding2 = Finding(id="test:2", category="app", risk=Risk.MED, title="Test 2", details="Test", recommendation="Test")
        report = ScanReport(host=host, findings=[finding1, finding2], timestamp="2026-01-01T00:00:00Z")
        baseline.save(report)
        
        # Test filtering - same findings should be filtered out
        new_findings = baseline.filter_new_findings([finding1, finding2])
        self.assertEqual(len(new_findings), 0)
        
        # Test with new finding
        finding3 = Finding(id="test:3", category="app", risk=Risk.HIGH, title="Test 3", details="Test", recommendation="Test")
        new_findings = baseline.filter_new_findings([finding1, finding2, finding3])
        self.assertEqual(len(new_findings), 1)
        self.assertEqual(new_findings[0].id, "test:3")
    
    def test_baseline_filter_changed_risk(self):
        """Test detecting findings with changed risk level."""
        baseline = Baseline(self.baseline_path)
        
        # Create and save baseline with HIGH risk
        host = HostInfo(os_version="15.0", build="24A335", arch="arm64", hostname="test")
        finding1 = Finding(id="test:1", category="app", risk=Risk.HIGH, title="Test 1", details="Test", recommendation="Test")
        report = ScanReport(host=host, findings=[finding1], timestamp="2026-01-01T00:00:00Z")
        baseline.save(report)
        
        # Same finding but now MED risk - should be detected as changed
        finding1_changed = Finding(id="test:1", category="app", risk=Risk.MED, title="Test 1", details="Test", recommendation="Test")
        new_findings = baseline.filter_new_findings([finding1_changed])
        self.assertEqual(len(new_findings), 1)
        self.assertEqual(new_findings[0].risk, Risk.MED)


class TestContext(unittest.TestCase):
    """Test context enrichment functions."""
    
    def test_parse_quarantine_source_homebrew(self):
        """Test parsing Homebrew Cask quarantine source."""
        quarantine = "0181;697f95d3;Homebrew\\x20Cask;082DC06F-877D-4038-9E75-6FAFE46B30B8"
        source = parse_quarantine_source(quarantine)
        self.assertEqual(source, "Homebrew Cask")
    
    def test_parse_quarantine_source_safari(self):
        """Test parsing Safari quarantine source."""
        quarantine = "01c3;68c09dae;Safari;99022C81-F416-4F34-9E0A-54297ABD776C"
        source = parse_quarantine_source(quarantine)
        self.assertEqual(source, "Safari")
    
    def test_parse_quarantine_source_invalid(self):
        """Test parsing invalid quarantine value."""
        self.assertIsNone(parse_quarantine_source(""))
        self.assertIsNone(parse_quarantine_source("invalid"))
        self.assertIsNone(parse_quarantine_source("0181;697f95d3"))
    
    def test_is_homebrew_quarantine(self):
        """Test Homebrew quarantine detection."""
        homebrew_quarantine = "0181;697f95d3;Homebrew\\x20Cask;082DC06F"
        safari_quarantine = "01c3;68c09dae;Safari;99022C81"
        
        self.assertTrue(is_homebrew_quarantine(homebrew_quarantine))
        self.assertFalse(is_homebrew_quarantine(safari_quarantine))
        self.assertFalse(is_homebrew_quarantine(""))
    
    def test_is_browser_quarantine(self):
        """Test browser quarantine detection."""
        safari_quarantine = "01c3;68c09dae;Safari;99022C81"
        chrome_quarantine = "01c3;68c09dae;Google\\x20Chrome;99022C81"
        homebrew_quarantine = "0181;697f95d3;Homebrew\\x20Cask;082DC06F"
        
        self.assertTrue(is_browser_quarantine(safari_quarantine))
        self.assertTrue(is_browser_quarantine(chrome_quarantine))
        self.assertFalse(is_browser_quarantine(homebrew_quarantine))
        self.assertFalse(is_browser_quarantine(""))
    
    @patch('os.stat')
    def test_should_trust_by_age(self, mock_stat):
        """Test age-based trust calculation."""
        from datetime import datetime, timedelta
        
        # Mock old file (40 days ago)
        old_time = (datetime.now() - timedelta(days=40)).timestamp()
        mock_stat.return_value = Mock(st_mtime=old_time)
        self.assertTrue(should_trust_by_age("/fake/path", threshold_days=30))
        
        # Mock recent file (10 days ago)
        recent_time = (datetime.now() - timedelta(days=10)).timestamp()
        mock_stat.return_value = Mock(st_mtime=recent_time)
        self.assertFalse(should_trust_by_age("/fake/path", threshold_days=30))
    
    @patch('os.path.exists')
    def test_app_context_app_store_detection(self, mock_exists):
        """Test App Store detection."""
        # Mock App Store app
        def exists_side_effect(path):
            return '_MASReceipt/receipt' in str(path)
        
        mock_exists.side_effect = exists_side_effect
        
        context = AppContext("/Applications/Pages.app/Contents/MacOS/Pages")
        self.assertTrue(context.is_app_store)
    
    @patch('macos_trust.context.AppContext._get_homebrew_apps')
    def test_app_context_homebrew_detection(self, mock_homebrew):
        """Test Homebrew detection."""
        mock_homebrew.return_value = {'gimp', 'postman', 'signal'}
        
        # Clear cached value if exists
        if hasattr(AppContext, '_homebrew_apps'):
            delattr(AppContext, '_homebrew_apps')
        
        context = AppContext("/Applications/GIMP.app/Contents/MacOS/gimp")
        self.assertTrue(context.is_homebrew)
        
        context2 = AppContext("/Applications/Safari.app/Contents/MacOS/Safari")
        self.assertFalse(context2.is_homebrew)


class TestEngineFiltering(unittest.TestCase):
    """Test engine-level filtering with config."""
    
    def test_apply_config_filters_ignore_findings(self):
        """Test filtering by ignore_findings list."""
        config = Config(ignore_findings=["test:1", "test:2"])
        
        findings = [
            Finding(id="test:1", category="app", risk=Risk.HIGH, title="Test 1", details="Test", recommendation="Test"),
            Finding(id="test:2", category="app", risk=Risk.MED, title="Test 2", details="Test", recommendation="Test"),
            Finding(id="test:3", category="app", risk=Risk.LOW, title="Test 3", details="Test", recommendation="Test"),
        ]
        
        filtered = _apply_config_filters(findings, config)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].id, "test:3")
    
    def test_apply_config_filters_ignore_patterns(self):
        """Test filtering by ignore_patterns regex."""
        config = Config(ignore_patterns=[".*:quarantined$", "^persistence:user:.*"])
        
        findings = [
            Finding(id="app:test:quarantined", category="app", risk=Risk.LOW, title="Test 1", details="Test", recommendation="Test"),
            Finding(id="persistence:user:test:spctl_rejected", category="persistence", risk=Risk.HIGH, title="Test 2", details="Test", recommendation="Test"),
            Finding(id="app:test:codesign_fail", category="app", risk=Risk.HIGH, title="Test 3", details="Test", recommendation="Test"),
        ]
        
        filtered = _apply_config_filters(findings, config)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].id, "app:test:codesign_fail")
    
    def test_apply_config_filters_combined(self):
        """Test combined filtering (ignore_findings + ignore_patterns)."""
        config = Config(
            ignore_findings=["app:specific:id"],
            ignore_patterns=[".*:quarantined$"]
        )
        
        findings = [
            Finding(id="app:specific:id", category="app", risk=Risk.HIGH, title="Test 1", details="Test", recommendation="Test"),
            Finding(id="app:test:quarantined", category="app", risk=Risk.LOW, title="Test 2", details="Test", recommendation="Test"),
            Finding(id="app:other:codesign_fail", category="app", risk=Risk.HIGH, title="Test 3", details="Test", recommendation="Test"),
        ]
        
        filtered = _apply_config_filters(findings, config)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].id, "app:other:codesign_fail")


class TestRulesWithConfig(unittest.TestCase):
    """Test rules with configuration."""
    
    def test_analyze_app_with_trusted_vendor(self):
        """Test app analysis with trusted vendor in config."""
        config = Config(trusted_vendors=["H7H8Q7M5CK"])
        
        app = {
            "name": "Postman",
            "bundle_id": "com.postmanlabs.mac",
            "exec_path": "/Applications/Postman.app/Contents/MacOS/Postman"
        }
        
        codesign_result = {
            "status": "fail",
            "team_id": "H7H8Q7M5CK",
            "raw": "code object is not signed at all"
        }
        
        findings = analyze_app(app, codesign_result=codesign_result, config=config)
        
        # Should have finding but downgraded to MED (not HIGH) because vendor is trusted
        self.assertTrue(len(findings) > 0)
        codesign_finding = next((f for f in findings if "codesign_fail" in f.id), None)
        self.assertIsNotNone(codesign_finding)
        # Type guard: we already asserted it's not None
        assert codesign_finding is not None
        self.assertEqual(codesign_finding.risk, Risk.MED)
    
    def test_analyze_app_quarantine_homebrew_trust(self):
        """Test quarantine handling with trust_homebrew_cask enabled."""
        config = Config(trust_homebrew_cask=True)
        
        app = {
            "name": "GIMP",
            "bundle_id": "org.gimp.gimp",
            "exec_path": "/Applications/GIMP.app/Contents/MacOS/gimp"
        }
        
        quarantine_result = {
            "is_quarantined": "true",
            "value": "0181;697f95d3;Homebrew\\x20Cask;082DC06F"
        }
        
        findings = analyze_app(app, quarantine_result=quarantine_result, config=config)
        
        # Should NOT create quarantine finding for Homebrew Cask when trusted
        quarantine_findings = [f for f in findings if "quarantined" in f.id]
        self.assertEqual(len(quarantine_findings), 0)
    
    def test_analyze_app_quarantine_browser_no_trust(self):
        """Test quarantine handling for browser downloads (not trusted)."""
        config = Config(trust_homebrew_cask=True)  # Only Homebrew trusted
        
        app = {
            "name": "UnknownApp",
            "bundle_id": "com.unknown.app",
            "exec_path": "/Applications/UnknownApp.app/Contents/MacOS/app"
        }
        
        quarantine_result = {
            "is_quarantined": "true",
            "value": "01c3;68c09dae;Safari;99022C81"
        }
        
        findings = analyze_app(app, quarantine_result=quarantine_result, config=config)
        
        # Should create quarantine finding for Safari downloads
        quarantine_findings = [f for f in findings if "quarantined" in f.id]
        self.assertEqual(len(quarantine_findings), 1)
        self.assertEqual(quarantine_findings[0].risk, Risk.LOW)


class TestIntegration(unittest.TestCase):
    """Integration tests for combined features."""
    
    def test_full_workflow_with_config_and_baseline(self):
        """Test complete workflow: config + baseline + filtering."""
        # Create temporary baseline
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        baseline_path = Path(temp_file.name)
        temp_file.close()
        
        try:
            # Setup config
            config = Config(
                min_risk="MED",
                exclude_vendors=["UBF8T346G9"],
                ignore_patterns=[".*:quarantined$"]
            )
            
            # Create initial findings
            host = HostInfo(os_version="15.0", build="24A335", arch="arm64", hostname="test")
            findings = [
                Finding(id="app:1:codesign_fail", category="app", risk=Risk.HIGH, title="Test 1", 
                       details="Test", recommendation="Test", evidence={"codesign_team_id": "UNKNOWN"}),
                Finding(id="app:2:codesign_fail", category="app", risk=Risk.HIGH, title="Test 2",
                       details="Test", recommendation="Test", evidence={"codesign_team_id": "UBF8T346G9"}),
                Finding(id="app:3:quarantined", category="app", risk=Risk.LOW, title="Test 3",
                       details="Test", recommendation="Test"),
            ]
            
            # Apply config filtering
            filtered = _apply_config_filters(findings, config)
            # Should filter out quarantined (pattern match)
            # Note: exclude_vendors filtering happens in CLI, not in _apply_config_filters
            self.assertEqual(len(filtered), 2)
            # Verify quarantined was filtered out
            filtered_ids = [f.id for f in filtered]
            self.assertNotIn("app:3:quarantined", filtered_ids)
            
            # Save baseline
            report = ScanReport(host=host, findings=filtered, timestamp="2026-01-01T00:00:00Z")
            baseline = Baseline(baseline_path)
            baseline.save(report)
            
            # Simulate new scan with one new finding
            new_findings = [
                Finding(id="app:1:codesign_fail", category="app", risk=Risk.HIGH, title="Test 1",
                       details="Test", recommendation="Test", evidence={"codesign_team_id": "UNKNOWN"}),
                Finding(id="app:4:spctl_rejected", category="app", risk=Risk.HIGH, title="Test 4",
                       details="Test", recommendation="Test"),
            ]
            
            # Load baseline and filter
            baseline.load()
            diff_findings = baseline.filter_new_findings(new_findings)
            
            # Should only show the new finding
            self.assertEqual(len(diff_findings), 1)
            self.assertEqual(diff_findings[0].id, "app:4:spctl_rejected")
            
        finally:
            # Cleanup
            if baseline_path.exists():
                baseline_path.unlink()


if __name__ == '__main__':
    unittest.main()
