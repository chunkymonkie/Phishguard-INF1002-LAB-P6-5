# Key Components:
import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

# PhishGuard components
from phishguard.schema import EmailRecord, RuleHit
from phishguard.pipeline.evaluate import build_email_record, evaluate_email_file
from phishguard.scoring.aggregate import evaluate_email as score_email
from phishguard.config import load_config
from phishguard.rules import RULES
from phishguard.ingestion.loaders import iterate_emails
from email.message import EmailMessage

# Storage system for saving analysis results
try:
    from phishguard.storage import EmailReportManager
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False
    EmailReportManager = None

#====================================
#    Phishing Detector Engine    =
#====================================
class PhishingDetector:
    
    def __init__(self, config_path: Optional[str] = None):
        # Load detection rules and configuration
        self.config = load_config(config_path) if config_path else load_config()
        
        # Initialize storage for saving results
        if STORAGE_AVAILABLE and EmailReportManager:
            try:
                self.report_manager = EmailReportManager(base_name="phishguard_analysis")
                self.batch_results = []  # Store results for batch saving
            except Exception as e:
                print(f"Warning: Could not initialize storage system: {e}")
                self.report_manager = None
                self.batch_results = []
        else:
            self.report_manager = None
            self.batch_results = []

    # ========================================================================
    #                      Main Analysis Functions                           =
    # ========================================================================

    def analyze_email(self, sender: str, subject: str, body: str) -> tuple[EmailRecord, float, List[RuleHit]]:

        # Create EmailMessage object from user input
        email_msg = EmailMessage()
        email_msg['From'] = sender
        email_msg['Subject'] = subject
        email_msg.set_content(body)
        
        # Use pipeline to build email record
        email_record = build_email_record(email_msg)
        
        # Use pipeline to evaluate email
        rule_hits, total_score, classification = score_email(email_record, RULES, self.config)
        
        # Save results if storage is available
        self._save_analysis_results(sender, subject, body, classification, total_score, rule_hits)
        
        return email_record, total_score, rule_hits

    def analyze_batch_emails(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze multiple emails from a file or folder using the pipeline.
        
        Args:
            file_path: Path to email file or folder containing email files
            
        Returns:
            Dictionary containing results and summary statistics
        """
        try:
            results = []
            email_count = 0
            
            # Process each email in the file/folder using pipeline components
            for path, email_msg in iterate_emails(file_path):
                try:
                    # Use pipeline to build email record
                    email_record = build_email_record(email_msg)
                    
                    # Use pipeline to evaluate email
                    rule_hits, total_score, classification = score_email(email_record, RULES, self.config)
                    
                    # Store results
                    email_count += 1
                    analysis_result = {
                        'email_record': email_record,
                        'total_score': total_score,
                        'rule_hits': rule_hits,
                        'classification': classification,
                        'email_number': email_count,
                        'filename': str(path)
                    }
                    results.append(analysis_result)
                    
                    # Save to report manager if available
                    self._save_analysis_results(
                        email_record.from_addr, email_record.subject, 
                        email_record.body_text or '', classification,
                        total_score, rule_hits
                    )
                    
                except Exception:
                    continue  # Skip problematic emails
            
            # Generate summary statistics
            if not results:
                return {'error': 'No valid emails found in file'}
            
            summary = self._generate_batch_summary(results)
            return {'results': results, 'summary': summary}
            
        except Exception as e:
            return {'error': f'Failed to process batch file: {str(e)}'}

    # ========================================================================
    #                         Helper Functions                               =
    # ========================================================================

    def save_batch_to_file(self, formats: List[str] = ["json", "csv"]) -> bool:
        """
        Save accumulated batch results to file(s).
        
        Args:
            formats: List of formats to save ('json', 'csv')
            
        Returns:
            True if successful, False otherwise
        """
        if not self.report_manager:
            print("Warning: Storage system not available")
            return False
            
        if not self.batch_results:
            print("Warning: No results to save")
            return False
            
        try:
            success = self.report_manager.save(self.batch_results, formats=formats)
            if success:
                print(f"Successfully saved {len(self.batch_results)} results")
            return success
        except Exception as e:
            print(f"Error saving batch results: {e}")
            return False
    
    def clear_batch_results(self):
        """Clear accumulated batch results"""
        self.batch_results = []

    def _save_analysis_results(self, sender: str, subject: str, body: str, classification: str, total_score: float, rule_hits: List[RuleHit]):
        """Save analysis results to report manager if available"""
        if self.report_manager:
            try:
                # Create result dictionary for storage
                result = {
                    'from_addr': sender,
                    'subject': subject,
                    'classification': classification,
                    'total_score': total_score,
                    'rule_hits': [
                        {
                            'rule_name': hit.rule_name,
                            'passed': hit.passed,
                            'score_delta': hit.score_delta,
                            'severity': hit.severity.value if hasattr(hit.severity, 'value') else str(hit.severity),  # Convert enum to string
                            'details': hit.details
                        } for hit in rule_hits
                    ]
                }
                
                # Add to batch results
                self.batch_results.append(result)
                
            except Exception as e:
                print(f"Warning: Could not save analysis results: {e}")

    def _generate_batch_summary(self, results: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics from batch results"""
        total_emails = len(results)
        
        # Count classifications
        safe_count = sum(1 for r in results if r['classification'].upper() == 'SAFE')
        suspicious_count = sum(1 for r in results if r['classification'].upper() == 'SUSPICIOUS')
        phishing_count = sum(1 for r in results if r['classification'].upper() == 'PHISHING')
        
        return {
            'total_emails': total_emails,
            'safe_count': safe_count,
            'suspicious_count': suspicious_count,
            'phishing_count': phishing_count,
            'safe_percentage': (safe_count / total_emails) * 100 if total_emails > 0 else 0,
            'suspicious_percentage': (suspicious_count / total_emails) * 100 if total_emails > 0 else 0,
            'phishing_percentage': (phishing_count / total_emails) * 100 if total_emails > 0 else 0
        }