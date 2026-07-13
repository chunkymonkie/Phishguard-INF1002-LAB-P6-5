import unittest

from typing import List , Dict
from phishguard.schema import EmailRecord
from phishguard.rules.whitelist import rule_whitelist_and_analyse
from phishguard.config import load_config
import copy

# Base EmailRecord used for test cases
BASE_REC = EmailRecord(
    from_display="Support",
    from_addr="support@nus.edu.sg",
    reply_to_addr=None,
    subject="Hello",
    body_text="This is a benign message.",
    body_html=None,
    urls=[], url_display_pairs=[], attachments=[], headers={},
    spf_pass=None, dkim_pass=None, dmarc_pass=None
)

# Example whitelist configuration for testing
EXAMPLE_WHITELIST =  {"rules": {
    "whitelist": {
      "enabled": True,
      "domains": {
        "nus.edu.sg":["meds"],
        "sit.edu.sg":[],
        "microsoft.com":[],
        "google.com":[],
        "paypal.com":[],
        "singpass.gov.sg":[]
      },
      "include_subdomains": "",
      "score_delta_on_match": -0.5
    }
}
                      }


class TestWhitelist(unittest.TestCase):
    # Test whitelist when enabled
    def test_enabled_true(self): # TestCase: Whitelist Check "enabled:true"
        # Take deep copy of EXAMPLE_WHITELIST and modify 'enabled' = True for this test.
        TEST_ENABLED_TRUE: Dict = copy.deepcopy(EXAMPLE_WHITELIST)
        TEST_ENABLED_TRUE['rules']['whitelist']['enabled']  = True
        hit = rule_whitelist_and_analyse(BASE_REC, TEST_ENABLED_TRUE)
        
        # expected -0.5, because Whitelist is enabled and BASE_REC.from_addr is in whitelist
        self.assertEqual(hit.score_delta, -0.5) 
        
        
    # Test whitelist when disabled
    def test_enabled_false(self): # TestCase: Whitelist Check "enabled:false"
        # Take deep copy of EXAMPLE_WHITELIST and modify 'enabled' = False for this test.
        TEST_ENABLED_FALSE: Dict = copy.deepcopy(EXAMPLE_WHITELIST)
        TEST_ENABLED_FALSE['rules']['whitelist']['enabled']  = False
        hit = rule_whitelist_and_analyse(BASE_REC, TEST_ENABLED_FALSE)
        
        # expected 0.0, Whitelist is disabled no checks were done, although BASE_REC.from_addr is in whitelist
        self.assertEqual(hit.score_delta, 0.0)
    
    
    
    # Test whitelist with subdomain matching enabled
    def test_subdomain_enabled(self):  # TestCase: "include_subdomain:enabled" , default checks domain, but does extra check on subdomain
        """
        Tests the way email address of sender will be analyzed, when include_subdomain is ENABLED.
        Different sub test cases of email addresses are used as shown below.
        -0.5 score_delta indicates match found , 0.0 when no match found, 0.0 by default
        """
        
        # Take deep copy of EXAMPLE_WHITELIST and modify 'include_subdomains' = True for this test.
        TEST_SUBDOMAIN_ENABLED: Dict = copy.deepcopy(EXAMPLE_WHITELIST)
        TEST_SUBDOMAIN_ENABLED['rules']['whitelist']['include_subdomains'] = True
        
        # Test cases for various subdomain scenarios
        CS_SUBD_REC = copy.deepcopy(BASE_REC)
        CS_SUBD_REC.from_addr = "support@cs.nus.edu.sg" # subdomain cs not in subdomain list
        
        MEDS_SUBD_REC = copy.deepcopy(BASE_REC)
        MEDS_SUBD_REC.from_addr = "support@meds.nus.edu.sg" # subdomain meds in subdomain list
        
        NONWHITELISTED_DOMAIN = copy.deepcopy(BASE_REC) # subdomain and domain not whitelisted
        NONWHITELISTED_DOMAIN.from_addr = "support@sg.ndu.edu.sg"
        
        INVALID_EMAIL_FORMAT = copy.deepcopy(BASE_REC) # email without @ sign 
        INVALID_EMAIL_FORMAT.from_addr = "asfgoogle.com"
        
        EMPTY_EMAIL = copy.deepcopy(BASE_REC) # email is ""
        EMPTY_EMAIL.from_addr = ""
        
        # Run whitelist checks for each test case
        nosubdomain_hit = rule_whitelist_and_analyse(BASE_REC, TEST_SUBDOMAIN_ENABLED)
        cs_hit = rule_whitelist_and_analyse(CS_SUBD_REC, TEST_SUBDOMAIN_ENABLED)
        meds_hit = rule_whitelist_and_analyse(MEDS_SUBD_REC, TEST_SUBDOMAIN_ENABLED)
        ndu_hit = rule_whitelist_and_analyse(NONWHITELISTED_DOMAIN, TEST_SUBDOMAIN_ENABLED)
        invalid_hit = rule_whitelist_and_analyse(INVALID_EMAIL_FORMAT, TEST_SUBDOMAIN_ENABLED)
        empty_hit = rule_whitelist_and_analyse(EMPTY_EMAIL, TEST_SUBDOMAIN_ENABLED)
        
        # Assert expected results for each scenario
        self.assertEqual(nosubdomain_hit.score_delta, 0.0)   # expected 0.0, BASE_REC.from_addr does NOT contain a subdomain
        self.assertEqual(cs_hit.score_delta, 0.0)            # expected 0.0, CS_SUBD_REC.from_addr subdomain NOT in TEST_SUBDOMAIN_ENABLED
        self.assertEqual(meds_hit.score_delta, -0.5)         # expected -0.5, MEDS_SUBD_REC.from_addr subdomain and domain IN TEST_SUBDOMAIN_ENABLED
        self.assertEqual(ndu_hit.score_delta, 0.0)           # expected 0.0, NONWHITELISTED_DOMAIN.from_addr subdomain and domain NOT in whitelist
        self.assertEqual(invalid_hit.score_delta, 0.0)       # expected 0.0, INVALID_EMAIL_FORMAT.from_addr is invalid format so skip whitelist check and return 
        self.assertEqual(empty_hit.score_delta, 0.0)         # expected 0.0, EMPTY_EMAIL.from_addr is "" so skip whitelist check and return


    # Test whitelist with subdomain matching disabled
    def test_subdomain_disabled(self):  # TestCase: "include_subdomain:disabled" , default checks domain, ignores subdomain
        """
        Tests the way email address of sender will be analyzed, when include_subdomain is DISABLED.
        Different sub test cases of email addresses are used as shown below.
        -0.5 score_delta indicates match found , 0.0 when no match found, 0.0 by default
        """
        
        # Take deep copy of EXAMPLE_WHITELIST and modify 'include_subdomains' = False for this test.
        TEST_SUBDOMAIN_ENABLED: Dict = copy.deepcopy(EXAMPLE_WHITELIST)
        TEST_SUBDOMAIN_ENABLED['rules']['whitelist']['include_subdomains'] = False
        
        # Test cases for various subdomain scenarios
        CS_SUBD_REC = copy.deepcopy(BASE_REC)
        CS_SUBD_REC.from_addr = "support@cs.nus.edu.sg" # subdomain cs not in subdomain list
        
        MEDS_SUBD_REC = copy.deepcopy(BASE_REC)
        MEDS_SUBD_REC.from_addr = "support@meds.nus.edu.sg" # subdomain meds in subdomain list
        
        NONWHITELISTED_DOMAIN = copy.deepcopy(BASE_REC) # subdomain and domain not whitelisted
        NONWHITELISTED_DOMAIN.from_addr = "support@sg.ndu.edu.sg"
        
        INVALID_EMAIL_FORMAT = copy.deepcopy(BASE_REC) # email without @ sign 
        INVALID_EMAIL_FORMAT.from_addr = "asfgoogle.com"
        
        EMPTY_EMAIL = copy.deepcopy(BASE_REC) # email is ""
        EMPTY_EMAIL.from_addr = ""
        
        # Run whitelist checks for each test case
        nosubdomain_hit = rule_whitelist_and_analyse(BASE_REC, TEST_SUBDOMAIN_ENABLED)
        cs_hit = rule_whitelist_and_analyse(CS_SUBD_REC, TEST_SUBDOMAIN_ENABLED)
        meds_hit = rule_whitelist_and_analyse(MEDS_SUBD_REC, TEST_SUBDOMAIN_ENABLED)
        ndu_hit = rule_whitelist_and_analyse(NONWHITELISTED_DOMAIN, TEST_SUBDOMAIN_ENABLED)
        invalid_hit = rule_whitelist_and_analyse(INVALID_EMAIL_FORMAT, TEST_SUBDOMAIN_ENABLED)
        empty_hit = rule_whitelist_and_analyse(EMPTY_EMAIL, TEST_SUBDOMAIN_ENABLED)
        
        # Assert expected results for each scenario
        self.assertEqual(nosubdomain_hit.score_delta, -0.5)   # expected -0.5, BASE_REC.from_addr does NOT contain a subdomain, but domain in TEST_SUBDOMAIN_ENABLED
        self.assertEqual(cs_hit.score_delta, -0.5)            # expected -0.5, CS_SUBD_REC.from_addr subdomain IGNORED, but domain in TEST_SUBDOMAIN_ENABLED
        self.assertEqual(meds_hit.score_delta, -0.5)         # expected -0.5, MEDS_SUBD_REC.from_addr subdomain IGNORED and domain IN TEST_SUBDOMAIN_ENABLED
        self.assertEqual(ndu_hit.score_delta, 0.0)           # expected 0.0, NONWHITELISTED_DOMAIN.from_addr subdomain IGNORED and domain NOT in TEST_SUBDOMAIN_ENABLED
        self.assertEqual(invalid_hit.score_delta, 0.0)       # expected 0.0, INVALID_EMAIL_FORMAT.from_addr is invalid format so skip whitelist check and return 
        self.assertEqual(empty_hit.score_delta, 0.0)         # expected 0.0, EMPTY_EMAIL.from_addr is "" so skip whitelist check and return

        
        
if __name__ == "__main__":
    unittest.main()
