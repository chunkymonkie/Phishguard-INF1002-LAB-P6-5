import argparse, json
from pathlib import Path

import sys

from phishguard.config import load_config
from phishguard.rules import *
from phishguard.pipeline.evaluate import *
from phishguard.pipeline.evaluate import evaluate_email_file
from phishguard.normalize.parse_mime import *
from phishguard.features.extractors import *
from phishguard.schema import EmailRecord
from phishguard.reporting.writers import write_json_results, write_csv_results
from phishguard.storage.storage import *

def launch_gui():
    """Launch the PhishGuard GUI application"""
    try:
        # Import GUI components
        import tkinter as tk
        from phishguard.app.ui import PhishingDetectorGUI
        
        print("🚀 Starting PhishGuard GUI...")
        
        # Create and run GUI
        root = tk.Tk()
        PhishingDetectorGUI(root)
        
        print("✅ GUI initialized successfully")
        print("📱 Application ready for use")
        
        root.mainloop()
        
    except ImportError as e:
        # Handle missing GUI dependencies
        print(f"❌ GUI dependencies not available: {e}", file=sys.stderr)
        print("Install tkinter or run in CLI mode", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        # Handle other GUI startup errors
        print(f"❌ Failed to start GUI: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    # Set up command-line argument parser
    ap = argparse.ArgumentParser("phishguard")
    ap.add_argument("--eml", help="Path to a single .eml or raw email")
    ap.add_argument("--record-json", help="Path to an EmailRecord JSON")
    ap.add_argument("--folder", help="Evaluate all .eml/raw files under this folder")
    ap.add_argument("--out-json", help="Write a JSON result file (single input) to this path")
    ap.add_argument("--out-csv", help="Write a CSV file (batch) to this path")
    ap.add_argument("--storage", help="Save results using EmailReportManager with timestamped files")
    ap.add_argument("--storage-dir", help="Directory for storage output (default: ./outPutResult)")
    ap.add_argument("--gui", help ="# Launch graphical interface")

    args = ap.parse_args()
    
    # Launch the GUI if requested
    if args.gui:
        launch_gui()
        return

    if not (args.eml or args.record_json or args.folder):
        print("Use --eml or --record_json or --folder to indicate path of input file/folder or --help")
        return 
    

    print(ap)  # Debug: print the argument parser

    # Load configuration for evaluation
    CFG = load_config()

    # Evaluate a single .eml or raw email file
    if args.eml:
        results = evaluate_email_file(args.eml, RULES, CFG)
        file_id, score, label, hits = results[0]

        # Prepare result payload
        payload = {
            "file_path": str(file_id),
            "classification": label,
            "total_score": score,
            "rule_hits": [
                {
                    "rule_name": h.rule_name,
                    "passed": h.passed,
                    "score_delta": h.score_delta,
                    "severity": getattr(h.severity, "name", str(h.severity)),
                    "details": h.details,
                }
                for h in hits
            ],
        }

        # Output results: storage, JSON, or print
        if args.storage:
            # Use EmailReportManager for storage
            storage_dir = args.storage_dir or "./outPutResult"
            manager = EmailReportManager(base_name=args.storage, output_dir=storage_dir)
            manager.save([payload])
        elif args.out_json:
            write_json_results(payload, args.out_json)
        else:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
        # rec = EmailRecord(**data)  # Unused variable removed

        results = evaluate_email_file_dict(args.record_json, RULES, CFG)
        
        # Output results: storage, JSON, or print
        rec = EmailRecord(**data)

        results = evaluate_email_file_dict(args.record_json, RULES, CFG)
        
        # Output results: storage, JSON, or print
        if args.storage:
            storage_dir = args.storage_dir or "./outPutResult"
            manager = EmailReportManager(base_name=args.storage, output_dir=storage_dir)
            manager.save(results)
        elif args.out_json:
            write_json_results(results, args.out_json)
        else:
            print(json.dumps(results, ensure_ascii=False, indent=2))
        return

    # Batch evaluate all emails in a folder
    if args.folder:
        results = evaluate_email_file_dict(args.folder, RULES, CFG)
        
        # Output results: storage or CSV
        if args.storage:
            storage_dir = args.storage_dir or "./outPutResult"
            manager = EmailReportManager(base_name=args.storage, output_dir=storage_dir)
            manager.save(results)
        else:
            out = args.out_csv or "results.csv"
            Path(out).parent.mkdir(parents=True, exist_ok = True)
            write_csv_results(results, Path(out))
            print(f"Wrote {out} with {len(results)} rows.")
        return
    
    # Launch the GUI if requested
    if args.gui:
        launch_gui()
        return

if __name__ == "__main__":
    main()
