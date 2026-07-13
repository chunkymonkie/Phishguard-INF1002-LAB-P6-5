import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from phishguard.reporting import writers  


class EmailReportManager:
    """
    Manages saving evaluation results into timestamped JSON/CSV files.
    Uses writers.py under the hood for actual serialization.
    """

    #==========================================
    #           Initialization                =
    #==========================================
    def __init__(self, base_name: str = "results", output_dir: Optional[str] = None):
        """
        Initializes the EmailReportManager.

        Args:
            base_name (str): Base name for the output files.
            output_dir (Optional[str]): Directory to save the output files. Defaults to ./outPutResult.
        """
        if output_dir is None:
            output_dir = os.path.join(os.getcwd(), "outPutResult")
        os.makedirs(output_dir, exist_ok=True)

        # Create a timestamp for unique file naming
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_path = Path(output_dir) / f"{base_name}_{timestamp}"

        # Set file paths for JSON and CSV outputs
        self.json_path = self.base_path.with_suffix(".json")
        self.csv_path = self.base_path.with_suffix(".csv")

    #==========================================
    #           Save Results                  =
    #==========================================
    def save(self, results: List[Dict[str, Any]], formats: List[str] = ["json", "csv"]) -> bool:
        """
        Save results in requested formats (default: both JSON and CSV).

        Args:
            results (List[Dict[str, Any]]): The evaluation results to save.
            formats (List[str]): List of formats to save ('json', 'csv').

        Returns:
            bool: True if all saves succeeded, False otherwise.
        """
        success = True
        for fmt in formats:
            # Choose the correct file path based on format
            target = self.json_path if fmt == "json" else self.csv_path
            ok = writers.write_results(results, str(target), format=fmt)
            if not ok:
                print(f"[!] Failed to write {fmt} results to {target}")
                success = False
            else:
                print(f"[+] Saved {fmt.upper()} results -> {target}")
        return success
