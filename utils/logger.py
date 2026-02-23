import logging
import json
import os
from datetime import datetime

def setup_logger(name):
    """Configures and returns a logger instance."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

def write_json_report(filename, data, subdirectory=None):
    """Writes data to a JSON file in the outputs directory with optional subdirectory and timestamping."""
    output_dir = os.path.join(os.getcwd(), 'outputs')
    
    # Add subdirectory if provided (e.g., 'diagnostic')
    if subdirectory:
        output_dir = os.path.join(output_dir, subdirectory)
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Generate timestamped filename if filename doesn't already include a timestamp
    if not any(char.isdigit() for char in filename):
        # Extract base name and extension
        name, ext = os.path.splitext(filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}{ext}"
    
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
        
    return filepath
