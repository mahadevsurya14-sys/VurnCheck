import logging
import sys

LOGGER_NAME = "VurnCheck"

def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(logging.INFO)
    return logger

def setup_logger_level(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    for name in [LOGGER_NAME, "VurnCheckRunner", "Crawler", "HTTPClient", "Scanner", "SQLiScanner", "XSSScanner", "DOMXSSScanner", "HeaderScanner", "DisclosureScanner"]:
        get_logger(name).setLevel(level)
