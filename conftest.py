"""Pytest configuration for the entire test suite."""

import logging


def pytest_configure(config):
    """Suppress noisy PyMongo debug logging during test cleanup."""
    logging.getLogger("pymongo").setLevel(logging.WARNING)
