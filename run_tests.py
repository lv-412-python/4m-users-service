"""Run tests for users service"""
import os
import unittest
from users_service import COV

def test():
    """Runs the unit tests without test coverage."""
    tests = unittest.TestLoader().discover('users_service/tests', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    return 1

def cov():
    """Runs the unit tests with coverage."""
    tests = unittest.TestLoader().discover('users_service/tests')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        COV.stop()
        COV.save()
        print('Coverage Summary:')
        COV.report()
        basedir = os.path.abspath(os.path.dirname(__file__))
        covdir = os.path.join(basedir, 'tmp/coverage')
        COV.html_report(directory=covdir)
        print('HTML version: file://%s/index.html' % covdir)
        COV.erase()
        return 0
    return 1

cov()
