"""Evidence isolation, signal matching and CAPTCHA boundary regressions."""

from foundation.verifier import Verifier, has_captcha_challenge


class TestVerifierBehavior:
    """Validate Stage 5 verifier behavior."""

    def test_contains_any_detects_signals_case_insensitive(self):
        """Verifies contains any detects signals case insensitive behavior."""
        v = Verifier()
        result = v.contains_any("Warning: MySQL syntax error", ["mysql", "oracle"])
        assert result.ok is True
        assert "mysql" in [item.lower() for item in result.evidence]


def test_captcha_detector_requires_a_challenge_control():
    """A CAPTCHA form control is classified as an out-of-scope boundary."""
    html = """
    <form><label>Enter CAPTCHA</label>
      <input name='captcha' type='text'><input name='Login' type='submit'>
    </form>
    """
    assert has_captcha_challenge(html) is True
