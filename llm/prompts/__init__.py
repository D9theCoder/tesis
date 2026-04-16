"""LLM prompts package — one prompt file per agent."""

from .brute_prompt import build_brute_prompt
from .cmdi_prompt import build_cmdi_prompt
from .csrf_prompt import build_csrf_prompt
from .idor_prompt import build_idor_prompt
from .lfi_prompt import build_lfi_prompt
from .lfi_to_rce_chain_prompt import build_lfi_to_rce_chain_prompt
from .orchestrator_prompt import build_orchestrator_prompt
from .sqli_blind_prompt import build_sqli_blind_prompt
from .sqli_prompt import build_sqli_prompt
from .sqli_to_creds_chain_prompt import build_sqli_to_creds_chain_prompt
from .upload_prompt import build_upload_prompt
from .upload_to_rce_chain_prompt import build_upload_to_rce_chain_prompt
from .weak_session_prompt import build_weak_session_prompt
from .xss_dom_prompt import build_xss_dom_prompt
from .xss_reflected_prompt import build_xss_reflected_prompt
from .xss_stored_prompt import build_xss_stored_prompt
from .xss_to_csrf_chain_prompt import build_xss_to_csrf_chain_prompt

__all__ = [
	"build_orchestrator_prompt",
	"build_sqli_prompt",
	"build_sqli_blind_prompt",
	"build_xss_reflected_prompt",
	"build_xss_stored_prompt",
	"build_xss_dom_prompt",
	"build_cmdi_prompt",
	"build_brute_prompt",
	"build_lfi_prompt",
	"build_upload_prompt",
	"build_csrf_prompt",
	"build_weak_session_prompt",
	"build_idor_prompt",
	"build_sqli_to_creds_chain_prompt",
	"build_upload_to_rce_chain_prompt",
	"build_xss_to_csrf_chain_prompt",
	"build_lfi_to_rce_chain_prompt",
]
