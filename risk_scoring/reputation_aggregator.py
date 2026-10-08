
import logging
import threading
from typing import Optional, List, Any
from dataclasses import dataclass, field

from risk_scoring.google_safe_browsing import check_url as gsb_check, GSBResult
from risk_scoring.virustotal_client import check_url as vt_check, VTResult

logger = logging.getLogger(__name__)


@dataclass
class ReputationResult:


    gsb_result: Optional[GSBResult] = None
    vt_result: Optional[VTResult] = None


    is_unsafe: bool = False
    tier1_score: float = 0.0
    evidence_strings: List[str] = field(default_factory=list)


    sources_checked: List[str] = field(default_factory=list)
    sources_flagged: List[str] = field(default_factory=list)
    fully_checked: bool = False

    @property
    def evidence_string(self) -> str:
        return self.evidence_strings[0] if self.evidence_strings else ""

    @property
    def badge_text(self) -> str:
        if not self.sources_flagged:
            if not self.fully_checked:
                return "ℹ️ No reputation APIs configured"
            return "✅ Clean (all feeds)"
        n = len(self.sources_flagged)
        sources = " + ".join(self.sources_flagged)
        return f"🚨 Flagged by {sources} ({n} feed{'s' if n > 1 else ''})"


def check_reputation(url: str) -> ReputationResult:
    gsb_result_holder: List[Optional[GSBResult]] = [None]
    vt_result_holder: List[Optional[VTResult]] = [None]
    errors: List[str] = []

    def _run_gsb():
        try:
            gsb_result_holder[0] = gsb_check(url)
        except Exception as e:
            logger.warning(f"Reputation: GSB thread error -- {e}")
            errors.append(f"gsb:{e}")

    def _run_vt():
        try:
            vt_result_holder[0] = vt_check(url)
        except Exception as e:
            logger.warning(f"Reputation: VT thread error -- {e}")
            errors.append(f"vt:{e}")


    t1 = threading.Thread(target=_run_gsb, daemon=True)
    t2 = threading.Thread(target=_run_vt, daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=8)
    t2.join(timeout=10)

    gsb: Optional[GSBResult] = gsb_result_holder[0]
    vt: Optional[VTResult] = vt_result_holder[0]

    return _aggregate(url, gsb, vt)


def _aggregate(url: str, gsb: Optional[GSBResult], vt: Optional[VTResult]) -> ReputationResult:
    result = ReputationResult(gsb_result=gsb, vt_result=vt)


    if gsb is not None:
        result.sources_checked.append("Google Safe Browsing")
    if vt is not None:
        result.sources_checked.append("VirusTotal")

    result.fully_checked = len(result.sources_checked) > 0


    if gsb is not None and gsb.is_unsafe and not gsb.error:
        result.is_unsafe = True
        result.tier1_score = max(result.tier1_score, gsb.tier1_score)
        result.evidence_strings.append(gsb.evidence_string)
        result.sources_flagged.append("Google Safe Browsing")
        logger.warning(f"Reputation: GSB flagged {url} -- {gsb.threat_types}")


    if vt is not None and vt.is_unsafe and not vt.error:
        result.is_unsafe = True
        result.tier1_score = max(result.tier1_score, vt.tier1_score)
        result.evidence_strings.append(vt.evidence_string)
        result.sources_flagged.append("VirusTotal")
        logger.warning(f"Reputation: VT flagged {url} -- {vt.malicious_count} engines")

    elif vt is not None and vt.malicious_count > 0 and not vt.error:

        ev = vt.evidence_string
        if ev:
            result.evidence_strings.append(ev)


    if len(result.sources_flagged) >= 2:
        result.tier1_score = min(result.tier1_score + 5.0, 100.0)
        result.evidence_strings.append(
            "[T1] REPUTATION CONSENSUS: Multiple independent threat feeds confirm this site is unsafe."
        )
        logger.warning(f"Reputation: CONSENSUS unsafe -- {url}")

    logger.debug(
        f"Reputation check for {url}: unsafe={result.is_unsafe} "
        f"score={result.tier1_score:.0f} "
        f"sources_checked={result.sources_checked} "
        f"sources_flagged={result.sources_flagged}"
    )

    return result


def get_all_api_status() -> dict:
    from risk_scoring.google_safe_browsing import get_api_status as gsb_status
    from risk_scoring.virustotal_client import get_api_status as vt_status
    return {
        "google_safe_browsing": gsb_status(),
        "virustotal": vt_status(),
    }