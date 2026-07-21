import subprocess
import sys

import pytest


def test_ctf_mode_reexports_the_neutral_shared_contracts() -> None:
    from pajin.domain.ctf import CTFInlineArtifact as DomainInlineArtifact
    from pajin.domain.ctf import CTFScenario as DomainScenario
    from pajin.modes.ctf import CTFInlineArtifact as PublicInlineArtifact
    from pajin.modes.ctf import CTFScenario as PublicScenario
    from pajin.modes.ctf.models import CTFInlineArtifact as ModeInlineArtifact
    from pajin.modes.ctf.models import CTFScenario as ModeScenario

    assert PublicScenario is ModeScenario is DomainScenario
    assert PublicInlineArtifact is ModeInlineArtifact is DomainInlineArtifact


@pytest.mark.parametrize(
    "script",
    [
        (
            "import sys; "
            "from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool; "
            "assert 'pajin.modes.ctf' not in sys.modules; "
            "assert 'pajin.modes.ctf.models' not in sys.modules; "
            "assert CTFCryptoXORTool.spec.tool_id == 'ctf.crypto-single-byte-xor'; "
            "assert CTFWebBackupProbeTool.spec.tool_id == 'ctf.web-backup-probe'"
        ),
        (
            "from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool; "
            "from pajin.modes.ctf import CTFChallengeService, CTFFlagValidatorRuntime; "
            "assert CTFCryptoXORTool.spec.tool_id == 'ctf.crypto-single-byte-xor'; "
            "assert CTFWebBackupProbeTool.spec.tool_id == 'ctf.web-backup-probe'; "
            "assert CTFChallengeService.__name__ == 'CTFChallengeService'; "
            "assert CTFFlagValidatorRuntime.__name__ == 'CTFFlagValidatorRuntime'"
        ),
        (
            "from pajin.modes.ctf import CTFChallengeService, CTFFlagValidatorRuntime; "
            "from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool; "
            "assert CTFChallengeService.__name__ == 'CTFChallengeService'; "
            "assert CTFFlagValidatorRuntime.__name__ == 'CTFFlagValidatorRuntime'; "
            "assert CTFCryptoXORTool.spec.tool_id == 'ctf.crypto-single-byte-xor'; "
            "assert CTFWebBackupProbeTool.spec.tool_id == 'ctf.web-backup-probe'"
        ),
    ],
    ids=["tool-layer-is-independent", "tools-first", "mode-first"],
)
def test_ctf_public_modules_are_import_order_independent(script: str) -> None:
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
