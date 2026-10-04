import pytest
from pathlib import Path
from codegate.config import load_config, CodeGateConfig

REPO_ROOT = Path(__file__).resolve().parents[1]

def test_load_config_returns_dataclass():
    cfg = load_config(str(REPO_ROOT / "config.yaml"))
    assert isinstance(cfg, CodeGateConfig)

def test_load_config_values():
    cfg = load_config(str(REPO_ROOT / "config.yaml"))
    assert cfg.alpha == 0.05
    assert cfg.delta == 0.05
    assert "CWE-89" in cfg.cwes
    assert len(cfg.generators) == 4

def test_load_config_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        load_config("does_not_exist.yaml")

def test_load_config_ignores_a_leftover_adjudicator_key(tmp_path):
    """
    The adjudicator was declared and validated but never called. The field
    is gone; an old config file carrying it must still load.
    """
    cfg_path = tmp_path / "legacy_config.yaml"
    cfg_path.write_text(
        "alpha: 0.05\ndelta: 0.05\nrandom_seed: 1\n"
        "cwes: [CWE-89]\nflavors: [vulnerable]\n"
        "generators: [model-a]\nadjudicator: model-a\nverifier: model-b\n"
        "samples_per_prompt: 1\nprompts_per_cwe: 1\n"
        "paths: {prompts_dir: x, fixtures_dir: y, runs_dir: z}\n"
    )
    cfg = load_config(str(cfg_path))
    assert not hasattr(cfg, "adjudicator")


def test_load_config_ignores_a_leftover_split_ratios_key(tmp_path):
    """
    `split_ratios` was parsed and validated but read by nothing -- splits
    come from each task group's `split:` key in the prompt YAML. The field
    is gone; an old config file carrying it must still load rather than
    crash, since the key is inert either way.
    """
    cfg_path = tmp_path / "legacy_config.yaml"
    cfg_path.write_text(
        "alpha: 0.05\ndelta: 0.05\nrandom_seed: 1\n"
        "cwes: [CWE-89]\nflavors: [vulnerable]\n"
        "generators: [model-a]\nadjudicator: model-b\nverifier: model-c\n"
        "samples_per_prompt: 1\nprompts_per_cwe: 1\n"
        "split_ratios: {train: 0.4, calib: 0.3, test: 0.3}\n"
        "paths: {prompts_dir: x, fixtures_dir: y, runs_dir: z}\n"
    )
    cfg = load_config(str(cfg_path))
    assert cfg.prompts_per_cwe == 1
    assert not hasattr(cfg, "split_ratios")
