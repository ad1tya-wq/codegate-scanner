import json
import pandas as pd
import pytest
from codegate.gate.ltt import LTTResult
from codegate.ranker.r2_embedding_lr import R2Ranker
from codegate.research.artifacts import (
    ArtifactVersionError,
    UncertifiedAlphaError,
    load_artifacts,
    load_calibration,
    load_model,
    save_calibration,
    save_model,
)


def _fitted_ranker() -> R2Ranker:
    gens = pd.DataFrame({
        "sample_id": ["s1", "s2"],
        "code": [
            "def f(conn, u):\n    return conn.execute(\"SELECT * FROM t WHERE c='\" + u + \"'\")\n",
            "def f(conn, u):\n    return conn.execute('SELECT * FROM t WHERE c=?', (u,))\n",
        ],
    })
    labels = pd.Series([1, 0], index=gens.index)
    return R2Ranker(random_seed=0).fit(gens, labels)


def _ltt_result(t_hat: float | None = 0.5) -> LTTResult:
    return LTTResult(
        t_hat=t_hat, alpha=0.05, delta=0.05, n_vuln_calib=10, coverage=0.6,
        trace=[(1.0, 0, 0.001, True), (0.5, 1, 0.02, True)],
    )


def test_save_and_load_model_round_trips(tmp_path):
    ranker = _fitted_ranker()
    path = tmp_path / "model.joblib"
    save_model(ranker, path)
    loaded = load_model(path)

    gens = pd.DataFrame({"sample_id": ["s1"], "code": ["def f(x):\n    return x\n"]})
    pd.testing.assert_frame_equal(ranker.score(gens), loaded.score(gens))


def test_load_model_missing_file_raises_actionable_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="codegate calibrate"):
        load_model(tmp_path / "does_not_exist.joblib")


def test_save_and_load_calibration_round_trips(tmp_path):
    path = tmp_path / "calibration.json"
    save_calibration(
        _ltt_result(), path, corpus_version="simulated-v2", is_provisional=True,
    )
    calib = load_calibration(path)

    assert calib.t_hat == 0.5
    assert calib.alpha == 0.05
    assert calib.delta == 0.05
    assert calib.n_vuln_calib == 10
    assert calib.ranker_id == "R2"
    assert calib.corpus_version == "simulated-v2"
    assert calib.is_provisional is True
    assert calib.created_at  # non-empty timestamp string


def test_calibration_file_is_readable_json_with_expected_keys(tmp_path):
    path = tmp_path / "calibration.json"
    save_calibration(_ltt_result(), path, corpus_version="real-540", is_provisional=False)
    raw = json.loads(path.read_text())
    assert set(raw) == {
        "t_hat", "alpha", "delta", "n_vuln_calib", "ranker_id",
        "corpus_version", "is_provisional", "created_at",
        "frontier",   # added 2026-10-04 for scan-time --alpha
        "method", "n_vuln_groups",   # added 2026-10-04 with the cluster-aware certificate
    }
    assert raw["is_provisional"] is False


def test_save_calibration_handles_uncertified_none_t_hat(tmp_path):
    path = tmp_path / "calibration.json"
    save_calibration(_ltt_result(t_hat=None), path, corpus_version="simulated-v2", is_provisional=True)
    calib = load_calibration(path)
    assert calib.t_hat is None


def test_load_calibration_missing_file_raises_actionable_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="codegate calibrate"):
        load_calibration(tmp_path / "does_not_exist.json")


def test_load_artifacts_returns_matching_pair(tmp_path):
    ranker = _fitted_ranker()
    model_path = tmp_path / "model.joblib"
    calib_path = tmp_path / "calibration.json"
    save_model(ranker, model_path)
    save_calibration(_ltt_result(), calib_path, corpus_version="simulated-v2", is_provisional=True)

    loaded_ranker, loaded_calib = load_artifacts(model_path, calib_path)
    assert loaded_ranker.RANKER_ID == "R2"
    assert loaded_calib.ranker_id == "R2"


def test_load_artifacts_rejects_ranker_id_mismatch(tmp_path):
    ranker = _fitted_ranker()
    model_path = tmp_path / "model.joblib"
    calib_path = tmp_path / "calibration.json"
    save_model(ranker, model_path)
    save_calibration(
        _ltt_result(), calib_path,
        corpus_version="simulated-v2", is_provisional=True, ranker_id="R0",
    )

    with pytest.raises(ArtifactVersionError, match="R0"):
        load_artifacts(model_path, calib_path)


# --- per-alpha thresholds (scan-time --alpha) -----------------------------------

_FRONTIER = pd.DataFrame({
    "alpha": [0.05, 0.10, 0.20],
    "t_hat": [0.66, 0.61, None],          # 0.20 deliberately uncertified
    "coverage": [0.50, 0.58, 0.0],
    "n_vuln_calib": [120, 120, 120],
})


def test_calibration_round_trips_its_frontier(tmp_path):
    path = tmp_path / "calibration.json"
    save_calibration(_ltt_result(), path, corpus_version="real-2160",
                     is_provisional=False, frontier=_FRONTIER)
    calib = load_calibration(path)
    assert [row["alpha"] for row in calib.frontier] == [0.05, 0.10, 0.20]
    assert calib.frontier[2]["t_hat"] is None


def test_at_alpha_returns_the_certified_threshold_for_that_alpha(tmp_path):
    path = tmp_path / "calibration.json"
    save_calibration(_ltt_result(), path, corpus_version="real-2160",
                     is_provisional=False, frontier=_FRONTIER)
    calib = load_calibration(path)
    at10 = calib.at_alpha(0.10)
    assert at10.alpha == 0.10 and at10.t_hat == 0.61
    assert calib.at_alpha(0.05) == calib            # the operating point itself


@pytest.mark.parametrize("alpha", [0.20, 0.42])    # uncertified, and never computed
def test_at_alpha_refuses_rather_than_interpolating(tmp_path, alpha):
    path = tmp_path / "calibration.json"
    save_calibration(_ltt_result(), path, corpus_version="real-2160",
                     is_provisional=False, frontier=_FRONTIER)
    with pytest.raises(UncertifiedAlphaError) as exc:
        load_calibration(path).at_alpha(alpha)
    assert exc.value.certified == [0.05, 0.10]


def test_a_calibration_written_before_frontiers_still_loads(tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(
        '{"t_hat": 0.66, "alpha": 0.05, "delta": 0.05, "n_vuln_calib": 60, "ranker_id": "R2", '
        '"corpus_version": "simulated-v2", "is_provisional": true, "created_at": "2026-09-01"}'
    )
    calib = load_calibration(path)
    assert calib.frontier == []
    assert calib.at_alpha(0.05).t_hat == 0.66
    with pytest.raises(UncertifiedAlphaError):
        calib.at_alpha(0.10)


def test_calibration_records_the_certificate_method_and_group_count(tmp_path):
    path = tmp_path / "calibration.json"
    grouped = LTTResult(t_hat=0.8, alpha=0.10, delta=0.05, n_vuln_calib=206, coverage=0.49,
                        trace=[], method="cluster-hb", n_vuln_groups=66)
    save_calibration(grouped, path, corpus_version="real-2040-sym", is_provisional=False)
    calib = load_calibration(path)
    assert calib.method == "cluster-hb" and calib.n_vuln_groups == 66


def test_a_calibration_written_before_methods_reads_as_sample_binomial(tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(
        '{"t_hat": 0.66, "alpha": 0.05, "delta": 0.05, "n_vuln_calib": 60, "ranker_id": "R2", '
        '"corpus_version": "simulated-v2", "is_provisional": true, "created_at": "2026-09-01"}'
    )
    calib = load_calibration(path)
    assert calib.method == "sample-binomial" and calib.n_vuln_groups is None
