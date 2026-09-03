"""
evaluation/validate_detection.py

Phase 6: Attack Validation -- TPR/FPR of the Phase 4 statistical
detector against every Phase 5 attack simulator.

Purpose
-------
Phase 4's detector is a QBER (quantum bit error rate) threshold test: it
only sees a mismatch_count and asks whether it's abnormally high
relative to a calibrated honest baseline. It can only ever catch things
that produce an ELEVATED mismatch_count -- and only intercept_resend
actually does that as an ongoing property of the attack. The other four
attacks (forgery's two variants, impersonation, replay/key-reuse) each
interact with mismatch_count very differently, and it's worth being
precise about which, because "detection rate" means something different
in each case:

  - intercept_resend: DOES disturb the channel (~1/3 QBER at full
    interception), for every trial, win or lose from Esha's perspective.
    "Detection rate" here means what it normally means: the fraction of
    ongoing attacks correctly flagged. This is the one case where the
    detector is doing real security work.

  - blind forgery: this is where it's easy to overstate the detector's
    blindness. A blind-forgery ATTEMPT that fails (the vast majority --
    per-qubit success is only 1/2, so at any realistic L most attempts
    have mismatch_count near L/2) IS flagged, same as an intercept-
    resend attack would be -- but only because a bad guess looks exactly
    like heavy channel noise, not because the detector recognized a
    forgery attempt specifically. And a blind-forgery attempt that
    SUCCEEDS is, by the very definition of "accepted" (mismatch_count <=
    threshold), never flagged -- flagging and rejection are the same
    check here. So "detection rate" for blind forgery just reproduces
    its (high) rejection rate; it says nothing about resistance to
    forgery beyond what the (1/2)^L-style bound in
    evaluation/security_analysis.py already says on its own.

  - intercepting forgery, impersonation, naive replay, key reuse: each
    of these ALWAYS produces mismatch_count == 0 by construction --
    there is no "attempt that fails and gets flagged" the way blind
    forgery has one. These are the genuinely, unconditionally invisible
    cases: no threshold, no calibration, no amount of statistical
    scrutiny of the disclosed measurement outcomes can ever catch them,
    because nothing about the physical measurement is disturbed at all.

`attack_detectability_summary()` measures all of this directly rather
than asserting it, but interprets blind forgery's number correctly: it
is reported and explained, not held to the same "should be ~0" bar as
the four always-mismatch_count_zero attacks.
"""

from __future__ import annotations
from dataclasses import dataclass
import numpy as np

from core.qds_protocol import generate_key_material, distribute_public_key, sign_bit, verify_bit
from core.noise import apply_depolarizing_noise
from detection.baseline import collect_baseline
from detection.thresholds import DEFAULT_FALSE_REJECT_ALPHA, calibrate_threshold
from attacks.intercept_resend import intercept_resend_attack
from attacks.forgery import blind_forgery_attempt, intercepting_forgery_attempt
from attacks.impersonation import impersonation_attack
from attacks.replay import naive_replay, key_reuse_attack


@dataclass
class SweepPoint:
    intercept_prob: float
    n_trials: int
    detection_rate: float
    mean_mismatch_count: float


def run_intercept_resend_trial(
    L: int,
    intercept_prob: float,
    rng: np.random.Generator,
    channel_noise_p: float = 0.0,
) -> int:
    """
    Runs one full honest-protocol-plus-attack cycle: fresh key material,
    distribution, intercept-resend attack at the given intensity, then
    HONEST signing (Aditi truthfully discloses her real key set -- the
    attack only touched the channel, not Aditi's disclosure) and
    then applies the configured ordinary depolarizing channel to Bharat's
    disclosed-key-set qubits before verification. This matches
    detection.baseline.run_honest_trial(): the channel acts on the
    post-distribution state Bharat holds, after Esha's resend in an attacked
    trial, rather than being added artificially to the final mismatch
    count. Verification uses mismatch_threshold=0 to observe the raw
    (uncalibrated) mismatch count this attack intensity produces.
    """
    km = generate_key_material(L, rng)
    distribute_public_key(km, rng)
    intercept_resend_attack(km, rng, intercept_prob=intercept_prob)
    sig = sign_bit(km, message_bit=0)
    for kq in km.key_set_0:
        kq.bharat_state = apply_depolarizing_noise(
            kq.bharat_state, channel_noise_p, target=0, n_qubits=1, rng=rng
        )
    result = verify_bit(km, sig, rng, mismatch_threshold=0)
    return result.mismatch_count


def sweep_intercept_resend_detection(
    L: int,
    channel_noise_p: float,
    intercept_probs: tuple[float, ...],
    rng: np.random.Generator,
    n_calibration_trials: int = 150,
    n_attack_trials: int = 100,
    alpha: float = DEFAULT_FALSE_REJECT_ALPHA,
) -> list[SweepPoint]:
    """
    Calibrates a detection threshold ONCE from an honest baseline (at
    `channel_noise_p`), then measures detection rate (true positive
    rate against the intercept-resend attack specifically) across a
    range of `intercept_probs` -- from a barely-tapped channel up to
    full interception. The threshold is calibrated a single time, not
    per intercept_prob, since a real detector is calibrated in advance
    from legitimate honest traffic and does not see attack-intensity
    labels during calibration.
    """
    baseline = collect_baseline(L=L, n_trials=n_calibration_trials,
                                 channel_noise_p=channel_noise_p, rng=rng)
    calib = calibrate_threshold(baseline, alpha=alpha)
    threshold = calib["mismatch_threshold"]

    points = []
    for p in intercept_probs:
        mismatch_counts = [
            run_intercept_resend_trial(L, p, rng, channel_noise_p)
            for _ in range(n_attack_trials)
        ]
        flagged = sum(1 for m in mismatch_counts if m > threshold)
        points.append(SweepPoint(
            intercept_prob=p,
            n_trials=n_attack_trials,
            detection_rate=flagged / n_attack_trials,
            mean_mismatch_count=float(np.mean(mismatch_counts)),
        ))
    return points


def minimum_detectable_intercept_prob(
    points: list[SweepPoint], detection_rate_floor: float = 0.5
) -> float | None:
    """
    Given a sweep, returns the smallest intercept_prob at which
    detection_rate reached at least `detection_rate_floor`. Returns
    None if no swept point reached the floor.
    """
    reaching = [pt.intercept_prob for pt in points if pt.detection_rate >= detection_rate_floor]
    return min(reaching) if reaching else None


def attack_detectability_summary(L: int, channel_noise_p: float, rng: np.random.Generator,
                                  alpha: float = DEFAULT_FALSE_REJECT_ALPHA, n_calibration_trials: int = 150,
                                  n_trials_per_attack: int = 50) -> dict[str, float]:
    """
    Calibrates a detector once, then runs every Phase 5 attack (full
    intercept-resend, blind forgery, intercepting forgery, impersonation,
    naive replay, key-reuse) and reports what fraction of each attack's
    ATTEMPTS the QBER-based detector flags (mismatch_count > calibrated
    threshold).

    IMPORTANT interpretation note (see module docstring): "blind_forgery"
    is NOT comparable to the other four numbers. Its detection_rate will
    be HIGH (most random guesses produce heavy mismatch and get flagged,
    same as noise would), and that is expected, not a sign the detector
    is somehow catching forgery attempts specifically -- flagging and
    rejection are the identical check for forgery. The four attacks that
    are actually, unconditionally invisible to this detector --
    intercepting_forgery, impersonation, naive_replay, key_reuse -- will
    each report ~0.0 here, always, regardless of L or threshold, because
    each produces mismatch_count == 0 by construction.
    """
    baseline = collect_baseline(L=L, n_trials=n_calibration_trials,
                                 channel_noise_p=channel_noise_p, rng=rng)
    threshold = calibrate_threshold(baseline, alpha=alpha)["mismatch_threshold"]

    def flagged_fraction(mismatch_counts: list[int]) -> float:
        return sum(1 for m in mismatch_counts if m > threshold) / len(mismatch_counts)

    # Intercept-resend (full interception) -- the one attack that SHOULD
    # be flagged frequently.
    ir_counts = [
        run_intercept_resend_trial(L, 1.0, rng, channel_noise_p)
        for _ in range(n_trials_per_attack)
    ]

    # Blind forgery -- only counts trials where the forgery was accepted
    # (mismatch_count <= threshold by definition of acceptance at small
    # L this may never happen; report mismatch_count regardless, since
    # detectability is about the mismatch signal, not acceptance).
    blind_counts = []
    for _ in range(n_trials_per_attack):
        km = generate_key_material(L, rng)
        distribute_public_key(km, rng)
        sig = blind_forgery_attempt(L=L, message_bit=0, rng=rng)
        blind_counts.append(verify_bit(km, sig, rng, mismatch_threshold=0).mismatch_count)

    # Intercepting forgery -- always mismatch_count == 0 by construction.
    intercept_forge_counts = []
    for _ in range(n_trials_per_attack):
        km = generate_key_material(L, rng)
        distribute_public_key(km, rng)
        sig = intercepting_forgery_attempt(km, message_bit=0, rng=rng)
        intercept_forge_counts.append(verify_bit(km, sig, rng, mismatch_threshold=0).mismatch_count)

    # Impersonation -- always mismatch_count == 0 by construction.
    imperson_counts = []
    for _ in range(n_trials_per_attack):
        attempt = impersonation_attack(L=L, message_bit=0, rng=rng)
        result = verify_bit(attempt.forged_key_material, attempt.forged_signature, rng,
                             mismatch_threshold=0)
        imperson_counts.append(result.mismatch_count)

    # Naive replay -- always mismatch_count == 0 by construction (it's a
    # resubmission of an already-honest signature).
    km_replay = generate_key_material(L, rng)
    distribute_public_key(km_replay, rng)
    captured_sig = sign_bit(km_replay, message_bit=0)
    replay_counts = [
        naive_replay(km_replay, captured_sig, rng).mismatch_count
        for _ in range(n_trials_per_attack)
    ]

    # Key reuse -- both resulting signatures are, individually, honest
    # and valid; the "attack" is the private-key exposure, not a
    # detectable verification event. mismatch_count == 0 for both.
    km_reuse = generate_key_material(L, rng)
    distribute_public_key(km_reuse, rng)
    reuse_counts = []
    for _ in range(n_trials_per_attack):
        exposure = key_reuse_attack(km_reuse, rng)
        reuse_counts.append(
            verify_bit(km_reuse, exposure.sig_bit_0, rng, mismatch_threshold=0).mismatch_count
        )

    return {
        "intercept_resend_full": flagged_fraction(ir_counts),
        "blind_forgery": flagged_fraction(blind_counts),
        "intercepting_forgery": flagged_fraction(intercept_forge_counts),
        "impersonation": flagged_fraction(imperson_counts),
        "naive_replay": flagged_fraction(replay_counts),
        "key_reuse": flagged_fraction(reuse_counts),
    }
