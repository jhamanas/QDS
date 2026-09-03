# Reproducibility and Evaluation Record

Run the complete test suite from the repository root with:

```powershell
Get-ChildItem tests/test_*.py | ForEach-Object { python $_.FullName }
```

Regenerate the checked-in evaluation outputs with a fixed seed:

```powershell
python -m evaluation.regenerate_results
```

This command writes `results/detection_results.json`,
`results/security_analysis.json`, `results/performance_benchmark.csv`, and
`results/reproducibility.json`. The provenance file records the UTC generation
time, Git commit, Python and NumPy versions, operating system, CPU identifier,
seed, trial counts, and SHA-256 digests of the generated artifacts.

The default evaluation is a simulator experiment: `L=64`, independent Pauli
channel noise `p=0.03`, and a fixed NumPy seed of `20260903`. For the Pauli
trajectory model, the same-basis honest mismatch probability is `2p/3`.
Attack trials receive the same ordinary channel noise as calibration trials;
attack intensity is varied separately. Benchmarks are machine-specific and
must be compared only with their recorded provenance.
