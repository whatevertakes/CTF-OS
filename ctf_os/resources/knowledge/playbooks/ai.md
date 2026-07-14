# AI playbook

## Scope and first branches

Fingerprint the supplied model, tokenizer, tensor, dataset, or agent source before execution. Branch by artifact family: ONNX graph and operators, PyTorch/state dictionary, HDF5 or numeric arrays, tokenizer/config mismatch, adversarial image preprocessing, embedding reconstruction, or prompt/agent trust boundaries. CPU execution is the default.

## Evidence-led pivots

Inspect metadata with `file`, `strings`, `binwalk`, `protoc`, `h5dump`, and Graphviz before loading it. Prefer `safetensors` and state dictionaries; treat pickle/joblib and full PyTorch objects as untrusted and inspect/load them only inside the restricted sandbox. Use PyTorch, ONNX Runtime, transformers/tokenizers, OpenCV, NumPy, or z3 only when the format and hypothesis justify them. Never download an external model unless it is explicitly approved.

## Validation

Record model hashes, shapes, dtypes, preprocessing, seeds, resource use, and the exact target observation. Use available Docker NVIDIA GPU/CUDA automatically for challenge inference, adversarial generation, inversion, embedding search, and bounded fine-tuning. Unsafe model formats stay inside the sandbox and `trust_remote_code=True` remains forbidden. A target-confirmed flag may be surfaced before a CPU replay.
