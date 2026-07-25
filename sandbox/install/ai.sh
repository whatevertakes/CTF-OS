#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

apt_install protobuf-compiler libprotobuf-dev hdf5-tools netcdf-bin graphviz libgl1 libglib2.0-0
pip_install_locked /opt/ctf-os/requirements-lock/ai.txt
pip_install_locked \
  /opt/ctf-os/requirements-lock/torch-cu126.txt \
  --index-url https://download.pytorch.org/whl/cu126

for command in protoc h5dump ncdump dot jupyter; do require_command "$command"; done
for module in torch torchvision sklearn onnx onnxruntime transformers tokenizers sentencepiece safetensors datasets joblib cv2 pandas; do require_import "$module"; done
python3 - <<'PY'
import numpy as np
import onnx
import onnxruntime as ort
import torch
from onnx import TensorProto, helper
assert torch.version.cuda is not None
assert torch.tensor([2, 3]).sum().item() == 5
node = helper.make_node("Identity", ["x"], ["y"])
graph = helper.make_graph([node], "smoke", [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1])], [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1])])
model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)], ir_version=9)
session = ort.InferenceSession(model.SerializeToString(), providers=["CPUExecutionProvider"])
assert session.run(None, {"x": np.array([7], dtype=np.float32)})[0][0] == 7
PY
