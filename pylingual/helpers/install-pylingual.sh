# TODO: consider using venv for pylingual and call
export PYTHONPATH=/var/lib/assemblyline/.local/lib/python3.11/site-packages
export HF_HUB_CACHE=/var/lib/assemblyline/.cache/huggingface/hub
CONFIG_PATH=/helpers/decompiler_config.yaml

for version in 3.8 3.9 3.10 3.11 3.12 3.13; do
    echo "Downloading Pylingual models for Python $version"
    python -c "import pylingual.models; from pathlib import Path; from pylingual.utils.version import PythonVersion; pylingual.models.load_models(Path('$CONFIG_PATH'), PythonVersion($version))"
    if [ $? -ne 0 ]; then
        echo "Failed to download Pylingual models for Python $version"
        exit 1
    fi
done
