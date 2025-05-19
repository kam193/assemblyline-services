# Pyenv is required for pylingual
echo "Installing pyenv"
export PYENV_ROOT="/var/lib/assemblyline/.pyenv"
curl -fsSL https://pyenv.run | bash

# 3.8 3.9 3.10 3.11 3.12 3.13
for version in 3.8 3.9 3.10 3.11 3.12 3.13; do
    echo "Installing Python $version"
    PATH=/var/lib/assemblyline/.pyenv/bin:$PATH pyenv install $version || (cat /tmp/python-build.*.log && false)
done
