#!/usr/bin/env sh
set -eu
MODEL="${DATASNIPER_MODEL:-qwen3-vl:4b-instruct-q4_K_M}"
if ! command -v ollama >/dev/null 2>&1; then
  case "$(uname -s)" in
    Darwin)
      command -v brew >/dev/null 2>&1 || {
        echo "Homebrew is required to install the private local runtime automatically." >&2
        exit 1
      }
      brew install ollama
      ;;
    Linux)
      command -v curl >/dev/null 2>&1 || {
        echo "curl is required to install the private local runtime automatically." >&2
        exit 1
      }
      installer_file="$(mktemp)"
      trap 'rm -f "$installer_file"' EXIT
      curl --proto '=https' --tlsv1.2 -fsSLo "$installer_file" https://ollama.com/install.sh
      sh "$installer_file"
      ;;
    *)
      echo "This platform is not supported by the automatic installer." >&2
      exit 1
      ;;
  esac
fi
ollama serve >/tmp/datasniper-ollama.log 2>&1 &
ollama list | grep -F "${MODEL%%:*}" >/dev/null 2>&1 || ollama pull "$MODEL"
ollama show "$MODEL" >/dev/null
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
.venv/bin/python -m playwright install chromium
echo "DataSniper is ready. The local intelligence service stays on this computer."
