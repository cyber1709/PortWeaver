# Contributing to PortWeaver

Thanks for your interest in improving **PortWeaver** — an AI-assisted, privacy-first Nmap scanner and report generator. Contributions of all sizes are welcome: bug reports, feature requests, docs, and code.

---

## Ground Rules

- **Be legal & ethical.** Only scan assets you own or are authorized to test.
- **Be respectful.** We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to abide by it.
- **Be pragmatic.** Keep changes small, focused, and well-documented.

---

## Ways to Contribute

- 🐛 **Report bugs** – clear steps to reproduce, expected vs actual behavior, OS, Python version, Nmap version.
- 💡 **Request features** – describe the problem, not just the solution; include example CLI/API.
- 🧹 **Improve docs** – clarify setup, examples, or add troubleshooting tips.
- 🧪 **Add tests** (coming soon) – smoke tests and parsers are especially helpful.
- 🧩 **Code contributions** – new enumerations, parsers, prompts, or UX polish.

Open an issue first for large changes to align on scope.

---

## Security

If you discover a **security vulnerability**, **do not** open a public issue. Please create a private report via GitHub **Security Advisories** for this repository, or contact the maintainers through the repo’s security policy if available. We will coordinate a fix and disclosure.

---

## Development Setup

```bash
# 1) Clone
git clone https://github.com/<YOUR_ORG_OR_USER>/PortWeaver.git
cd PortWeaver

# 2) Python (3.9+ recommended) & dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3) System deps
# macOS (Homebrew):
brew install nmap ollama

# 4) Pull at least one local model with Ollama
ollama pull llama3.1
# (optional) more models for A/B:
# ollama pull qwen2.5:7b-instruct

# 5) Run
sudo python scanner.py --mode internal --org "TestLab"
# or:
sudo python scanner.py --mode external --target 192.0.2.0/24 --org "Acme"
