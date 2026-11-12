# Contributing to Aegis Security Scanner

Thank you for your interest in contributing!

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Development Setup

### Scanner (Python)
```bash
pip install -e .
pip install pytest
pytest tests/
```

### VS Code Extension
```bash
cd vscode-extension
npm install
npm run compile
# Press F5 in VS Code to test
```

## Adding Security Patterns

1. Edit `aegis.py`
2. Add patterns to the appropriate section (js_patterns, tf_patterns, etc.)
3. Add fix suggestion to FIX_SUGGESTIONS dict
4. Test on sample code

## Code Style

- Python: Follow PEP 8
- JavaScript: Use ESLint defaults
- Add docstrings and comments

## Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- Tag issues appropriately

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
