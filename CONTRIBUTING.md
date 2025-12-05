# Contributing to SHULUT Scanner

Thank you for contributing to SHULUT 2.0 Scanner! We appreciate your help in making this project better.

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Help others learn
- Report security issues responsibly

## How to Contribute

### 1. Fork & Clone

```bash
git clone https://github.com/yourusername/shulut-scanner.git
cd shulut-scanner
git remote add upstream https://github.com/original/shulut-scanner.git
```

### 2. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 3. Make Changes

- Follow existing code style
- Add tests for new features
- Update documentation
- Run tests locally

### 4. Commit & Push

```bash
git commit -m "feat: describe your change"
git push origin feature/your-feature-name
```

### 5. Create Pull Request

- Provide clear description
- Reference related issues
- Ensure CI/CD passes

## Development Setup

```bash
# Install dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v --cov

# Run linter
flake8 shulut_detector.py

# Run security check
bandit -r .
```

## Contribution Areas

### High Priority
- [ ] Additional detection signatures
- [ ] Performance optimizations
- [ ] Cross-platform testing
- [ ] Documentation improvements

### Medium Priority
- [ ] Language translations
- [ ] Tool integrations
- [ ] Example scenarios
- [ ] Video tutorials

### Welcome Contributions
- Bug fixes
- Documentation typos
- Test coverage
- Code refactoring

## Testing Requirements

All contributions must include:
- Unit tests for new features
- Integration tests if applicable
- Code coverage > 80%
- All existing tests passing

## Code Style

- Follow PEP 8
- Use type hints
- Document functions with docstrings
- Keep lines < 100 characters

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open a GitHub discussion
- Create an issue for questions
- Check existing documentation

Thank you! 🙏
