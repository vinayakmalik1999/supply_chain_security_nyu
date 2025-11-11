# Contributing to Rekor Verifier Utility

Thank you for your interest in contributing to this project! This is an educational project for NYU Software Supply Chain Security class.

## Getting Started

### Prerequisites

- Python 3.9
- Git
## Development Workflow

### Before Making Changes

1. **Create a new branch** for your feature or fix
```bash
git checkout -b feature/your-feature-name
```

2. **Understand the codebase** by reviewing:
   - `README.md` - Project overview
   - `SECURITY.md` - Security considerations

### Code Style and Standards

#### Python Style Guide

- Follow PEP 8 style guidelines
- Use descriptive variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and modular

#### Docstring Format

Use Google-style docstrings:

```python
def function_name(param1, param2):
    """
    Brief description of the function.

    Args:
        param1 (type): Description of param1.
        param2 (type): Description of param2.

    Returns:
        type: Description of return value.

    Raises:
        ExceptionType: When this exception occurs.
    """
    pass
```

### Running Code Quality Checks

Before submitting any code, run all quality checks:

#### 1. Ruff (Fast Linter)
```bash
ruff check .
```

Fix auto-fixable issues:
```bash
ruff check --fix .
```

#### 2. Pylint
```bash
pylint .
```

Aim for a score of 9.0 or higher.

#### 3. Mypy (Type Checking)
```bash
mypy main.py util.py merkle_proof.py
```

All type errors should be resolved.

#### 4. Bandit (Security Analysis)
```bash
bandit -r .
```

Address any security issues identified.

### Testing Your Changes

#### Manual Testing

Test the main workflows:

**1. Fetch checkpoint**
```bash
python main.py --checkpoint
```

**2. Verify inclusion**
```bash
python main.py --inclusion <log-index> --artifact artifact.md
```

**3. Verify consistency**
```bash
python main.py --consistency --tree-id <tree-id> --tree-size <tree-size> --root-hash <root-hash>
```

**4. Debug mode**
```bash
python main.py --debug --checkpoint
```

#### Test Edge Cases

- Invalid log indices
- Missing or corrupted artifact files
- Malformed checkpoint data
- Network failures (can simulate with invalid URLs)

## Commit Guidelines

### Commit Message Format

Use clear, descriptive commit messages:

```
<type>: <short summary>

<detailed description if needed>
```

**Types:**
- `feature`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests

**Examples:**
```
feature: add support for batch verification of multiple artifacts

fix: handle timeout errors in Rekor API calls gracefully

docs: update SECURITY.md with new policy

refactor: extract certificate parsing into separate function
```

### Commit Best Practices

- Keep commits atomic (one logical change per commit)
- Write meaningful commit messages
- Reference issues if applicable (e.g., "Fixes #123")

## Pull Request Process

### Before Submitting

1. ✅ All linters pass (ruff, pylint, mypy, bandit)
2. ✅ Code is manually tested
3. ✅ Docstrings are up to date
4. ✅ No debug print statements left in code
5. ✅ Branch is up to date with main

### Creating a Pull Request

1. **Push your branch**
```bash
git push origin feature/your-feature-name
```

2. **Open a Pull Request** with:
   - Clear title describing the change
   - Description of what was changed and why
   - Any breaking changes highlighted
   - Screenshots/output if relevant

3. **PR Description Template**
```markdown
## Description
Brief description of changes

## Changes Made
- Change 1
- Change 2

## Testing
How the changes were tested

## Checklist
- [ ] Code passes all linters
- [ ] Manually tested
- [ ] Documentation updated
- [ ] Security considerations addressed
```

## Code Review Guidelines

- Be responsive to feedback
- Keep discussions constructive
- Update PR based on review comments
- Ask questions if feedback is unclear

## Security Contributions

Security is critical for this project. When contributing:

1. **Never commit secrets** or API keys
2. **Validate all inputs** from users and external APIs
3. **Use constant-time comparisons** for cryptographic values
4. **Handle exceptions** gracefully without leaking sensitive info
5. **Review SECURITY.md** before working on crypto code

Report security vulnerabilities privately (see SECURITY.md).

## Questions or Help?

- Review existing documentation: `README.md`, `SECURITY.md`
- Open an issue for discussion

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

Thank you for contributing! 🎉
