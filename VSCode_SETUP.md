# VSCode/Cursor Setup Guide

This is a quick reference for setting up and using VSCode/Cursor with the app-size-analyzer project.

## 🚀 Quick Setup

1. **Open the project:**

   ```bash
   code app-size-analyzer.code-workspace
   # OR
   code .
   ```

2. **Install recommended extensions** (when prompted)

3. **Setup development environment:**

   ```bash
   make dev-setup
   ```

4. **Select Python interpreter:** `Ctrl+Shift+P` → "Python: Select Interpreter" → `./venv/bin/python`

## 🐛 Debug Configurations

| Configuration                 | Purpose                      | Arguments                                                                   |
| ----------------------------- | ---------------------------- | --------------------------------------------------------------------------- |
| Debug CLI: Help               | Test basic CLI functionality | `--help`                                                                    |
| Debug CLI: Analyze iOS Sample | Debug with sample artifact   | `analyze --input tests/artifacts/sample.ipa --output output.json --verbose` |
| Debug CLI: Custom Arguments   | Debug with your own args     | `[]` (prompts for input)                                                    |
| Debug Current Test File       | Debug currently open test    | Current file                                                                |
| Debug Specific Test           | Debug by test name pattern   | Prompts for test name                                                       |
| Debug All Tests               | Debug entire test suite      | All tests                                                                   |

## 🧪 Running Tests in Test Explorer

1. **Open Test Explorer:** `View → Test → Show Test Explorer`
2. **Discover tests:** Tests are auto-discovered from `tests/` directory
3. **Run tests:** Click ▶️ next to test/suite
4. **Debug tests:** Right-click → "Debug Test"
5. **Filter tests:** Use test markers (`unit`, `integration`, `slow`, `cli`)

## ⚡ Available Tasks

Access via `Ctrl+Shift+P` → "Tasks: Run Task":

### Development Tasks

- **Setup Development Environment** - Initial project setup
- **Run CLI Tool** - Execute CLI with custom arguments

### Testing Tasks

- **Run All Tests** - Complete test suite
- **Run Unit Tests** - Unit tests only
- **Run Integration Tests** - Integration tests only
- **Run Tests with Coverage** - Tests + coverage report

### Code Quality Tasks

- **Lint Code** - flake8, isort, black checks
- **Format Code** - Auto-format code
- **Type Check** - mypy type checking

### Build Tasks

- **Build Package** - Create wheel + source dist
- **Run CI Pipeline** - Full CI locally
- **Clean Build Artifacts** - Cleanup

## 📊 Test Coverage

1. **Generate coverage:**

   ```bash
   make test-coverage
   ```

2. **View in VSCode:**
   - Install "Coverage Gutters" extension
   - `Ctrl+Shift+P` → "Coverage Gutters: Display Coverage"
   - See green/red indicators in editor gutter

## 🔧 Configuration Files

| File                               | Purpose                 |
| ---------------------------------- | ----------------------- |
| `.vscode/launch.json`              | Debug configurations    |
| `.vscode/settings.json`            | Workspace settings      |
| `.vscode/tasks.json`               | Build/test tasks        |
| `.vscode/extensions.json`          | Recommended extensions  |
| `app-size-analyzer.code-workspace` | Complete workspace file |
| `pytest.ini`                       | Pytest configuration    |

## 🎯 Key Features Enabled

- ✅ **Auto-formatting** on save (Black + isort)
- ✅ **Real-time linting** (flake8)
- ✅ **Type checking** (mypy)
- ✅ **Test discovery** and execution
- ✅ **Debug support** for CLI and tests
- ✅ **Code coverage** visualization
- ✅ **IntelliSense** and auto-completion
- ✅ **Problem highlighting** in Problems panel
- ✅ **PYTHONPATH** automatically configured

## 🛠️ Troubleshooting

### Tests not discovered?

1. Check Python interpreter: `./venv/bin/python`
2. Reload window: `Ctrl+Shift+P` → "Developer: Reload Window"
3. Check test output: `View → Output → Python Test Log`

### Linting not working?

1. Ensure dev dependencies installed: `make install-dev`
2. Check Python interpreter path
3. Restart VSCode

### Debug not working?

1. Verify virtual environment: `source venv/bin/activate`
2. Check PYTHONPATH in debug configuration
3. Ensure CLI module exists: `ls src/app_size_analyzer/cli.py`

## 🚀 Pro Tips

1. **Use Command Palette:** `Ctrl+Shift+P` for quick access to all features
2. **Keyboard shortcuts:**
   - `F5` - Start debugging
   - `Ctrl+Shift+T` - Reopen closed test
   - `Ctrl+Shift+\`` - Open new terminal
   - `Ctrl+\`` - Toggle terminal
3. **Test shortcuts:** Right-click in Test Explorer for context menu
4. **Coverage shortcuts:** Use Coverage Gutters status bar buttons
5. **Multi-cursor editing:** `Ctrl+D` to select next occurrence
