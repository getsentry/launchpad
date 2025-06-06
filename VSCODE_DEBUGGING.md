# VSCode/Cursor Debugging & Testing Guide

This guide explains how to effectively use VSCode/Cursor for debugging and testing the app-size-analyzer CLI tool.

## 🚀 Quick Setup

1. **Open the project:**
   ```bash
   # Option 1: Use the workspace file (recommended)
   code app-size-analyzer.code-workspace
   
   # Option 2: Open the folder directly
   code .
   ```

2. **Install recommended extensions** when prompted, or install manually:
   - Python (ms-python.python)
   - Pylance (ms-python.vscode-pylance)
   - Black Formatter (ms-python.black-formatter)
   - Flake8 (ms-python.flake8)
   - Test Explorer (littlefoxteam.vscode-python-test-adapter)

3. **Set up development environment:**
   ```bash
   make dev-setup
   ```

4. **Select Python interpreter:** 
   - `Ctrl/Cmd + Shift + P` → "Python: Select Interpreter" 
   - Choose `./venv/bin/python`

## 🐛 Debug Configurations

The project includes several pre-configured debug configurations accessible via the Debug panel (F5):

### CLI Debugging

| Configuration | Purpose | Usage |
|---------------|---------|--------|
| **Debug CLI: Help** | Test basic CLI functionality | Runs `python -m app_size_analyzer.cli --help` |
| **Debug CLI: Analyze iOS Sample** | Debug with real artifact | Analyzes sample .xcarchive.zip file |
| **Debug CLI: Custom Arguments** | Debug with custom args | Prompts for custom CLI arguments |

### Test Debugging

| Configuration | Purpose | Usage |
|---------------|---------|--------|
| **Debug Current Test File** | Debug the currently open test file | Place cursor in test file and run |
| **Debug Specific Test** | Debug a specific test by name | Prompts for test name pattern |
| **Debug All Tests** | Debug entire test suite | Runs all tests with debugger |

### How to Debug

1. **Set breakpoints:** Click in the gutter (left of line numbers) or press `F9`
2. **Start debugging:** Press `F5` or use Debug panel
3. **Choose configuration:** Select from the dropdown
4. **Debug controls:**
   - `F5` - Continue
   - `F10` - Step over
   - `F11` - Step into
   - `Shift+F11` - Step out
   - `Shift+F5` - Stop

## 🧪 Test Explorer Integration

### Automatic Test Discovery

Tests are automatically discovered when you:
- Open a test file
- Save changes to test files
- Refresh the test explorer

### Running Tests

**Via Test Explorer Panel:**
1. Open Test Explorer: `Ctrl/Cmd + Shift + P` → "Test: Focus on Test Explorer View"
2. Click ▶️ next to individual tests, test classes, or test files
3. Right-click for more options (debug, run with coverage, etc.)

**Via Command Palette:**
- `Ctrl/Cmd + Shift + P` → "Test: Run All Tests"
- `Ctrl/Cmd + Shift + P` → "Test: Run Tests in Current File"

**Via Codelens (inline buttons):**
- Look for "Run Test" and "Debug Test" buttons above test functions

### Test Debugging

1. **Set breakpoints** in test code
2. **Right-click test** in Test Explorer → "Debug Test"
3. **Or use debug configurations** for more control

## 📁 File Navigation

### Quick File Access
- `Ctrl/Cmd + P` - Quick file search
- `Ctrl/Cmd + Shift + P` - Command palette
- `Ctrl/Cmd + Shift + O` - Go to symbol in file
- `Ctrl/Cmd + T` - Go to symbol in workspace

### Project Structure Overview
```
├── src/app_size_analyzer/       # Main package
│   ├── cli.py                   # CLI entry point
│   ├── analyzer/                # Analysis modules
│   └── models.py                # Data models
├── tests/                       # Test files
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   └── artifacts/               # Sample files for testing
└── .vscode/                     # IDE configurations
```

## ⚙️ Code Quality Features

### Automatic Formatting
- **On Save:** Code is automatically formatted with Black
- **Manual:** `Shift+Alt+F` or right-click → "Format Document"

### Import Organization
- **On Save:** Imports are automatically sorted with isort
- **Manual:** `Ctrl/Cmd + Shift + P` → "Python: Sort Imports"

### Linting
- **Real-time:** Flake8 shows errors/warnings as you type
- **Type checking:** MyPy provides static type analysis
- **Problems panel:** `Ctrl/Cmd + Shift + M` to view all issues

## 🔧 Tasks Integration

Access pre-configured tasks via `Ctrl/Cmd + Shift + P` → "Tasks: Run Task":

- **Setup Development Environment** - `make dev-setup`
- **Run All Tests** - `make test`
- **Run Linting** - `make lint`
- **Format Code** - `make format`
- **Build Package** - `make build`
- **Check Coverage** - `make test-coverage`

## 📊 Coverage Integration

### Viewing Coverage
1. **Run tests with coverage:** `make test-coverage`
2. **Install Coverage Gutters extension** (recommended)
3. **View coverage:** Green/red lines in editor gutter show covered/uncovered code
4. **Coverage report:** Open `htmlcov/index.html` in browser

### Coverage Commands
- `Ctrl/Cmd + Shift + P` → "Coverage Gutters: Display Coverage"
- `Ctrl/Cmd + Shift + P` → "Coverage Gutters: Watch Coverage"

## 🚨 Troubleshooting

### Python Interpreter Issues
```bash
# If Python interpreter is not found:
make dev-setup
# Then: Ctrl/Cmd + Shift + P → "Python: Select Interpreter" → ./venv/bin/python
```

### Test Discovery Issues
```bash
# If tests are not discovered:
# 1. Check Python interpreter is set correctly
# 2. Reload window: Ctrl/Cmd + Shift + P → "Developer: Reload Window"
# 3. Clear test cache: Ctrl/Cmd + Shift + P → "Test: Clear All Tests"
```

### Module Import Issues
```bash
# If modules can't be imported:
# 1. Check PYTHONPATH in terminal: echo $PYTHONPATH
# 2. Should include: /workspace/src
# 3. Restart VSCode/Cursor if needed
```

### Debug Configuration Issues
```bash
# If debug configurations don't work:
# 1. Ensure virtual environment is activated
# 2. Check .vscode/launch.json paths are correct
# 3. Verify Python interpreter path in launch.json
```

## 💡 Pro Tips

1. **Use the integrated terminal:** `Ctrl/Cmd + `` for quick commands
2. **Split editor:** `Ctrl/Cmd + \` to view code and tests side-by-side
3. **Zen mode:** `Ctrl/Cmd + K Z` for distraction-free coding
4. **Multi-cursor:** `Alt + Click` to edit multiple locations
5. **Code folding:** `Ctrl/Cmd + Shift + [` to fold code blocks
6. **Git integration:** Use Source Control panel for version control
7. **Marketplace:** Explore extensions for additional functionality

## 🔍 Keyboard Shortcuts Summary

| Action | Shortcut |
|--------|----------|
| Start Debugging | `F5` |
| Toggle Breakpoint | `F9` |
| Step Over | `F10` |
| Step Into | `F11` |
| Run Tests | `Ctrl/Cmd + Shift + T` |
| Quick Open | `Ctrl/Cmd + P` |
| Command Palette | `Ctrl/Cmd + Shift + P` |
| Format Document | `Shift + Alt + F` |
| Toggle Terminal | `Ctrl/Cmd + `` |
| Problems Panel | `Ctrl/Cmd + Shift + M` |