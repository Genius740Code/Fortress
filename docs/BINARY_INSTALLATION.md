# Binary Installation Guide

This guide covers installing Fortress through binary distributions for various package managers and platforms.

## 🚀 Quick Installation

### NPM (Node.js)

```bash
# Install globally
npm install -g fortress-cli

# Install as dependency
npm install fortress-cli
```

### PyPI (Python)

```bash
# Install from PyPI
pip install fortress

# Install with optional features
pip install fortress[dev,test]
```

### Standalone Binaries

Download the appropriate binary for your platform from the [GitHub Releases](https://github.com/Genius740Code/Fortress/releases).

## 📦 Platform-Specific Installation

### Windows

#### NPM
```powershell
# Using npm
npm install -g fortress-cli

# Using PowerShell (admin)
npm install -g fortress-cli --global
```

#### Python
```powershell
# Using pip
pip install fortress

# Using conda
conda install -c conda-forge fortress
```

#### Binary
1. Download `fortress-cli-x.x.x-x86_64-pc-windows-msvc.zip`
2. Extract to a directory in your PATH
3. Run `fortress --version` to verify

### macOS

#### NPM
```bash
# Using npm
npm install -g fortress-cli

# Using Homebrew (if available)
brew install fortress-cli
```

#### Python
```bash
# Using pip
pip install fortress

# Using Homebrew
brew install fortress
```

#### Binary
```bash
# Download and install
curl -L "https://github.com/Genius740Code/Fortress/releases/latest/download/fortress-cli-x.x.x-x86_64-apple-darwin.tar.gz" | tar -xz
sudo mv fortress /usr/local/bin/
```

### Linux

#### NPM
```bash
# Using npm
npm install -g fortress-cli

# Using package managers
sudo apt install nodejs npm
npm install -g fortress-cli
```

#### Python
```bash
# Using pip
pip install fortress

# Using system package manager
# Ubuntu/Debian
sudo apt install python3-pip
pip3 install fortress

# CentOS/RHEL
sudo yum install python3-pip
pip3 install fortress

# Arch Linux
sudo pacman -S python-pip
pip install fortress
```

#### Binary
```bash
# Download and install
curl -L "https://github.com/Genius740Code/Fortress/releases/latest/download/fortress-cli-x.x.x-x86_64-unknown-linux-gnu.tar.gz" | tar -xz
sudo mv fortress /usr/local/bin/
```

## 🔧 Development Installation

### From Source

```bash
# Clone repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress

# Build from source
cargo build --release

# Install CLI
cargo install --path crates/fortress-cli
```

### Development Versions

#### NPM
```bash
# Install latest development version
npm install fortress-cli@next

# Install from git
npm install git+https://github.com/Genius740Code/Fortress.git#main
```

#### Python
```bash
# Install from source
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress/crates/fortress-python
pip install -e .

# Install development version
pip install fortress --pre
```

## 🏗️ Building Binaries

### Prerequisites

- Rust 1.70+
- Node.js 14+ (for NPM)
- Python 3.8+ (for PyPI)
- Git

### Build All Binaries

```bash
# Clone repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress

# Run build script
./scripts/build-binaries.sh
```

### Build Specific Platforms

#### NPM Binaries
```bash
cd crates/fortress-cli-napi
npm install
npm run build -- --target x86_64-unknown-linux-gnu
```

#### Python Wheels
```bash
cd crates/fortress-python
pip install maturin
maturin build --release
```

#### CLI Binaries
```bash
cargo build --release --target x86_64-unknown-linux-gnu
```

## 🧪 Testing Binaries

```bash
# Test all binaries
./scripts/test-binaries.sh

# Test specific components
cd crates/fortress-cli-napi && npm test
cd crates/fortress-python && python -m pytest
```

## 📋 Supported Platforms

### NPM Packages
- Windows x64/x86
- macOS x64/ARM64
- Linux x64/ARM64
- FreeBSD x64/ARM64

### Python Wheels
- Windows x64/x86
- macOS x64/ARM64
- Linux x64 (manylinux)
- Linux ARM64 (manylinux)

### Standalone CLI
- Windows x64/x86
- macOS x64/ARM64
- Linux x64/ARM64
- Linux ARMv7

## 🔍 Verification

After installation, verify your installation:

```bash
# Check CLI version
fortress --version

# Check Python installation
python -c "import fortress; print(fortress.__version__)"

# Check NPM installation
node -e "console.log(require('fortress-cli').getFortressVersion())"
```

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Linux/macOS
sudo chmod +x /usr/local/bin/fortress

# Windows (admin PowerShell)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### PATH Issues
```bash
# Add to PATH (Linux/macOS)
echo 'export PATH=$PATH:/path/to/fortress' >> ~/.bashrc
source ~/.bashrc

# Windows (PowerShell)
$env:PATH += ";C:\path\to\fortress"
```

#### Python Virtual Environments
```bash
# Activate virtual environment first
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install fortress
```

#### Node.js Version
```bash
# Check Node.js version
node --version  # Should be 14+

# Update Node.js if needed
nvm install 18
nvm use 18
```

### Getting Help

- [Documentation](https://docs.fortress-db.com)
- [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- [Discord Community](https://discord.gg/fortress)
- [Email Support](mailto:support@fortress-db.com)

## 📚 Additional Resources

- [API Documentation](API_DOCUMENTATION.md)
- [CLI Documentation](CLI_DOCUMENTATION.md)
- [Usage Examples](USAGE_EXAMPLES.md)
- [Development Guide](../CONTRIBUTING.md)
