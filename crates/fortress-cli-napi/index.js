const { existsSync } = require('fs');
const { join } = require('path');

const { platform, arch } = process;

let nativeBinding;

if (platform === 'android') {
  if (arch === 'arm64') {
    nativeBinding = require('./android-arm64');
  } else if (arch === 'arm') {
    nativeBinding = require('./android-arm-eabi');
  } else {
    throw new Error(`Unsupported architecture on Android ${arch}`);
  }
} else if (platform === 'win32') {
  if (arch === 'x64') {
    nativeBinding = require('./win32-x64-msvc');
  } else if (arch === 'ia32') {
    nativeBinding = require('./win32-ia32-msvc');
  } else if (arch === 'arm64') {
    nativeBinding = require('./win32-arm64-msvc');
  } else {
    throw new Error(`Unsupported architecture on Windows: ${arch}`);
  }
} else if (platform === 'darwin') {
  if (arch === 'x64') {
    nativeBinding = require('./darwin-x64');
  } else if (arch === 'arm64') {
    nativeBinding = require('./darwin-arm64');
  } else {
    throw new Error(`Unsupported architecture on macOS: ${arch}`);
  }
} else if (platform === 'freebsd') {
  if (arch === 'x64') {
    nativeBinding = require('./freebsd-x64');
  } else if (arch === 'arm64') {
    nativeBinding = require('./freebsd-arm64');
  } else {
    throw new Error(`Unsupported architecture on FreeBSD: ${arch}`);
  }
} else if (platform === 'linux') {
  if (arch === 'x64') {
    if (existsSync(join(__dirname, 'linux-x64-gnu'))) {
      nativeBinding = require('./linux-x64-gnu');
    } else {
      nativeBinding = require('./linux-x64-musl');
    }
  } else if (arch === 'arm64') {
    if (existsSync(join(__dirname, 'linux-arm64-gnu'))) {
      nativeBinding = require('./linux-arm64-gnu');
    } else {
      nativeBinding = require('./linux-arm64-musl');
    }
  } else if (arch === 'arm') {
    nativeBinding = require('./linux-arm-gnueabihf');
  } else if (arch === 'riscv64') {
    nativeBinding = require('./linux-riscv64-gnu');
  } else if (arch === 's390x') {
    nativeBinding = require('./linux-s390x-gnu');
  } else {
    throw new Error(`Unsupported architecture on Linux: ${arch}`);
  }
} else {
  throw new Error(`Unsupported OS: ${platform}, architecture: ${arch}`);
}

module.exports = nativeBinding;
