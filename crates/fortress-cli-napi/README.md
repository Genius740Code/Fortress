# fortress-cli-napi

NAPI bindings for Fortress CLI - Node.js native bindings for the Fortress secure database CLI tool.

## Installation

```bash
npm install fortress-cli-napi
```

## Usage

```javascript
const { FortressCLI } = require('fortress-cli-napi');

// Initialize Fortress CLI
const cli = new FortressCLI();

// Run CLI commands programmatically
await cli.init();
await cli.serverStart();
await cli.keyCreate({ name: 'my-key', algorithm: 'aes256-gcm' });
```

## Features

- ✅ **Native Performance**: NAPI bindings for maximum performance
- ✅ **Complete CLI API**: All CLI commands available programmatically  
- ✅ **Cross-Platform**: Windows, macOS, and Linux support
- ✅ **TypeScript Support**: Full TypeScript definitions included
- ✅ **Error Handling**: Comprehensive error reporting

## API Reference

### FortressCLI

#### Constructor
```javascript
const cli = new FortressCLI(options?);
```

#### Methods

##### `init()`
Initialize Fortress configuration.

```javascript
await cli.init();
```

##### `serverStart(options?)`
Start the Fortress server.

```javascript
await cli.serverStart({ 
  host: '0.0.0.0', 
  port: 8080,
  daemon: false 
});
```

##### `keyCreate(options)`
Create a new encryption key.

```javascript
await cli.keyCreate({
  name: 'my-key',
  algorithm: 'aes256-gcm',
  length: 256
});
```

##### `keyList()`
List all encryption keys.

```javascript
const keys = await cli.keyList();
console.log(keys);
```

##### `encrypt(options)`
Encrypt data.

```javascript
const encrypted = await cli.encrypt({
  keyId: 'my-key',
  input: 'secret data',
  output: 'encrypted.dat'
});
```

##### `decrypt(options)`
Decrypt data.

```javascript
const decrypted = await cli.decrypt({
  keyId: 'my-key',
  input: 'encrypted.dat'
});
```

## Supported Algorithms

- `aegis256` - AEGIS-256 (recommended)
- `aes256-gcm` - AES-256-GCM
- `chacha20-poly1305` - ChaCha20-Poly1305

## Error Handling

```javascript
try {
  await cli.keyCreate({ name: 'my-key' });
} catch (error) {
  console.error('CLI Error:', error.message);
  console.error('Error Code:', error.code);
}
```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress/crates/fortress-cli-napi

# Install dependencies
npm install

# Build NAPI bindings
npm run build

# Run tests
npm test
```

### Requirements

- Node.js 16+
- Rust 1.70+
- NAPI-rs CLI (`npm install -g @napi-rs/cli`)

## License

This project is licensed under the Server Side Public License (SSPL) - see the [LICENSE](../../LICENSE) file for details.

## Support

- 📖 [Documentation](https://github.com/Genius740Code/Fortress/blob/main/docs)
- 🐛 [Issue Tracker](https://github.com/Genius740Code/Fortress/issues)
- 💬 [Discussions](https://github.com/Genius740Code/Fortress/discussions)
