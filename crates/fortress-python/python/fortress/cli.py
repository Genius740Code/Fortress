#!/usr/bin/env python3
"""
Fortress Python SDK Command Line Interface
"""

import argparse
import asyncio
import json
import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any, List

import fortress


class FortressCLI:
    """Fortress Command Line Interface"""
    
    def __init__(self):
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the command line argument parser."""
        parser = argparse.ArgumentParser(
            prog="fortress-python",
            description="Fortress Python SDK Command Line Interface",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  fortress-python version                    Show version information
  fortress-python list-algorithms            List available algorithms
  fortress-python encrypt --data "Hello"     Encrypt data
  fortress-python generate-key --algorithm aegis256
  fortress-python create-config --profile fortress
            """
        )
        
        # Global options
        parser.add_argument(
            "--verbose", "-v",
            action="store_true",
            help="Enable verbose output"
        )
        parser.add_argument(
            "--config", "-c",
            type=str,
            help="Path to configuration file"
        )
        parser.add_argument(
            "--format", "-f",
            choices=["json", "table", "plain"],
            default="plain",
            help="Output format (default: plain)"
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(
            dest="command",
            help="Available commands",
            metavar="COMMAND"
        )
        
        # Version command
        version_parser = subparsers.add_parser(
            "version",
            help="Show version information"
        )
        version_parser.add_argument(
            "--build-info",
            action="store_true",
            help="Show detailed build information"
        )
        
        # List algorithms command
        list_algs_parser = subparsers.add_parser(
            "list-algorithms",
            help="List available encryption algorithms"
        )
        list_algs_parser.add_argument(
            "--details",
            action="store_true",
            help="Show algorithm details"
        )
        
        # Generate key command
        gen_key_parser = subparsers.add_parser(
            "generate-key",
            help="Generate encryption key"
        )
        gen_key_parser.add_argument(
            "--algorithm", "-a",
            required=True,
            choices=fortress.list_algorithms(),
            help="Encryption algorithm"
        )
        gen_key_parser.add_argument(
            "--output", "-o",
            type=str,
            help="Output file for the key (default: stdout)"
        )
        gen_key_parser.add_argument(
            "--base64",
            action="store_true",
            help="Output key in base64 format"
        )
        
        # Encrypt command
        encrypt_parser = subparsers.add_parser(
            "encrypt",
            help="Encrypt data"
        )
        encrypt_parser.add_argument(
            "--data", "-d",
            type=str,
            help="Data to encrypt (string)"
        )
        encrypt_parser.add_argument(
            "--file", "-f",
            type=str,
            help="File to encrypt"
        )
        encrypt_parser.add_argument(
            "--key", "-k",
            type=str,
            help="Encryption key (hex or base64)"
        )
        encrypt_parser.add_argument(
            "--key-file",
            type=str,
            help="File containing encryption key"
        )
        encrypt_parser.add_argument(
            "--algorithm", "-a",
            default="aegis256",
            choices=fortress.list_algorithms(),
            help="Encryption algorithm (default: aegis256)"
        )
        encrypt_parser.add_argument(
            "--output", "-o",
            type=str,
            help="Output file for ciphertext (default: stdout)"
        )
        encrypt_parser.add_argument(
            "--base64",
            action="store_true",
            help="Output ciphertext in base64 format"
        )
        
        # Decrypt command
        decrypt_parser = subparsers.add_parser(
            "decrypt",
            help="Decrypt data"
        )
        decrypt_parser.add_argument(
            "--data", "-d",
            type=str,
            help="Data to decrypt (string or base64)"
        )
        decrypt_parser.add_argument(
            "--file", "-f",
            type=str,
            help="File to decrypt"
        )
        decrypt_parser.add_argument(
            "--key", "-k",
            type=str,
            help="Decryption key (hex or base64)"
        )
        decrypt_parser.add_argument(
            "--key-file",
            type=str,
            help="File containing decryption key"
        )
        decrypt_parser.add_argument(
            "--algorithm", "-a",
            default="aegis256",
            choices=fortress.list_algorithms(),
            help="Encryption algorithm (default: aegis256)"
        )
        decrypt_parser.add_argument(
            "--output", "-o",
            type=str,
            help="Output file for plaintext (default: stdout)"
        )
        decrypt_parser.add_argument(
            "--base64",
            action="store_true",
            help="Input data is in base64 format"
        )
        
        # Create config command
        create_config_parser = subparsers.add_parser(
            "create-config",
            help="Create Fortress configuration"
        )
        create_config_parser.add_argument(
            "--profile", "-p",
            choices=["lightning", "balanced", "fortress", "startup", "enterprise"],
            default="balanced",
            help="Configuration profile (default: balanced)"
        )
        create_config_parser.add_argument(
            "--output", "-o",
            type=str,
            help="Output file for configuration (default: stdout)"
        )
        
        # Key management commands
        key_mgmt_parser = subparsers.add_parser(
            "key-mgmt",
            help="Key management operations"
        )
        key_mgmt_subparsers = key_mgmt_parser.add_subparsers(
            dest="key_mgmt_command",
            help="Key management commands"
        )
        
        # List keys
        list_keys_parser = key_mgmt_subparsers.add_parser(
            "list",
            help="List managed keys"
        )
        
        # Test command
        test_parser = subparsers.add_parser(
            "test",
            help="Run Fortress tests"
        )
        test_parser.add_argument(
            "--algorithm", "-a",
            choices=fortress.list_algorithms(),
            help="Test specific algorithm"
        )
        test_parser.add_argument(
            "--quick",
            action="store_true",
            help="Run quick tests only"
        )
        
        return parser
    
    async def run(self, args: Optional[List[str]] = None) -> int:
        """Run the CLI with the given arguments."""
        parsed_args = self.parser.parse_args(args)
        
        if not parsed_args.command:
            self.parser.print_help()
            return 1
        
        try:
            if parsed_args.command == "version":
                return await self._cmd_version(parsed_args)
            elif parsed_args.command == "list-algorithms":
                return await self._cmd_list_algorithms(parsed_args)
            elif parsed_args.command == "generate-key":
                return await self._cmd_generate_key(parsed_args)
            elif parsed_args.command == "encrypt":
                return await self._cmd_encrypt(parsed_args)
            elif parsed_args.command == "decrypt":
                return await self._cmd_decrypt(parsed_args)
            elif parsed_args.command == "create-config":
                return await self._cmd_create_config(parsed_args)
            elif parsed_args.command == "key-mgmt":
                return await self._cmd_key_management(parsed_args)
            elif parsed_args.command == "test":
                return await self._cmd_test(parsed_args)
            else:
                print(f"Unknown command: {parsed_args.command}", file=sys.stderr)
                return 1
                
        except Exception as e:
            if parsed_args.verbose:
                import traceback
                traceback.print_exc()
            else:
                print(f"Error: {e}", file=sys.stderr)
            return 1
    
    async def _cmd_version(self, args) -> int:
        """Handle version command."""
        if args.build_info:
            build_info = fortress.get_build_info()
            if args.format == "json":
                print(json.dumps(build_info, indent=2))
            else:
                print(f"Fortress version: {fortress.get_version()}")
                print(f"Build timestamp: {build_info['timestamp']}")
                print(f"Git SHA: {build_info['git_sha']}")
                print(f"Rust version: {build_info['rust_version']}")
                print(f"Target: {build_info['target']}")
        else:
            print(fortress.get_version())
        return 0
    
    async def _cmd_list_algorithms(self, args) -> int:
        """Handle list-algorithms command."""
        algorithms = fortress.list_algorithms()
        
        if args.details:
            if args.format == "json":
                details = {}
                for alg in algorithms:
                    try:
                        if alg == "aegis256":
                            algorithm = fortress.EncryptionAlgorithm.aegis256()
                        elif alg == "chacha20poly1305":
                            algorithm = fortress.EncryptionAlgorithm.chacha20poly1305()
                        elif alg == "aes256gcm":
                            algorithm = fortress.EncryptionAlgorithm.aes256gcm()
                        else:
                            continue
                        
                        details[alg] = {
                            "key_size": algorithm.key_size(),
                            "nonce_size": algorithm.nonce_size(),
                            "tag_size": algorithm.tag_size()
                        }
                    except:
                        details[alg] = {"error": "Failed to create algorithm"}
                
                print(json.dumps(details, indent=2))
            else:
                print("Available encryption algorithms:")
                for alg in algorithms:
                    print(f"  {alg}")
        else:
            if args.format == "json":
                print(json.dumps(algorithms, indent=2))
            else:
                for alg in algorithms:
                    print(alg)
        
        return 0
    
    async def _cmd_generate_key(self, args) -> int:
        """Handle generate-key command."""
        key = fortress.generate_key(args.algorithm)
        
        if args.base64:
            import base64
            key_data = base64.b64encode(key).decode()
        else:
            key_data = key.hex()
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(key_data)
            if args.verbose:
                print(f"Key generated and saved to {args.output}")
        else:
            print(key_data)
        
        return 0
    
    async def _cmd_encrypt(self, args) -> int:
        """Handle encrypt command."""
        # Get data to encrypt
        if args.data:
            data = args.data.encode()
        elif args.file:
            with open(args.file, 'rb') as f:
                data = f.read()
        else:
            print("Error: Either --data or --file must be specified", file=sys.stderr)
            return 1
        
        # Get key
        key = self._get_key(args)
        if key is None:
            return 1
        
        # Create algorithm
        algorithm = self._get_algorithm(args.algorithm)
        if algorithm is None:
            return 1
        
        # Encrypt
        ciphertext = await algorithm.encrypt(data, key)
        
        # Output
        if args.base64:
            import base64
            output_data = base64.b64encode(ciphertext).decode()
        else:
            output_data = ciphertext.hex()
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_data)
            if args.verbose:
                print(f"Data encrypted and saved to {args.output}")
        else:
            print(output_data)
        
        return 0
    
    async def _cmd_decrypt(self, args) -> int:
        """Handle decrypt command."""
        # Get data to decrypt
        if args.data:
            if args.base64:
                import base64
                data = base64.b64decode(args.data)
            else:
                data = bytes.fromhex(args.data)
        elif args.file:
            with open(args.file, 'rb') as f:
                data = f.read()
        else:
            print("Error: Either --data or --file must be specified", file=sys.stderr)
            return 1
        
        # Get key
        key = self._get_key(args)
        if key is None:
            return 1
        
        # Create algorithm
        algorithm = self._get_algorithm(args.algorithm)
        if algorithm is None:
            return 1
        
        # Decrypt
        try:
            plaintext = await algorithm.decrypt(data, key)
        except fortress.FortressError as e:
            print(f"Decryption failed: {e}", file=sys.stderr)
            return 1
        
        # Output
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(plaintext)
            if args.verbose:
                print(f"Data decrypted and saved to {args.output}")
        else:
            print(plaintext.decode())
        
        return 0
    
    async def _cmd_create_config(self, args) -> int:
        """Handle create-config command."""
        config = fortress.create_config(args.profile)
        config_dict = config.to_dict()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(config_dict, f, indent=2)
            if args.verbose:
                print(f"Configuration saved to {args.output}")
        else:
            print(json.dumps(config_dict, indent=2))
        
        return 0
    
    async def _cmd_key_management(self, args) -> int:
        """Handle key management commands."""
        if not args.key_mgmt_command:
            print("Error: Key management command required", file=sys.stderr)
            return 1
        
        key_manager = fortress.KeyManager()
        
        if args.key_mgmt_command == "list":
            try:
                keys = await key_manager.list_keys()
                if args.format == "json":
                    print(json.dumps(keys, indent=2))
                else:
                    for key_id in keys:
                        print(key_id)
            except fortress.FortressError as e:
                print(f"Failed to list keys: {e}", file=sys.stderr)
                return 1
        
        return 0
    
    async def _cmd_test(self, args) -> int:
        """Handle test command."""
        print("Running Fortress tests...")
        
        if args.quick:
            algorithms = [args.algorithm] if args.algorithm else ["aegis256"]
        else:
            algorithms = [args.algorithm] if args.algorithm else ["aegis256", "chacha20poly1305"]
        
        success = True
        for algorithm in algorithms:
            try:
                print(f"Testing {algorithm}...")
                await self._test_algorithm(algorithm)
                print(f"✅ {algorithm} tests passed")
            except Exception as e:
                print(f"❌ {algorithm} tests failed: {e}")
                success = False
        
        if success:
            print("🎉 All tests passed!")
            return 0
        else:
            print("❌ Some tests failed")
            return 1
    
    async def _test_algorithm(self, algorithm_name: str):
        """Test a specific algorithm."""
        algorithm = self._get_algorithm(algorithm_name)
        key = fortress.generate_key(algorithm_name)
        
        # Test basic encryption/decryption
        test_data = b"Hello, Fortress! Test data."
        ciphertext = await algorithm.encrypt(test_data, key)
        plaintext = await algorithm.decrypt(ciphertext, key)
        
        if plaintext != test_data:
            raise Exception("Encryption/decryption roundtrip failed")
        
        # Test empty data
        empty_ciphertext = await algorithm.encrypt(b"", key)
        empty_plaintext = await algorithm.decrypt(empty_ciphertext, key)
        
        if empty_plaintext != b"":
            raise Exception("Empty data encryption/decryption failed")
    
    def _get_key(self, args) -> Optional[bytes]:
        """Get encryption key from arguments."""
        if args.key:
            try:
                # Try hex first, then base64
                try:
                    return bytes.fromhex(args.key)
                except ValueError:
                    import base64
                    return base64.b64decode(args.key)
            except Exception as e:
                print(f"Invalid key format: {e}", file=sys.stderr)
                return None
        elif args.key_file:
            try:
                with open(args.key_file, 'rb') as f:
                    key_data = f.read()
                
                # Try to decode as hex or base64
                try:
                    return bytes.fromhex(key_data.decode().strip())
                except ValueError:
                    import base64
                    return base64.b64decode(key_data.strip())
            except Exception as e:
                print(f"Failed to read key file: {e}", file=sys.stderr)
                return None
        else:
            print("Error: Either --key or --key-file must be specified", file=sys.stderr)
            return None
    
    def _get_algorithm(self, algorithm_name: str):
        """Get encryption algorithm by name."""
        try:
            if algorithm_name == "aegis256":
                return fortress.EncryptionAlgorithm.aegis256()
            elif algorithm_name == "chacha20poly1305":
                return fortress.EncryptionAlgorithm.chacha20poly1305()
            elif algorithm_name == "aes256gcm":
                return fortress.EncryptionAlgorithm.aes256gcm()
            elif algorithm_name == "xchacha20poly1305":
                return fortress.EncryptionAlgorithm.xchacha20poly1305()
            elif algorithm_name == "blake3_encrypt":
                return fortress.EncryptionAlgorithm.blake3_encrypt()
            elif algorithm_name == "hmacsha512_encrypt":
                return fortress.EncryptionAlgorithm.hmacsha512_encrypt()
            elif algorithm_name == "aes256ctr":
                return fortress.EncryptionAlgorithm.aes256ctr()
            elif algorithm_name == "argon2id_encrypt":
                return fortress.EncryptionAlgorithm.argon2id_encrypt()
            elif algorithm_name == "composite_encrypt":
                return fortress.EncryptionAlgorithm.composite_encrypt()
            else:
                print(f"Unknown algorithm: {algorithm_name}", file=sys.stderr)
                return None
        except Exception as e:
            print(f"Failed to create algorithm {algorithm_name}: {e}", file=sys.stderr)
            return None


def main():
    """Main entry point for the CLI."""
    cli = FortressCLI()
    return asyncio.run(cli.run())


if __name__ == "__main__":
    sys.exit(main())
