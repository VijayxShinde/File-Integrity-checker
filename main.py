#!/usr/bin/env python3
"""
File Integrity Checker - Production Ready Version
Monitor and track file changes with comprehensive reporting and notifications.
"""

import os
import hashlib
import json
import sqlite3
import logging
import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import fnmatch
import stat

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


# ==================== Color Utilities ====================
class Colors:
    """Color output utility class."""
    @staticmethod
    def success(text: str) -> str:
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}" if COLORAMA_AVAILABLE else text

    @staticmethod
    def error(text: str) -> str:
        return f"{Fore.RED}{text}{Style.RESET_ALL}" if COLORAMA_AVAILABLE else text

    @staticmethod
    def warning(text: str) -> str:
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}" if COLORAMA_AVAILABLE else text

    @staticmethod
    def info(text: str) -> str:
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}" if COLORAMA_AVAILABLE else text


# ==================== Data Models ====================
@dataclass
class FileMetadata:
    """Store file metadata and hash information."""
    file_path: str
    hash_value: str
    size: int
    modified_time: float
    permissions: int
    hash_function: str
    timestamp: str


@dataclass
class FileChange:
    """Track file changes."""
    file_path: str
    change_type: str  # 'modified', 'deleted', 'new', 'permission_changed'
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


# ==================== Configuration Management ====================
class ConfigManager:
    """Manage configuration from files or defaults."""

    DEFAULT_CONFIG = {
        'hash_function': 'sha256',
        'exclude_patterns': [
            '.git', '.gitignore', '__pycache__', '*.pyc', '.env',
            'node_modules', '.venv', 'venv', '.DS_Store', '.idea',
            '*.log', 'tmp', 'temp', 'build', 'dist', '.pytest_cache'
        ],
        'max_workers': 4,
        'chunk_size': 8192,
        'enable_notifications': False,
        'notification_email': None,
        'notification_webhook': None,
        'db_path': 'file_integrity.db',
        'log_level': 'INFO'
    }

    @staticmethod
    def load_config(config_path: Optional[str] = None) -> Dict:
        """Load configuration from file or use defaults."""
        config = ConfigManager.DEFAULT_CONFIG.copy()

        if config_path and Path(config_path).exists():
            try:
                if config_path.endswith('.json'):
                    with open(config_path, 'r') as f:
                        config.update(json.load(f))
                elif config_path.endswith('.yaml') and YAML_AVAILABLE:
                    with open(config_path, 'r') as f:
                        config.update(yaml.safe_load(f))
                logging.info(f"Configuration loaded from {config_path}")
            except Exception as e:
                logging.error(f"Failed to load config from {config_path}: {e}")

        return config


# ==================== Logging Setup ====================
def setup_logging(log_level: str = 'INFO', log_file: Optional[str] = None):
    """Configure logging with file and console handlers."""
    log_format = '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'
    
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        handlers=handlers
    )


# ==================== Database Management ====================
class FileIntegrityDB:
    """SQLite database for storing file hashes and changes."""

    def __init__(self, db_path: str = 'file_integrity.db'):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY,
                    file_path TEXT UNIQUE NOT NULL,
                    hash_value TEXT NOT NULL,
                    size INTEGER,
                    modified_time REAL,
                    permissions INTEGER,
                    hash_function TEXT,
                    timestamp TEXT,
                    monitored_dir TEXT
                )
            ''')

            # Changes table for audit trail
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (file_path) REFERENCES files(file_path)
                )
            ''')

            # Create indices for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON files(file_path)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON files(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON changes(timestamp)')
            
            conn.commit()
        logging.info(f"Database initialized: {self.db_path}")

    def save_file_metadata(self, metadata: FileMetadata, monitored_dir: str = None):
        """Save or update file metadata."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO files 
                (file_path, hash_value, size, modified_time, permissions, hash_function, timestamp, monitored_dir)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metadata.file_path, metadata.hash_value, metadata.size,
                metadata.modified_time, metadata.permissions, metadata.hash_function,
                metadata.timestamp, monitored_dir
            ))
            conn.commit()

    def get_file_metadata(self, file_path: str) -> Optional[FileMetadata]:
        """Retrieve stored metadata for a file."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path, hash_value, size, modified_time, permissions, hash_function, timestamp
                FROM files WHERE file_path = ?
            ''', (file_path,))
            row = cursor.fetchone()
            if row:
                return FileMetadata(*row)
        return None

    def log_change(self, change: FileChange):
        """Log a file change to the audit trail."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO changes (file_path, change_type, old_value, new_value, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (change.file_path, change.change_type, change.old_value, change.new_value, change.timestamp))
            conn.commit()

    def get_changes(self, file_path: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Retrieve change history."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if file_path:
                cursor.execute('''
                    SELECT file_path, change_type, old_value, new_value, timestamp
                    FROM changes WHERE file_path = ?
                    ORDER BY timestamp DESC LIMIT ?
                ''', (file_path, limit))
            else:
                cursor.execute('''
                    SELECT file_path, change_type, old_value, new_value, timestamp
                    FROM changes ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            
            return [dict(zip(['file_path', 'change_type', 'old_value', 'new_value', 'timestamp'], row))
                    for row in cursor.fetchall()]

    def get_all_files(self, monitored_dir: Optional[str] = None) -> Dict[str, FileMetadata]:
        """Retrieve all monitored files."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if monitored_dir:
                cursor.execute('''
                    SELECT file_path, hash_value, size, modified_time, permissions, hash_function, timestamp
                    FROM files WHERE monitored_dir = ?
                ''', (monitored_dir,))
            else:
                cursor.execute('''
                    SELECT file_path, hash_value, size, modified_time, permissions, hash_function, timestamp
                    FROM files
                ''')
            
            return {row[0]: FileMetadata(*row) for row in cursor.fetchall()}

    def delete_file(self, file_path: str):
        """Remove file from database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM files WHERE file_path = ?', (file_path,))
            conn.commit()


# ==================== File Hashing ====================
class FileHasher:
    """Handle file hashing operations."""

    SUPPORTED_ALGORITHMS = hashlib.algorithms_available

    @staticmethod
    def validate_hash_function(hash_function: str) -> bool:
        """Validate if hash function is supported."""
        if hash_function not in FileHasher.SUPPORTED_ALGORITHMS:
            logging.error(f"Unsupported hash function: {hash_function}")
            return False
        return True

    @staticmethod
    def calculate_hash(file_path: str, hash_function: str = 'sha256', chunk_size: int = 8192) -> Optional[str]:
        """Calculate file hash with progress indication."""
        if not FileHasher.validate_hash_function(hash_function):
            return None

        try:
            hash_func = hashlib.new(hash_function)
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            return None
        except (IOError, OSError) as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return None

    @staticmethod
    def get_file_metadata(file_path: str, hash_function: str = 'sha256', chunk_size: int = 8192) -> Optional[FileMetadata]:
        """Get complete file metadata including hash."""
        try:
            file_stat = os.stat(file_path)
            file_hash = FileHasher.calculate_hash(file_path, hash_function, chunk_size)
            
            if file_hash is None:
                return None

            return FileMetadata(
                file_path=str(file_path),
                hash_value=file_hash,
                size=file_stat.st_size,
                modified_time=file_stat.st_mtime,
                permissions=stat.S_IMODE(file_stat.st_mode),
                hash_function=hash_function,
                timestamp=datetime.now().isoformat()
            )
        except (OSError, IOError) as e:
            logging.error(f"Error getting metadata for {file_path}: {e}")
            return None


# ==================== File Discovery ====================
class FileDiscovery:
    """Discover and filter files for monitoring."""

    @staticmethod
    def should_exclude(file_path: str, exclude_patterns: List[str]) -> bool:
        """Check if file matches any exclude pattern."""
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(file_path, f'*{pattern}*') or fnmatch.fnmatch(Path(file_path).name, pattern):
                return True
        return False

    @staticmethod
    def discover_files(directory: str, exclude_patterns: List[str] = None, 
                      extensions: Optional[List[str]] = None) -> List[str]:
        """Discover all files in directory matching criteria."""
        exclude_patterns = exclude_patterns or []
        files = []

        try:
            for root, dirs, filenames in os.walk(directory):
                # Remove excluded directories to prevent traversal
                dirs[:] = [d for d in dirs if not FileDiscovery.should_exclude(d, exclude_patterns)]

                for filename in filenames:
                    file_path = os.path.join(root, filename)
                    
                    if FileDiscovery.should_exclude(file_path, exclude_patterns):
                        continue
                    
                    if extensions and not any(filename.endswith(ext) for ext in extensions):
                        continue

                    files.append(file_path)
        except (OSError, PermissionError) as e:
            logging.error(f"Error discovering files in {directory}: {e}")

        return files


# ==================== File Integrity Monitor ====================
class FileIntegrityMonitor:
    """Main class for file monitoring and integrity checking."""

    def __init__(self, config: Dict = None, db_path: str = 'file_integrity.db'):
        self.config = config or ConfigManager.load_config()
        self.db = FileIntegrityDB(db_path)
        self.hasher = FileHasher()

    def initialize_monitoring(self, directory: str, 
                            extensions: Optional[List[str]] = None) -> Tuple[int, int]:
        """Initialize file monitoring for a directory."""
        if not os.path.isdir(directory):
            logging.error(f"Directory not found: {directory}")
            return 0, 0

        directory = os.path.abspath(directory)
        logging.info(f"Initializing monitoring for: {directory}")

        files = FileDiscovery.discover_files(directory, self.config['exclude_patterns'], extensions)
        
        if not files:
            logging.warning("No files found matching criteria")
            return 0, 0

        successful = 0
        failed = 0

        iterator = tqdm(files, desc="Processing files") if TQDM_AVAILABLE else files

        for file_path in iterator:
            metadata = self.hasher.get_file_metadata(
                file_path,
                self.config['hash_function'],
                self.config['chunk_size']
            )
            
            if metadata:
                self.db.save_file_metadata(metadata, directory)
                successful += 1
            else:
                failed += 1
                logging.warning(f"Failed to process: {file_path}")

        logging.info(f"Initialization complete: {successful} files processed, {failed} failed")
        return successful, failed

    def check_integrity(self, directory: str) -> Dict:
        """Check integrity of files in directory."""
        directory = os.path.abspath(directory)
        logging.info(f"Checking integrity for: {directory}")

        stored_files = self.db.get_all_files(directory)
        current_files = set(FileDiscovery.discover_files(directory, self.config['exclude_patterns']))
        
        results = {
            'unchanged': [],
            'modified': [],
            'deleted': [],
            'new': [],
            'permission_changed': [],
            'timestamp': datetime.now().isoformat()
        }

        # Check existing files
        for file_path, old_metadata in stored_files.items():
            if file_path not in current_files:
                results['deleted'].append(file_path)
                change = FileChange(file_path, 'deleted', old_metadata.hash_value, None)
                self.db.log_change(change)
                logging.warning(Colors.error(f"Deleted: {file_path}"))
                continue

            current_metadata = self.hasher.get_file_metadata(
                file_path,
                self.config['hash_function'],
                self.config['chunk_size']
            )

            if not current_metadata:
                results['deleted'].append(file_path)
                continue

            # Check hash
            if current_metadata.hash_value != old_metadata.hash_value:
                results['modified'].append({
                    'file': file_path,
                    'old_hash': old_metadata.hash_value,
                    'new_hash': current_metadata.hash_value
                })
                change = FileChange(file_path, 'modified', old_metadata.hash_value, current_metadata.hash_value)
                self.db.log_change(change)
                logging.warning(Colors.warning(f"Modified: {file_path}"))
                self.db.save_file_metadata(current_metadata, directory)
            else:
                results['unchanged'].append(file_path)

            # Check permissions
            if current_metadata.permissions != old_metadata.permissions:
                results['permission_changed'].append({
                    'file': file_path,
                    'old_perms': oct(old_metadata.permissions),
                    'new_perms': oct(current_metadata.permissions)
                })
                change = FileChange(file_path, 'permission_changed', 
                                  oct(old_metadata.permissions), oct(current_metadata.permissions))
                self.db.log_change(change)
                logging.warning(Colors.warning(f"Permissions changed: {file_path}"))
                self.db.save_file_metadata(current_metadata, directory)

        # Check for new files
        for file_path in current_files:
            if file_path not in stored_files:
                metadata = self.hasher.get_file_metadata(
                    file_path,
                    self.config['hash_function'],
                    self.config['chunk_size']
                )
                if metadata:
                    results['new'].append(file_path)
                    change = FileChange(file_path, 'new', None, metadata.hash_value)
                    self.db.log_change(change)
                    self.db.save_file_metadata(metadata, directory)
                    logging.info(Colors.success(f"New file: {file_path}"))

        return results

    def export_report(self, output_format: str = 'json', output_file: Optional[str] = None) -> str:
        """Export integrity report in various formats."""
        changes = self.db.get_changes(limit=1000)
        
        if output_format == 'json':
            report = json.dumps(changes, indent=2)
        elif output_format == 'csv':
            import csv
            from io import StringIO
            output = StringIO()
            writer = csv.DictWriter(output, fieldnames=['file_path', 'change_type', 'old_value', 'new_value', 'timestamp'])
            writer.writeheader()
            writer.writerows(changes)
            report = output.getvalue()
        else:
            report = str(changes)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logging.info(f"Report exported to: {output_file}")

        return report


# ==================== CLI ====================
def main():
    """Command-line interface."""
    parser = argparse.ArgumentParser(
        description='File Integrity Checker - Monitor and track file changes',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--version', action='version', version='%(prog)s 2.0.0')
    parser.add_argument('--config', help='Path to configuration file (JSON/YAML)')
    parser.add_argument('--log-file', help='Log file path')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    parser.add_argument('--db', default='file_integrity.db', help='Database path')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Initialize command
    init_parser = subparsers.add_parser('init', help='Initialize monitoring for a directory')
    init_parser.add_argument('directory', help='Directory to monitor')
    init_parser.add_argument('--hash', default='sha256', help='Hash function (default: sha256)')
    init_parser.add_argument('--extensions', nargs='+', help='File extensions to include')
    init_parser.add_argument('--exclude', nargs='+', help='Patterns to exclude')

    # Check command
    check_parser = subparsers.add_parser('check', help='Check file integrity')
    check_parser.add_argument('directory', help='Directory to check')

    # History command
    history_parser = subparsers.add_parser('history', help='Show change history')
    history_parser.add_argument('--file', help='Specific file to show history for')
    history_parser.add_argument('--limit', type=int, default=50, help='Number of records to show')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export integrity report')
    export_parser.add_argument('--format', choices=['json', 'csv', 'text'], default='json')
    export_parser.add_argument('--output', help='Output file path')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level, args.log_file)

    # Load configuration
    config = ConfigManager.load_config(args.config)
    if args.log_level:
        config['log_level'] = args.log_level

    monitor = FileIntegrityMonitor(config, args.db)

    if args.command == 'init':
        extensions = args.extensions if args.extensions else None
        exclude = args.exclude if args.exclude else config['exclude_patterns']
        config['exclude_patterns'] = exclude
        
        successful, failed = monitor.initialize_monitoring(args.directory, extensions)
        print(Colors.success(f"\n✓ Initialization complete: {successful} files monitored ({failed} failed)"))

    elif args.command == 'check':
        results = monitor.check_integrity(args.directory)
        
        print("\n" + "="*60)
        print(Colors.info("FILE INTEGRITY REPORT"))
        print("="*60)
        print(f"Unchanged files: {len(results['unchanged'])}")
        print(Colors.warning(f"Modified files: {len(results['modified'])}"))
        if results['modified']:
            for item in results['modified']:
                print(f"  • {item['file']}")
        print(Colors.error(f"Deleted files: {len(results['deleted'])}"))
        if results['deleted']:
            for item in results['deleted']:
                print(f"  • {item}")
        print(Colors.success(f"New files: {len(results['new'])}"))
        if results['new']:
            for item in results['new']:
                print(f"  • {item}")
        print(Colors.warning(f"Permission changes: {len(results['permission_changed'])}"))
        if results['permission_changed']:
            for item in results['permission_changed']:
                print(f"  • {item['file']}")
        print("="*60)

    elif args.command == 'history':
        changes = monitor.db.get_changes(args.file, args.limit)
        if changes:
            print("\n" + "="*80)
            print(Colors.info("CHANGE HISTORY"))
            print("="*80)
            for change in changes:
                print(f"File: {change['file_path']}")
                print(f"  Type: {change['change_type']} | Time: {change['timestamp']}")
                if change['old_value']:
                    print(f"  Old: {change['old_value'][:50]}...")
                if change['new_value']:
                    print(f"  New: {change['new_value'][:50]}...")
                print()
        else:
            print("No changes found.")

    elif args.command == 'export':
        report = monitor.export_report(args.format, args.output)
        if not args.output:
            print(report)
        print(Colors.success(f"\n✓ Report exported successfully"))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
