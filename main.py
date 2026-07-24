import os
import hashlib
import json

def validate_hash_function(hash_function):
    """Validate if the hash function is supported."""
    try:
        hashlib.new(hash_function)
        return True
    except ValueError:
        print(f"Unsupported hash function: {hash_function}")
        return False

def calculate_hash(file_path, hash_function):
    """Calculate the hash of a file using the specified hash function."""
    hash_func = hashlib.new(hash_function)
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except (IOError, OSError) as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def monitor_files(file_list_path, hash_function="sha256"):
    """Monitor files for changes based on hash comparison."""
    if not validate_hash_function(hash_function):
        return
    
    try:
        with open(file_list_path, 'r') as f:
            file_data = json.load(f)
    except FileNotFoundError:
        print(f"File list not found: {file_list_path}")
        return
    except json.JSONDecodeError:
        print("Invalid JSON format in the file list.")
        return
    
    if not file_data:
        print("File list is empty.")
        return

    changed_files = []
    unchanged_files = []
    missing_files = []

    for file_path, stored_hash in file_data.items():
        current_hash = calculate_hash(file_path, hash_function)
        if current_hash is None:
            missing_files.append(file_path)
            continue
        if current_hash != stored_hash:
            changed_files.append(file_path)
            print(f"✓ File changed: {file_path}")
        else:
            unchanged_files.append(file_path)
            print(f"✓ File unchanged: {file_path}")
    
    # Summary
    print("\n" + "="*50)
    print(f"Summary: {len(unchanged_files)} unchanged, {len(changed_files)} changed, {len(missing_files)} missing")
    if changed_files:
        print("Changed files:", changed_files)
    if missing_files:
        print("Missing files:", missing_files)

def initialize_file_list(directory, hash_function="sha256"):
    """Initialize a file list with hash values for all files in a directory."""
    if not os.path.isdir(directory):
        print(f"Directory not found: {directory}")
        return
    
    if not validate_hash_function(hash_function):
        return
    
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path, hash_function)
            if file_hash is not None:
                file_hashes[file_path] = file_hash
    
    if not file_hashes:
        print("No files found in the directory.")
        return
    
    output_file = "file_list.json"
    with open(output_file, 'w') as f:
        json.dump(file_hashes, f, indent=4)
    print(f"✓ File list saved to {output_file} ({len(file_hashes)} files)")

if __name__ == "__main__":
    print("File Integrity Checker")
    print("1. Initialize file list")
    print("2. Monitor files for changes")
    choice = input("Choose an option (1/2): ")

    if choice == "1":
        directory = input("Enter the directory to monitor: ")
        hash_function = input("Enter the hash function (default: sha256): ") or "sha256"
        initialize_file_list(directory, hash_function)
    elif choice == "2":
        file_list_path = input("Enter the file list path (e.g., file_list.json): ")
        hash_function = input("Enter the hash function (default: sha256): ") or "sha256"
        monitor_files(file_list_path, hash_function)
    else:
        print("Invalid choice. Exiting.")
