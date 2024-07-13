import os

def traverse_directory_and_save_content(output_filename='file_contents2.txt'):
    cwd = os.getcwd()
    ignored_extensions = ['.lock', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff','.sum','.mod']

    with open(output_filename, 'w') as output_file:
        for root, dirs, files in os.walk(cwd):
            # Skip .github, target, and .git folders
            dirs[:] = [d for d in dirs if d not in ['.github', 'target', '.git']]
            
            for file in files:
                # Skip files with ignored extensions
                if any(file.endswith(ext) for ext in ignored_extensions):
                    continue
                
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except Exception as e:
                    content = f"Could not read file: {e}"

                output_file.write(f"File: {file_path}\n")
                output_file.write(f"Content:\n{content}\n")
                output_file.write("=" * 80 + "\n")

if __name__ == "__main__":
    traverse_directory_and_save_content()
