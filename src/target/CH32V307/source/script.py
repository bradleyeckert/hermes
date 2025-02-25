import os

def count_user_folders(start_path):
    """
    Walks through all directories starting from start_path, counting subdirectories named 'User' or 'user'.
    
    Args:
    - start_path (str): The path from which to start the search.
    
    Returns:
    - int: The count of 'User' or 'user' named directories.
    """
    user_folder_count = 0
    
    # Walk through all directories and subdirectories
    for root, dirs, files in os.walk(start_path):
        # Check if 'User' or 'user' is among the directory names
        user_folder_count += dirs.count('User') + dirs.count('user')
    
    return user_folder_count

# Example usage
if __name__ == "__main__":
    start_directory = 'C:/sample_proj_resources/wch/projects/ch32v30x\ch32v307vct6-evt-r1-1v1/Samples'
    count = count_user_folders(start_directory)
    print(f"Number of 'User' or 'user' folders found: {count}")
