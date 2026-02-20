try:
    from labapi import Client, User, Notebook
    from labapi.tree import NotebookDirectory, NotebookPage
    from labapi.entry import TextEntry, Entry
    print("Imports successful")
except ImportError as e:
    print(f"Import failed: {e}")
    exit(1)
